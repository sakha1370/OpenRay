from __future__ import annotations

import asyncio
import collections
import dataclasses
import shutil
import time
import uuid
from pathlib import Path

from .config import Settings
from .domain import Observation, Outcome
from .exports import build_snapshot, validate_clients_async
from .fetch import discover
from .files import atomic_write, json_text
from .publishing import install_snapshot
from .scheduling import validate_batch
from .storage import Store, file_sha256, migrate
from .validation import SITE_TARGETS, Target, Validator


def legacy_backup(root: Path, destination: Path):
    destination.mkdir(parents=True, exist_ok=True)
    manifest = {}
    paths = list((root / ".state").glob("*.json")) + list((root / ".state").glob("tested*.txt*"))
    paths += (
        list((root / "output").glob("*.txt"))
        + list((root / "src/converter").glob("*.json"))
        + list((root / "src/converter").glob("*.yaml"))
    )
    for source in paths:
        if not source.is_file():
            continue
        relative = source.relative_to(root)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        digest = file_sha256(source)
        if file_sha256(target) != digest:
            raise RuntimeError("legacy backup verification failed")
        manifest[relative.as_posix()] = digest
    atomic_write(destination / "manifest.json", json_text(manifest))


def initialize(store: Store, root: Path) -> dict:
    if store.db.execute("SELECT 1 FROM meta WHERE key='legacy_migrated'").fetchone():
        return {}
    backup = store.path.parent / "backups" / ("legacy-" + uuid.uuid4().hex)
    legacy_backup(root, backup)
    report = migrate(store, root)
    atomic_write(backup / "migration_report.json", json_text(report))
    return report


async def run(
    settings: Settings,
    mode: str = "combined",
    context: str = "global",
    *,
    install: bool = False,
    validator_factory=Validator,
) -> tuple[int, dict]:
    started = time.monotonic()
    run_id = uuid.uuid4().hex
    deadline = started + settings.budget
    # Exports and 14 client gates took 17-29 s in production; short budgets keep the full reserve.
    validation_deadline = deadline - min(60, settings.budget * 0.25)
    stats = {
        "run": run_id,
        "mode": mode,
        "context": context,
        "outcomes": {},
        "checks": 0,
        "budget_exhausted": False,
        "snapshot": "",
        "core_errors": 0,
    }
    with Store(settings.database) as store:
        stats["migration"] = initialize(store, settings.root)
        installed_manifest = settings.root / "output/manifest.json"
        if installed_manifest.is_file():
            from .exports import verify_snapshot

            try:
                acknowledged = verify_snapshot(settings.root)["id"]
            except (ValueError, OSError):
                acknowledged = ""
            with store.transaction() as db:
                db.execute("UPDATE snapshot SET published=1 WHERE id=?", (acknowledged,))
        stats["recovered_pending"] = store.recover_pending()
        if not any((settings.xray, settings.singbox, settings.mihomo)) and validator_factory is Validator:
            stats["error"] = "validation requires an installed core"
            stats["core_errors"] = 1
            stats["wall_s"] = time.monotonic() - started
            atomic_write(settings.database.parent / "runs" / (run_id + ".json"), json_text(stats))
            return 2, stats
        results = []
        targets = (
            SITE_TARGETS
            if mode == "sites"
            else (
                Target(
                    "connectivity",
                    (settings.test_url,),
                    allowed=(settings.test_status,),
                    body_sha256=settings.body_sha256,
                ),
            )
        )
        if mode == "combined" and context == "global" and settings.check_sites:
            targets += SITE_TARGETS
        try:
            async with asyncio.timeout_at(validation_deadline):
                # Time a stage leaves unused flows to later stages instead of idling.
                carry = 0.0
                if mode in {"combined", "discovery"}:
                    allowance = min(validation_deadline - time.monotonic(), settings.budget * 0.15)
                    began = time.monotonic()
                    try:
                        async with asyncio.timeout(allowance):
                            stats["discovery"] = await discover(settings, store)
                    except TimeoutError:
                        stats["discovery"] = {"budget_exhausted": True}
                    stats["discovery_s"] = time.monotonic() - began
                    carry = max(0.0, allowance - stats["discovery_s"])
                async with validator_factory(settings) as validator:
                    for target in targets:
                        # (accepted, retests): retests get their own share so due failures can
                        # reach retirement while never-checked candidates keep arriving.
                        categories = (
                            ((True, False), (False, True), (False, False))
                            if mode == "combined" and target.id == "connectivity"
                            else ((mode != "discovery", False),)
                        )
                        for index, (accepted, retests) in enumerate(categories):
                            remaining = max(0, validation_deadline - time.monotonic())
                            if len(targets) > 1:
                                fraction = (
                                    (0.30 if accepted else 0.15)
                                    if target.id == "connectivity"
                                    else (0.25 if mode == "combined" else 1) / len(SITE_TARGETS)
                                )
                                allotted = min(remaining, settings.budget * fraction + carry)
                            else:
                                allotted = remaining / (len(categories) - index)
                            began = time.monotonic()
                            validator.settings = dataclasses.replace(
                                settings, timeout=settings.existing_timeout if accepted else settings.timeout
                            )
                            # Workers consult immutable per-run settings; lease/probe deadline is selected here.
                            try:
                                await validate_batch(
                                    settings,
                                    store,
                                    validator,
                                    target,
                                    context,
                                    run_id,
                                    accepted,
                                    results,
                                    time.monotonic() + allotted,
                                    retests,
                                )
                            except TimeoutError:
                                stats["budget_exhausted"] = True
                            used = time.monotonic() - began
                            carry = max(0.0, allotted - used)
                            stats.setdefault("stages", []).append(
                                {
                                    "target": target.id,
                                    "accepted": accepted,
                                    "retests": retests,
                                    "allotted_s": round(allotted, 1),
                                    "used_s": round(used, 1),
                                    "checks": len(results)
                                    - sum(s["checks"] for s in stats.get("stages", [])),
                                }
                            )
        except TimeoutError:
            stats["budget_exhausted"] = True
        except BaseException:
            store.release(run_id)
            raise
        from .domain import parse_uri

        positives = {r["target"] for r in results if r["outcome"] == "success"}
        with store.transaction() as db:
            for item in results:
                if item["outcome"] not in {Outcome.PROXY_FAILURE.value, Outcome.TIMEOUT.value}:
                    continue
                if item["target"] not in positives:
                    item["outcome"] = Outcome.TARGET_FAILURE.value
                    item["detail"] = (
                        "batch lacks a successful positive control; failure not attributed to proxy"
                    )
                store.observe(
                    item["event_id"],
                    run_id,
                    parse_uri(item["uri"]),
                    context,
                    item["target"],
                    Observation(
                        Outcome(item["outcome"]),
                        item["elapsed_ms"],
                        item["detail"],
                        item["status"],
                        item["core"],
                    ),
                    version=item["version"],
                    now=item["time"],
                    cooldown=settings.cooldown,
                    death_after=settings.death_after,
                    db=db,
                )
                db.execute("DELETE FROM pending WHERE event_id=?", (item["event_id"],))
            db.execute("UPDATE health SET lease_owner=NULL,lease_until=NULL WHERE lease_owner=?", (run_id,))
        counts = collections.Counter(item["outcome"] for item in results)
        stats["checks"], stats["outcomes"] = len(results), dict(counts)
        stats["core_errors"] = counts[Outcome.CORE_FAILURE.value]
        stats["wall_s"] = time.monotonic() - started
        stats["checks_per_minute"] = len(results) * 60 / stats["wall_s"] if stats["wall_s"] else 0
        stats["p50_ms"] = _percentile(results, 0.5)
        stats["p95_ms"] = _percentile(results, 0.95)
        stats["p99_ms"] = _percentile(results, 0.99)
        stats["due"] = store.due(context)
        stats["pending_due"] = sum(v for k, v in stats["due"].items() if k != "retired")
        if context != "global":
            bundle = {"schema": 1, "id": run_id, "context": context, "observations": results}
            bundle_path = settings.database.parent / "runs" / (run_id + ".bundle.json")
            atomic_write(bundle_path, json_text(bundle))
            stats["bundle"] = str(bundle_path.resolve())
        code = 2 if stats["core_errors"] else 0
        if not stats["core_errors"]:
            snapshot = build_snapshot(
                store,
                settings.root,
                settings.database.parent / "snapshots",
                local=mode == "local",
                local_context=context,
            )
            stats["client_validation"] = await validate_clients_async(
                snapshot, settings.singbox, settings.mihomo, deadline=deadline
            )
            if (
                any(not item["valid"] for item in stats["client_validation"])
                or install
                and not (settings.singbox and settings.mihomo)
            ):
                code = 3
            else:
                stats["snapshot"] = str(snapshot.resolve())
                if install:
                    install_snapshot(snapshot, settings.root)
        stats["validation_wall_s"] = stats["wall_s"]
        stats["wall_s"] = time.monotonic() - started
        stats["checks_per_minute"] = len(results) * 60 / stats["wall_s"] if stats["wall_s"] else 0
        atomic_write(settings.database.parent / "runs" / (run_id + ".json"), json_text(stats))
        return code, stats


def _percentile(results: list[dict], q: float) -> float:
    if not results:
        return 0
    values = sorted(item["elapsed_ms"] for item in results)
    return values[min(len(values) - 1, int((len(values) - 1) * q))]
