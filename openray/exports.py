from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path, PurePosixPath

from .domain import ALIASES, SCHEMES, Proxy
from .files import atomic_write, json_text, lines_text
from .geo import Geo
from .render import convert
from .storage import SCHEMA_VERSION, Store, file_sha256
from .validation import SITE_TARGETS
from .yamlio import dump_yaml


def rank(proxies: list[Proxy], scores: dict, context: str) -> list[Proxy]:
    def key(p):
        values = scores.get(p.identity, {})
        primary = values.get(context, 0)
        secondary = values.get("iran", 0) if context == "global" else values.get("global", 0)
        if context in {"mci", "irancell", "tci", "others"}:
            return (-primary, -values.get("iran", 0), -values.get("global", 0), p.identity)
        return (-primary, -secondary, p.identity)

    return sorted(proxies, key=key)[:100]


def build_snapshot(
    store: Store, root: Path, destination: Path, *, local: bool = False, local_context="others"
) -> Path:
    import yaml

    proxies, scores, health = store.view()
    geo = Geo(root)
    counters: dict[str, int] = {}
    try:
        proxies = [geo.label(p, counters) for p in proxies]
    finally:
        geo.close()
    files: dict[str, bytes] = {}

    def write(name: str, content: str):
        files[name] = content.encode("utf-8")

    write("output/all_valid_proxies.txt", lines_text(p.uri for p in proxies))
    write("output/main_top100_checked.txt", lines_text(p.uri for p in rank(proxies, scores, "global")))
    if local:
        locally_valid = {
            h["proxy_id"]
            for h in health
            if h["context"] == local_context
            and h["target"] == "connectivity"
            and h["last_success"] is not None
            and h["outcome"] == "success"
        }
        write(
            "output/Iran_valid_proxies.txt", lines_text(p.uri for p in proxies if p.identity in locally_valid)
        )
    for kind in sorted((SCHEMES - set(ALIASES)) | {p.scheme for p in proxies}):
        write(f"output/kind/{kind}.txt", lines_text(p.uri for p in proxies if p.scheme == kind))
    country_contract = json.loads((Path(__file__).parent / "assets/public-countries.json").read_text())
    for cc in sorted(set(country_contract) | {p.country for p in proxies}):
        write(f"output/country/{cc}.txt", lines_text(p.uri for p in proxies if p.country == cc))
    iran_ids = {
        h["proxy_id"]
        for h in health
        if h["context"] in {"iran", "mci", "irancell", "tci", "others"}
        and h["target"] == "connectivity"
        and h["last_success"] is not None
        and h["outcome"] == "success"
    }
    iran_proxies = [p for p in proxies if p.identity in iran_ids]
    if not local:
        write("output/Iran_valid_proxies.txt", lines_text(p.uri for p in iran_proxies))
    write("output_iran/all_valid_proxies.txt", lines_text(p.uri for p in iran_proxies))
    write("output_iran/all_valid_proxies_for_iran.txt", lines_text(p.uri for p in iran_proxies))
    conversions = [
        ("output/converted/all_valid_proxies", proxies),
        ("output_iran/converted/iran_all_valid_proxies", iran_proxies),
    ]
    for context in ("iran", "mci", "irancell", "tci", "others"):
        ranked = rank(proxies, scores, context)
        name = "iran_top100_checked.txt" if context == "iran" else context + "_top100.txt"
        write("output_iran/" + name, lines_text(p.uri for p in ranked))
        if context == "iran":
            write("output_iran/iran_top100.txt", lines_text(p.uri for p in ranked))
        conversions.append((f"output_iran/converted/{context}_top100", ranked))
    site_ids = tuple(target.id for target in SITE_TARGETS)
    # Sites are only re-checked through proxies that pass connectivity, so require it here too.
    alive = {
        h["proxy_id"]
        for h in health
        if h["context"] == "global" and h["target"] == "connectivity" and h["outcome"] == "success"
    }
    sets = {}
    for site in site_ids:
        eligible = {
            h["proxy_id"]
            for h in health
            if h["context"] == "global"
            and h["target"] == site
            and h["outcome"] == "success"
            and h["last_success"] is not None
            and h["proxy_id"] in alive
        }
        sets[site] = eligible
        write(f"output/site_access/{site}.txt", lines_text(p.uri for p in proxies if p.identity in eligible))
    common = set.intersection(*sets.values())
    write("output/site_access/all_sites.txt", lines_text(p.uri for p in proxies if p.identity in common))
    clash_path, sing_path = root / "src/converter/config.yaml", root / "src/converter/singbox.json"
    assets = Path(__file__).parent / "assets"
    clash_template = (
        yaml.safe_load(clash_path.read_text(encoding="utf-8"))
        if clash_path.exists()
        else json.loads((assets / "clash-template.json").read_text(encoding="utf-8"))
    )
    sing_template = json.loads(
        (sing_path if sing_path.exists() else assets / "singbox-template.json").read_text(encoding="utf-8")
    )
    reports = {}
    for prefix, collection in conversions:
        clash, sing, report = convert(
            collection,
            clash_template,
            sing_template,
            portable=os.environ.get("OPENRAY_CLIENT_TUN", "0") != "1",
        )
        write(prefix + "_clash_config.yaml", dump_yaml(clash))
        write(prefix + "_singbox_config.json", json_text(sing))
        reports[prefix] = report
    if os.environ.get("OPENRAY_EXPORT_V2RAY", "").lower() in {"1", "true", "yes", "on"}:
        from .render import Unsupported, xray_outbound

        report = []
        for p in proxies:
            try:
                outbound = xray_outbound(p)
                name = re.sub(r'[\\/:*?"<>|]', "_", p.remark or p.identity[:12])
                name = re.sub(r"\s+", "_", name).strip("._ ")[:120] + ".json"
                config = {
                    "log": {"loglevel": "warning"},
                    "inbounds": [
                        {"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"udp": True}}
                    ],
                    "outbounds": [outbound],
                }
                write("output/v2ray_configs/" + name, json_text(config))
            except (Unsupported, ValueError, KeyError):
                report.append(
                    {"id": p.identity, "format": "xray", "reason": "no faithful Xray export adapter"}
                )
        reports["output/v2ray_configs"] = report
    write("output/conversion_report.json", json_text(reports))
    # Compatibility scores are a materialized export, never authoritative state.
    counts = {
        p.uri: {
            "global": scores.get(p.identity, {}).get("global", 0),
            "iran": {
                "total": scores.get(p.identity, {}).get("iran", 0),
                "operators": {
                    k: scores.get(p.identity, {}).get(k, 0) for k in ("mci", "irancell", "tci", "others")
                },
            },
        }
        for p in proxies
    }
    write("output/check_counts.json", json_text(counts))
    write("output/.state/check_counts.json", json_text(counts))
    manifest = {
        "schema": 1,
        "database_schema": SCHEMA_VERSION,
        "identity_version": 2,
        "proxy_count": len(proxies),
        "files": {
            name: {"sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)}
            for name, body in sorted(files.items())
        },
        "client_profiles": {"singbox": "1.14.1", "mihomo": "1.19.16"},
        "format_omissions": sum(len(v) for v in reports.values()),
    }
    from . import __version__

    package = Path(__file__).parent
    manifest["producer"] = {
        "version": __version__,
        "code_sha256": hashlib.sha256(
            json_text(
                {
                    p.relative_to(package).as_posix(): hashlib.sha256(
                        p.read_text(encoding="utf-8").encode()
                    ).hexdigest()
                    for p in sorted(package.rglob("*.py"))
                }
            ).encode()
        ).hexdigest(),
        "core_lock_sha256": file_sha256(package / "assets/cores.lock.json"),
        "rules_lock_sha256": file_sha256(package / "assets/rules.lock.json"),
        "templates_sha256": hashlib.sha256(json_text([clash_template, sing_template]).encode()).hexdigest(),
        "geo_mmdb_sha256": file_sha256(root / "src/GeoLite2-Country.mmdb")
        if (root / "src/GeoLite2-Country.mmdb").is_file()
        else None,
    }
    snapshot_id = hashlib.sha256(json_text(manifest).encode()).hexdigest()
    manifest["id"] = snapshot_id
    staging = destination / snapshot_id
    for name, body in files.items():
        atomic_write(staging / name, body)
    atomic_write(staging / "output/manifest.json", json_text(manifest))
    verify_snapshot(staging)
    with store.transaction() as db:
        db.execute(
            "INSERT OR IGNORE INTO snapshot VALUES(?,?,?,0)",
            (snapshot_id, json_text(manifest), __import__("time").time()),
        )
    return staging


def verify_snapshot(snapshot: Path) -> dict:
    import yaml

    manifest = json.loads((snapshot / "output/manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != 1:
        raise ValueError("unsupported snapshot manifest")
    claimed = manifest["id"]
    unsigned = dict(manifest)
    del unsigned["id"]
    if hashlib.sha256(json_text(unsigned).encode()).hexdigest() != claimed:
        raise ValueError("snapshot manifest identity mismatch")
    for name, info in manifest["files"].items():
        if "\\" in name or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:
            raise ValueError("unsafe snapshot path")
        path = (snapshot / name).resolve()
        if not path.is_relative_to(snapshot.resolve()) or name.split("/")[0] not in {"output", "output_iran"}:
            raise ValueError("unsafe snapshot path")
        if path.stat().st_size != info["bytes"] or file_sha256(path) != info["sha256"]:
            raise ValueError("snapshot file hash mismatch")
        if name.endswith(".json"):
            json.loads(path.read_text(encoding="utf-8"))
        elif name.endswith(".yaml"):
            yaml.safe_load(path.read_text(encoding="utf-8"))
    raw = (snapshot / "output/all_valid_proxies.txt").read_text(encoding="utf-8").splitlines()
    if len(raw) != manifest["proxy_count"] or len(set(raw)) != len(raw):
        raise ValueError("snapshot proxy count/dedup mismatch")
    for directory in ("kind", "country"):
        partition = [
            line
            for name in manifest["files"]
            if name.startswith(f"output/{directory}/")
            for line in (snapshot / name).read_text(encoding="utf-8").splitlines()
        ]
        if sorted(partition) != sorted(raw):
            raise ValueError("snapshot partition mismatch")
    return manifest


def validate_clients(snapshot: Path, singbox: str = "", mihomo: str = "") -> list[dict]:
    return asyncio.run(validate_clients_async(snapshot, singbox, mihomo))


async def validate_clients_async(
    snapshot: Path, singbox: str = "", mihomo: str = "", *, deadline: float | None = None
) -> list[dict]:
    from .validation import spawn_owned, terminate

    deadline = deadline if deadline is not None else time.monotonic() + 120
    snapshot = snapshot.resolve()
    manifest = verify_snapshot(snapshot)
    results = []
    with tempfile.TemporaryDirectory(prefix="openray-clients-") as cache:
        for name in manifest["files"]:
            command = None
            if name.endswith("_singbox_config.json") and singbox:
                command = [singbox, "check", "-c", str(snapshot / name)]
            elif name.endswith("_clash_config.yaml") and mihomo:
                command = [mihomo, "-t", "-d", cache, "-f", str(snapshot / name)]
            if command:
                valid = False
                diagnostic = Path(cache) / "diagnostic.log"
                with diagnostic.open("wb") as log:
                    process = None
                    try:
                        async with asyncio.timeout_at(min(deadline, time.monotonic() + 60)):
                            if time.monotonic() >= deadline:
                                raise TimeoutError
                            process = await spawn_owned(
                                *command,
                                stdout=log,
                                stderr=asyncio.subprocess.STDOUT,
                                cwd=cache,
                                creationflags=0x08000000 if os.name == "nt" else 0,
                            )
                            await process.wait()
                            valid = process.returncode == 0
                    except (TimeoutError, OSError):
                        pass
                    finally:
                        await asyncio.shield(terminate(process))
                # Core diagnostics can contain credentials; retain only hash and outcome.
                results.append(
                    {
                        "file": name,
                        "valid": valid,
                        "diagnostic_sha256": file_sha256(diagnostic),
                    }
                )
    return results
