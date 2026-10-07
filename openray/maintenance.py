"""Explicit retention with backups, retained event identities and safe path checks."""

from __future__ import annotations

import re
import shutil
import time
from pathlib import Path

from .storage import Store
from .validation import SITE_TARGETS


def maintain(
    store: Store,
    retention_days: int = 90,
    apply: bool = False,
    *,
    observation_days: int = 3,
    unlisted_days: int = 3,
) -> dict:
    if retention_days < 7:
        raise ValueError("retention must be at least seven days")
    if not 1 <= observation_days <= retention_days or unlisted_days < 1:
        raise ValueError("observation and unlisted windows must be at least a day")
    now, parent = time.time(), store.path.parent.resolve()
    cutoff = now - retention_days * 86400
    count = lambda sql, *args: store.db.execute("SELECT count(*) " + sql, args).fetchone()[0]  # noqa: E731
    # Global events come only from this collector's runs, whose ids cannot recur, so they expire
    # without tombstones. Regional bundle events keep tombstones so an old bundle never counts twice.
    global_events = ("FROM observation WHERE context='global' AND time<?", now - observation_days * 86400)
    regional_events = ("FROM observation WHERE context!='global' AND time<?", cutoff)
    # Site rows are only leased for accepted proxies; never-observed rows for the rest are
    # empty placeholders, and leasing re-creates one when its proxy is accepted.
    placeholder = (
        "FROM health WHERE target!='connectivity' AND observed_at=0 AND lease_owner IS NULL "
        "AND proxy_id IN (SELECT id FROM proxy WHERE accepted=0)"
    )
    checked = ("connectivity",) + tuple(target.id for target in SITE_TARGETS)
    marks = ",".join("?" for _ in checked)
    # Targets no longer checked can neither change nor be exported.
    dropped_targets = [
        f"FROM {t} WHERE context='global' AND target NOT IN ({marks})" for t in ("health", "observation")
    ]
    # Never-accepted candidates no source has listed for days; a source that lists one again re-adds it.
    unlisted = ("FROM proxy WHERE accepted=0 AND seen<?", now - unlisted_days * 86400)
    # Aliases that differ only by remark name the same proxy; discovery matches on the text before '#'.
    remarks = (
        "FROM alias WHERE rowid NOT IN (SELECT min(rowid) FROM alias "
        "GROUP BY proxy_id,substr(uri,1,instr(uri||'#','#')-1))"
    )
    stale = store.db.execute(
        "SELECT id FROM snapshot WHERE created<? AND published=1 ORDER BY created DESC", (cutoff,)
    ).fetchall()[2:]
    snapshots = [parent / "snapshots" / row[0] for row in stale if re.fullmatch(r"[a-f0-9]{64}", row[0])]
    runs = []
    for path in (parent / "runs").glob("*.json"):
        if path.stat().st_mtime >= cutoff:
            continue
        if path.name.endswith(".bundle.json"):
            bundle_id = path.name.removesuffix(".bundle.json")
            if not store.db.execute(
                "SELECT 1 FROM meta WHERE key=?", ("published_bundle:" + bundle_id,)
            ).fetchone():
                continue  # Unpublished completed regional work is never removed.
        runs.append(path)
    report = {
        "dry_run": not apply,
        # The legacy history stays in git (.state/tested*.txt.bin); the scheduler never read this copy.
        "legacy_hashes_to_drop": count("FROM legacy_tested"),
        "global_observations_to_drop": count(*global_events),
        "regional_observations_to_archive": count(*regional_events),
        "placeholders_to_drop": count(placeholder),
        "dropped_target_rows": sum(count(sql, *checked) for sql in dropped_targets),
        "unlisted_candidates_to_purge": count(*unlisted),
        "remark_aliases_to_drop": count(remarks),
        "snapshots_to_prune": len(snapshots),
        "run_files_to_prune": len(runs),
        "integrity": store.db.execute("PRAGMA integrity_check").fetchone()[0],
    }
    if apply:
        if report["integrity"] != "ok":
            raise ValueError("maintenance rejected a corrupt database")
        if store.db.execute("SELECT 1 FROM health WHERE lease_until>? LIMIT 1", (now,)).fetchone():
            raise ValueError("maintenance requires idle validation workers")
        if any(v for k, v in report.items() if k not in {"dry_run", "integrity"}):
            store.backup(parent / "backups" / ("maintenance-" + str(time.time_ns()) + ".sqlite3"))
        # Children are deleted before their proxies. Per-row foreign key enforcement would scan the
        # unindexed alias.proxy_id once per purged proxy (over an hour for 130,000); one full check
        # before commit keeps the same guarantee.
        store.db.execute("PRAGMA foreign_keys=OFF")
        try:
            with store.transaction() as db:
                db.execute("DELETE " + placeholder)
                for sql in dropped_targets:
                    db.execute("DELETE " + sql, checked)
                db.execute("CREATE TEMP TABLE gone AS SELECT id " + unlisted[0], (unlisted[1],))
                for table in ("observation", "alias", "health", "score"):
                    db.execute(f"DELETE FROM {table} WHERE proxy_id IN (SELECT id FROM gone)")
                db.execute("DELETE FROM proxy WHERE id IN (SELECT id FROM gone)")
                db.execute("DROP TABLE gone")
                db.execute("DELETE " + remarks)
                db.execute("DELETE FROM legacy_tested")
                db.execute("INSERT OR IGNORE INTO meta VALUES('legacy_history_released',?)", (str(now),))
                db.execute(
                    "INSERT OR IGNORE INTO event_identity SELECT event_id,run,proxy_id,context,target,version "
                    + regional_events[0],
                    (regional_events[1],),
                )
                db.execute("DELETE " + regional_events[0], (regional_events[1],))
                db.execute("DELETE " + global_events[0], (global_events[1],))
                db.execute("DELETE FROM source WHERE fetched<? AND body IS NULL", (cutoff,))
                if db.execute("PRAGMA foreign_key_check").fetchone():
                    raise ValueError("maintenance would orphan rows")
        finally:
            store.db.execute("PRAGMA foreign_keys=ON")
        # Only acknowledged immutable snapshots are eligible, and two old ones remain.
        for path in snapshots:
            _safe(path, parent / "snapshots")
            if path.exists():
                shutil.rmtree(path)
            with store.transaction() as db:
                db.execute("DELETE FROM snapshot WHERE id=?", (path.name,))
        for path in runs:
            _safe(path, parent / "runs")
            path.unlink(missing_ok=True)
        # Preserve legacy backups indefinitely until the operational cutover is signed off.
        backups = sorted(
            (parent / "backups").glob("maintenance-*.sqlite3"), key=lambda p: p.stat().st_mtime, reverse=True
        )
        for path in backups[2:]:
            if path.stat().st_mtime < cutoff:
                _safe(path, parent / "backups")
                path.unlink()
        store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        free, pages = (
            store.db.execute(f"PRAGMA {name}").fetchone()[0] for name in ("freelist_count", "page_count")
        )
        # A few daily expiries used to rewrite the whole file on every run.
        if free > pages // 10:
            store.db.execute("VACUUM")
        store.db.execute("PRAGMA optimize")
    return report


def _safe(path: Path, directory: Path):
    resolved, boundary = path.resolve(), directory.resolve()
    if path.is_symlink() or not resolved.is_relative_to(boundary) or resolved == boundary:
        raise ValueError("unsafe retention path")
