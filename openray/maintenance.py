"""Explicit retention with backups, retained event identities and safe path checks."""

from __future__ import annotations

import re
import shutil
import time
from pathlib import Path

from .storage import Store


def maintain(store: Store, retention_days: int = 90, apply: bool = False) -> dict:
    if retention_days < 7:
        raise ValueError("retention must be at least seven days")
    now, parent = time.time(), store.path.parent.resolve()
    cutoff = now - retention_days * 86400
    expired = store.db.execute("SELECT count(*) FROM legacy_tested WHERE time<?", (cutoff,)).fetchone()[0]
    observations = store.db.execute("SELECT count(*) FROM observation WHERE time<?", (cutoff,)).fetchone()[0]
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
        "legacy_hashes_to_prune": expired,
        "observations_to_archive": observations,
        "snapshots_to_prune": len(snapshots),
        "run_files_to_prune": len(runs),
        "integrity": store.db.execute("PRAGMA integrity_check").fetchone()[0],
    }
    if apply:
        if report["integrity"] != "ok":
            raise ValueError("maintenance rejected a corrupt database")
        if store.db.execute("SELECT 1 FROM health WHERE lease_until>? LIMIT 1", (now,)).fetchone():
            raise ValueError("maintenance requires idle validation workers")
        store.backup(parent / "backups" / ("maintenance-" + str(time.time_ns()) + ".sqlite3"))
        with store.transaction() as db:
            db.execute("DELETE FROM legacy_tested WHERE time<?", (cutoff,))
            db.execute(
                "INSERT OR IGNORE INTO event_identity SELECT event_id,run,proxy_id,context,target,version "
                "FROM observation WHERE time<?",
                (cutoff,),
            )
            db.execute("DELETE FROM observation WHERE time<?", (cutoff,))
            db.execute("DELETE FROM source WHERE fetched<? AND body IS NULL", (cutoff,))
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
        if expired or observations:
            store.db.execute("VACUUM")
        store.db.execute("PRAGMA optimize")
    return report


def _safe(path: Path, directory: Path):
    resolved, boundary = path.resolve(), directory.resolve()
    if path.is_symlink() or not resolved.is_relative_to(boundary) or resolved == boundary:
        raise ValueError("unsafe retention path")
