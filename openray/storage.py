from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import sqlite3
import struct
import tempfile
import threading
import time
import uuid
from pathlib import Path

from .domain import IDENTITY_VERSION, Observation, Outcome, ParseError, Proxy, parse_uri
from .files import fsync_directory

SCHEMA_VERSION = 4
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS proxy(id TEXT PRIMARY KEY,identity_version INTEGER NOT NULL,
 uri TEXT NOT NULL,scheme TEXT NOT NULL,created REAL NOT NULL,accepted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS alias(uri TEXT PRIMARY KEY,proxy_id TEXT NOT NULL REFERENCES proxy(id),source TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS source(url TEXT PRIMARY KEY,etag TEXT,modified TEXT,body BLOB,
 fetched REAL,outcome TEXT,failures INTEGER NOT NULL DEFAULT 0,next_due REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS score(proxy_id TEXT NOT NULL REFERENCES proxy(id),context TEXT NOT NULL,
 count INTEGER NOT NULL DEFAULT 0 CHECK(count>=0),PRIMARY KEY(proxy_id,context));
CREATE TABLE IF NOT EXISTS health(proxy_id TEXT NOT NULL REFERENCES proxy(id),context TEXT NOT NULL,
 target TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 1,last_success REAL,first_failure REAL,
 failures INTEGER NOT NULL DEFAULT 0,next_due REAL NOT NULL DEFAULT 0,lease_owner TEXT,lease_until REAL,
 outcome TEXT,observed_at REAL NOT NULL DEFAULT 0,PRIMARY KEY(proxy_id,context,target));
CREATE INDEX IF NOT EXISTS health_due ON health(context,target,next_due,lease_until);
CREATE TABLE IF NOT EXISTS observation(event_id TEXT PRIMARY KEY,run TEXT NOT NULL,
 proxy_id TEXT NOT NULL REFERENCES proxy(id),context TEXT NOT NULL,target TEXT NOT NULL,
 version INTEGER NOT NULL,outcome TEXT NOT NULL,time REAL NOT NULL,elapsed_ms REAL NOT NULL,
 detail TEXT NOT NULL,status INTEGER,core TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS observation_proxy ON observation(proxy_id,context,target,time);
CREATE TABLE IF NOT EXISTS legacy_tested(hash BLOB PRIMARY KEY CHECK(length(hash)=20),time INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS migration(path TEXT PRIMARY KEY,sha256 TEXT NOT NULL,rows INTEGER NOT NULL,time REAL NOT NULL);
CREATE TABLE IF NOT EXISTS snapshot(id TEXT PRIMARY KEY,manifest TEXT NOT NULL,created REAL NOT NULL,published INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS bundle(id TEXT PRIMARY KEY,sha256 TEXT NOT NULL,imported REAL NOT NULL);
CREATE TABLE IF NOT EXISTS pending(event_id TEXT PRIMARY KEY,run TEXT NOT NULL,context TEXT NOT NULL,payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS event_identity(event_id TEXT PRIMARY KEY,run TEXT NOT NULL,proxy_id TEXT NOT NULL,
 context TEXT NOT NULL,target TEXT NOT NULL,version INTEGER NOT NULL);
"""


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=False)
        if os.name != "nt" and self.path.is_file():
            self.path.chmod(0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=30000")
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            self.close()
            raise ValueError("database schema is newer than this OpenRay")
        self.db.executescript(SCHEMA)
        with self.transaction() as db:
            if "observed_at" not in {r["name"] for r in db.execute("PRAGMA table_info(health)")}:
                db.execute("ALTER TABLE health ADD COLUMN observed_at REAL NOT NULL DEFAULT 0")
                db.execute(
                    "UPDATE health SET observed_at=max(COALESCE(last_success,0),COALESCE(first_failure,0),"
                    "COALESCE((SELECT max(time) FROM observation o WHERE o.proxy_id=health.proxy_id "
                    "AND o.context=health.context AND o.target=health.target AND o.version=health.version),0))"
                )
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    @contextlib.contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield self.db
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def add(self, proxy: Proxy, source: str = "", accepted: bool = False, db=None) -> bool:
        if db is None:
            with self.transaction() as tx:
                return self.add(proxy, source, accepted, tx)
        cursor = db.execute(
            "INSERT OR IGNORE INTO proxy VALUES(?,?,?,?,?,?)",
            (proxy.identity, IDENTITY_VERSION, proxy.uri, proxy.scheme, time.time(), int(accepted)),
        )
        db.execute("INSERT OR IGNORE INTO alias VALUES(?,?,?)", (proxy.uri, proxy.identity, source))
        if accepted:
            db.execute("UPDATE proxy SET accepted=1 WHERE id=?", (proxy.identity,))
        return cursor.rowcount == 1

    def lease(
        self,
        context: str,
        target: str,
        owner: str,
        limit: int,
        duration: float,
        *,
        now: float | None = None,
        accepted_only: bool = False,
        version: int = 1,
        source_only: bool = False,
    ) -> list[Proxy]:
        now = time.time() if now is None else now
        with self.transaction() as db:
            db.execute(
                "INSERT OR IGNORE INTO health(proxy_id,context,target,version) SELECT id,?,?,? FROM proxy",
                (context, target, version),
            )
            db.execute(
                "UPDATE health SET version=?,next_due=0,last_success=NULL,first_failure=NULL,failures=0,outcome=NULL,"
                "observed_at=0,lease_owner=NULL,lease_until=NULL WHERE context=? AND target=? AND version<?",
                (version, context, target, version),
            )
            rows = db.execute(
                "SELECT p.id,p.uri FROM health h JOIN proxy p ON p.id=h.proxy_id "
                "WHERE h.context=? AND h.target=? AND h.next_due<=? "
                "AND (h.lease_until IS NULL OR h.lease_until<=?) "
                "AND (?=0 OR p.accepted=1) AND (?=0 OR p.accepted=0) "
                "AND h.version=? "
                "AND NOT EXISTS (SELECT 1 FROM observation o WHERE o.proxy_id=h.proxy_id "
                "AND o.context=h.context AND o.target=h.target AND o.version=h.version AND o.run=?) "
                "ORDER BY h.next_due,p.created,p.id LIMIT ?",
                (context, target, now, now, int(accepted_only), int(source_only), version, owner, limit),
            ).fetchall()
            db.executemany(
                "UPDATE health SET lease_owner=?,lease_until=? WHERE proxy_id=? AND context=? AND target=?",
                [(owner, now + duration, r["id"], context, target) for r in rows],
            )
            return [parse_uri(r["uri"]) for r in rows]

    def release(self, owner: str):
        with self.transaction() as db:
            db.execute("UPDATE health SET lease_owner=NULL,lease_until=NULL WHERE lease_owner=?", (owner,))

    def pending(self, event_id: str, run: str, context: str, payload: dict):
        with self.transaction() as db:
            db.execute(
                "INSERT OR IGNORE INTO pending VALUES(?,?,?,?)", (event_id, run, context, json.dumps(payload))
            )

    def recover_pending(self):
        with self.transaction() as db:
            rows = db.execute(
                "SELECT * FROM pending p WHERE NOT EXISTS (SELECT 1 FROM health h "
                "WHERE h.lease_owner=p.run AND h.lease_until>?)",
                (time.time(),),
            ).fetchall()
            for row in rows:
                item = json.loads(row["payload"])
                self.observe(
                    row["event_id"],
                    row["run"],
                    parse_uri(item["uri"]),
                    row["context"],
                    item["target"],
                    Observation(
                        Outcome.TARGET_FAILURE,
                        item["elapsed_ms"],
                        "interrupted batch; proxy attribution unconfirmed",
                    ),
                    version=item["version"],
                    now=item["time"],
                    db=db,
                )
            db.executemany("DELETE FROM pending WHERE event_id=?", [(row["event_id"],) for row in rows])
            return len(rows)

    def observe(
        self,
        event_id: str,
        run: str,
        proxy: Proxy,
        context: str,
        target: str,
        result: Observation,
        *,
        version: int = 1,
        now: float | None = None,
        cooldown: float = 28800,
        death_after: float = 259200,
        db=None,
    ) -> bool:
        now = time.time() if now is None else now
        if not math.isfinite(now) or now < 0 or not math.isfinite(result.elapsed_ms) or result.elapsed_ms < 0:
            raise ValueError("invalid observation time/duration")
        if version < 1 or context not in {"global", "iran", "mci", "irancell", "tci", "others"}:
            raise ValueError("invalid observation version/context")
        if db is None:
            with self.transaction() as tx:
                return self.observe(
                    event_id,
                    run,
                    proxy,
                    context,
                    target,
                    result,
                    version=version,
                    now=now,
                    cooldown=cooldown,
                    death_after=death_after,
                    db=tx,
                )
        archived = db.execute(
            "SELECT run,proxy_id,context,target,version FROM event_identity WHERE event_id=?", (event_id,)
        ).fetchone()
        if archived:
            if tuple(archived) != (run, proxy.identity, context, target, version):
                raise ValueError("observation identity collision")
            return False
        self.add(proxy, db=db)
        inserted = db.execute(
            "INSERT OR IGNORE INTO observation VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event_id,
                run,
                proxy.identity,
                context,
                target,
                version,
                result.outcome.value,
                now,
                result.elapsed_ms,
                result.detail,
                result.status,
                result.core,
            ),
        )
        if not inserted.rowcount:
            prior = db.execute(
                "SELECT run,proxy_id,context,target,version FROM observation WHERE event_id=?", (event_id,)
            ).fetchone()
            if tuple(prior) != (run, proxy.identity, context, target, version):
                raise ValueError("observation identity collision")
            return False
        db.execute(
            "INSERT OR IGNORE INTO health(proxy_id,context,target,version) VALUES(?,?,?,?)",
            (proxy.identity, context, target, version),
        )
        row = db.execute(
            "SELECT * FROM health WHERE proxy_id=? AND context=? AND target=?",
            (proxy.identity, context, target),
        ).fetchone()
        if row["version"] > version:
            return True  # Old regional bundles remain auditable without reverting a newer target policy.
        if row["version"] < version:
            db.execute(
                "UPDATE health SET last_success=NULL,first_failure=NULL,failures=0,outcome=NULL,observed_at=0 "
                "WHERE proxy_id=? AND context=? AND target=?",
                (proxy.identity, context, target),
            )
            row = db.execute(
                "SELECT * FROM health WHERE proxy_id=? AND context=? AND target=?",
                (proxy.identity, context, target),
            ).fetchone()
        last_success, first_failure, failures = row["last_success"], row["first_failure"], row["failures"]
        health_outcome = row["outcome"]
        # Regional runs can arrive out of order. Historical successes still count
        # exactly once, but only the latest observation may change current health.
        if result.outcome == Outcome.SUCCESS and target == "connectivity":
            db.execute(
                "INSERT INTO score VALUES(?,?,1) ON CONFLICT(proxy_id,context) DO UPDATE SET count=count+1",
                (proxy.identity, context),
            )
            if context in {"mci", "irancell", "tci", "others"}:
                db.execute(
                    "INSERT INTO score VALUES(?,'iran',1) ON CONFLICT(proxy_id,context) DO UPDATE SET count=count+1",
                    (proxy.identity,),
                )
        if now < row["observed_at"]:
            return True
        if result.outcome == Outcome.SUCCESS:
            health_outcome = result.outcome.value
            last_success, first_failure, failures = now, None, 0
            if target == "connectivity":
                if context == "global":
                    db.execute("UPDATE proxy SET accepted=1 WHERE id=?", (proxy.identity,))
            next_due = now + cooldown
        elif result.outcome in {Outcome.PROXY_FAILURE, Outcome.TIMEOUT, Outcome.BLOCKED}:
            health_outcome = result.outcome.value
            first_failure = now if first_failure is None else first_failure
            failures += 1
            next_due = now + cooldown
            if (
                context == "global"
                and target == "connectivity"
                and failures >= 2
                and now - first_failure >= death_after
            ):
                db.execute("UPDATE proxy SET accepted=0 WHERE id=?", (proxy.identity,))
        else:
            # Scheduling advances without contaminating connection health.
            next_due = now + (3600 if result.outcome in {Outcome.UNSUPPORTED, Outcome.INVALID_CONFIG} else 60)
        db.execute(
            "UPDATE health SET version=?,last_success=?,first_failure=?,failures=?,next_due=?,"
            "lease_owner=CASE WHEN lease_owner=? THEN NULL ELSE lease_owner END,"
            "lease_until=CASE WHEN lease_owner=? THEN NULL ELSE lease_until END,"
            "outcome=?,observed_at=? WHERE proxy_id=? AND context=? AND target=?",
            (
                version,
                last_success,
                first_failure,
                failures,
                next_due,
                run,
                run,
                health_outcome,
                now,
                proxy.identity,
                context,
                target,
            ),
        )
        return True

    def view(self) -> tuple[list[Proxy], dict[str, dict[str, int]], list[dict]]:
        with self.transaction() as db:
            proxies = [
                parse_uri(r[0]) for r in db.execute("SELECT uri FROM proxy WHERE accepted=1 ORDER BY id")
            ]
            scores: dict[str, dict[str, int]] = {}
            for row in db.execute("SELECT * FROM score"):
                scores.setdefault(row["proxy_id"], {})[row["context"]] = row["count"]
            health = [dict(r) for r in db.execute("SELECT * FROM health ORDER BY proxy_id,context,target")]
            return proxies, scores, health

    def backup(self, destination: Path):
        destination = Path(destination)
        if destination.resolve() == self.path.resolve() or any(
            Path(str(destination) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")
        ):
            raise ValueError("backup destination must not be a live database")
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".backup-", suffix=".sqlite3", dir=destination.parent)
        os.close(descriptor)
        temporary = Path(temporary)
        try:
            with self.lock, contextlib.closing(sqlite3.connect(temporary)) as target:
                self.db.backup(target)
                if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise RuntimeError("backup integrity check failed")
            with temporary.open("r+b") as handle:
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            fsync_directory(destination.parent)
        finally:
            temporary.unlink(missing_ok=True)

    def status(self) -> dict:
        return {
            table: self.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in (
                "proxy",
                "alias",
                "observation",
                "event_identity",
                "health",
                "legacy_tested",
                "snapshot",
            )
        }

    def import_bundle(self, payload: dict) -> int:
        if (
            not isinstance(payload, dict)
            or not isinstance(payload.get("id"), str)
            or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", payload["id"])
            or not isinstance(payload.get("observations"), list)
            or len(payload["observations"]) > 100000
        ):
            raise ValueError("invalid regional bundle structure")
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(encoded).hexdigest()
        if payload.get("schema") != 1 or payload.get("context") not in {
            "iran",
            "mci",
            "tci",
            "irancell",
            "others",
        }:
            raise ValueError("invalid regional bundle schema/context")
        count = 0
        with self.transaction() as db:
            existing = db.execute("SELECT sha256 FROM bundle WHERE id=?", (payload["id"],)).fetchone()
            if existing:
                if existing[0] != digest:
                    raise ValueError("bundle identity collision")
                return 0
            for item in payload["observations"]:
                if (
                    not isinstance(item, dict)
                    or not isinstance(item.get("uri"), str)
                    or not isinstance(item.get("event_id"), str)
                    or not 1 <= len(item["event_id"]) <= 128
                    or not isinstance(item.get("target", "connectivity"), str)
                    or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", item.get("target", "connectivity"))
                    or not isinstance(item.get("outcome"), str)
                    or not isinstance(item.get("detail", ""), str)
                    or len(item.get("detail", "")) > 1024
                    or not isinstance(item.get("core", ""), str)
                    or len(item.get("core", "")) > 64
                    or len(item["uri"]) > 65536
                ):
                    raise ValueError("invalid regional observation structure")
                status = item.get("status")
                if status is not None and (type(status) is not int or not 100 <= status <= 599):
                    raise ValueError("invalid regional HTTP status")
                elapsed = item.get("elapsed_ms", 0)
                if (
                    not isinstance(elapsed, (int, float))
                    or not math.isfinite(elapsed)
                    or not 0 <= elapsed <= 86400000
                ):
                    raise ValueError("invalid regional observation duration")
                version = item.get("version", 1)
                if not isinstance(version, int) or not 1 <= version <= 100000:
                    raise ValueError("invalid regional target version")
                proxy = parse_uri(item["uri"])
                result = Observation(
                    Outcome(item["outcome"]),
                    item.get("elapsed_ms", 0),
                    item.get("detail", ""),
                    item.get("status"),
                    item.get("core", ""),
                )
                if (
                    not isinstance(item.get("time"), (int, float))
                    or not math.isfinite(item["time"])
                    or not 0 <= item["time"] <= time.time() + 300
                ):
                    raise ValueError("invalid regional observation time")
                count += self.observe(
                    item["event_id"],
                    payload["id"],
                    proxy,
                    payload["context"],
                    item.get("target", "connectivity"),
                    result,
                    version=item.get("version", 1),
                    now=item["time"],
                    db=db,
                )
            db.execute("INSERT INTO bundle VALUES(?,?,?)", (payload["id"], digest, time.time()))
        return count


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def restore_backup(source: Path, destination: Path):
    source, destination = source.resolve(), destination.resolve()
    if destination.exists():
        raise ValueError(
            "restore requires an absent destination database; preserve the existing checkpoint first"
        )
    if not source.is_file() or Path(str(source) + "-wal").exists():
        raise ValueError("restore requires a closed transactional backup, not a live WAL database")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".restore-" + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    try:
        with contextlib.closing(sqlite3.connect(source.as_uri() + "?immutable=1", uri=True)) as original:
            version = original.execute("PRAGMA user_version").fetchone()[0]
            if (
                version < 1
                or version > SCHEMA_VERSION
                or original.execute("PRAGMA integrity_check").fetchone()[0] != "ok"
            ):
                raise ValueError("invalid or incompatible checkpoint")
            with contextlib.closing(sqlite3.connect(temporary)) as restored:
                original.backup(restored)
        with temporary.open("r+b") as f:
            os.fsync(f.fileno())
        os.replace(temporary, destination)
        fsync_directory(destination.parent)
    finally:
        temporary.unlink(missing_ok=True)


def migrate(store: Store, root: Path) -> dict:
    """Read-only legacy inputs. Baseline scores merge by max, never by ambiguous addition."""
    report = {"invalid": 0, "aliases": 0, "score_aliases": 0, "tested": 0, "site_negatives": 0}
    available = root / "output/all_valid_proxies.txt"
    counts = root / ".state/check_counts.json"
    paths = ([available] if available.exists() else []) + ([counts] if counts.exists() else [])
    paths += sorted((root / ".state").glob("tested*.txt*"))
    site = root / ".state/site_access_blocked.json"
    if site.exists():
        paths.append(site)
    with store.transaction() as db:
        for path in paths:
            digest = file_sha256(path)
            prior = db.execute("SELECT sha256 FROM migration WHERE path=?", (str(path.resolve()),)).fetchone()
            if prior:
                if prior[0] != digest:
                    raise ValueError(
                        "legacy input changed after import; use an explicit new migration database"
                    )
                continue
            count = 0
            if path == available:
                for line in path.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    try:
                        proxy = parse_uri(line)
                        store.add(proxy, "legacy-valid", True, db)
                        count += 1
                    except ParseError:
                        report["invalid"] += 1
            elif path == counts:
                for uri, value in json.loads(path.read_text(encoding="utf-8")).items():
                    try:
                        proxy = parse_uri(uri)
                    except ParseError:
                        report["invalid"] += 1
                        continue
                    store.add(proxy, "legacy-score", db=db)
                    report["score_aliases"] += 1
                    values = {"global": value} if isinstance(value, int) else dict(value)
                    if "global" not in values and "main" in values:
                        values["global"] = values["main"]
                    iran = values.get("iran", {})
                    if isinstance(iran, int):
                        values["iran"] = iran
                    elif isinstance(iran, dict):
                        operators = iran.get("operators", iran)
                        values.update(
                            {k: v for k, v in operators.items() if k in {"mci", "irancell", "tci", "others"}}
                        )
                        values["iran"] = int(
                            iran.get(
                                "total",
                                sum(int(operators.get(k, 0)) for k in ("mci", "irancell", "tci", "others")),
                            )
                        )
                    for context in ("global", "iran", "mci", "irancell", "tci", "others"):
                        v = max(0, int(values.get(context, 0)))
                        db.execute(
                            "INSERT INTO score VALUES(?,?,?) ON CONFLICT(proxy_id,context) DO UPDATE SET count=max(count,excluded.count)",
                            (proxy.identity, context, v),
                        )
                    if isinstance(value, dict) and value.get("alive_first_fail_at") is not None:
                        first = float(value["alive_first_fail_at"])
                        due = float(value.get("alive_next_check_at", 0))
                        db.execute(
                            "INSERT INTO health(proxy_id,context,target,first_failure,failures,next_due) "
                            "VALUES(?,'global','connectivity',?,1,?) ON CONFLICT(proxy_id,context,target) "
                            "DO UPDATE SET first_failure=max(COALESCE(first_failure,0),excluded.first_failure),"
                            "failures=max(failures,1),next_due=max(next_due,excluded.next_due)",
                            (proxy.identity, first, due),
                        )
                    count += 1
            elif path == site:
                # Old negatives have no observation time; import as immediately due, never permanent exclusions.
                data = json.loads(path.read_text(encoding="utf-8"))
                for uri, targets in data.items():
                    if "://" not in uri or not isinstance(targets, list):
                        continue
                    try:
                        proxy = parse_uri(uri)
                    except ParseError:
                        continue
                    store.add(proxy, "legacy-site", db=db)
                    for target in targets:
                        db.execute(
                            "INSERT OR IGNORE INTO health(proxy_id,context,target,outcome,next_due) VALUES(?,?,?,?,0)",
                            (proxy.identity, "global", str(target), "blocked"),
                        )
                        report["site_negatives"] += 1
                    count += 1
            else:
                with path.open("rb") as f:
                    if path.suffix == ".bin":
                        while chunk := f.read(28 * 10000):
                            if len(chunk) % 28:
                                raise ValueError("truncated legacy binary history")
                            records = [
                                (chunk[i + 8 : i + 28], struct.unpack_from(">Q", chunk, i)[0])
                                for i in range(0, len(chunk), 28)
                            ]
                            db.executemany(
                                "INSERT INTO legacy_tested VALUES(?,?) ON CONFLICT(hash) DO UPDATE SET time=max(time,excluded.time)",
                                records,
                            )
                            count += len(records)
                    else:
                        for line in f:
                            parts = line.decode("ascii").strip().split()
                            if not parts:
                                continue
                            raw = bytes.fromhex(parts[-1])
                            if len(raw) != 20:
                                raise ValueError("invalid legacy SHA1")
                            stamp = int(parts[0]) if len(parts) > 1 else 0
                            db.execute(
                                "INSERT INTO legacy_tested VALUES(?,?) ON CONFLICT(hash) DO UPDATE SET time=max(time,excluded.time)",
                                (raw, stamp),
                            )
                            count += 1
                report["tested"] += count
            db.execute(
                "INSERT INTO migration VALUES(?,?,?,?)", (str(path.resolve()), digest, count, time.time())
            )
        report["aliases"] = db.execute("SELECT count(*) FROM alias").fetchone()[0]
        db.execute("INSERT OR REPLACE INTO meta VALUES('legacy_migrated','1')")
    return report
