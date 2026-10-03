from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import os
import sqlite3
import sys
from pathlib import Path

from .config import Settings
from .files import atomic_write, json_text


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="openray")
    p.add_argument("--root", type=Path)
    p.add_argument("--database", type=Path)
    sub = p.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="discover, validate and stage a deterministic snapshot")
    run.add_argument("sources", nargs="?", type=Path)
    run.add_argument(
        "--mode", choices=("combined", "discovery", "existing", "iran", "local", "sites"), default="combined"
    )
    run.add_argument("--context", choices=("global", "iran", "mci", "irancell", "tci", "others"))
    operators = run.add_mutually_exclusive_group()
    for name in ("mci", "irancell", "tci"):
        operators.add_argument("--" + name, action="store_true")
    run.add_argument(
        "--install", action="store_true", help="install validated snapshot at compatibility output paths"
    )
    run.add_argument("--workers", type=int)
    run.add_argument("--budget", type=float)
    run.add_argument("--report", type=Path)
    for command in (
        "status",
        "migrate",
        "export",
        "backup",
        "restore",
        "import-bundle",
        "verify",
        "publish",
        "publish-bundle",
        "maintenance",
    ):
        q = sub.add_parser(command)
        if command in {"backup", "restore", "import-bundle", "verify", "publish", "publish-bundle"}:
            q.add_argument("path", type=Path)
        if command == "export":
            q.add_argument("--install", action="store_true")
        if command == "publish":
            q.add_argument("--branch", default="main")
        if command == "publish-bundle":
            q.add_argument("--branch", default="operator-observations")
        if command == "maintenance":
            q.add_argument("--apply", action="store_true")
            q.add_argument("--retention-days", type=int, default=90)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        settings = Settings.from_env(args.root)
        if args.database:
            settings = dataclasses.replace(settings, database=args.database.resolve())
        if args.command == "run":
            if os.environ.get("OPENRAY_ENABLE_STAGE3") == "0":
                raise ValueError("end-to-end validation cannot be disabled for a production run")
            from .pipeline import run

            changes = {}
            if args.sources:
                changes["sources"] = args.sources.resolve()
            if args.workers is not None:
                if not 1 <= args.workers <= 128:
                    raise ValueError("workers must be between 1 and 128")
                changes.update(
                    workers=min(
                        args.workers, max(1, (int(os.environ.get("OPENRAY_MEMORY_MB", "2048")) - 256) // 96)
                    ),
                    queue_size=max(settings.queue_size, args.workers),
                )
            if args.budget is not None:
                if not 0 < args.budget <= 86400:
                    raise ValueError("budget must be between 0 and 86400 seconds")
                changes["budget"] = args.budget
            operator = next((op for op in ("mci", "irancell", "tci") if getattr(args, op)), None)
            if operator and args.context and args.context != operator:
                raise ValueError("operator flag conflicts with context")
            context = args.context or operator or ("others" if args.mode in {"iran", "local"} else "global")
            settings = dataclasses.replace(settings, **changes)

            async def execute():
                import signal

                task = asyncio.current_task()
                loop = asyncio.get_running_loop()
                previous = signal.getsignal(signal.SIGTERM)
                signal.signal(signal.SIGTERM, lambda *_: loop.call_soon_threadsafe(task.cancel))
                try:
                    return await run(settings, args.mode, context, install=args.install)
                finally:
                    signal.signal(signal.SIGTERM, previous)

            code, report = asyncio.run(execute())
            if args.report:
                atomic_write(args.report, json_text(report))
            print(json_text(report), end="")
            return code
        if args.command == "verify":
            from .exports import verify_snapshot

            print(json_text(verify_snapshot(args.path)), end="")
            return 0
        if args.command == "publish":
            from .publishing import git_publish

            print(git_publish(args.path.resolve(), settings.root, args.branch))
            if settings.database.is_file():
                from .exports import verify_snapshot
                from .storage import Store

                with Store(settings.database) as store, store.transaction() as db:
                    db.execute(
                        "UPDATE snapshot SET published=1 WHERE id=?", (verify_snapshot(args.path)["id"],)
                    )
            return 0
        if args.command == "publish-bundle":
            from .publishing import publish_bundle
            from .storage import Store, file_sha256

            payload = json.loads(args.path.read_text(encoding="utf-8"))
            digest, key = file_sha256(args.path), "published_bundle:" + str(payload.get("id", ""))
            with Store(settings.database) as store:
                prior = store.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
                if prior:
                    if prior[0] != digest:
                        raise ValueError("regional bundle identity collision")
                    print("Regional bundle already published")
                    return 0
                print(publish_bundle(args.path.resolve(), settings.root, args.branch))
                with store.transaction() as db:
                    db.execute("INSERT INTO meta VALUES(?,?)", (key, digest))
            return 0
        if args.command == "restore":
            from .storage import restore_backup

            restore_backup(args.path, settings.database)
            return 0
        from .storage import Store

        if args.command not in {"migrate", "export", "import-bundle"} and not settings.database.is_file():
            raise ValueError("database does not exist; run migrate or restore first")
        with Store(settings.database) as store:
            if args.command in {"export", "import-bundle"}:
                from .pipeline import initialize

                initialize(store, settings.root)
            if args.command == "status":
                print(json_text(store.status()), end="")
            elif args.command == "migrate":
                from .pipeline import initialize

                print(json_text(initialize(store, settings.root)), end="")
            elif args.command == "backup":
                if not store.db.execute("SELECT 1 FROM meta WHERE key='legacy_migrated'").fetchone():
                    raise ValueError("refusing to checkpoint an uninitialized database")
                store.backup(args.path)
            elif args.command == "import-bundle":
                print(store.import_bundle(json.loads(args.path.read_text(encoding="utf-8"))))
            elif args.command == "export":
                from .exports import build_snapshot, validate_clients
                from .publishing import install_snapshot

                path = build_snapshot(store, settings.root, settings.database.parent / "snapshots")
                if args.install:
                    if not settings.singbox or not settings.mihomo:
                        raise ValueError("installation requires both client schema validators")
                    if any(not r["valid"] for r in validate_clients(path, settings.singbox, settings.mihomo)):
                        raise ValueError("installation rejected an invalid client export")
                    install_snapshot(path, settings.root)
                print(path.resolve())
            elif args.command == "maintenance":
                from .maintenance import maintain

                print(json_text(maintain(store, args.retention_days, args.apply)), end="")
        return 0
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("OpenRay: cancelled; completed observations retained", file=sys.stderr)
        return 130
    except (ValueError, OSError, RuntimeError, sqlite3.Error) as exc:
        # Exception messages are controlled by this package. Network/core details are redacted at origin.
        print(f"OpenRay: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


def legacy(mode: str, argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if mode == "combined" and os.environ.get("OPENRAY_RECHECK_EXISTING") == "0":
        mode = "discovery"
    return main(["run", "--mode", mode, "--install", *args])
