"""Isolate peak RSS when comparing legacy full-history loading and indexed SQLite startup."""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def worker(kind, root, database):
    import psutil

    started = time.perf_counter()
    if kind == "legacy":
        hashes = set()
        for p in sorted((root / ".state").glob("tested*.txt.bin")):
            data = p.read_bytes()
            if len(data) % 28:
                raise ValueError("truncated binary input")
            hashes.update(data[i + 8 : i + 28].hex() for i in range(0, len(data), 28))
        rows = len(hashes)
    else:
        from openray.storage import Store

        with Store(database) as store:
            rows = store.db.execute("SELECT count(*) FROM legacy_tested").fetchone()[0]
            store.db.execute("SELECT uri FROM proxy WHERE accepted=1 ORDER BY id LIMIT 5000").fetchall()
    memory = psutil.Process().memory_info()
    print(
        json.dumps(
            {
                "kind": kind,
                "rows": rows,
                "wall_s": time.perf_counter() - started,
                "rss_bytes": memory.rss,
                "peak_rss_bytes": getattr(memory, "peak_wset", memory.rss),
            }
        )
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument("--database", type=Path, default=Path("benchmark-results/migration-final.sqlite3"))
    p.add_argument("--worker", choices=["legacy", "sqlite"])
    p.add_argument("--output", type=Path, default=Path("benchmark-results/state.json"))
    a = p.parse_args()
    if a.worker:
        worker(a.worker, a.root, a.database)
    else:
        rows = []
        for kind in ["legacy", "sqlite"]:
            r = subprocess.run(
                [
                    sys.executable,
                    __file__,
                    "--worker",
                    kind,
                    "--root",
                    str(a.root),
                    "--database",
                    str(a.database),
                ],
                capture_output=True,
                check=True,
            )
            rows.append(json.loads(r.stdout))
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(rows, indent=2) + "\n")
        print(json.dumps(rows, indent=2))
