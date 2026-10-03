"""Verify imported aliases, all context counters, source hashes and streamed history."""

import argparse
import json
import struct
from pathlib import Path

from openray.domain import ParseError, parse_uri
from openray.files import atomic_write, json_text
from openray.storage import Store, file_sha256


def verify(root: Path, database: Path, deep_history=False):
    expected, invalid = {}, 0
    counts = json.loads((root / ".state/check_counts.json").read_text(encoding="utf-8"))
    for uri, value in counts.items():
        try:
            proxy = parse_uri(uri)
        except ParseError:
            invalid += 1
            continue
        values = {"global": value} if isinstance(value, int) else dict(value)
        iran = values.get("iran", {})
        if isinstance(iran, dict):
            values.update(iran.get("operators", iran))
            values["iran"] = iran.get(
                "total", sum(values.get(c, 0) for c in ("mci", "tci", "irancell", "others"))
            )
        for context in ("global", "iran", "mci", "irancell", "tci", "others"):
            key = (proxy.identity, context)
            expected[key] = max(expected.get(key, 0), int(values.get(context, 0)))
    with Store(database) as store:
        actual = {(r[0], r[1]): r[2] for r in store.db.execute("SELECT * FROM score")}
        if actual != expected:
            raise AssertionError("migrated context scores differ from alias maxima")
        for row in store.db.execute("SELECT path,sha256 FROM migration"):
            if file_sha256(Path(row[0])) != row[1]:
                raise AssertionError("legacy migration input was modified")
        checked = 0
        if deep_history:
            for path in sorted((root / ".state").glob("tested*.txt.bin")):
                with path.open("rb") as history:
                    while chunk := history.read(28 * 500):
                        if len(chunk) % 28:
                            raise AssertionError("truncated source history")
                        records = [
                            (chunk[i + 8 : i + 28], struct.unpack_from(">Q", chunk, i)[0])
                            for i in range(0, len(chunk), 28)
                        ]
                        query = (
                            "SELECT hash,time FROM legacy_tested WHERE hash IN ("
                            + ",".join("?" for _ in records)
                            + ")"
                        )
                        matches = dict(store.db.execute(query, [r[0] for r in records]))
                        if any(matches.get(key, -1) < stamp for key, stamp in records):
                            raise AssertionError("historical timestamp/hash was lost")
                        checked += len(records)
        report = {
            "scores_match": True,
            "source_hashes_match": True,
            "invalid_score_aliases": invalid,
            "history_records_verified": checked,
            "status": store.status(),
            "score_totals": {
                c: sum(v for (p, ctx), v in actual.items() if ctx == c)
                for c in ("global", "iran", "mci", "irancell", "tci", "others")
            },
            "integrity": store.db.execute("PRAGMA integrity_check").fetchone()[0],
        }
        if report["integrity"] != "ok":
            raise AssertionError("migration database integrity failed")
        return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("database", type=Path)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--deep-history", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("benchmark-results/migration-verification.json"))
    args = parser.parse_args()
    result = verify(args.root, args.database, args.deep_history)
    atomic_write(args.output, json_text(result))
    print(json_text(result), end="")
