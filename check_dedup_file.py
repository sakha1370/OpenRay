#!/usr/bin/env python3
"""
Scan a proxy list for deduplication issues using OpenRay dedup logic.

Reports:
  1. Duplicate dedup keys (same key, multiple lines — file not fully deduped)
  2. Same normalized URI, different dedup keys (logic inconsistency)
  3. Same server/port/password, different dedup keys (likely missed duplicates)

Usage:
  python check_dedup_file.py
  python check_dedup_file.py --file output/all_valid_proxies.txt
  python check_dedup_file.py --limit 20   # show at most 20 issue groups per category
"""

from __future__ import annotations

import argparse
import sys

from check_duplicates import (
    analyze_proxies,
    find_bucket_key_mismatches,
    find_duplicate_key_groups,
    find_norm_key_mismatches,
    group_by_key,
    load_proxies_from_file,
)
from src.constants import AVAILABLE_FILE


def _print_sample(items: list, limit: int, formatter) -> None:
    for item in items[:limit]:
        formatter(item)
    if len(items) > limit:
        print(f"  ... and {len(items) - limit} more")


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan proxy file for dedup issues")
    parser.add_argument(
        "--file",
        "-f",
        default=AVAILABLE_FILE,
        help=f"Proxy list to scan (default: {AVAILABLE_FILE})",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=15,
        help="Max issue groups to print per category (default: 15)",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Write deduplicated proxies back to the input file (keeps first occurrence per key)",
    )
    args = parser.parse_args()

    try:
        proxies = load_proxies_from_file(args.file)
    except OSError as e:
        print(f"Cannot read {args.file}: {e}", file=sys.stderr)
        return 2

    if not proxies:
        print(f"No proxies in {args.file}")
        return 0

    rows = analyze_proxies(proxies)
    key_groups = group_by_key(rows)
    dup_keys = find_duplicate_key_groups(key_groups)
    norm_mismatches = find_norm_key_mismatches(rows)
    bucket_mismatches = find_bucket_key_mismatches(rows)

    unique_keys = len(key_groups)
    duplicate_lines = sum(len(v) - 1 for v in dup_keys.values())

    print(f"File: {args.file}")
    print(f"Total lines: {len(proxies)}")
    print(f"Unique dedup keys: {unique_keys}")
    print(f"Duplicate-key groups: {len(dup_keys)} ({duplicate_lines} extra lines)")
    print(f"Norm/key mismatches: {len(norm_mismatches)}")
    print(f"Connection bucket mismatches: {len(bucket_mismatches)}")
    print()

    if dup_keys:
        print("=== Duplicate dedup keys (should be merged) ===")
        _print_sample(
            sorted(dup_keys.items(), key=lambda kv: -len(kv[1])),
            args.limit,
            lambda kv: print(
                f"  x{len(kv[1])} key={kv[0][:72]}{'...' if len(kv[0]) > 72 else ''}\n"
                + "\n".join(f"    L{item.line_no}: {item.uri[:100]}{'...' if len(item.uri) > 100 else ''}" for item in kv[1][:3])
                + (f"\n    ... {len(kv[1]) - 3} more lines" if len(kv[1]) > 3 else "")
            ),
        )
        print()

    if norm_mismatches:
        print("=== Same normalized URI, different dedup keys ===")
        _print_sample(
            norm_mismatches,
            args.limit,
            lambda issue: print(
                f"  norm={issue[0][:80]}{'...' if len(issue[0]) > 80 else ''}\n"
                + "\n".join(f"    L{item.line_no} key={item.key[:60]}..." for item in issue[2][:4])
            ),
        )
        print()

    if bucket_mismatches:
        print("=== Same server/port/password, different dedup keys ===")
        _print_sample(
            sorted(bucket_mismatches, key=lambda x: -len(x[2])),
            args.limit,
            lambda issue: print(
                f"  bucket={issue[0]}\n"
                f"  keys ({len(issue[1])}):\n"
                + "\n".join(f"    {k[:90]}{'...' if len(k) > 90 else ''}" for k in sorted(issue[1])[:3])
                + "\n"
                + "\n".join(f"    L{item.line_no}: {item.uri[:95]}{'...' if len(item.uri) > 95 else ''}" for item in issue[2][:3])
                + (f"\n    ... {len(issue[2]) - 3} more lines" if len(issue[2]) > 3 else "")
            ),
        )
        print()

    has_failures = bool(dup_keys or norm_mismatches)
    has_issues = has_failures or bool(bucket_mismatches)

    if args.fix and dup_keys:
        from src.io_ops import write_text_file_atomic

        seen: set[str] = set()
        deduped: list[str] = []
        for row in rows:
            if row.key in seen:
                continue
            seen.add(row.key)
            deduped.append(row.uri)
        write_text_file_atomic(args.file, deduped)
        print(f"Fixed: wrote {len(deduped)} unique proxies to {args.file} (removed {len(proxies) - len(deduped)} duplicates)")
        has_failures = bool(norm_mismatches)

    if has_failures:
        print("FAIL: deduplication issues found")
        return 1

    if has_issues:
        print("WARN: connection bucket mismatches remain (often different paths/hosts on same server)")
        return 0

    print("PASS: no deduplication issues detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
