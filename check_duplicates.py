#!/usr/bin/env python3
"""
Test whether proxy URIs are treated as duplicates by OpenRay dedup logic.

Usage:
  python check_duplicates.py
  python check_duplicates.py <proxy-uri> [<proxy-uri> ...]
  python check_duplicates.py --file path/to/proxies.txt

Exit code 0 when all inputs share one dedup key; 1 when multiple unique keys exist.
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict

from src.common import get_openray_dedup_key, normalize_proxy_uri

# Known regression case: tcp/"" vs raw/"none" for the same VMess server
DEFAULT_SAMPLES = [
    "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTo3ZTczMWVjMy1mOGUxLTQzZjYtOTJjZi0zOTc4ZDE0NzA1YzRAcjNtcmNnMDA3MTE3ZmI4LmN5YmVydmVuYS5jb206NTAwOTk/#%5BOpenRay%5D%20%F0%9F%87%B9%F0%9F%87%BC%20TW-507",
    "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTo3ZTczMWVjMy1mOGUxLTQzZjYtOTJjZi0zOTc4ZDE0NzA1YzRAcjNtcmNnMDA3MTE3ZmI4LmN5YmVydmVuYS5jb206NTAwOTk=#%5BOpenRay%5D%20%F0%9F%87%B9%F0%9F%87%BC%20TW-255"
]


def _load_proxies(args: argparse.Namespace) -> list[str]:
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if args.proxies:
        return list(args.proxies)
    return list(DEFAULT_SAMPLES)


def main() -> int:
    parser = argparse.ArgumentParser(description="Test OpenRay proxy duplicate detection")
    parser.add_argument("proxies", nargs="*", help="Proxy URIs to compare")
    parser.add_argument("--file", "-f", help="Read proxy URIs from a text file (one per line)")
    args = parser.parse_args()

    proxies = _load_proxies(args)
    if len(proxies) < 2:
        print("Need at least two proxy URIs to compare.", file=sys.stderr)
        return 2

    groups: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for i, proxy in enumerate(proxies, 1):
        key = get_openray_dedup_key(proxy)
        norm = normalize_proxy_uri(proxy)
        groups[key].append((i, proxy))
        print(f"{i} norm: {norm}")
        print(f"{i} key : {key}")

    unique = len(groups)
    print(f"unique keys: {unique}")

    if unique == 1:
        print("PASS: all proxies are duplicates (same dedup key)")
        return 0

    print("FAIL: proxies are NOT treated as duplicates")
    for key, items in groups.items():
        indices = ", ".join(str(idx) for idx, _ in items)
        print(f"  group [{indices}]: {key[:80]}{'...' if len(key) > 80 else ''}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
