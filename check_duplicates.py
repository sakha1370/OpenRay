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
from dataclasses import dataclass
from typing import Iterable

from src.common import get_openray_dedup_key, normalize_proxy_uri
from src.constants import AVAILABLE_FILE

# Known regression case: double-encoded vs single-encoded WS path
DEFAULT_SAMPLES = [
    "trojan://8r%3C%5B9%27l6hAO%238ZQi@43.168.16.112:443?security=tls&sni=Koma-YT.PAGeS.Dev&type=ws&path=%252FtrTelegram%25F0%259F%2587%25A8%25F0%259F%2587%25B3%2520%2540WangCai2&Host=Koma-YT.PAGeS.Dev#%5BOpenRay%5D%20%F0%9F%87%AD%F0%9F%87%B0%20HK-1543",
    "trojan://8r%3C%5B9%27l6hAO%238ZQi@43.168.16.112:443?security=tls&sni=Koma-YT.PAGeS.Dev&type=ws&path=%2FtrTelegram%F0%9F%87%A8%F0%9F%87%B3%20%40WangCai2&Host=Koma-YT.PAGeS.Dev#%5BOpenRay%5D%20%F0%9F%87%AD%F0%9F%87%B0%20HK-1577",
]


@dataclass(frozen=True)
class ProxyDedupInfo:
    line_no: int
    uri: str
    key: str
    norm: str


def load_proxies_from_file(path: str) -> list[str]:
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def analyze_proxies(proxies: Iterable[str], *, line_offset: int = 1) -> list[ProxyDedupInfo]:
    rows: list[ProxyDedupInfo] = []
    for i, proxy in enumerate(proxies, line_offset):
        rows.append(
            ProxyDedupInfo(
                line_no=i,
                uri=proxy,
                key=get_openray_dedup_key(proxy),
                norm=normalize_proxy_uri(proxy),
            )
        )
    return rows


def group_by_key(rows: list[ProxyDedupInfo]) -> dict[str, list[ProxyDedupInfo]]:
    groups: dict[str, list[ProxyDedupInfo]] = defaultdict(list)
    for row in rows:
        groups[row.key].append(row)
    return dict(groups)


def group_by_norm(rows: list[ProxyDedupInfo]) -> dict[str, list[ProxyDedupInfo]]:
    groups: dict[str, list[ProxyDedupInfo]] = defaultdict(list)
    for row in rows:
        groups[row.norm].append(row)
    return dict(groups)


def connection_bucket(row: ProxyDedupInfo) -> str:
    """Coarse bucket: scheme + first 4 dedup fields (server, port, password, method)."""
    parts = row.key.split("|", 5)
    if len(parts) >= 5:
        return "|".join(parts[:5])
    return row.key


def group_by_connection_bucket(rows: list[ProxyDedupInfo]) -> dict[str, list[ProxyDedupInfo]]:
    groups: dict[str, list[ProxyDedupInfo]] = defaultdict(list)
    for row in rows:
        groups[connection_bucket(row)].append(row)
    return dict(groups)


def find_duplicate_key_groups(groups: dict[str, list[ProxyDedupInfo]]) -> dict[str, list[ProxyDedupInfo]]:
    return {k: items for k, items in groups.items() if len(items) > 1}


def find_norm_key_mismatches(rows: list[ProxyDedupInfo]) -> list[tuple[str, set[str], list[ProxyDedupInfo]]]:
    """Same normalized URI but different dedup keys."""
    issues: list[tuple[str, set[str], list[ProxyDedupInfo]]] = []
    for norm, items in group_by_norm(rows).items():
        keys = {item.key for item in items}
        if len(keys) > 1:
            issues.append((norm, keys, items))
    return issues


def find_bucket_key_mismatches(rows: list[ProxyDedupInfo]) -> list[tuple[str, set[str], list[ProxyDedupInfo]]]:
    """Same server/port/password but different dedup keys (likely dedup bug)."""
    issues: list[tuple[str, set[str], list[ProxyDedupInfo]]] = []
    for bucket, items in group_by_connection_bucket(rows).items():
        keys = {item.key for item in items}
        if len(keys) > 1:
            issues.append((bucket, keys, items))
    return issues


def _load_proxies(args: argparse.Namespace) -> list[str]:
    if args.file:
        return load_proxies_from_file(args.file)
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

    rows = analyze_proxies(proxies)
    groups = group_by_key(rows)
    for row in rows:
        print(f"{row.line_no} norm: {row.norm}")
        print(f"{row.line_no} key : {row.key}")

    unique = len(groups)
    print(f"unique keys: {unique}")

    if unique == 1:
        print("PASS: all proxies are duplicates (same dedup key)")
        return 0

    print("FAIL: proxies are NOT treated as duplicates")
    for key, items in groups.items():
        indices = ", ".join(str(item.line_no) for item in items)
        print(f"  group [{indices}]: {key[:80]}{'...' if len(key) > 80 else ''}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
