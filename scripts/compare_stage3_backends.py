#!/usr/bin/env python3
"""Compare Stage 3 backends (subprocess, pool, api) on the same URI list."""
from __future__ import annotations

import argparse
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, 'src'))

from constants import V2RAY_CORE_PATH  # noqa: E402
from stage3.engine import Stage3Engine  # noqa: E402
from stage3.types import BackendKind  # noqa: E402


def _load_uris(path: str, limit: int) -> list:
    uris = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            u = line.strip()
            if u and not u.startswith('#'):
                uris.append(u)
            if limit > 0 and len(uris) >= limit:
                break
    return uris


def main() -> int:
    parser = argparse.ArgumentParser(description='Compare Stage 3 backends')
    parser.add_argument('--input', '-i', default=os.path.join(REPO_ROOT, 'output', 'all_valid_proxies.txt'))
    parser.add_argument('--limit', '-n', type=int, default=20)
    parser.add_argument('--timeout', '-t', type=int, default=15)
    parser.add_argument('--backends', default='subprocess,pool,api')
    args = parser.parse_args()

    if not V2RAY_CORE_PATH or not os.path.exists(V2RAY_CORE_PATH):
        print(f"Xray core not found: {V2RAY_CORE_PATH}")
        return 1

    if not os.path.exists(args.input):
        print(f"Input not found: {args.input}")
        return 1

    uris = _load_uris(args.input, args.limit)
    if not uris:
        print('No URIs to test')
        return 1

    kinds = []
    for name in args.backends.split(','):
        name = name.strip().lower()
        if name in ('subprocess', 'pool', 'api'):
            kinds.append(BackendKind(name))

    all_results: dict = {}
    for kind in kinds:
        os.environ['OPENRAY_STAGE3_BACKEND'] = kind.value
        engine = Stage3Engine(kind=kind)
        print(f"\n=== backend={kind.value} ({len(uris)} uris) ===")
        results = engine.validate_many(uris, timeout_s=args.timeout)
        all_results[kind.value] = results
        engine.shutdown()

    print('\n=== mismatches vs subprocess ===')
    base = all_results.get('subprocess', {})
    for kind in kinds:
        if kind.value == 'subprocess':
            continue
        cur = all_results.get(kind.value, {})
        mismatches = 0
        for u in uris:
            if base.get(u) != cur.get(u):
                mismatches += 1
                print(f"  {kind.value}: {u[:60]}... subprocess={base.get(u)} {kind.value}={cur.get(u)}")
        print(f"{kind.value}: {mismatches}/{len(uris)} mismatches")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
