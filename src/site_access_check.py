from __future__ import annotations

import os
import sys
from typing import Dict, List, Optional, Set

from .common import get_openray_dedup_key, log
from .constants import (
    AVAILABLE_FILE,
    SITE_ACCESS_COMBINED_FILE,
    SITE_ACCESS_DIR,
    SITE_ACCESS_TARGETS,
    SITE_ACCESS_TIMEOUT_S,
    V2RAY_CORE_PATH,
)
from .io_ops import ensure_dirs, read_lines, write_text_file_atomic
from .stage3.backends.site_access import SiteAccessBackend
from .stage3.probe import SiteTarget


def _deduplicate_proxies(proxies: List[str]) -> List[str]:
    seen: Set[str] = set()
    deduped: List[str] = []
    for uri in proxies:
        key = get_openray_dedup_key(uri)
        if key not in seen:
            seen.add(key)
            deduped.append(uri)
    return deduped


def _normalize_targets() -> List[SiteTarget]:
    targets: List[SiteTarget] = []
    for entry in SITE_ACCESS_TARGETS:
        targets.append({
            'id': str(entry['id']),
            'url': str(entry['url']),
            'blocked_codes': tuple(entry.get('blocked_codes', (403,))),
        })
    return targets


def _aggregate_results(
    uris: List[str],
    results: Dict[str, Optional[Dict[str, bool]]],
    targets: List[SiteTarget],
) -> tuple[Dict[str, List[str]], List[str]]:
    per_site: Dict[str, List[str]] = {t['id']: [] for t in targets}
    combined: List[str] = []

    for uri in uris:
        site_results = results.get(uri)
        if not site_results:
            continue
        all_passed = True
        for target in targets:
            passed = bool(site_results.get(target['id']))
            if passed:
                per_site[target['id']].append(uri)
            else:
                all_passed = False
        if all_passed:
            combined.append(uri)

    return per_site, combined


def main() -> int:
    ensure_dirs()
    os.makedirs(SITE_ACCESS_DIR, exist_ok=True)

    if not os.path.exists(AVAILABLE_FILE):
        log(f"Input not found: {AVAILABLE_FILE}")
        return 0

    lines = [ln.strip() for ln in read_lines(AVAILABLE_FILE) if ln.strip()]
    if not lines:
        log("No proxies to check for site access.")
        return 0

    targets = _normalize_targets()
    if not targets:
        log("No site access targets configured.")
        return 0

    proxies = _deduplicate_proxies(lines)
    log(f"Site access check: {len(proxies)} proxies, {len(targets)} target(s)")

    core_path = (V2RAY_CORE_PATH or '').strip()
    if not core_path or not os.path.exists(core_path):
        log("Xray core not found; skipping site access check.")
        return 1

    backend = SiteAccessBackend(targets)
    try:
        if not backend._enabled:
            log("Site access backend not enabled; skipping.")
            return 1
        results = backend.validate_many(proxies, timeout_s=int(SITE_ACCESS_TIMEOUT_S))
    finally:
        backend.shutdown()

    per_site, combined = _aggregate_results(proxies, results, targets)

    for target in targets:
        output_name = str(target.get('output_file') or f"{target['id']}.txt")
        output_path = os.path.join(SITE_ACCESS_DIR, output_name)
        site_proxies = per_site.get(target['id'], [])
        write_text_file_atomic(output_path, site_proxies)
        log(f"  {target['id']}: {len(site_proxies)} proxies -> {output_path}")

    combined_path = os.path.join(SITE_ACCESS_DIR, SITE_ACCESS_COMBINED_FILE)
    write_text_file_atomic(combined_path, combined)
    log(f"  all sites: {len(combined)} proxies -> {combined_path}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
