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
from .site_access_state import (
    mark_site_blocked,
    save_blocked_state,
    sites_to_test,
    sync_blocked_state,
)
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
        target: SiteTarget = {
            'id': str(entry['id']),
            'url': str(entry['url']),
        }
        if 'allowed_codes' in entry:
            target['allowed_codes'] = tuple(entry['allowed_codes'])
        else:
            target['blocked_codes'] = tuple(entry.get('blocked_codes', (403,)))
        targets.append(target)
    return targets


def _targets_for_proxy(
    uri: str,
    targets: List[SiteTarget],
    blocked_state: Dict[str, Set[str]],
) -> List[SiteTarget]:
    site_ids = sites_to_test(uri, [t['id'] for t in targets], blocked_state)
    allowed = set(site_ids)
    return [t for t in targets if t['id'] in allowed]


def _apply_failures_to_state(
    results: Dict[str, Optional[Dict[str, bool]]],
    blocked_state: Dict[str, Set[str]],
) -> int:
    """Mark failed site checks as permanently blocked; return number of new blocks."""
    new_blocks = 0
    for uri, site_results in results.items():
        if not site_results:
            continue
        for site_id, passed in site_results.items():
            if passed:
                continue
            before = len(blocked_state.get(uri, set()))
            mark_site_blocked(blocked_state, uri, site_id)
            if len(blocked_state.get(uri, set())) > before:
                new_blocks += 1
    return new_blocks


def _aggregate_results(
    uris: List[str],
    results: Dict[str, Optional[Dict[str, bool]]],
    targets: List[SiteTarget],
    blocked_state: Dict[str, Set[str]],
) -> tuple[Dict[str, List[str]], List[str]]:
    per_site: Dict[str, List[str]] = {t['id']: [] for t in targets}
    combined: List[str] = []

    for uri in uris:
        blocked = blocked_state.get(uri, set())
        site_results = results.get(uri) or {}

        for target in targets:
            site_id = target['id']
            if site_id in blocked:
                continue
            if site_results.get(site_id):
                per_site[site_id].append(uri)

        if blocked:
            continue
        if site_results and all(site_results.get(t['id']) for t in targets):
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
    blocked_state = sync_blocked_state(proxies)

    targets_by_uri: Dict[str, List[SiteTarget]] = {
        uri: _targets_for_proxy(uri, targets, blocked_state) for uri in proxies
    }
    proxies_to_test = [uri for uri in proxies if targets_by_uri[uri]]
    skipped = len(proxies) - len(proxies_to_test)
    permanently_blocked_pairs = sum(len(sites) for sites in blocked_state.values())

    log(
        f"Site access check: {len(proxies)} proxies, {len(targets)} target(s), "
        f"{len(proxies_to_test)} to test, {skipped} fully skipped "
        f"({permanently_blocked_pairs} permanent site blocks loaded)"
    )

    core_path = (V2RAY_CORE_PATH or '').strip()
    if not core_path or not os.path.exists(core_path):
        log("Xray core not found; skipping site access check.")
        return 1

    results: Dict[str, Optional[Dict[str, bool]]] = {}
    if proxies_to_test:
        backend = SiteAccessBackend(targets)
        try:
            if not backend._enabled:
                log("Site access backend not enabled; skipping.")
                return 1
            results = backend.validate_many(
                proxies_to_test,
                timeout_s=int(SITE_ACCESS_TIMEOUT_S),
                targets_by_uri=targets_by_uri,
            )
        finally:
            backend.shutdown()

    new_blocks = _apply_failures_to_state(results, blocked_state)
    if new_blocks:
        log(f"Site access: marked {new_blocks} new permanent site block(s)")
    save_blocked_state(blocked_state)

    per_site, combined = _aggregate_results(proxies, results, targets, blocked_state)

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
