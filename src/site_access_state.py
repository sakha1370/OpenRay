from __future__ import annotations

import json
import os
from typing import Dict, List, Set

from .constants import SITE_ACCESS_STATE_FILE, STATE_DIR
from .common import log

_VERSIONS_KEY = '_versions'


def _ensure_state_dir() -> None:
    os.makedirs(STATE_DIR, exist_ok=True)


def _parse_versions(raw: object) -> Dict[str, int]:
    if not isinstance(raw, dict):
        return {}
    versions: Dict[str, int] = {}
    for site_id, value in raw.items():
        if not isinstance(site_id, str) or not site_id.strip():
            continue
        try:
            versions[site_id] = int(value)
        except (TypeError, ValueError):
            continue
    return versions


def _load_raw() -> tuple[Dict[str, Set[str]], Dict[str, int]]:
    """Return ({proxy_uri: {site_id, ...}}, {site_id: version})."""
    _ensure_state_dir()
    if not os.path.exists(SITE_ACCESS_STATE_FILE):
        return {}, {}
    try:
        with open(SITE_ACCESS_STATE_FILE, 'r', encoding='utf-8') as f:
            raw = json.load(f)
        if not isinstance(raw, dict):
            return {}, {}
        stored_versions = _parse_versions(raw.get(_VERSIONS_KEY))
        state: Dict[str, Set[str]] = {}
        for uri, sites in raw.items():
            if uri == _VERSIONS_KEY:
                continue
            if not isinstance(uri, str) or not uri.strip():
                continue
            if isinstance(sites, list):
                state[uri] = {str(s) for s in sites if s}
            elif isinstance(sites, dict):
                state[uri] = {str(k) for k, v in sites.items() if v}
        return state, stored_versions
    except Exception as e:
        log(f"Failed to load site access blocked state: {e}")
        return {}, {}


def load_blocked_state() -> Dict[str, Set[str]]:
    """Return {proxy_uri: {site_id, ...}} for permanently skipped site checks."""
    state, _ = _load_raw()
    return state


def save_blocked_state(
    state: Dict[str, Set[str]],
    target_versions: Dict[str, int],
) -> None:
    _ensure_state_dir()
    payload: Dict[str, object] = {
        _VERSIONS_KEY: {site_id: int(ver) for site_id, ver in sorted(target_versions.items())},
    }
    payload.update({uri: sorted(sites) for uri, sites in sorted(state.items()) if sites})
    tmp_path = SITE_ACCESS_STATE_FILE + '.tmp'
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write('\n')
    os.replace(tmp_path, SITE_ACCESS_STATE_FILE)


def _sites_with_version_bump(
    target_versions: Dict[str, int],
    stored_versions: Dict[str, int],
) -> Set[str]:
    bumped: Set[str] = set()
    for site_id, ver in target_versions.items():
        old = stored_versions.get(site_id)
        if old is not None and old != ver:
            bumped.add(site_id)
    return bumped


def _clear_sites(state: Dict[str, Set[str]], site_ids: Set[str]) -> int:
    """Remove permanent blocks for site_ids; return number of proxy-site pairs cleared."""
    if not site_ids:
        return 0
    cleared = 0
    for uri in list(state.keys()):
        overlap = state[uri] & site_ids
        if not overlap:
            continue
        cleared += len(overlap)
        state[uri] -= site_ids
        if not state[uri]:
            del state[uri]
    return cleared


def sync_blocked_state(
    active_proxies: List[str],
    target_versions: Dict[str, int],
) -> Dict[str, Set[str]]:
    """Drop stale proxies and re-test sites whose target version was bumped."""
    state, stored_versions = _load_raw()

    bumped = _sites_with_version_bump(target_versions, stored_versions)
    if bumped:
        cleared = _clear_sites(state, bumped)
        log(
            f"Site access state: cleared {cleared} block(s) for "
            f"{sorted(bumped)} (target version changed)"
        )

    active = set(active_proxies)
    cleaned = {uri: sites for uri, sites in state.items() if uri in active}
    if len(cleaned) != len(state):
        removed = len(state) - len(cleaned)
        log(f"Site access state: removed {removed} stale proxy entries")

    save_blocked_state(cleaned, target_versions)
    return cleaned


def mark_site_blocked(state: Dict[str, Set[str]], uri: str, site_id: str) -> None:
    if uri not in state:
        state[uri] = set()
    state[uri].add(site_id)


def sites_to_test(
    uri: str,
    all_site_ids: List[str],
    blocked_state: Dict[str, Set[str]],
) -> List[str]:
    blocked = blocked_state.get(uri, set())
    return [site_id for site_id in all_site_ids if site_id not in blocked]
