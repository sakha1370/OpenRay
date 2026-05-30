from __future__ import annotations

import json
import os
from typing import Dict, List, Set

from .constants import SITE_ACCESS_STATE_FILE, STATE_DIR
from .common import log


def _ensure_state_dir() -> None:
    os.makedirs(STATE_DIR, exist_ok=True)


def load_blocked_state() -> Dict[str, Set[str]]:
    """Return {proxy_uri: {site_id, ...}} for permanently skipped site checks."""
    _ensure_state_dir()
    if not os.path.exists(SITE_ACCESS_STATE_FILE):
        return {}
    try:
        with open(SITE_ACCESS_STATE_FILE, 'r', encoding='utf-8') as f:
            raw = json.load(f)
        if not isinstance(raw, dict):
            return {}
        state: Dict[str, Set[str]] = {}
        for uri, sites in raw.items():
            if not isinstance(uri, str) or not uri.strip():
                continue
            if isinstance(sites, list):
                state[uri] = {str(s) for s in sites if s}
            elif isinstance(sites, dict):
                state[uri] = {str(k) for k, v in sites.items() if v}
        return state
    except Exception as e:
        log(f"Failed to load site access blocked state: {e}")
        return {}


def save_blocked_state(state: Dict[str, Set[str]]) -> None:
    _ensure_state_dir()
    payload = {uri: sorted(sites) for uri, sites in sorted(state.items()) if sites}
    tmp_path = SITE_ACCESS_STATE_FILE + '.tmp'
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write('\n')
    os.replace(tmp_path, SITE_ACCESS_STATE_FILE)


def sync_blocked_state(active_proxies: List[str]) -> Dict[str, Set[str]]:
    """Drop state entries for proxies no longer in the alive list."""
    state = load_blocked_state()
    active = set(active_proxies)
    cleaned = {uri: sites for uri, sites in state.items() if uri in active}
    if len(cleaned) != len(state):
        removed = len(state) - len(cleaned)
        log(f"Site access state: removed {removed} stale proxy entries")
        save_blocked_state(cleaned)
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
