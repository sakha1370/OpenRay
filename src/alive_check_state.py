from __future__ import annotations

import time
from typing import Any, Dict, Optional

from .constants import ALIVE_CHECK_COOLDOWN_H, ALIVE_DEATH_AFTER_H


def default_count_entry() -> Dict[str, Any]:
    return {
        "global": 0,
        "iran": {
            "total": 0,
            "operators": {
                "mci": 0,
                "irancell": 0,
                "tci": 0,
                "others": 0,
            },
        },
        "consecutive_failures": 0,
    }


def ensure_count_entry(counts: Dict[str, Any], uri: str) -> Dict[str, Any]:
    if uri not in counts:
        counts[uri] = default_count_entry()
    return counts[uri]


def is_in_alive_cooldown(uri: str, counts: Dict[str, Any], now: Optional[float] = None) -> bool:
    """True when proxy should skip Stage 3 alive recheck until cooldown expires."""
    entry = counts.get(uri)
    if not entry:
        return False
    next_at = entry.get("alive_next_check_at")
    if next_at is None:
        return False
    ts = now if now is not None else time.time()
    try:
        return ts < float(next_at)
    except (TypeError, ValueError):
        return False


def record_alive_success(counts: Dict[str, Any], uri: str) -> None:
    """Reset alive failure streak and cooldown after a successful check."""
    entry = ensure_count_entry(counts, uri)
    entry.pop("alive_next_check_at", None)
    entry.pop("alive_first_fail_at", None)
    entry["consecutive_failures"] = 0


def record_alive_failure(counts: Dict[str, Any], uri: str, now: Optional[float] = None) -> bool:
    """Apply 8h cooldown; return True if proxy should be removed (3-day failure streak)."""
    ts = now if now is not None else time.time()
    entry = ensure_count_entry(counts, uri)

    if entry.get("alive_first_fail_at") is None:
        entry["alive_first_fail_at"] = ts

    first_fail = float(entry["alive_first_fail_at"])
    death_after_s = int(ALIVE_DEATH_AFTER_H) * 3600
    if ts - first_fail >= death_after_s:
        return True

    cooldown_s = int(ALIVE_CHECK_COOLDOWN_H) * 3600
    entry["alive_next_check_at"] = ts + cooldown_s
    entry["consecutive_failures"] = int(entry.get("consecutive_failures", 0)) + 1
    return False


def clear_alive_state(counts: Dict[str, Any], uri: str) -> None:
    entry = counts.get(uri)
    if not entry:
        return
    entry.pop("alive_next_check_at", None)
    entry.pop("alive_first_fail_at", None)
