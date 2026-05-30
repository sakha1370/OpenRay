from __future__ import annotations

import os
import threading
from typing import Optional

from .types import Stage3Summary, TimingStats

_global_summary: Optional[Stage3Summary] = None
_lock = threading.Lock()


def reset_summary(backend: str) -> Stage3Summary:
    global _global_summary
    with _lock:
        _global_summary = Stage3Summary(backend=backend)
        return _global_summary


def get_summary() -> Optional[Stage3Summary]:
    return _global_summary


def record_check(result: Optional[bool], timing: TimingStats) -> None:
    with _lock:
        if _global_summary is not None:
            _global_summary.record(result, timing)


def log_summary_if_debug() -> None:
    with _lock:
        summary = _global_summary
    if summary is None:
        return
    debug = os.environ.get('OPENRAY_DEBUG', '').strip().lower() in ('1', 'true', 'yes')
    if debug:
        from ..common import log
        log(summary.format_line())
