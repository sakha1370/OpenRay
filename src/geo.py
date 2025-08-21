from __future__ import annotations

from typing import Dict, Iterable, Optional, Tuple

from .parsing import _extract_our_cc_and_num_from_uri


def _country_flag(cc: Optional[str]) -> str:
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "🌐"
    cc = cc.upper()
    try:
        return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)
    except Exception:
        return "🌐"


def _build_country_counters(existing: Iterable[str]) -> Dict[str, int]:
    counters: Dict[str, int] = {}
    for line in existing:
        parsed = _extract_our_cc_and_num_from_uri(line)
        if parsed:
            cc, num = parsed
            prev = counters.get(cc, 0)
            if num > prev:
                counters[cc] = num
    return counters
