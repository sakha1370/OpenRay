from __future__ import annotations


from typing import Dict, Iterable, Optional, Tuple
import os
import geoip2.database
from .parsing import is_ip_address


from .parsing import _extract_our_cc_and_num_from_uri
def get_country_code_geoip2(ip: str, mmdb_path: str = None) -> Optional[str]:
    """
    Returns 2-letter country code for a static IP using local GeoLite2-Country.mmdb.
    Handles errors gracefully.
    """
    if not is_ip_address(ip):
        return None
    if mmdb_path is None:
        mmdb_path = os.path.join(os.path.dirname(__file__), "../GeoLite2-Country.mmdb")
    try:
        reader = geoip2.database.Reader(mmdb_path)
        response = reader.country(ip)
        cc = response.country.iso_code
        reader.close()
        if isinstance(cc, str) and len(cc) == 2:
            return cc.upper()
    except Exception:
        return None
    return None


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
