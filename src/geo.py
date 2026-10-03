"""Legacy geolocation helper; the main pipeline reuses openray.geo.Geo."""

from openray.geo import Geo
from openray.domain import Proxy, parse_uri
from openray.config import Settings


def _get_country_code_from_ip(ip):
    geo = Geo(Settings.from_env().root)
    try:
        return geo.country(Proxy("", "socks", ip, 1))
    finally:
        geo.close()


def _country_flag(cc):
    return "".join(chr(127397 + ord(c)) for c in cc) if cc and len(cc) == 2 and cc != "XX" else "🌐"


def _build_country_counters(uris):
    counts = {}
    for uri in uris:
        try:
            p = parse_uri(uri)
            cc = p.country
            counts[cc] = counts.get(cc, 0) + 1
        except ValueError:
            continue
    return counts
