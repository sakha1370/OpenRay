from __future__ import annotations

import base64
import ipaddress
import json
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode

from .domain import Proxy, b64decode, parse_uri


class Geo:
    def __init__(self, root: Path):
        self.reader = None
        try:
            import maxminddb

            self.reader = maxminddb.open_database(str(root / "src/GeoLite2-Country.mmdb"))
        except (ImportError, OSError):
            pass

    def close(self):
        if self.reader:
            self.reader.close()

    def country(self, proxy: Proxy) -> str:
        try:
            ipaddress.ip_address(proxy.server)
            record = self.reader.get(proxy.server) if self.reader else {}
            return (record or {}).get("country", {}).get("iso_code", "XX")
        except Exception:
            return "XX"

    def label(self, proxy: Proxy, counters: dict[str, int]) -> Proxy:
        cc = proxy.country if "[OpenRay]" in proxy.remark else self.country(proxy)
        counters[cc] = counters.get(cc, 0) + 1
        flag = "".join(chr(127397 + ord(c)) for c in cc) if cc != "XX" else "🌐"
        remark = f"[OpenRay] {flag}{cc}-{counters[cc]}"
        if proxy.scheme == "vmess":
            data = json.loads(b64decode(proxy.uri.split("://", 1)[1].split("#", 1)[0]))
            data["ps"] = remark
            uri = (
                "vmess://"
                + base64.b64encode(
                    json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
                ).decode()
            )
        elif proxy.scheme == "ssr":
            body = b64decode(proxy.uri.split("://", 1)[1].split("#", 1)[0]).decode()
            connection, _, query = body.partition("/?")
            params = [(k, v) for k, v in parse_qsl(query, keep_blank_values=True) if k != "remarks"]
            params.append(("remarks", base64.urlsafe_b64encode(remark.encode()).decode().rstrip("=")))
            uri = "ssr://" + base64.urlsafe_b64encode(
                (connection + "/?" + urlencode(params)).encode()
            ).decode().rstrip("=")
        else:
            uri = proxy.uri.split("#", 1)[0] + "#" + quote(remark)
        return parse_uri(uri)
