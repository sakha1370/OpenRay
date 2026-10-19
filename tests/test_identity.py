"""Identity v3 hashes the connection a client makes, so URIs it merges must render identically.

The renderers in render.py are the specification: a parameter may leave the identity only if every
client profile ignores it for that connection and its mere presence cannot change what is supported.
"""

import base64
import json
import random
import unittest

from openray import render
from openray.domain import parse_uri
from tests.test_domain import UUID

PBK = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
BASE = f"vless://{UUID}@example.com:443"
REALITY = f"security=reality&pbk={PBK}&sni=front.test&flow=xtls-rprx-vision"
RENDERERS = (render.xray_outbound, render.singbox_outbound, render.clash_proxy)


def vmess(**fields) -> str:
    data = {"add": "example.com", "port": 443, "id": UUID, **fields}
    return "vmess://" + base64.b64encode(json.dumps(data).encode()).decode()


def outcome(renderer, proxy):
    """Rendered config, or the failure, without the names derived from the identity itself."""

    def strip(value):
        if isinstance(value, dict):
            return {k: strip(v) for k, v in value.items() if k not in {"name", "tag"}}
        return [strip(v) for v in value] if isinstance(value, list) else value

    try:
        return json.dumps(strip(renderer(proxy)), sort_keys=True, default=str)
    except Exception as exc:  # an identical refusal is part of being the same connection
        return f"{type(exc).__name__}: {exc}"


class IdentityTests(unittest.TestCase):
    def assertSameConnection(self, *uris):
        proxies = [parse_uri(u) for u in uris]
        self.assertEqual(len({p.identity for p in proxies}), 1, uris)
        for renderer in RENDERERS:
            self.assertEqual(len({outcome(renderer, p) for p in proxies}), 1, (renderer.__name__, uris))

    def assertDifferentConnection(self, left, right):
        self.assertNotEqual(parse_uri(left).identity, parse_uri(right).identity, (left, right))

    def test_spelling_and_defaults_of_the_same_connection(self):
        self.assertSameConnection(
            f"{BASE}?{REALITY}",
            f"{BASE}?{REALITY}&type=tcp",
            f"{BASE}?{REALITY}&type=raw&headerType=none&encryption=none",
            f"{BASE}?{REALITY}&fp=chrome&network=tcp",  # Reality defaults to chrome in every client
            f"{BASE}?{REALITY}&fp=&alpn=&sid=",
            f"{BASE}?{REALITY}#any-remark",
        )
        self.assertSameConnection(
            f"{BASE}?security=tls",
            f"{BASE}?security=tls&sni=example.com",
            f"{BASE}?security=tls&servername=example.com",
            f"{BASE}?security=TLS&peer=example.com&allowInsecure=0",
            f"{BASE}?security=tls&insecure=false&fp=&alpn=",
        )
        self.assertSameConnection(
            f"{BASE}?security=tls&allowInsecure=1", f"{BASE}?security=tls&insecure=true"
        )
        self.assertSameConnection(f"{BASE}?type=grpc&serviceName=s", f"{BASE}?type=gun&serviceName=s")
        self.assertSameConnection(
            "trojan://pw@example.com", "trojan://pw@example.com:443?security=tls&type=tcp"
        )

    def test_parameters_the_connection_never_reads(self):
        # Advertising tags, and transport options of a transport this connection does not use.
        self.assertSameConnection(
            f"{BASE}?{REALITY}",
            f"{BASE}?{REALITY}&host=Join-the-channel&path=%2Fjunk%3Fed%3D2560&telegram=chan&descriptions=x&_t=1",
            f"{BASE}?{REALITY}&ed=2560&eh=h&serviceName=s&service=t&headerType=none",
        )
        # TLS options mean nothing without TLS, Reality keys nothing without Reality.
        self.assertSameConnection(
            f"{BASE}?type=ws&path=%2Fa",
            f"{BASE}?type=ws&path=%2Fa&sni=other.test&fp=firefox&alpn=h2&allowInsecure=1&pbk=abc&sid=ab",
            f"{BASE}?type=ws&path=%2Fa&security=none&security=tls",  # repeated keys: the first one wins
        )
        self.assertSameConnection(
            f"{BASE}?security=tls",
            f"{BASE}?security=tls&pbk={PBK}&sid=ab",
            f"{BASE}?security=tls&host=x&path=%2Fy",
        )
        self.assertSameConnection(
            f"{BASE}?type=ws&path=%2Fp&host=h.test",
            f"{BASE}?type=ws&path=%2Fp&host=h.test&headerType=none&serviceName=x",
        )
        self.assertSameConnection(
            f"{BASE}?type=grpc&serviceName=s", f"{BASE}?type=grpc&serviceName=s&path=%2Fx&host=y"
        )

    def test_vmess_json_shape_is_not_a_connection(self):
        self.assertSameConnection(
            vmess(net="tcp", aid=0, tls="", type="none", host="", path=""),
            vmess(net="tcp", aid="0", scy="auto", ps="named", v="2"),
            vmess(net="raw", aid="00", tls="none", type="none", host="ignored", path="/ignored"),
        )
        self.assertSameConnection(
            vmess(net="ws", path="/w", host="h.test", tls="tls"),
            vmess(net="ws", path="/w", host="h.test", tls="tls", fp="", alpn=""),
        )
        # An explicit sni is a different server name from VMess's blank default, so these stay apart.
        self.assertDifferentConnection(vmess(net="ws", tls="tls", sni="h.test"), vmess(net="ws", tls="tls"))

    def test_everything_that_changes_the_connection_stays(self):
        pairs = [
            (f"{BASE}?type=ws&path=%2Fa", f"{BASE}?type=ws&path=%2Fb"),
            (f"{BASE}?type=ws&host=a.test", f"{BASE}?type=ws&host=b.test"),
            (f"{BASE}?type=ws&ed=2560", f"{BASE}?type=ws"),
            (f"{BASE}?type=ws", f"{BASE}?type=wss"),
            (f"{BASE}?type=ws", f"{BASE}?type=httpupgrade"),
            (f"{BASE}?type=grpc&serviceName=a", f"{BASE}?type=grpc&serviceName=b"),
            (f"{BASE}?headerType=http&host=a.test", f"{BASE}?headerType=http&host=b.test"),
            (f"{BASE}?headerType=http&path=%2Fa", f"{BASE}?headerType=http&path=%2Fb"),
            (f"{BASE}?headerType=http", f"{BASE}?headerType=none"),
            (f"{BASE}?headerType=", f"{BASE}"),  # a blank header is refused, an absent one is "none"
            (f"{BASE}?security=tls&sni=a.test", f"{BASE}?security=tls&sni=b.test"),
            (f"{BASE}?security=tls&fp=chrome", f"{BASE}?security=tls&fp=firefox"),
            (f"{BASE}?security=tls&alpn=h2", f"{BASE}?security=tls"),
            (f"{BASE}?security=tls&allowInsecure=1", f"{BASE}?security=tls"),
            (f"{BASE}?security=tls", f"{BASE}?security=none"),
            (f"{BASE}?security=tls", f"{BASE}"),
            (f"{BASE}?{REALITY}", f"{BASE}?{REALITY.replace('front.test', 'other.test')}"),
            (f"{BASE}?{REALITY}", f"{BASE}?{REALITY}&sid=ab"),
            (f"{BASE}?{REALITY}", f"{BASE}?{REALITY.replace('reality', 'tls')}"),
            (f"{BASE}?{REALITY}", f"{BASE}?{REALITY.replace('xtls-rprx-vision', 'xtls-rprx-vision-udp443')}"),
            (f"{BASE}?flow=xtls-rprx-vision", f"{BASE}"),
            (f"{BASE}?packetEncoding=xudp", f"{BASE}"),
            (f"{BASE}?encryption=mlkem", f"{BASE}"),
            (f"{BASE}", f"{BASE.replace('443', '8443')}"),
            (f"{BASE}", f"{BASE.replace('example.com', 'other.test')}"),
            (f"{BASE}", f"{BASE.replace(UUID, UUID[:-1] + '2')}"),
            (f"{BASE}?type=kcp&headerType=wechat-video", f"{BASE}?type=kcp"),
            (f"{BASE}", f"{BASE}/path"),  # a URI path is unknown to the renderers, so it is kept
        ]
        for left, right in pairs:
            with self.subTest(left=left, right=right):
                self.assertDifferentConnection(left, right)

    def test_parameters_that_gate_client_support_are_kept(self):
        # sing-box and mihomo refuse these by presence alone, so folding them in would hide the
        # variant a client can use behind one it cannot.
        for left, right in (
            (f"{BASE}?type=ws&mode=multi", f"{BASE}?type=ws"),
            (f"{BASE}?{REALITY}&spx=%2F", f"{BASE}?{REALITY}"),
            (f"{BASE}?type=grpc&authority=a.test", f"{BASE}?type=grpc"),
            (f"{BASE}?type=xhttp&extra=%7B%7D", f"{BASE}?type=xhttp"),
            (f"{BASE}?multiMode=true", f"{BASE}"),
            ("trojan://pw@example.com?encryption=none", "trojan://pw@example.com"),
            ("trojan://pw@example.com?flow=xtls-rprx-vision", "trojan://pw@example.com"),
            ("trojan://pw@example.com?security=", "trojan://pw@example.com"),  # blank means no TLS
            (f"{BASE}?unknown=a", f"{BASE}"),
            (f"{BASE}?unknown=a", f"{BASE}?unknown=b"),
            (f"{BASE}?unknown=1&unknown=2", f"{BASE}?unknown=2&unknown=1"),
            (f"{BASE}?type=ws&unknown=a&path=%2Fa", f"{BASE}?type=ws&path=%2Fa"),
            (vmess(aid=0), vmess(aid=1)),
            (vmess(scy=None), vmess()),
            (vmess(flow=0), vmess()),
            (vmess(extra="a"), vmess(extra="b")),
        ):
            with self.subTest(left=left, right=right):
                self.assertDifferentConnection(left, right)

    def test_merged_uris_render_identically_over_the_parameter_grid(self):
        """Differential fuzz: same identity implies same rendering in every client profile."""
        grid = {
            "type": [None, "tcp", "raw", "ws", "grpc"],
            "security": [None, "", "none", "tls", "reality"],
            "headerType": [None, "none", "http"],
            "host": [None, "h.test"],
            "path": [None, "/p"],
            "serviceName": [None, "s"],
            "sni": [None, "example.com", "other.test"],
            "fp": [None, "", "chrome"],
            "allowInsecure": [None, "0", "1"],
            "encryption": [None, "none"],
            "mode": [None, "multi"],
            "spx": [None, "/"],
            "telegram": [None, "t"],
            "pbk": [None, PBK],
            "flow": [None, "", "xtls-rprx-vision"],
            "packetEncoding": [None, "", "xudp"],
        }
        rng = random.Random(20261019)
        groups: dict[str, list] = {}
        for scheme in ("vless", "trojan"):
            for _ in range(3000):
                query = "&".join(
                    f"{key}={value}"
                    for key, values in grid.items()
                    # Weighted to absent so that generated URIs collide often enough to be compared.
                    if (value := rng.choices(values, [4] + [1] * (len(values) - 1))[0]) is not None
                )
                userinfo = UUID if scheme == "vless" else "secret"
                proxy = parse_uri(f"{scheme}://{userinfo}@example.com:443?{query}")
                groups.setdefault(proxy.identity, []).append(proxy)
        merged = [g for g in groups.values() if len(g) > 1]
        self.assertGreater(len(merged), 150, "the fuzz must actually merge URIs to test anything")
        for group in merged:
            for renderer in RENDERERS:
                with self.subTest(renderer=renderer.__name__, uri=group[0].uri):
                    self.assertEqual(len({outcome(renderer, p) for p in group}), 1, [p.uri for p in group])
