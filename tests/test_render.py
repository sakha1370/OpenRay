import base64
import json
import unittest

from openray.domain import parse_uri
from openray.render import Unsupported, clash_proxy, convert, singbox_outbound, xray_outbound
from tests.test_domain import UUID, VLESS


def ss(method: str):
    auth = base64.urlsafe_b64encode(f"{method}:secret".encode()).decode().rstrip("=")
    return parse_uri(f"ss://{auth}@example.com:80")


class RenderTests(unittest.TestCase):
    def test_no_name_collision_and_deterministic(self):
        proxies = [
            parse_uri(VLESS + "#same"),
            parse_uri(VLESS.replace("example.com", "other.test") + "#same"),
        ]
        a = convert(proxies)
        self.assertEqual(a, convert(list(reversed(proxies))))
        self.assertEqual(len(a[0]["proxies"]), 2)
        self.assertEqual(len([o for o in a[1]["outbounds"] if o["type"] == "vless"]), 2)

    def test_grpc_tls_ws_and_passwords(self):
        p = parse_uri(VLESS + "?type=grpc&serviceName=service&security=tls&sni=front.test")
        ob = singbox_outbound(p)
        self.assertTrue(ob["tls"]["enabled"])
        self.assertEqual(ob["transport"]["service_name"], "service")
        self.assertEqual(xray_outbound(p)["streamSettings"]["grpcSettings"]["serviceName"], "service")
        ws = singbox_outbound(parse_uri(VLESS + "?type=ws&host=front.test&path=%2Fws%3Ftoken%3Da"))
        self.assertEqual(ws["transport"]["path"], "/ws?token=a")
        self.assertEqual(ws["transport"]["headers"]["Host"], "front.test")
        tuic = singbox_outbound(parse_uri(f"tuic://{UUID}:secret@example.com:443"))
        self.assertEqual(tuic["password"], "secret")
        for uri in [
            "trojan://secret@example.com:443",
            "hy2://secret@example.com:443",
            "ss://YWVzLTEyOC1nY206cGFzcw@example.com:80",
        ]:
            self.assertEqual(len(convert([parse_uri(uri)])[0]["proxies"]), 1)

    def test_explicit_unsupported_report(self):
        clash, sing, report = convert([parse_uri(f"juicity://{UUID}:secret@example.com:443")])
        self.assertEqual(len(report), 2)
        self.assertEqual(clash["proxies"], [])
        # A known option from another protocol must not be silently ignored.
        self.assertEqual(len(convert([parse_uri(VLESS + "?obfs=required")])[2]), 2)
        self.assertEqual(len(convert([parse_uri(VLESS + "?headerType=http")])[2]), 2)

    def test_vmess_metadata_is_preserved_or_reported(self):
        fields = {"add": "example.test", "port": 443, "id": UUID, "tls": "tls", "fp": "firefox", "alpn": "h2"}
        uri = "vmess://" + base64.b64encode(json.dumps(fields).encode()).decode()
        outbound = singbox_outbound(parse_uri(uri))
        self.assertEqual(outbound["tls"]["utls"]["fingerprint"], "firefox")
        self.assertEqual(outbound["tls"]["alpn"], ["h2"])
        fields["future_security"] = "required"
        uri = "vmess://" + base64.b64encode(json.dumps(fields).encode()).decode()
        self.assertEqual(len(convert([parse_uri(uri)])[2]), 2)

    def test_vmess_json_null_is_unset(self):
        fields = {"add": "example.test", "port": 443, "id": UUID, "tls": "tls", "fp": None, "alpn": None}
        p = parse_uri("vmess://" + base64.b64encode(json.dumps(fields).encode()).decode())
        self.assertEqual((p.get("fp"), p.get("alpn")), ("", ""))
        self.assertNotIn("utls", singbox_outbound(p)["tls"])
        self.assertNotIn("alpn", xray_outbound(p)["streamSettings"]["tlsSettings"])
        # mihomo rejected the whole client file over one "scy": "null"; unset security is auto.
        for scy in (None, "null", ""):
            fields.update(scy=scy)
            p = parse_uri("vmess://" + base64.b64encode(json.dumps(fields).encode()).decode())
            self.assertEqual(clash_proxy(p)["cipher"], "auto")
            self.assertEqual(xray_outbound(p)["settings"]["vnext"][0]["users"][0]["security"], "auto")
        fields.update(scy="tls")
        self.assertEqual(
            len(convert([parse_uri("vmess://" + base64.b64encode(json.dumps(fields).encode()).decode())])[2]),
            2,
        )

    def test_each_core_receives_only_ciphers_it_accepts(self):
        legacy = ss("aes-256-cfb")
        with self.assertRaises(Unsupported):
            xray_outbound(legacy)
        self.assertEqual(singbox_outbound(legacy)["method"], "aes-256-cfb")
        self.assertEqual(clash_proxy(legacy)["cipher"], "aes-256-cfb")
        alias = ss("CHACHA20-POLY1305")
        self.assertEqual(xray_outbound(alias)["settings"]["servers"][0]["method"], "chacha20-ietf-poly1305")
        self.assertEqual(singbox_outbound(alias)["method"], "chacha20-ietf-poly1305")
        # Clients refuse a Shadowsocks 2022 key of the wrong size.
        self.assertEqual(len(convert([ss("2022-blake3-aes-256-gcm")])[2]), 2)
        with self.assertRaises(ValueError):
            xray_outbound(ss("2022-blake3-aes-256-gcm"))
        # Sources sometimes put a channel name where the cipher belongs.
        self.assertEqual(len(convert([ss("TelegramChannel")])[2]), 2)
        with self.assertRaises(Unsupported):
            xray_outbound(ss("TelegramChannel"))

    def test_core_specific_transport_and_flow_limits(self):
        reality = f"?security=reality&pbk={base64.urlsafe_b64encode(bytes(32)).decode().rstrip('=')}&sid=ab"
        ws = parse_uri(VLESS + reality + "&type=ws")
        with self.assertRaises(Unsupported):
            xray_outbound(ws)
        self.assertTrue(singbox_outbound(ws)["tls"]["reality"]["enabled"])
        grpc = parse_uri(VLESS + reality + "&type=grpc&serviceName=s")
        self.assertEqual(xray_outbound(grpc)["streamSettings"]["security"], "reality")
        with self.assertRaises(Unsupported):
            clash_proxy(parse_uri(VLESS + "?security=tls&flow=xtls-rprx-direct"))
        self.assertEqual(
            clash_proxy(parse_uri(VLESS + "?security=tls&flow=xtls-rprx-vision"))["flow"], "xtls-rprx-vision"
        )
