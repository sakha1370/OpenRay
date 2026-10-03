import base64
import json
import unittest

from openray.domain import parse_uri
from openray.render import convert, singbox_outbound, xray_outbound
from tests.test_domain import UUID, VLESS


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
