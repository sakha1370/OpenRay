import base64
import json
import unittest

from openray.domain import ParseError, extract_uris, parse_uri

UUID = "11111111-1111-4111-8111-111111111111"
VLESS = f"vless://{UUID}@example.com:443"


class ProtocolTests(unittest.TestCase):
    def test_transport_identity(self):
        for left, right in (
            ("serviceName=a", "serviceName=b"),
            ("path=%2Fws%3Ftoken%3Da", "path=%2Fws%3Ftoken%3Db"),
            ("fp=chrome", "fp=firefox"),
            ("unknown=a", "unknown=b"),
        ):
            self.assertNotEqual(
                parse_uri(VLESS + "?" + left).identity, parse_uri(VLESS + "?" + right).identity
            )
        self.assertEqual(parse_uri(VLESS + "#one").identity, parse_uri(VLESS + "#two").identity)
        self.assertEqual(parse_uri(VLESS + "?a=1&b=2").identity, parse_uri(VLESS + "?b=2&a=1").identity)

    def test_ss_sip002_legacy_ipv6(self):
        auth = base64.urlsafe_b64encode(b"aes-128-gcm:secret").decode().rstrip("=")
        full = base64.urlsafe_b64encode(b"aes-128-gcm:secret@[::1]:1").decode().rstrip("=")
        first = parse_uri(f"ss://{auth}@[::1]:1#same")
        self.assertEqual(first.identity, parse_uri(f"ss://{full}#other").identity)
        self.assertEqual(first.port, 1)

    def test_all_recognized_protocols(self):
        vmess = base64.b64encode(
            json.dumps({"add": "example.com", "port": 443, "id": UUID, "net": "grpc", "path": "svc"}).encode()
        ).decode()
        ssr = base64.b64encode(b"example.com:443:origin:aes-128-cfb:plain:cGFzcw/?remarks=bmFtZQ").decode()
        uris = [
            f"vmess://{vmess}",
            VLESS,
            "trojan://secret@example.com:443",
            "ss://YWVzLTEyOC1nY206cGFzcw@example.com:80",
            f"ssr://{ssr}",
            "hysteria://example.com:443?auth=pass",
            "hy2://pass@example.com:443",
            f"tuic://{UUID}:secret@example.com:443",
            f"juicity://{UUID}:secret@example.com:443",
            "wireguard://key@example.com:51820?publickey=peer",
            "socks://u:p@example.com:1080",
            "http://u:p@example.com:80",
            "https://u:p@example.com:443",
        ]
        self.assertEqual(len({parse_uri(u).scheme for u in uris}), len(uris))
        self.assertEqual(parse_uri(uris[7]).password, "secret")

    def test_invalid_and_encoded_subscription(self):
        for value in (
            VLESS + VLESS,
            "vless://@example.com:443",
            VLESS.replace(":443", ":65536"),
            "ss://!!!",
            "trojan://password@example.test:0",
            "http://example.test:0",
            "https://example.test:0",
            "socks://example.test:0",
        ):
            with self.assertRaises((ParseError, UnicodeError)):
                parse_uri(value)
        self.assertEqual(extract_uris(base64.b64encode((VLESS + "\n").encode()).decode()), [VLESS])
