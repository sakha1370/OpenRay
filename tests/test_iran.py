import base64
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from openray import iran
from openray.domain import parse_uri
from openray.iran import bucket, drop_reason, fix, node_rates, normalize, probe_verdict
from tools import iran_filter

UUID = "11111111-1111-4111-8111-111111111111"
HEX = UUID.replace("-", "")
REALITY = f"vless://{UUID}@example.com:443?security=reality&pbk=abc&sni=www.apple.com&type=tcp&fp=chrome"
TLS_WS = f"vless://{UUID}@1.2.3.4:443?security=tls&type=ws&host=cdn.example.com&path=%2Fws"
TROJAN = "trojan://secret@9.9.9.9:443?type=ws&sni=t.example.com&fp=chrome"


def vmess(**fields) -> str:
    data = {"add": "example.com", "port": 443, "id": UUID, "net": "ws", "tls": "tls", "ps": "name"}
    data.update(fields)
    return "vmess://" + base64.b64encode(json.dumps(data).encode()).decode()


def vmess_json(uri: str) -> dict:
    return json.loads(base64.b64decode(uri.split("://", 1)[1]))


class DropTests(unittest.TestCase):
    def test_reasons(self):
        cases = {
            "hy2://pass@example.com:443": "udp-quic",
            f"tuic://{UUID}:secret@example.com:443": "udp-quic",
            "socks://u:p@example.com:1080": "plaintext-proxy",
            "http://u:p@example.com:80": "plaintext-proxy",
            "https://u:p@example.com:443": "plaintext-proxy",
            REALITY.replace("type=tcp", "type=ws"): "reality-transport",
        }
        for uri, reason in cases.items():
            self.assertEqual(drop_reason(parse_uri(uri)), reason, uri)

    def test_everything_else_stays(self):
        for uri in (REALITY, TLS_WS, TROJAN, "ss://aes-128-gcm:pass@example.com:80", vmess()):
            self.assertIsNone(drop_reason(parse_uri(uri)), uri)


class NormalizeTests(unittest.TestCase):
    def test_spelling_fixes_keep_identity(self):
        raw = f"vless://{HEX}@example.com:443?type=raw&security=reality&pbk=abc&sni=www.apple.com#name"
        proxy = parse_uri(raw)
        edit = normalize(proxy)
        self.assertEqual(set(edit.tags), {"uuid", "type", "fp"})
        self.assertEqual(parse_uri(edit.uri).identity, proxy.identity)
        self.assertTrue(edit.uri.startswith(f"vless://{UUID}@example.com:443?type=tcp&"))
        self.assertTrue(edit.uri.endswith("&fp=chrome#name"))

    def test_vmess_id_and_network(self):
        proxy = parse_uri(vmess(id=HEX, net="raw"))
        edit = normalize(proxy)
        data = vmess_json(edit.uri)
        self.assertEqual((data["id"], data["net"], data["ps"]), (UUID, "tcp", "name"))
        self.assertEqual(parse_uri(edit.uri).identity, proxy.identity)

    def test_non_ascii_is_percent_encoded(self):
        raw = f"vless://{UUID}@example.com:443?security=tls&sni=example.com&fp=chrome&path=/–x#n"
        proxy = parse_uri(raw)
        edit = normalize(proxy)
        self.assertEqual(edit.tags, ("ascii",))
        self.assertTrue(edit.uri.isascii())
        self.assertEqual(parse_uri(edit.uri).get("path"), "/–x")
        self.assertEqual(parse_uri(edit.uri).identity, proxy.identity)

    def test_clean_link_is_left_alone(self):
        self.assertIsNone(normalize(parse_uri(REALITY)))
        self.assertIsNone(normalize(parse_uri("ss://aes-128-gcm:pass@example.com:80")))


class FixTests(unittest.TestCase):
    def test_sni_and_fingerprint(self):
        proxy = parse_uri(TLS_WS + "&sni=1.2.3.4#n")
        edit = fix(proxy)
        self.assertEqual(set(edit.tags), {"fp", "sni"})
        edited = parse_uri(edit.uri)
        self.assertEqual((edited.get("sni"), edited.get("fp")), ("cdn.example.com", "chrome"))
        self.assertIn("path=%2Fws", edit.uri)
        self.assertEqual((edited.server, edited.port, edited.username), (proxy.server, proxy.port, UUID))
        self.assertNotEqual(edited.identity, proxy.identity)

    def test_junk_alpn_is_cleaned_or_removed(self):
        base = f"vless://{UUID}@example.com:443?security=tls&sni=example.com&fp=chrome"
        edit = fix(parse_uri(base + "&alpn=h2,vpn_channel,http%2F1.1"))
        self.assertEqual(edit.tags, ("alpn",))
        self.assertEqual(parse_uri(edit.uri).get("alpn"), "h2,http/1.1")
        edit = fix(parse_uri(base + "&alpn=vpn_channel#n"))
        self.assertNotIn("alpn", edit.uri)

    def test_unsafe_fingerprint_on_reality(self):
        edit = fix(parse_uri(REALITY.replace("fp=chrome", "fp=unsafe")))
        self.assertEqual(edit.tags, ("fp",))
        self.assertIn("fp=chrome", edit.uri)
        self.assertNotIn("unsafe", edit.uri)

    def test_vmess_is_edited_inside_the_json(self):
        edit = fix(parse_uri(vmess(add="1.2.3.4", host="cdn.example.com", sni="")))
        data = vmess_json(edit.uri)
        self.assertEqual((data["fp"], data["sni"]), ("chrome", "cdn.example.com"))
        self.assertEqual((data["ps"], data["add"], data["id"]), ("name", "1.2.3.4", UUID))

    def test_nothing_to_fix(self):
        for uri in (
            REALITY,
            f"vless://{UUID}@example.com:443?security=none&type=ws",
            TROJAN,
            "ss://aes-128-gcm:pass@example.com:80",
        ):
            self.assertIsNone(fix(parse_uri(uri)), uri)


class QueryEditTests(unittest.TestCase):
    def test_other_bytes_are_preserved(self):
        uri = "vless://u@h:1?pbk=a+b%2Fc&Fingerprint=none&fp=x&path=%2F%3Fed%3D2048#r"
        self.assertEqual(
            iran._set_params(uri, {"fp": "chrome"}),
            "vless://u@h:1?pbk=a+b%2Fc&fp=chrome&path=%2F%3Fed%3D2048#r",
        )
        self.assertEqual(iran._set_params("vless://u@h:1?alpn=x#r", {"alpn": None}), "vless://u@h:1#r")
        self.assertEqual(iran._set_params("vless://u@h:1#r", {"fp": "chrome"}), "vless://u@h:1?fp=chrome#r")


class RankTests(unittest.TestCase):
    def test_buckets(self):
        cases = (
            (REALITY, False, 2),
            (REALITY, True, 1),
            (f"vless://{UUID}@example.com:443?security=tls&type=grpc&serviceName=s", False, 2),
            (f"vless://{UUID}@example.com:443?security=tls&type=ws", False, 3),
            (f"vless://{UUID}@example.com:443?security=tls&type=httpupgrade", False, 4),
            (f"vless://{UUID}@example.com:443?security=none&type=ws", False, 5),
            ("trojan://secret@example.com:443", False, 2),
            ("trojan://secret@example.com:443?type=ws", False, 3),
            ("ss://aes-128-gcm:pass@example.com:80", False, 4),
            ("ss://rc4-md5:pass@example.com:80", False, 5),
            # Evidence lifts a line to the top, but never out of the last tier.
            (f"vless://{UUID}@example.com:443?security=tls&type=ws", True, 1),
            (f"vless://{UUID}@example.com:443?security=none&type=ws", True, 5),
            ("ss://rc4-md5:pass@example.com:80", True, 5),
        )
        for uri, evidence, expected in cases:
            self.assertEqual(bucket(parse_uri(uri), iran_evidence=evidence), expected, uri)

    def test_port_tiers(self):
        for port, expected in ((443, 0), (80, 1), (8443, 1), (2053, 1), (23576, 2), (10444, 2)):
            self.assertEqual(iran.port_rank(parse_uri(f"trojan://secret@example.com:{port}")), expected, port)


class ProbeTests(unittest.TestCase):
    def test_verdicts(self):
        probes = {
            "a:1": {"n1": [True], "n2": [False, False]},
            "b:1": {"n1": [True], "n2": [True]},
            "c:1": {"n1": [False, False], "n2": [False, False]},
        }
        rates = node_rates(probes)
        self.assertAlmostEqual(rates["n1"], 2 / 3)
        self.assertAlmostEqual(rates["n2"], 1 / 3)
        self.assertEqual(probe_verdict(probes["a:1"], rates), "reachable")
        self.assertEqual(probe_verdict(probes["c:1"], rates), "unreachable")

    def test_thin_evidence_keeps_the_line(self):
        failing = {"n1": [False, False], "n2": [False]}
        self.assertEqual(probe_verdict(failing, {"n1": 0.9, "n2": 0.9}), "unknown")
        self.assertEqual(probe_verdict(failing, {"n1": 0.2, "n2": 0.1}), "unknown")
        self.assertEqual(probe_verdict({}, {"n1": 0.9}), "unknown")

    def test_only_ipv4_literals_are_probed(self):
        self.assertEqual(iran_filter.endpoint_key(parse_uri(TLS_WS)), "1.2.3.4:443")
        self.assertIsNone(iran_filter.endpoint_key(parse_uri(REALITY)))
        self.assertIsNone(iran_filter.endpoint_key(parse_uri(f"vless://{UUID}@[2001:db8::1]:443")))


def run(*argv) -> int:
    with contextlib.redirect_stdout(io.StringIO()):
        return iran_filter.main([str(a) for a in argv])


class ToolTests(unittest.TestCase):
    def test_prepare_and_assemble(self):
        lines = [
            REALITY + "#a",
            TLS_WS + "&sni=1.2.3.4#b",
            "hy2://pass@example.com:443#c",
            "socks5://u:p@5.6.7.8:1080#d",
            TROJAN + "#e",
            "not a proxy",
            REALITY + "#dup",
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, work, results = root / "source.txt", root / "work", root / "results"
            source.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertEqual(run("prepare", "--source", source, "--work", work, "--shards", 2), 0)
            prepared = json.loads((work / "prepare.json").read_text(encoding="utf-8"))
            self.assertEqual(prepared["kept"], 3)
            self.assertEqual(prepared["candidates"], 4)
            self.assertEqual(prepared["fixes_offered"], {"fp": 1, "sni": 1})
            self.assertEqual(
                prepared["dropped"],
                {"udp-quic": 1, "plaintext-proxy": 1, "unparseable": 1, "duplicate": 1},
            )

            # The repaired link rescues an original that fails; everything else passes.
            outcomes = {
                "0.o": ("success", 300),
                "1.o": ("proxy_failure", 0),
                "1.f": ("success", 200),
                "2.o": ("success", 100),
            }
            rows = [{"id": key, "outcome": o, "ms": ms} for key, (o, ms) in outcomes.items()]
            results.mkdir()
            (results / "results-0.jsonl").write_text(iran_filter.jsonl_text(rows), encoding="utf-8")
            common = ("--work", work, "--results", results, "--summary", root / "summary.md")

            out, report_path = root / "plain.txt", root / "plain.json"
            code = run("assemble", *common, "--output", out, "--report", report_path, "--min-lines", 1)
            self.assertEqual(code, 0)
            published = out.read_text(encoding="utf-8").split("\n")[:-1]
            self.assertEqual(len(published), 3)
            self.assertEqual(published[0], REALITY + "#a")
            self.assertTrue(published[1].startswith("trojan://secret@9.9.9.9:443"))
            self.assertIn("sni=cdn.example.com", published[2])
            self.assertIn("fp=chrome", published[2])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["gates"], "pass")
            self.assertEqual(report["repairs"]["sni: rescued (original fails)"], 1)

            probe = {
                "status": "ok",
                "endpoints": {"9.9.9.9:443": {"ir1": [True]}, "1.2.3.4:443": {"ir1": [False, False]}},
            }
            (root / "probe.json").write_text(json.dumps(probe), encoding="utf-8")
            out = root / "probed.txt"
            args = ("--probe", root / "probe.json", "--output", out, "--report", root / "probed.json")
            self.assertEqual(run("assemble", *common, *args, "--min-lines", 1), 0)
            published = out.read_text(encoding="utf-8").split("\n")[:-1]
            self.assertEqual(published, [TROJAN + "#e", REALITY + "#a"])
            report = json.loads((root / "probed.json").read_text(encoding="utf-8"))
            self.assertEqual(report["verdicts"], {"unprobed": 1, "unreachable": 1, "reachable": 1})
            self.assertEqual(report["probe_stats"]["reached by no node"], 1)
            self.assertEqual(report["probe_stats"]["share of endpoints reached by ir1"], "50%")

            out = root / "gated.txt"
            code = run("assemble", *common, "--output", out, "--report", root / "gated.json")
            self.assertEqual(code, 3)
            self.assertFalse(out.exists())
            report = json.loads((root / "gated.json").read_text(encoding="utf-8"))
            self.assertTrue(report["gates"].startswith("FAIL"))


if __name__ == "__main__":
    unittest.main()
