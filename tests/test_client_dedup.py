"""Published lists are thinned to what clients that remove duplicates (v2rayN) would keep anyway."""

import base64
import json
import tempfile
import unittest
from pathlib import Path

from openray.domain import Observation, Outcome, parse_uri
from openray.exports import build_snapshot, client_unique, verify_snapshot
from openray.storage import Store
from tests.test_domain import UUID, VLESS

TLS = f"{VLESS}?security=tls&sni=example.com&fp=chrome"


def vmess(**fields) -> str:
    data = {"add": "example.com", "port": 443, "id": UUID, **fields}
    return "vmess://" + base64.b64encode(json.dumps(data).encode()).decode()


class ClientKeyTests(unittest.TestCase):
    def assertMerged(self, *uris):
        proxies = [parse_uri(u) for u in uris]
        self.assertGreater(len({p.identity for p in proxies}), 1, "identity should still tell them apart")
        self.assertEqual(len({p.client_key for p in proxies}), 1, uris)

    def assertDistinct(self, left, right):
        self.assertNotEqual(parse_uri(left).client_key, parse_uri(right).client_key, (left, right))

    def test_parameters_v2rayn_ignores_do_not_separate_variants(self):
        self.assertMerged(
            TLS,
            f"{TLS}&allowInsecure=1",
            f"{TLS}&packetEncoding=xudp",
            f"{TLS}&insecure=1&packetEncoding=none",
            f"{TLS}&spx=%2F",
            f"{TLS}&unknown=1",
        )
        self.assertMerged(
            f"{VLESS}?type=grpc&serviceName=s&security=tls&sni=a.test",
            f"{VLESS}?type=grpc&serviceName=s&security=tls&sni=a.test&mode=multi&authority=b.test",
        )
        self.assertMerged(vmess(net="tcp"), vmess(net="tcp", pcs="", vcn="", mux="1", aid=2))

    def test_blank_and_absent_are_the_same_to_clients(self):
        self.assertMerged(
            "hysteria2://pw@example.com:443?sni=a.test",
            "hysteria2://pw@example.com:443/?sni=a.test&obfs=&obfs-password=",
            "hysteria2://pw@example.com:443?sni=a.test&insecure=1",
        )
        self.assertMerged(
            f"{VLESS}?security=tls&fp=chrome",
            f"{VLESS}?security=tls&fp=chrome&sni=",  # an empty SNI means the server name
            f"{VLESS}?security=tls&fp=chrome&sni=example.com&allowInsecure=1",
        )

    def test_everything_a_client_compares_still_separates(self):
        base = f"{VLESS}?security=tls&sni=example.com"
        for variant in (
            f"{VLESS}?security=tls&sni=other.test",
            f"{base}&alpn=h2",
            f"{base}&fp=firefox",
            f"{base}&flow=xtls-rprx-vision",
            f"{base}&type=ws&path=%2Fa",
            f"{base}&type=grpc&serviceName=s",
            f"{VLESS}?security=none",
            base.replace(":443", ":444"),
            base.replace(UUID[:8], "00000000"),
            base.replace("example.com", "other.test"),
        ):
            self.assertDistinct(base, variant)
        self.assertDistinct(f"{base}&type=ws&path=%2Fa", f"{base}&type=ws&path=%2Fb")
        reality = f"{VLESS}?security=reality&sni=a.test&fp=chrome&pbk=KEY"
        self.assertDistinct(f"{reality}&sid=aa", f"{reality}&sid=bb")
        self.assertDistinct(f"{reality}&sid=aa", f"{reality.replace('KEY', 'OTHER')}&sid=aa")
        self.assertDistinct(
            "hysteria2://pw@example.com:443?obfs=salamander&obfs-password=a",
            "hysteria2://pw@example.com:443?obfs=salamander&obfs-password=b",
        )
        self.assertDistinct(vmess(scy="aes-128-gcm"), vmess(scy="none"))
        self.assertDistinct(vmess(net="ws", path="/a"), vmess(net="ws", path="/b"))
        self.assertDistinct(
            "trojan://pw@example.com:443?sni=a.test", "trojan://other@example.com:443?sni=a.test"
        )

    def test_uris_with_one_identity_share_a_client_key(self):
        for left, right in ((TLS, f"{TLS}#remark"), (vmess(net="tcp"), vmess(net="raw"))):
            self.assertEqual(parse_uri(left).identity, parse_uri(right).identity, (left, right))
            self.assertEqual(parse_uri(left).client_key, parse_uri(right).client_key, (left, right))


class ClientUniqueTests(unittest.TestCase):
    def test_keeps_verified_tls_then_udp_capable_variant_in_list_order(self):
        insecure, strict, xudp = (
            parse_uri(f"{TLS}&{extra}")
            for extra in ("allowInsecure=1", "allowInsecure=0", "packetEncoding=xudp")
        )
        other = parse_uri(TLS.replace("example.com", "other.test"))
        self.assertEqual(client_unique([insecure, other, strict]), [other, strict])
        self.assertEqual(client_unique([strict, xudp]), [xudp])
        self.assertEqual(client_unique([xudp, strict]), [xudp])
        self.assertEqual(client_unique([]), [])

    def test_distinct_connections_are_all_kept(self):
        proxies = [parse_uri(TLS.replace("example.com", f"h{n}.test")) for n in range(5)]
        self.assertEqual(client_unique(iter(proxies)), proxies)


class SnapshotTests(unittest.TestCase):
    def observe(self, store, proxy, target, outcome=Outcome.SUCCESS):
        store.observe(f"{proxy.identity}{target}", "r", proxy, "global", target, Observation(outcome), now=1)

    def test_lists_publish_one_variant_but_never_lose_a_checked_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            strict, insecure = (parse_uri(f"{TLS}&allowInsecure={flag}") for flag in (0, 1))
            lonely = parse_uri(TLS.replace("example.com", "lonely.test"))
            with Store(root / "state.sqlite3") as store:
                for proxy in (strict, insecure, lonely):
                    store.add(proxy, accepted=True)
                    self.observe(store, proxy, "connectivity")
                self.observe(store, insecure, "aistudio")  # only the allowInsecure variant reached the site
                self.observe(store, lonely, "aistudio")
                snapshot = build_snapshot(store, root, root / "snapshots")

            manifest = verify_snapshot(snapshot)

            def variants(name):
                uris = (snapshot / name).read_text().split()
                return sorted(parse_uri(u).get("allowInsecure", "-") for u in uris)

            self.assertEqual(manifest["proxy_count"], 2)
            self.assertEqual(variants("output/all_valid_proxies.txt"), ["-", "0"])
            self.assertEqual(variants("output/site_access/aistudio.txt"), ["-", "1"])
            self.assertEqual(len((snapshot / "output/kind/vless.txt").read_text().split()), 2)


if __name__ == "__main__":
    unittest.main()
