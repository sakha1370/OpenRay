import base64
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from openray.config import Settings
from openray.domain import parse_uri
from openray.exports import build_snapshot, validate_clients_async
from openray.render import convert
from openray.storage import Store
from tests.test_domain import UUID

CORES = Settings.from_env(Path(__file__).resolve().parents[1])


@unittest.skipUnless(CORES.singbox and CORES.mihomo, "pinned client validators required")
class ClientExportTests(unittest.IsolatedAsyncioTestCase):
    async def test_ssr_wireguard_reality_https_client_schemas(self):
        ssr = (
            base64.urlsafe_b64encode(
                b"example.test:443:auth_sha1_v4:aes-128-cfb:plain:cGFzcw/?protoparam=MQ&obfsparam=bG9jYWxob3N0"
            )
            .decode()
            .rstrip("=")
        )
        key = base64.b64encode(bytes(range(32))).decode()
        proxies = [
            parse_uri("ssr://" + ssr),
            parse_uri(
                "wireguard://example.test:51820?"
                + urlencode(
                    {
                        "privatekey": key,
                        "publickey": key,
                        "address": "10.0.0.2/32,fd00::2/128",
                        "reserved": "0,1,2",
                    }
                )
            ),
            parse_uri(
                f"vless://{UUID}@example.test:443?"
                + urlencode(
                    {"security": "reality", "pbk": key.rstrip("="), "sid": "08", "sni": "example.test"}
                )
            ),
            parse_uri("https://user:password@example.test:443?insecure=1"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            templates = root / "src/converter"
            templates.mkdir(parents=True)
            clash, sing, _ = convert([])
            # This controlled schema test needs no external geodata/rule downloads.
            (templates / "config.yaml").write_text(json.dumps(clash), encoding="utf-8")
            (templates / "singbox.json").write_text(json.dumps(sing), encoding="utf-8")
            with Store(root / "state.sqlite3") as store:
                for proxy in proxies:
                    store.add(proxy, accepted=True)
                snapshot = build_snapshot(store, root, root / "snapshots")
            results = await validate_clients_async(snapshot, CORES.singbox, CORES.mihomo)
            self.assertEqual(len(results), 14)
            self.assertTrue(all(r["valid"] for r in results), results)
