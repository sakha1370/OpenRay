import asyncio
import re
import tempfile
import unittest
from pathlib import Path

from openray.config import Settings
from openray.domain import Observation, Outcome, parse_uri
from openray.exports import build_snapshot, verify_snapshot
from openray.pipeline import run
from openray.storage import Store
from tests.test_domain import VLESS


class FakeValidator:
    def __init__(self, settings):
        self.settings = settings

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass

    async def check(self, proxy, target=None):
        await asyncio.sleep(0)
        return Observation(Outcome.SUCCESS if proxy.server.startswith("good") else Outcome.PROXY_FAILURE, 1)


class PipelineTests(unittest.IsolatedAsyncioTestCase):
    async def test_no_unvalidated_tail_and_resumption(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sources.txt").write_text("subscription.txt\n")
            (root / "subscription.txt").write_text(
                "\n".join(VLESS.replace("example.com", f"good{n}.test") for n in range(5))
            )
            settings = Settings(root, root / "state.sqlite3", root / "sources.txt", workers=2, batch_size=2)
            code, report = await run(settings, "discovery", validator_factory=FakeValidator)
            self.assertEqual(code, 0)
            self.assertEqual(report["checks"], 2)
            with Store(settings.database) as store:
                self.assertEqual(len(store.view()[0]), 2)
            code, report = await run(settings, "discovery", validator_factory=FakeValidator)
            self.assertEqual(report["checks"], 2)
            with Store(settings.database) as store:
                self.assertEqual(len(store.view()[0]), 4)

    async def test_outage_does_not_evict_or_count_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = Settings(root, root / "state.sqlite3", root / "sources.txt", workers=2)
            with Store(settings.database) as store:
                for n in range(6):
                    store.add(parse_uri(VLESS.replace("example.com", f"bad{n}.test")), accepted=True)
            code, report = await run(settings, "existing", validator_factory=FakeValidator)
            self.assertEqual(report["outcomes"], {"target_failure": 6})
            with Store(settings.database) as store:
                self.assertEqual(len(store.view()[0]), 6)
                self.assertTrue(all(h["failures"] == 0 for h in store.view()[2]))

    async def test_snapshot_deterministic_partition_and_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with Store(root / "state.sqlite3") as store:
                store.add(parse_uri(VLESS), accepted=True)
                a = build_snapshot(store, root, root / "snapshots")
                b = build_snapshot(store, root, root / "snapshots")
                self.assertEqual(a, b)
                manifest = verify_snapshot(a)
                self.assertEqual(manifest["proxy_count"], 1)
                readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
                urls = re.findall(
                    r"https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/([^\s\"<>)]+)",
                    readme,
                )
                self.assertTrue(set(urls) <= set(manifest["files"]), set(urls) - set(manifest["files"]))
                (a / "output/all_valid_proxies.txt").write_text("tampered")
                with self.assertRaises(ValueError):
                    verify_snapshot(a)

    async def test_local_export_excludes_unchecked_tail_and_keeps_global_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = Settings(root, root / "state.sqlite3", root / "sources.txt", workers=2, batch_size=2)
            with Store(settings.database) as store:
                for n in range(5):
                    store.add(parse_uri(VLESS.replace("example.com", f"good{n}.test")), accepted=True)
            code, report = await run(settings, "local", "others", validator_factory=FakeValidator)
            path = Path(report["snapshot"])
            self.assertEqual(code, 0)
            self.assertEqual(len((path / "output/Iran_valid_proxies.txt").read_text().splitlines()), 2)
            self.assertEqual(len((path / "output/all_valid_proxies.txt").read_text().splitlines()), 5)
            with Store(settings.database) as store:
                self.assertTrue(all("global" not in contexts for contexts in store.view()[1].values()))

    async def test_site_exports_require_current_connectivity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            alive, dead = (parse_uri(VLESS.replace("example.com", f"{n}.test")) for n in ("alive", "dead"))
            with Store(root / "state.sqlite3") as store:
                for proxy, outcome in ((alive, Outcome.SUCCESS), (dead, Outcome.PROXY_FAILURE)):
                    store.add(proxy, accepted=True)
                    store.observe(
                        proxy.server + "c", "r", proxy, "global", "connectivity", Observation(outcome), now=1
                    )
                    store.observe(
                        proxy.server + "s",
                        "r",
                        proxy,
                        "global",
                        "aistudio",
                        Observation(Outcome.SUCCESS),
                        now=1,
                    )
                snapshot = build_snapshot(store, root, root / "snapshots")
            listed = (snapshot / "output/site_access/aistudio.txt").read_text().splitlines()
            self.assertEqual([parse_uri(uri).server for uri in listed], ["alive.test"])
