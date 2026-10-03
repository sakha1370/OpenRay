import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openray.config import Settings
from openray.converter_cli import legacy
from openray.storage import Store
from src import site_access_state
from tests.test_domain import VLESS


class CompatibilityTests(unittest.TestCase):
    def test_no_argument_converter_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(root, root / "state.sqlite3", root / "sources.txt")
            (root / "test.txt").write_text(VLESS)
            (root / "output_iran").mkdir()
            (root / "output_iran/all_valid_proxies_for_iran.txt").write_text(VLESS)
            with (
                patch("openray.converter_cli.Settings.from_env", return_value=settings),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(legacy(argv=[]), 0)
                self.assertEqual(legacy(regional=True, argv=[]), 0)
            self.assertTrue((root / "clash.yaml").is_file())
            self.assertTrue((root / "output_iran/converted/clash.yaml").is_file())

    def test_legacy_site_blocks_expire_and_follow_target_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(root, root / "state.sqlite3", root / "sources.txt")
            with patch.object(site_access_state.Settings, "from_env", return_value=settings):
                site_access_state.save_blocked_state({VLESS: {"cursor"}}, {"cursor": 1})
                self.assertEqual(site_access_state.load_blocked_state(), {VLESS: {"cursor"}})
                self.assertEqual(site_access_state.sync_blocked_state([VLESS], {"cursor": 2}), {})
                site_access_state.save_blocked_state({VLESS: {"cursor"}}, {"cursor": 2})
                with Store(settings.database) as store, store.transaction() as db:
                    db.execute("UPDATE health SET next_due=0")
                self.assertEqual(site_access_state.load_blocked_state(), {})
                self.assertFalse((root / ".state/site_access_blocked.json").exists())
