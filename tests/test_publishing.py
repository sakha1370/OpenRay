import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openray.domain import parse_uri
from openray.exports import build_snapshot
from openray.publishing import git_publish, install_snapshot, publish_bundle
from openray.storage import Store
from tests.test_domain import VLESS


class PublishingTests(unittest.TestCase):
    def test_install_rejects_linked_export_directory_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with Store(root / ".state/state.sqlite3") as store:
                store.add(parse_uri(VLESS), accepted=True)
                snapshot = build_snapshot(store, root, root / ".state/snapshots")
            code = root / "source"
            code.mkdir()
            sentinel = code / "vless.txt"
            sentinel.write_text("source must survive\n")
            (root / "output").mkdir()
            linked = root / "output/kind"
            if os.name == "nt":
                subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(linked), str(code)],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                linked.symlink_to(code, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "linked export"):
                install_snapshot(snapshot, root)
            self.assertEqual(sentinel.read_text(), "source must survive\n")
            self.assertFalse((root / "output/all_valid_proxies.txt").exists())
            self.assertFalse((root / "output/manifest.json").exists())

    def repository(self, root):
        remote, repo = root / "remote.git", root / "repo"

        def git(*args, cwd=root):
            return (
                subprocess.check_output(["git", *map(str, args)], cwd=cwd, stderr=subprocess.DEVNULL)
                .decode()
                .strip()
            )

        git("init", "--bare", remote)
        git("init", "-b", "main", repo)
        git("config", "user.name", "Test", cwd=repo)
        git("config", "user.email", "test@localhost", cwd=repo)
        (repo / "code.py").write_text("original\n")
        git("add", "code.py", cwd=repo)
        git("commit", "-m", "init", cwd=repo)
        git("remote", "add", "origin", remote, cwd=repo)
        git("push", "origin", "main", cwd=repo)
        return repo, remote, git

    def test_empty_snapshot_cleanup_and_concurrent_remote_update(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, remote, git = self.repository(root)
            with Store(repo / ".state/state.sqlite3") as store:
                store.add(parse_uri(VLESS), accepted=True)
                full = build_snapshot(store, repo, repo / ".state/snapshots")
                git_publish(full, repo, require_clients=False)
                with store.transaction() as db:
                    db.execute("UPDATE proxy SET accepted=0")
                empty = build_snapshot(store, repo, repo / ".state/snapshots")
            actual_run, raced = subprocess.run, []

            def run(args, **kwargs):
                if args[:2] == ["git", "push"] and not raced:
                    raced.append(True)
                    other = root / "other"
                    git("clone", remote, other)
                    git("checkout", "main", cwd=other)
                    (other / "code.py").write_text("concurrent update\n")
                    (other / "output/country/stale.txt").write_text("obsolete\n")
                    git("add", "code.py", "output/country/stale.txt", cwd=other)
                    git(
                        "-c",
                        "user.name=Test",
                        "-c",
                        "user.email=test@localhost",
                        "commit",
                        "-m",
                        "concurrent",
                        cwd=other,
                    )
                    git("push", "origin", "main", cwd=other)
                return actual_run(args, **kwargs)

            with patch("openray.publishing.subprocess.run", side_effect=run):
                commit = git_publish(empty, repo, require_clients=False)
            self.assertEqual(git("show", commit + ":code.py", cwd=repo), "concurrent update")
            names = git("ls-tree", "-r", "--name-only", commit, cwd=repo)
            self.assertIn("output/kind/vless.txt", names)
            self.assertEqual(git("show", commit + ":output/kind/vless.txt", cwd=repo), "")
            self.assertNotIn("output/country/stale.txt", names)
            self.assertEqual(git("show", commit + ":output/all_valid_proxies.txt", cwd=repo), "")
            self.assertEqual((repo / "code.py").read_text(), "original\n")

    def test_regional_publication_isolated_and_coordinator_idempotent(self):
        from tools.import_regional import import_remote

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, remote, git = self.repository(root)
            main = git("rev-parse", "HEAD", cwd=repo)
            bundle = root / "bundle.json"
            bundle.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "id": "regional",
                        "context": "mci",
                        "observations": [
                            {"uri": VLESS, "event_id": "regional-event", "time": 100, "outcome": "success"}
                        ],
                    }
                )
            )
            commit = publish_bundle(bundle, repo)
            self.assertEqual(git("rev-parse", "refs/heads/main", cwd=remote), main)
            self.assertEqual(publish_bundle(bundle, repo), commit)
            database = repo / ".state/coordinator.sqlite3"
            self.assertEqual(import_remote(repo, database)["observations"], 1)
            self.assertEqual(import_remote(repo, database)["observations"], 0)
            with Store(database) as store:
                self.assertEqual(store.view()[1][parse_uri(VLESS).identity]["mci"], 1)

    def test_publish_preserves_code_and_caller_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            remote = root / "remote.git"
            repo = root / "repo"

            def git(*args, cwd=root):
                return (
                    subprocess.check_output(["git", *map(str, args)], cwd=cwd, stderr=subprocess.DEVNULL)
                    .decode()
                    .strip()
                )

            git("init", "--bare", remote)
            git("init", "-b", "main", repo)
            git("config", "user.name", "Test", cwd=repo)
            git("config", "user.email", "test@localhost", cwd=repo)
            (repo / "code.py").write_text("original\n")
            git("add", "code.py", cwd=repo)
            git("commit", "-m", "init", cwd=repo)
            git("remote", "add", "origin", remote, cwd=repo)
            git("push", "origin", "main", cwd=repo)
            with Store(repo / ".state/state.sqlite3") as store:
                store.add(parse_uri(VLESS), accepted=True)
                snapshot = build_snapshot(store, repo, repo / ".state/snapshots")
            (repo / "code.py").write_text("uncommitted work\n")
            commit = git_publish(snapshot, repo, require_clients=False)
            self.assertEqual((repo / "code.py").read_text(), "uncommitted work\n")
            self.assertEqual(git("show", commit + ":code.py", cwd=repo), "original")
            manifest = json.loads(git("show", commit + ":output/manifest.json", cwd=repo))
            self.assertEqual(manifest["proxy_count"], 1)
            self.assertEqual(git_publish(snapshot, repo, require_clients=False), commit)
