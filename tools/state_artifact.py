"""Restore a verified checkpoint artifact without forwarding tokens on redirects."""

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import urllib.error
import urllib.request
import zipfile
from contextlib import closing
from pathlib import Path

from openray.storage import restore_backup


def restore(destination: Path):
    repository = os.environ["GITHUB_REPOSITORY"]
    headers = {
        "Authorization": "Bearer " + os.environ["GH_TOKEN"],
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    base = f"https://api.github.com/repos/{repository}/actions/artifacts"
    with urllib.request.urlopen(
        urllib.request.Request(base + "?name=openray-state&per_page=30", headers=headers), timeout=30
    ) as response:
        artifacts = json.loads(response.read(1024 * 1024))["artifacts"]
    valid = [
        a for a in artifacts if not a["expired"] and a.get("workflow_run", {}).get("head_branch") == "main"
    ]
    if not valid:
        if Path("output/manifest.json").is_file():
            raise ValueError(
                "published transactional state exists but its checkpoint is unavailable; restore a durable backup"
            )
        print("No prior checkpoint artifact; legacy migration required")
        return
    selected = max(valid, key=lambda a: a["id"])

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(NoRedirect())
    try:
        opener.open(urllib.request.Request(f"{base}/{selected['id']}/zip", headers=headers), timeout=30)
        raise ValueError("artifact API did not redirect")
    except urllib.error.HTTPError as exc:
        if exc.code != 302:
            raise
        url = exc.headers["Location"]
        exc.close()
        if not url.startswith("https://"):
            raise ValueError("artifact download must use HTTPS")
    with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryFile() as compressed:
        digest, size = hashlib.sha256(), 0
        with urllib.request.urlopen(url, timeout=60) as response:
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > 512 * 1024 * 1024:
                    raise ValueError("checkpoint archive exceeds limit")
                digest.update(chunk)
                compressed.write(chunk)
        if selected.get("digest") and selected["digest"] != "sha256:" + digest.hexdigest():
            raise ValueError("checkpoint artifact checksum mismatch")
        compressed.seek(0)
        checkpoint = Path(directory) / "checkpoint.sqlite3"
        with zipfile.ZipFile(compressed) as archive:
            info = archive.getinfo("checkpoint.sqlite3")
            if info.file_size > 2 * 1024**3:
                raise ValueError("checkpoint exceeds limit")
            with archive.open(info) as member, checkpoint.open("wb") as target:
                shutil.copyfileobj(member, target, 1024 * 1024)
        with closing(sqlite3.connect(checkpoint.as_uri() + "?immutable=1", uri=True)) as check:
            if not check.execute("SELECT 1 FROM meta WHERE key='legacy_migrated'").fetchone():
                raise ValueError("checkpoint is not initialized")
        restore_backup(checkpoint, destination)
    print(f"Restored verified checkpoint from artifact {selected['id']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    restore(parser.parse_args().destination)
