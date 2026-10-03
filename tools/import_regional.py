"""The global coordinator imports append-only regional bundles exactly once."""

import json
import subprocess
from pathlib import Path

from openray.config import Settings
from openray.pipeline import initialize
from openray.storage import Store


def import_remote(repository: Path, database: Path, branch="operator-observations") -> dict:
    def git(*args):
        result = subprocess.run(["git", *args], cwd=repository, capture_output=True, timeout=120)
        if result.returncode:
            raise RuntimeError("regional observation fetch failed")
        return result.stdout

    if not git("ls-remote", "--heads", "origin", branch).strip():
        return {"bundles": 0, "observations": 0}
    git("fetch", "origin", branch)
    revision = git("rev-parse", "FETCH_HEAD").decode().strip()
    names = (
        git("ls-tree", "-r", "--name-only", revision, "--", ".state/regional_results").decode().splitlines()
    )
    if len(names) > 10000:
        raise ValueError("regional bundle catalog exceeds limit; archive acknowledged bundles")
    report = {"bundles": 0, "observations": 0}
    with Store(database) as store:
        initialize(store, repository)
        for name in names:
            if not name.endswith(".bundle.json"):
                continue
            if int(git("cat-file", "-s", f"{revision}:{name}")) > 50 * 1024 * 1024:
                raise ValueError("regional bundle exceeds limit")
            payload = json.loads(git("show", f"{revision}:{name}"))
            report["observations"] += store.import_bundle(payload)
            report["bundles"] += 1
    return report


if __name__ == "__main__":
    settings = Settings.from_env()
    print(json.dumps(import_remote(settings.root, settings.database), sort_keys=True))
