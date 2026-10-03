"""Copy only verified manifest members, excluding client caches and local state."""

import json
import shutil
from pathlib import Path

from openray.exports import verify_snapshot


def stage(report: Path, destination: Path):
    snapshot = Path(json.loads(report.read_text(encoding="utf-8"))["snapshot"])
    manifest = verify_snapshot(snapshot)
    for name in [*manifest["files"], "output/manifest.json"]:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(snapshot / name, target)
    verify_snapshot(destination)


if __name__ == "__main__":
    stage(Path("artifacts/run.json"), Path("artifacts/snapshot"))
