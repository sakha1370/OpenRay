from __future__ import annotations

import json
import subprocess
import time
import uuid
from pathlib import Path, PurePosixPath

from .exports import verify_snapshot
from .files import atomic_write
from .locking import file_lock


def install_snapshot(snapshot: Path, root: Path):
    with file_lock(root / ".state/publication.lock"):
        _install_snapshot(snapshot, root)


def _export_destination(root: Path, name: str, *, directory=False) -> Path:
    """Reject linked export paths, including links to code inside the same root."""
    parts = PurePosixPath(name).parts
    if (
        "\\" in name
        or ":" in name
        or PurePosixPath(name).is_absolute()
        or ".." in parts
        or len(parts) < 2
        or parts[0] not in {"output", "output_iran"}
    ):
        raise ValueError("unsafe export destination")
    target = root / name
    for current in (target, *target.parents):
        if current == root:
            break
        if current.is_symlink() or current.is_junction():
            raise ValueError("linked export destination")
        if current != target and current.exists() and not current.is_dir():
            raise ValueError("export parent is not a directory")
    if not target.resolve().is_relative_to(root):
        raise ValueError("unsafe export destination")
    if target.exists() and target.is_dir() != directory:
        raise ValueError("export destination has the wrong file type")
    return target


def _install_snapshot(snapshot: Path, root: Path):
    """Manifest is replaced last. Multi-file atomic reads use its immutable snapshot id."""
    manifest = verify_snapshot(snapshot)
    root = root.resolve()
    previous_path = _export_destination(root, "output/manifest.json")
    previous = (
        json.loads(previous_path.read_text(encoding="utf-8")) if previous_path.exists() else {"files": {}}
    )
    # Check every write and deletion before materializing any member.
    destinations = {
        name: _export_destination(root, name) for name in set(manifest["files"]) | set(previous["files"])
    }
    stale = []
    for directory in ("output/kind", "output/country"):
        parent = _export_destination(root, directory, directory=True)
        for path in parent.glob("*.txt"):
            name = path.relative_to(root).as_posix()
            target = _export_destination(root, name)
            if name not in manifest["files"]:
                stale.append(target)
    for name in manifest["files"]:
        atomic_write(destinations[name], (snapshot / name).read_bytes())
    for name in set(previous["files"]) - set(manifest["files"]):
        destinations[name].unlink(missing_ok=True)
    for path in stale:
        path.unlink(missing_ok=True)
    atomic_write(previous_path, (snapshot / "output/manifest.json").read_bytes())


def _publish(
    repository: Path, branch: str, retries: int, materialize, message: str, *, regional=False
) -> str:
    def git(*args, cwd=repository):
        result = subprocess.run(["git", *map(str, args)], cwd=cwd, capture_output=True, timeout=120)
        if result.returncode:
            raise RuntimeError("git publication command failed; immutable snapshot retained for retry")
        return result.stdout.decode().strip()

    git("check-ref-format", "--branch", branch)
    worktree = repository / ".state" / "publish" / uuid.uuid4().hex
    if not worktree.resolve().is_relative_to(repository.resolve()) or not worktree.resolve().is_relative_to(
        (repository / ".state/publish").resolve()
    ):
        raise ValueError("unsafe publication worktree")
    worktree.parent.mkdir(parents=True, exist_ok=True)
    registered = False
    try:
        for attempt in range(retries):
            remote_branch = branch
            if regional and not git("ls-remote", "--heads", "origin", branch):
                remote_branch = "main"
            git("fetch", "origin", remote_branch)
            revision = git("rev-parse", "FETCH_HEAD")
            if registered:
                git("worktree", "remove", "--force", worktree)
                registered = False
            git("worktree", "add", "--detach", worktree, revision)
            registered = True
            allowed = materialize(worktree)
            git("add", "-f", "--", *allowed, cwd=worktree)
            staged = git("diff", "--cached", "--name-only", cwd=worktree).splitlines()
            if any(
                not name.startswith(".state/regional_results/")
                if regional
                else name.split("/")[0] not in {"output", "output_iran"}
                for name in staged
            ):
                raise ValueError("publication attempted to modify a non-export path")
            if not staged:
                return revision
            git(
                "-c",
                "user.name=OpenRay",
                "-c",
                "user.email=openray@localhost",
                "commit",
                "-m",
                message,
                cwd=worktree,
            )
            commit = git("rev-parse", "HEAD", cwd=worktree)
            push = subprocess.run(
                ["git", "push", "origin", f"{commit}:refs/heads/{branch}"],
                cwd=repository,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
            )
            if push.returncode == 0:
                return commit
            if attempt + 1 < retries:
                time.sleep(min(attempt + 1, 2))
        raise RuntimeError("publication retries exhausted; snapshot retained")
    finally:
        if registered:
            git("worktree", "remove", "--force", worktree)


def git_publish(
    snapshot: Path, repository: Path, branch: str = "main", retries: int = 3, *, require_clients: bool = True
) -> str:
    """Use fetched remote code plus export files; never reset the caller checkout."""
    manifest = verify_snapshot(snapshot)
    if require_clients:
        from .config import Settings
        from .exports import validate_clients

        settings = Settings.from_env(repository)
        if not settings.singbox or not settings.mihomo:
            raise ValueError("publishing requires both pinned client schema validators")
        if any(not item["valid"] for item in validate_clients(snapshot, settings.singbox, settings.mihomo)):
            raise ValueError("publishing rejected an invalid client export")

    def materialize(worktree):
        install_snapshot(snapshot, worktree)
        return [d for d in ("output", "output_iran") if (worktree / d).exists()]

    with file_lock(repository / ".state/git-publication.lock"):
        return _publish(
            repository, branch, retries, materialize, f"Update proxy snapshot {manifest['id'][:12]} [skip ci]"
        )


def publish_bundle(path: Path, repository: Path, branch="operator-observations", retries=3) -> str:
    import re
    import tempfile

    from .files import json_text
    from .storage import Store

    if path.stat().st_size > 50 * 1024 * 1024:
        raise ValueError("regional bundle exceeds limit")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", payload.get("id", "")) or branch == "main":
        raise ValueError("unsafe regional bundle identity/branch")
    with tempfile.TemporaryDirectory() as temporary, Store(Path(temporary) / "verify.sqlite3") as store:
        store.import_bundle(payload)
    name = f".state/regional_results/{payload['context']}/{payload['id']}.bundle.json"
    body = json_text(payload).encode()

    def materialize(worktree):
        destination = worktree / name
        if destination.exists() and json.loads(destination.read_text(encoding="utf-8")) != payload:
            raise ValueError("regional bundle identity collision")
        atomic_write(destination, body)
        return [name]

    with file_lock(repository / ".state/git-publication.lock"):
        return _publish(
            repository,
            branch,
            retries,
            materialize,
            f"Record regional observations {payload['id'][:12]} [skip ci]",
            regional=True,
        )
