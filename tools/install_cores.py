"""Install reviewed, SHA-256 pinned core assets without elevated privileges."""

import argparse
import gzip
import hashlib
import json
import os
import platform
import sysconfig
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from openray.files import atomic_write


def install(destination: Path, names: list[str]):
    manifest = json.loads(
        (Path(__file__).resolve().parents[1] / "openray/assets/cores.lock.json").read_text()
    )
    if platform.machine().lower() not in {"amd64", "x86_64"} and sysconfig.get_platform() != "win-amd64":
        raise ValueError("core lock currently supports Windows/Linux amd64 only")
    destination.mkdir(parents=True, exist_ok=True)
    system = "windows" if os.name == "nt" else "linux"
    for kind in names:
        asset_name, asset = next((n, v) for n, v in manifest[kind]["assets"].items() if system in n)
        if len(asset["sha256"]) != 64:
            raise ValueError("asset lacks a pinned checksum")
        digest = hashlib.sha256()
        with tempfile.TemporaryFile() as archive:
            with urllib.request.urlopen(asset["url"], timeout=60) as response:
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > 512 * 1024 * 1024:
                        raise ValueError("core download exceeds limit")
                    digest.update(chunk)
                    archive.write(chunk)
            if digest.hexdigest() != asset["sha256"]:
                raise ValueError("core archive checksum mismatch")
            archive.seek(0)
            binary_name = {"xray": "xray", "singbox": "sing-box", "mihomo": "mihomo"}[kind] + (
                ".exe" if os.name == "nt" else ""
            )
            if asset_name.endswith(".zip"):
                with zipfile.ZipFile(archive) as z:
                    member = next(
                        n
                        for n in z.namelist()
                        if Path(n).name == binary_name or kind == "mihomo" and n.endswith(".exe")
                    )
                    data = z.read(member)
            elif asset_name.endswith(".tar.gz"):
                with tarfile.open(fileobj=archive, mode="r:gz") as t:
                    member = next(
                        m for m in t.getmembers() if Path(m.name).name == binary_name and m.isfile()
                    )
                    data = t.extractfile(member).read()
            else:
                data = gzip.decompress(archive.read())
            path = destination / binary_name
            atomic_write(path, data)
            path.chmod(0o755)
            print(f"Installed {kind} {manifest[kind]['version']}: {path}", flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--destination", type=Path, default=Path(".tools"))
    p.add_argument("cores", nargs="*")
    a = p.parse_args()
    names = a.cores or ["xray", "singbox", "mihomo"]
    if any(n not in {"xray", "singbox", "mihomo"} for n in names):
        p.error("unknown core")
    install(a.destination, names)
