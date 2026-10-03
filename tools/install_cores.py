"""Install reviewed, SHA-256 pinned core assets without elevated privileges."""

import argparse
import gzip
import hashlib
import http.client
import json
import os
import platform
import ssl
import sysconfig
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from openray.files import atomic_write

MAX_DOWNLOAD = 512 * 1024 * 1024


def download(asset: dict, archive, attempts: int = 4):
    """Restart interrupted downloads; never retry an untrusted archive or certificate."""
    for attempt in range(attempts):
        archive.seek(0)
        archive.truncate()
        digest = hashlib.sha256()
        try:
            request = urllib.request.Request(asset["url"], headers={"User-Agent": "OpenRay-core-installer/2"})
            with urllib.request.urlopen(request, timeout=60) as response:
                expected = response.headers.get("Content-Length")
                expected = int(expected) if expected is not None else None
                if expected is not None and expected > MAX_DOWNLOAD:
                    raise ValueError("core download exceeds limit")
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_DOWNLOAD:
                        raise ValueError("core download exceeds limit")
                    digest.update(chunk)
                    archive.write(chunk)
                if expected is not None and total != expected:
                    raise http.client.IncompleteRead(b"", max(0, expected - total))
            if digest.hexdigest() != asset["sha256"]:
                raise ValueError("core archive checksum mismatch")
            archive.seek(0)
            return
        except (urllib.error.URLError, OSError, http.client.IncompleteRead) as exc:
            certificate_error = isinstance(
                exc.reason if isinstance(exc, urllib.error.URLError) else exc,
                ssl.SSLCertVerificationError,
            )
            permanent_status = (
                isinstance(exc, urllib.error.HTTPError) and exc.code not in {408, 429} and exc.code < 500
            )
            if certificate_error or permanent_status or attempt + 1 == attempts:
                raise
            delay = min(2**attempt, 8)
            print(
                f"Transient core download error ({type(exc).__name__}); "
                f"retry {attempt + 2}/{attempts} in {delay}s",
                flush=True,
            )
            time.sleep(delay)


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
        with tempfile.TemporaryFile() as archive:
            download(asset, archive)
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
