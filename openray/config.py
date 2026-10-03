from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path


def env_int(name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high}")
    return value


@dataclass(frozen=True)
class Settings:
    root: Path
    database: Path
    sources: Path
    workers: int = 8
    fetch_workers: int = 8
    queue_size: int = 32
    timeout: float = 12
    fetch_timeout: float = 15
    max_body: int = 10 * 1024 * 1024
    budget: float = 3000
    batch_size: int = 5000
    cooldown: float = 8 * 3600
    death_after: float = 72 * 3600
    xray: str = ""
    singbox: str = ""
    mihomo: str = ""
    backend: str = "subprocess"
    allow_private_sources: bool = False
    test_url: str = "https://cp.cloudflare.com/generate_204"
    test_status: int = 204
    body_sha256: str = ""
    tcp_prefilter: bool = False
    check_sites: bool = True
    existing_timeout: float = 12
    source_cache_mb: int = 128

    @classmethod
    def from_env(cls, root: Path | None = None) -> Settings:
        root = (root or Path(os.environ.get("OPENRAY_ROOT", Path.cwd()))).resolve()
        workers = env_int("OPENRAY_STAGE3_POOL_SIZE", env_int("OPENRAY_STAGE3_WORKERS", 8, 1, 128), 1, 128)
        # Bound workers by explicitly configured memory, leaving room for Python and exports.
        memory = env_int("OPENRAY_MEMORY_MB", 2048, 256, 1048576)
        workers = min(workers, max(1, (memory - 256) // 96))
        backend = os.environ.get("OPENRAY_STAGE3_BACKEND", "subprocess")
        if backend not in {"subprocess", "pool", "api", "xray_api"}:
            raise ValueError("unknown OPENRAY_STAGE3_BACKEND")

        def core(name: str) -> str:
            local = root / ".tools" / (name + (".exe" if os.name == "nt" else ""))
            return str(local) if local.is_file() else (shutil.which(name) or "")

        return cls(
            root=root,
            database=Path(os.environ.get("OPENRAY_DATABASE", root / ".state/openray.sqlite3")),
            sources=Path(os.environ.get("OPENRAY_SOURCES", root / "sources.txt")),
            workers=workers,
            fetch_workers=env_int("OPENRAY_FETCH_WORKERS", 8, 1, 128),
            queue_size=env_int("OPENRAY_QUEUE_SIZE", workers * 4, workers, 4096),
            timeout=env_int("OPENRAY_STAGE3_NEW_TIMEOUT_S", 12, 1, 120),
            fetch_timeout=env_int("OPENRAY_FETCH_TIMEOUT", 15, 1, 120),
            budget=env_int("OPENRAY_RUN_BUDGET_S", 3000, 1, 86400),
            batch_size=env_int("OPENRAY_STAGE3_MAX", 5000, 1, 1000000),
            cooldown=env_int("OPENRAY_ALIVE_CHECK_COOLDOWN_H", 8, 0, 720) * 3600,
            death_after=env_int("OPENRAY_ALIVE_DEATH_AFTER_H", 72, 1, 8760) * 3600,
            xray=os.environ.get(
                "OPENRAY_V2RAY_CORE",
                os.environ.get("V2RAY_CORE_PATH", os.environ.get("OPENRAY_XRAY", core("xray"))),
            ),
            singbox=os.environ.get("OPENRAY_SINGBOX", core("sing-box")),
            mihomo=os.environ.get("OPENRAY_MIHOMO", core("mihomo")),
            backend=backend,
            allow_private_sources=os.environ.get("OPENRAY_ALLOW_PRIVATE_SOURCES", "0") == "1",
            test_url=os.environ.get("OPENRAY_TEST_URL", "https://cp.cloudflare.com/generate_204"),
            test_status=env_int("OPENRAY_TEST_STATUS", 204, 100, 599),
            body_sha256=os.environ.get("OPENRAY_TEST_BODY_SHA256", ""),
            check_sites=os.environ.get("OPENRAY_CHECK_SITES", "1") != "0",
            source_cache_mb=env_int("OPENRAY_SOURCE_CACHE_MB", 128, 1, 4096),
            existing_timeout=env_int("OPENRAY_STAGE3_EXISTING_TIMEOUT_S", 12, 1, 120),
        )
