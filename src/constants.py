"""Deprecated settings aliases. No imports perform network probes or benchmarks."""

import os
from openray.config import Settings

_s = Settings.from_env()
REPO_ROOT = str(_s.root)
STATE_DIR = str(_s.database.parent)
OUTPUT_DIR = str(_s.root / "output")
TESTED_FILE = os.path.join(STATE_DIR, "tested.txt")
AVAILABLE_FILE = os.path.join(OUTPUT_DIR, "all_valid_proxies.txt")
KIND_DIR = os.path.join(OUTPUT_DIR, "kind")
COUNTRY_DIR = os.path.join(OUTPUT_DIR, "country")
SOURCES_FILE = str(_s.sources)
FETCH_WORKERS = _s.fetch_workers
PING_WORKERS = _s.workers
FETCH_TIMEOUT = _s.fetch_timeout
PING_TIMEOUT_MS = 1000
CONNECT_TIMEOUT_MS = 1500
PROBE_TIMEOUT_MS = 1200
ENABLE_STAGE2 = 0
ENABLE_STAGE3 = 1
STAGE3_WORKERS = STAGE3_POOL_SIZE = _s.workers
STAGE3_MAX = _s.batch_size
STAGE3_EXISTING_TIMEOUT_S = _s.existing_timeout
STAGE3_NEW_TIMEOUT_S = _s.timeout
V2RAY_CORE_PATH = _s.xray
USER_AGENT = "OpenRay/2"
TCP_FALLBACK_PORTS = (443, 80, 8080, 8443)
ALIVE_CHECK_COOLDOWN_H = _s.cooldown / 3600
ALIVE_DEATH_AFTER_H = _s.death_after / 3600
SITE_ACCESS_POOL_SIZE = _s.workers
SITE_ACCESS_STATE_FILE = os.path.join(STATE_DIR, "site_access_blocked.json")
NEW_URIS_LIMIT_ENABLED = 0
NEW_URIS_LIMIT = 25000
CONSECUTIVE_REQUIRED = 1
EXISTING_PROXY_FAILURE_LIMIT = 24


def _is_ci_env():
    return any(os.environ.get(k) for k in ("CI", "GITHUB_ACTIONS", "GITLAB_CI"))
