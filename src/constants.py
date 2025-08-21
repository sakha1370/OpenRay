import os
import sys
import shutil
from typing import Optional, List

# Determine repository root as parent of this src directory
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Directories and files
STATE_DIR = os.path.join(REPO_ROOT, '.state')
OUTPUT_DIR = os.path.join(REPO_ROOT, 'output')
TESTED_FILE = os.path.join(STATE_DIR, 'tested.txt')  # stores SHA1 per tested proxy URI
AVAILABLE_FILE = os.path.join(OUTPUT_DIR, 'all_valid_proxies.txt')
STREAKS_FILE = os.path.join(STATE_DIR, 'streaks.json')
LAST24H_FILE = os.path.join(OUTPUT_DIR, 'proxies_last24h.txt')
KIND_DIR = os.path.join(OUTPUT_DIR, 'kind')
COUNTERY_DIR = os.path.join(OUTPUT_DIR, 'countery')


def _env_int(name: str, default: int, min_v: Optional[int] = None, max_v: Optional[int] = None) -> int:
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        n = int(val)
    except Exception:
        return default
    if min_v is not None and n < min_v:
        n = min_v
    if max_v is not None and n > max_v:
        n = max_v
    return n


def _get_sources_file() -> str:
    # Priority: CLI arg > env OPENRAY_SOURCES > default sources.txt (fallback to small.txt if missing)
    candidate = None
    if len(sys.argv) > 1 and sys.argv[1].strip():
        candidate = sys.argv[1].strip()
        if not os.path.isabs(candidate):
            candidate = os.path.join(REPO_ROOT, candidate)
    elif os.environ.get('OPENRAY_SOURCES'):
        candidate = os.environ.get('OPENRAY_SOURCES').strip()
        if not os.path.isabs(candidate):
            candidate = os.path.join(REPO_ROOT, candidate)
    else:
        # Default to sources.txt if present; else fallback to small.txt; else default to sources.txt path
        default_sources = os.path.join(REPO_ROOT, 'sources.txt')
        small_sources = os.path.join(REPO_ROOT, 'small.txt')
        candidate = default_sources if os.path.exists(default_sources) else (small_sources if os.path.exists(small_sources) else default_sources)
    return candidate


SOURCES_FILE = _get_sources_file()

# Tuning (overridable by environment)
FETCH_TIMEOUT = _env_int('OPENRAY_FETCH_TIMEOUT', 20, 1, 120)  # seconds per source fetch
FETCH_WORKERS = _env_int('OPENRAY_FETCH_WORKERS', 24, 1, 256)
PING_WORKERS = _env_int('OPENRAY_PING_WORKERS', 64, 1, 1024)
PING_TIMEOUT_MS = _env_int('OPENRAY_PING_TIMEOUT_MS', 1000, 100, 10000)  # per ping attempt
# TCP connect timeout for checking specific proxy ports (ms)
CONNECT_TIMEOUT_MS = _env_int('OPENRAY_CONNECT_TIMEOUT_MS', 1500, 100, 10000)
# Ports to try for TCP connectivity fallback (when ICMP ping is blocked, e.g., in CI)
TCP_FALLBACK_PORTS: List[int] = [80, 443, 8080, 8443, 2052, 2082, 2086, 2095]
USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/122.0 Safari/537.36'
)

# Stage 2/3 controls (overridable by environment)
ENABLE_STAGE2 = _env_int('OPENRAY_ENABLE_STAGE2', 1, 0, 1)  # 1=enable TLS probe after TCP
PROBE_TIMEOUT_MS = _env_int('OPENRAY_PROBE_TIMEOUT_MS', 1200, 100, 10000)
ENABLE_STAGE3 = _env_int('OPENRAY_ENABLE_STAGE3', 1, 0, 1)  # default enable
# Validate up to many proxies with core by default (can be reduced via env)
STAGE3_MAX = _env_int('OPENRAY_STAGE3_MAX', 5000, 1, 100000)

def _auto_find_v2ray_core() -> str:
    # Priority 1: explicit env OPENRAY_V2RAY_CORE
    try:
        env = os.environ.get('OPENRAY_V2RAY_CORE', '').strip()
    except Exception:
        env = ''

    def _exists(p: str) -> bool:
        try:
            return bool(p) and os.path.exists(p)
        except Exception:
            return False

    if env:
        p = env
        if not os.path.isabs(p):
            cand = os.path.join(REPO_ROOT, p)
            if _exists(cand):
                return cand
            w = shutil.which(p)
            if w:
                return w
        if _exists(p):
            return p

    # Priority 2: PATH lookup
    for name in ('xray.exe', 'xray', 'v2ray.exe', 'v2ray'):
        w = shutil.which(name)
        if w:
            return w

    # Priority 3: Local repo candidates
    for folder in (REPO_ROOT, os.path.join(REPO_ROOT, 'bin'), os.path.join(REPO_ROOT, 'tools')):
        for name in ('xray.exe', 'v2ray.exe', 'xray', 'v2ray'):
            p = os.path.join(folder, name)
            if _exists(p):
                return p

    return ''

V2RAY_CORE_PATH = _auto_find_v2ray_core()

# Streak selection parameters (overridable)
CONSECUTIVE_REQUIRED = _env_int('OPENRAY_STREAK_REQUIRED', 5, 1, 100)
LAST24H_WINDOW_SECONDS = _env_int('OPENRAY_LAST24H_SECONDS', 24 * 3600, 60, 7 * 24 * 3600)
