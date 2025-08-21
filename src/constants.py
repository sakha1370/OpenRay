import os
import sys
import shutil
import multiprocessing
from typing import Optional, List

# Determine repository root as parent of this src directory
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Directories and files
STATE_DIR = os.path.join(REPO_ROOT, '.state')
OUTPUT_DIR = os.path.join(REPO_ROOT, 'output')
TESTED_FILE = os.path.join(STATE_DIR, 'tested.txt')  # stores SHA1 per tested proxy URI
AVAILABLE_FILE = os.path.join(OUTPUT_DIR, 'all_valid_proxies.txt')
STREAKS_FILE = os.path.join(STATE_DIR, 'streaks.json')
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


def _get_system_specs():
    """Get system CPU cores and available memory."""
    try:
        cpu_cores = multiprocessing.cpu_count()
    except Exception:
        cpu_cores = 2  # fallback

    try:
        # Get available memory in GB
        import psutil
        memory_gb = psutil.virtual_memory().total / (1024 ** 3)
    except ImportError:
        # Fallback without psutil - estimate based on common CI environments
        memory_gb = 16 if os.environ.get('GITHUB_ACTIONS') else 8
    except Exception:
        memory_gb = 8  # conservative fallback

    return cpu_cores, memory_gb


def _adaptive_workers(base_per_core: int, max_total: int, min_total: int = 1) -> int:
    """Calculate optimal worker count based on system specs."""
    cpu_cores, memory_gb = _get_system_specs()

    # Base calculation: workers per core
    workers = cpu_cores * base_per_core

    # Memory constraint (rough estimate: 100MB per worker)
    max_by_memory = int(memory_gb * 1024 / 100)  # MB
    workers = min(workers, max_by_memory)

    # Apply bounds
    return max(min_total, min(workers, max_total))


def _adaptive_timeout(base_ms: int, is_network: bool = True) -> int:
    """Calculate adaptive timeout based on system and environment."""
    cpu_cores, memory_gb = _get_system_specs()

    # Slower systems need more time
    cpu_factor = 1.0 if cpu_cores >= 4 else 1.3

    # CI environments typically have better network
    env_factor = 0.8 if os.environ.get('GITHUB_ACTIONS') else 1.0

    if is_network:
        env_factor *= 0.9  # Network is usually good in CI

    return int(base_ms * cpu_factor * env_factor)



# Tuning (overridable by environment)
# Adaptive parameter calculation
FETCH_TIMEOUT = _env_int('OPENRAY_FETCH_TIMEOUT',
                        _adaptive_timeout(20000, True) // 1000, 1, 120)
FETCH_WORKERS = _env_int('OPENRAY_FETCH_WORKERS',
                        _adaptive_workers(6, 64, 8), 1, 256)
PING_WORKERS = _env_int('OPENRAY_PING_WORKERS',
                       _adaptive_workers(16, 256, 32), 1, 1024)
PING_TIMEOUT_MS = _env_int('OPENRAY_PING_TIMEOUT_MS',
                          _adaptive_timeout(1000, True), 100, 10000)

# TCP connect timeout for checking specific proxy ports (ms)
CONNECT_TIMEOUT_MS = _env_int('OPENRAY_CONNECT_TIMEOUT_MS',
                             _adaptive_timeout(1500, True), 100, 10000)
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


def _adaptive_stage3_workers() -> int:
    """Calculate optimal Stage 3 worker count (V2Ray core validation)."""
    cpu_cores, memory_gb = _get_system_specs()

    # Stage 3 is CPU+memory intensive (spawning V2Ray processes)
    # More conservative than ping workers
    base_workers = cpu_cores * 2  # 2x cores for CPU-bound tasks

    # Memory constraint: V2Ray processes use ~50-100MB each
    max_by_memory = int(memory_gb * 1024 / 75)  # Conservative 75MB per process

    # Apply reasonable bounds
    workers = min(base_workers, max_by_memory)
    return max(4, min(workers, 64))  # Range: 4-64 workers

# Stage 3 adaptive workers
STAGE3_WORKERS = _env_int('OPENRAY_STAGE3_WORKERS', 
                         _adaptive_stage3_workers(), 4, 256)

# Limit for number of new URIs processed per run (overridable)
NEW_URIS_LIMIT_ENABLED = _env_int('OPENRAY_NEW_URIS_LIMIT_ENABLED', 1, 0, 1)
NEW_URIS_LIMIT = _env_int('OPENRAY_NEW_URIS_LIMIT', 10000, 1, 1000000)

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
