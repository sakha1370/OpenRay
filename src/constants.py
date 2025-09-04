import os
import sys
import shutil
import multiprocessing
import time
from typing import Optional, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# Determine repository root as parent of this src directory
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Directories and files
STATE_DIR = os.path.join(REPO_ROOT, '.state')
OUTPUT_DIR = os.path.join(REPO_ROOT, 'output')
TESTED_FILE = os.path.join(STATE_DIR, 'tested.txt')  # stores SHA1 per tested proxy URI
AVAILABLE_FILE = os.path.join(OUTPUT_DIR, 'all_valid_proxies.txt')
STREAKS_FILE = os.path.join(STATE_DIR, 'streaks.json')
KIND_DIR = os.path.join(OUTPUT_DIR, 'kind')
COUNTRY_DIR = os.path.join(OUTPUT_DIR, 'country')


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


def _is_ci_env() -> bool:
    """Detect common CI environments beyond just GitHub Actions.

    Recognizes a broad set of CI-specific environment indicators.
    """
    try:
        ci_vars = (
            'CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'BUILD_ID', 'BUILD_NUMBER', 'TF_BUILD',
            'CIRCLECI', 'TRAVIS', 'APPVEYOR', 'JENKINS_URL', 'TEAMCITY_VERSION',
            'BITBUCKET_BUILD_NUMBER', 'DRONE', 'WOODPECKER', 'BUILDKITE'
        )
        for k in ci_vars:
            v = os.environ.get(k)
            if isinstance(v, str) and v.strip():
                # Some providers set explicit boolean-like strings
                if v.strip().lower() in ('1', 'true', 'yes', 'on'):
                    return True
                # Others just set a non-empty marker (e.g., Jenkins URL)
                if k not in ('CI',):  # 'CI' is often set to 'true' specifically
                    return True
        return False
    except Exception:
        return False


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
        memory_gb = 16 if _is_ci_env() else 8
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
    env_factor = 0.8 if _is_ci_env() else 1.0

    if is_network:
        env_factor *= 0.9  # Network is usually good in CI

    return int(base_ms * cpu_factor * env_factor)


def _benchmark_worker_pool(worker_counts: List[int], test_duration: float = 2.0) -> Tuple[int, float]:
    """Benchmark different worker counts to find optimal performance.
    
    Returns: (optimal_worker_count, performance_score)
    """
    try:
        # Simple benchmark: create/destroy thread pools and measure overhead
        results = []
        
        for worker_count in worker_counts:
            start_time = time.time()
            
            # Test pool creation and basic task execution
            with ThreadPoolExecutor(max_workers=worker_count) as pool:
                # Submit dummy tasks to warm up the pool
                futures = [pool.submit(lambda: time.sleep(0.001)) for _ in range(min(worker_count * 2, 100))]
                
                # Wait for completion
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception:
                        pass
            
            end_time = time.time()
            overhead = end_time - start_time
            
            # Score: lower overhead is better, but we want some workers
            # Penalize very low worker counts (too slow) and very high (too much overhead)
            if worker_count < 4:
                score = overhead * 2  # Penalty for too few workers
            elif worker_count > 128:
                score = overhead * 1.5  # Penalty for too many workers
            else:
                score = overhead
            
            results.append((worker_count, score))
        
        # Find the worker count with best score
        best_worker, best_score = min(results, key=lambda x: x[1])
        return best_worker, best_score
        
    except Exception:
        # Fallback to heuristic if benchmarking fails
        return _adaptive_workers(16, 128, 32), 1.0

def _discover_optimal_workers() -> Tuple[int, int]:
    """Automatically discover optimal worker counts for current environment."""
    try:
        cpu_cores, memory_gb = _get_system_specs()
        
        # Test different worker ranges based on system specs - MAXIMUM PERFORMANCE
        if _is_ci_env():
            # CI environments: test maximum ranges
            test_ranges = [
                list(range(24, 73, 8)),      # 24, 32, 40, 48, 56, 64, 72
                list(range(48, 145, 16)),    # 48, 64, 80, 96, 112, 128, 144
                list(range(96, 257, 32)),    # 96, 128, 160, 192, 224, 256
            ]
        else:
            # Local environments: test aggressive performance ranges
            if cpu_cores >= 8:
                # High-end systems: maximum performance ranges
                test_ranges = [
                    list(range(16, cpu_cores * 4 + 1, 4)),    # 16, 20, 24, 28, 32, 36, 40, 44, 48
                    list(range(32, cpu_cores * 6 + 1, 8)),    # 32, 40, 48, 56, 64, 72
                    list(range(64, cpu_cores * 8 + 1, 16)),   # 64, 80, 96, 112, 128
                ]
            else:
                # Standard systems: aggressive ranges
                test_ranges = [
                    list(range(12, 41, 4)),   # 12, 16, 20, 24, 28, 32, 36, 40
                    list(range(24, 81, 8)),   # 24, 32, 40, 48, 56, 64, 72, 80
                    list(range(48, 145, 16)), # 48, 64, 80, 96, 112, 128, 144
                ]
        
        # Find optimal for each type
        optimal_fetch = _benchmark_worker_pool(test_ranges[0])[0]
        optimal_ping = _benchmark_worker_pool(test_ranges[1])[0]
        
        # Apply memory constraints - more aggressive for performance
        if cpu_cores >= 8 and memory_gb >= 16:
            # High-end systems: allow higher memory usage for maximum performance
            max_by_memory = int(memory_gb * 1024 / 70)  # 70MB per worker (aggressive)
            optimal_fetch = min(optimal_fetch, max_by_memory // 2)
            optimal_ping = min(optimal_ping, max_by_memory)
        elif cpu_cores >= 4 and memory_gb >= 8:
            # Medium systems: moderate memory usage
            max_by_memory = int(memory_gb * 1024 / 85)  # 85MB per worker
            optimal_fetch = min(optimal_fetch, max_by_memory // 2)
            optimal_ping = min(optimal_ping, max_by_memory)
        else:
            # Standard systems: balanced memory usage
            max_by_memory = int(memory_gb * 1024 / 100)  # 100MB per worker
            optimal_fetch = min(optimal_fetch, max_by_memory // 2)
            optimal_ping = min(optimal_ping, max_by_memory)
        
        return optimal_fetch, optimal_ping
        
    except Exception:
        # Fallback to aggressive heuristics for maximum performance
        if cpu_cores >= 8:
            return _adaptive_workers(16, 128, 24), _adaptive_workers(32, 256, 48)
        else:
            return _adaptive_workers(12, 96, 16), _adaptive_workers(24, 192, 32)

def _discover_optimal_timeouts() -> Tuple[int, int, int]:
    """Automatically discover optimal timeout values for current environment."""
    try:
        cpu_cores, memory_gb = _get_system_specs()
        
        # Test network responsiveness
        test_hosts = ['1.1.1.1', '8.8.8.8', '208.67.222.222']
        timeouts = []
        
        for host in test_hosts:
            try:
                import socket
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((host, 443))
                sock.close()
                response_time = (time.time() - start) * 1000  # Convert to ms
                timeouts.append(response_time)
            except Exception:
                timeouts.append(1000)  # Default 1 second
        
        # Calculate optimal timeouts based on network performance
        avg_response = sum(timeouts) / len(timeouts) if timeouts else 1000
        
        # Base timeouts with network adaptation - MAXIMUM PERFORMANCE
        if avg_response < 50:  # Very fast network (<50ms)
            ping_timeout = max(300, min(800, int(avg_response * 4)))
            connect_timeout = max(400, min(1200, int(avg_response * 6)))
            probe_timeout = max(350, min(1000, int(avg_response * 5)))
        elif avg_response < 100:  # Fast network (<100ms)
            ping_timeout = max(350, min(1000, int(avg_response * 3)))
            connect_timeout = max(500, min(1500, int(avg_response * 5)))
            probe_timeout = max(400, min(1200, int(avg_response * 4)))
        elif avg_response < 200:  # Moderate network (<200ms)
            ping_timeout = max(400, min(1200, int(avg_response * 2.5)))
            connect_timeout = max(600, min(1800, int(avg_response * 4)))
            probe_timeout = max(500, min(1500, int(avg_response * 3)))
        else:  # Slower network
            ping_timeout = max(500, min(1500, int(avg_response * 2)))
            connect_timeout = max(700, min(2500, int(avg_response * 3)))
            probe_timeout = max(600, min(2000, int(avg_response * 2.5)))
        
        return ping_timeout, connect_timeout, probe_timeout
        
    except Exception:
        # Fallback to aggressive timeouts for maximum performance
        return _adaptive_timeout(800, True), _adaptive_timeout(1200, True), _adaptive_timeout(1000, True)

# Tuning (overridable by environment)
# Auto-discovered optimal parameters with fallbacks
_CI = _is_ci_env()

# Auto-discover optimal parameters
try:
    _opt_fetch, _opt_ping = _discover_optimal_workers()
    _opt_ping_timeout, _opt_connect_timeout, _opt_probe_timeout = _discover_optimal_timeouts()
    # print(f"Auto-discovered optimal parameters: FETCH={_opt_fetch}, PING={_opt_ping}, "
    #       f"PING_TIMEOUT={_opt_ping_timeout}ms, CONNECT_TIMEOUT={_opt_connect_timeout}ms, "
    #       f"PROBE_TIMEOUT={_opt_probe_timeout}ms")
except Exception as e:
    # print(f"Auto-discovery failed, using heuristics: {e}")
    _opt_fetch, _opt_ping = _adaptive_workers(8 if _CI else 6, 96 if _CI else 64, 16 if _CI else 8), _adaptive_workers(24 if _CI else 16, 192 if _CI else 256, 48 if _CI else 32)
    _opt_ping_timeout, _opt_connect_timeout, _opt_probe_timeout = _adaptive_timeout(1000, True), _adaptive_timeout(1500, True), _adaptive_timeout(1200, True)

# Timeouts (optimized for speed - reduced for faster failure detection)
FETCH_TIMEOUT = _env_int('OPENRAY_FETCH_TIMEOUT',
                        _adaptive_timeout(15000, True) // 1000, 1, 120)
PING_TIMEOUT_MS = _env_int('OPENRAY_PING_TIMEOUT_MS',
                          min(_opt_ping_timeout, 350), 50, 10000)

# Workers (maximum performance with safety limits)
FETCH_WORKERS = _env_int('OPENRAY_FETCH_WORKERS', max(_opt_fetch, 16), 1, 512)
PING_WORKERS = _env_int('OPENRAY_PING_WORKERS', max(_opt_ping, 32), 1, 2048)

# TCP connect timeout for checking specific proxy ports (ms) - maximum performance
CONNECT_TIMEOUT_MS = _env_int('OPENRAY_CONNECT_TIMEOUT_MS',
                             min(_opt_connect_timeout, 500), 50, 10000)
# Ports to try for TCP connectivity fallback (when ICMP ping is blocked, e.g., in CI)
TCP_FALLBACK_PORTS: List[int] = [80, 443, 8080, 8443, 2052, 2082, 2086, 2095]
USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/122.0 Safari/537.36'
)

# Stage 2/3 controls (overridable by environment)
ENABLE_STAGE2 = _env_int('OPENRAY_ENABLE_STAGE2', 1, 0, 1)  # 1=enable TLS probe after TCP
PROBE_TIMEOUT_MS = _env_int('OPENRAY_PROBE_TIMEOUT_MS', min(_opt_probe_timeout, 450), 50, 10000)
ENABLE_STAGE3 = _env_int('OPENRAY_ENABLE_STAGE3', 1, 0, 1)  # default enable
# Validate up to many proxies with core by default (can be reduced via env)
STAGE3_MAX = _env_int('OPENRAY_STAGE3_MAX', 5000, 1, 100000)


def _adaptive_stage3_workers() -> int:
    """Calculate optimal Stage 3 worker count (V2Ray core validation) - MAXIMUM PERFORMANCE."""
    cpu_cores, memory_gb = _get_system_specs()

    # Stage 3 is CPU+memory intensive (spawning V2Ray processes)
    # Aggressive approach for maximum performance
    if cpu_cores >= 8:
        base_workers = cpu_cores * 3  # 3x cores for high-end systems
        memory_per_process = 65  # More aggressive memory estimate
    else:
        base_workers = cpu_cores * 2  # 2x cores for standard systems
        memory_per_process = 75  # Balanced memory estimate

    # Memory constraint: V2Ray processes use ~65-100MB each
    max_by_memory = int(memory_gb * 1024 / memory_per_process)

    # Apply reasonable bounds
    workers = min(base_workers, max_by_memory)

    # In CI environments, keep this modest to avoid OOM and process thrash
    if _is_ci_env():
        workers = min(workers, 16)

    return max(8, min(workers, 128))  # Range: 8-128 workers (increased for performance)

# Stage 3 adaptive workers (maximum performance)
STAGE3_WORKERS = _env_int('OPENRAY_STAGE3_WORKERS',
                         max(_adaptive_stage3_workers(), 24), 4, 512)

# Limit for number of new URIs processed per run (overridable)
NEW_URIS_LIMIT_ENABLED = _env_int('OPENRAY_NEW_URIS_LIMIT_ENABLED', 1, 0, 1)
NEW_URIS_LIMIT = _env_int('OPENRAY_NEW_URIS_LIMIT', 25000, 1, 1000000)

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

# Debug mode - set OPENRAY_DEBUG=1 to enable detailed parameter logging
if os.environ.get('OPENRAY_DEBUG', '').strip() in ('1', 'true', 'yes'):
    print("\n" + "="*70)
    print("🚀 OPENRAY MAXIMUM PERFORMANCE PARAMETERS")
    print("="*70)
    print("⚙️  WORKERS:")
    print(f"   FETCH_WORKERS: {FETCH_WORKERS} (was: {_opt_fetch})")
    print(f"   PING_WORKERS: {PING_WORKERS} (was: {_opt_ping})")
    print(f"   STAGE3_WORKERS: {STAGE3_WORKERS}")
    print("⏱️  TIMEOUTS:")
    print(f"   PING_TIMEOUT_MS: {PING_TIMEOUT_MS}ms (auto: {_opt_ping_timeout}ms)")
    print(f"   CONNECT_TIMEOUT_MS: {CONNECT_TIMEOUT_MS}ms (auto: {_opt_connect_timeout}ms)")
    print(f"   PROBE_TIMEOUT_MS: {PROBE_TIMEOUT_MS}ms (auto: {_opt_probe_timeout}ms)")
    print("📊 SYSTEM INFO:")
    cpu_cores, memory_gb = _get_system_specs()
    print(f"   CPU Cores: {cpu_cores}")
    print(f"   Memory: {memory_gb:.1f}GB")
    print(f"   Environment: {'CI' if _CI else 'Local'}")
    print("="*70 + "\n")
