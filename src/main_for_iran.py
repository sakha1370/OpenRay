from __future__ import annotations

import argparse
import os
import sys
import time
from typing import List, Dict, Callable, Any, Optional
import socket
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from tqdm import tqdm  # progress bar
except Exception:
    tqdm = None

# Patch constants BEFORE importing modules that read them
from . import constants as C

# Determine input proxies file (existing curated list)
INPUT_FILE = os.path.join(C.REPO_ROOT, 'output', 'all_valid_proxies.txt')

# Redirect state and output to Iran-specific locations
C.STATE_DIR = os.path.join(C.REPO_ROOT, '.state_iran')
C.OUTPUT_DIR = os.path.join(C.REPO_ROOT, 'output_iran')

# Recompute dependent constant paths
C.TESTED_FILE = os.path.join(C.STATE_DIR, 'tested.txt')
C.AVAILABLE_FILE = os.path.join(C.OUTPUT_DIR, 'all_valid_proxies_for_iran.txt')
C.KIND_DIR = os.path.join(C.OUTPUT_DIR, 'kind')
C.COUNTRY_DIR = os.path.join(C.OUTPUT_DIR, 'country')

# Provide an empty sources file so the main pipeline skips fetching new sources
EMPTY_SOURCES = os.path.join(C.REPO_ROOT, 'sources_iran.txt')
C.SOURCES_FILE = EMPTY_SOURCES

# Override Iran-specific settings
# Disable rechecking existing proxies for Iran (set to '0' to disable)
os.environ['OPENRAY_RECHECK_EXISTING'] = '1'

# Set NEW_URIS_LIMIT to a lower value for Iran-specific processing
C.NEW_URIS_LIMIT = 10000  # Reduced from default 25000 for Iran-specific processing

# Iran-specific check count tracking files (shared with main.py)
CHECK_COUNTS_FILE = os.path.join(C.REPO_ROOT, '.state', 'check_counts.json')
TOP100_FILE = os.path.join(C.OUTPUT_DIR, 'iran_top100_checked.txt')

# Internet connectivity monitoring
INTERNET_CHECK_INTERVAL = 30  # Check connectivity every 30 seconds during proxy checking
INTERNET_RETRY_DELAY = 60    # Wait 60 seconds before retrying when internet is down
INTERNET_MONITORING_ACTIVE = False
LAST_INTERNET_CHECK = 0
INTERNET_STATUS = True

def _robust_internet_check(host="8.8.8.8", port=53, timeout=5) -> bool:
    """Robust internet connectivity check using multiple methods."""
    try:
        # Method 1: Socket connection to Google DNS
        socket.setdefaulttimeout(timeout)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return True
    except Exception:
        pass

    try:
        # Method 2: Socket connection to Cloudflare DNS
        socket.setdefaulttimeout(timeout)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex(("1.1.1.1", 53))
        sock.close()
        if result == 0:
            return True
    except Exception:
        pass

    # Method 3: Try to resolve a well-known domain
    try:
        socket.gethostbyname("google.com")
        return True
    except Exception:
        pass

    return False

def _monitor_internet_connectivity():
    """Background thread to monitor internet connectivity."""
    global INTERNET_STATUS, LAST_INTERNET_CHECK

    while INTERNET_MONITORING_ACTIVE:
        current_time = time.time()

        # Only check if enough time has passed since last check
        if current_time - LAST_INTERNET_CHECK >= INTERNET_CHECK_INTERVAL:
            LAST_INTERNET_CHECK = current_time
            new_status = _robust_internet_check()

            if new_status != INTERNET_STATUS:
                if new_status:
                    log("✅ Internet connection restored")
                else:
                    log("❌ Internet connection lost - will retry in 60 seconds")
                INTERNET_STATUS = new_status

        time.sleep(5)  # Check every 5 seconds for responsiveness

def _start_internet_monitoring():
    """Start the background internet monitoring thread."""
    global INTERNET_MONITORING_ACTIVE

    if INTERNET_MONITORING_ACTIVE:
        return  # Already running

    INTERNET_MONITORING_ACTIVE = True
    monitor_thread = threading.Thread(target=_monitor_internet_connectivity, daemon=True)
    monitor_thread.start()
    log("Started internet connectivity monitoring")

def _stop_internet_monitoring():
    """Stop the background internet monitoring."""
    global INTERNET_MONITORING_ACTIVE
    INTERNET_MONITORING_ACTIVE = False
    log("Stopped internet connectivity monitoring")

def _wait_for_internet_with_retry(max_retries=10):
    """Wait for internet connection with retry logic."""
    global INTERNET_STATUS

    for attempt in range(max_retries):
        if INTERNET_STATUS:
            if attempt > 0:
                log(f"✅ Internet connection available after {attempt} checks")
            return True

        wait_time = INTERNET_RETRY_DELAY
        log(f"⏳ Waiting {wait_time} seconds for internet connection (attempt {attempt + 1}/{max_retries})")
        time.sleep(wait_time)

        # Force a fresh connectivity check
        INTERNET_STATUS = _robust_internet_check()

    log(f"❌ Failed to restore internet connection after {max_retries} attempts")
    return False

def _execute_with_connectivity_retry(func: Callable, *args, **kwargs) -> Any:
    """Execute a function with automatic retry on connectivity issues."""
    max_attempts = 3

    for attempt in range(max_attempts):
        try:
            if not INTERNET_STATUS:
                if not _wait_for_internet_with_retry(5):  # Wait up to 5 minutes
                    raise Exception("Internet connection unavailable")

            result = func(*args, **kwargs)
            return result

        except Exception as e:
            if "connection" in str(e).lower() or "timeout" in str(e).lower() or "unreachable" in str(e).lower():
                log(f"⚠️ Network error detected (attempt {attempt + 1}/{max_attempts}): {e}")
                INTERNET_STATUS = False  # Force connectivity recheck

                if attempt < max_attempts - 1:
                    if not _wait_for_internet_with_retry(3):  # Wait up to 3 minutes
                        continue
                else:
                    log(f"❌ Max retry attempts reached for: {e}")
                    raise e
            else:
                # Non-connectivity error, re-raise immediately
                raise e

    raise Exception("Max retry attempts reached")

def _patch_network_functions():
    """Patch network functions to include connectivity monitoring."""
    try:
        from . import net as net_module

        # Store original functions
        original_ping_host = net_module.ping_host
        original_connect_host_port = net_module.connect_host_port
        original_validate_with_v2ray_core = net_module.validate_with_v2ray_core
        original_fetch_urls_async_batch = net_module.fetch_urls_async_batch

        def _monitored_ping_host(host: str) -> bool:
            """Monitored ping_host with connectivity retry."""
            def _ping_operation():
                return original_ping_host(host)

            try:
                return _execute_with_connectivity_retry(_ping_operation)
            except Exception as e:
                log(f"⚠️ Ping failed for {host}: {e}")
                return False

        def _monitored_connect_host_port(host: str, port: int) -> bool:
            """Monitored connect_host_port with connectivity retry."""
            def _connect_operation():
                return original_connect_host_port(host, port)

            try:
                return _execute_with_connectivity_retry(_connect_operation)
            except Exception as e:
                log(f"⚠️ Connection failed for {host}:{port}: {e}")
                return False

        def _monitored_validate_with_v2ray_core(uri: str, timeout_s: int = 10) -> Optional[bool]:
            """Monitored validate_with_v2ray_core with connectivity retry."""
            def _validate_operation():
                return original_validate_with_v2ray_core(uri, timeout_s)

            try:
                return _execute_with_connectivity_retry(_validate_operation)
            except Exception as e:
                log(f"⚠️ V2Ray validation failed for {uri}: {e}")
                return False

        def _monitored_fetch_urls_async_batch(urls: List[str], timeout: int = 10) -> Dict[str, Optional[str]]:
            """Monitored fetch_urls_async_batch with connectivity retry."""
            def _fetch_operation():
                return original_fetch_urls_async_batch(urls, timeout)

            try:
                return _execute_with_connectivity_retry(_fetch_operation)
            except Exception as e:
                log(f"⚠️ URL fetch failed: {e}")
                return {url: None for url in urls}

        # Apply patches
        net_module.ping_host = _monitored_ping_host
        net_module.connect_host_port = _monitored_connect_host_port
        net_module.validate_with_v2ray_core = _monitored_validate_with_v2ray_core
        net_module.fetch_urls_async_batch = _monitored_fetch_urls_async_batch

        log("🔧 Applied network function patches for connectivity monitoring")

    except Exception as e:
        log(f"⚠️ Failed to patch network functions: {e}")

# Now import the rest of the pipeline after patching constants
from .common import log  # noqa: E402
from .io_ops import ensure_dirs, read_lines, write_text_file_atomic  # noqa: E402
from . import main as main_pipeline  # noqa: E402


def _seed_available_from_input() -> None:
    """Seed the Iran-specific AVAILABLE_FILE with contents of INPUT_FILE (if present)."""
    try:
        ensure_dirs()
        lines: List[str] = []
        if os.path.exists(INPUT_FILE):
            lines = [ln.strip() for ln in read_lines(INPUT_FILE) if ln.strip()]
        else:
            log(f"Input not found: {INPUT_FILE}")
        # write_text_file_atomic(C.AVAILABLE_FILE, lines)
        # Ensure empty sources file exists so main() doesn't exit
        try:
            if not os.path.exists(EMPTY_SOURCES):
                with open(EMPTY_SOURCES, 'w', encoding='utf-8') as f:
                    f.write('')
        except Exception:
            pass
    except Exception as e:
        log(f"Seeding available proxies failed: {e}")

def _load_check_counts() -> Dict[str, Any]:
    """Load check counts with new structure: {proxy: {"global": count, "iran": {"total": count, "operators": {...}}, "consecutive_failures": count}}"""
    try:
        if os.path.exists(CHECK_COUNTS_FILE):
            with open(CHECK_COUNTS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    result = {}
                    for proxy, value in data.items():
                        if isinstance(value, dict):
                            # Handle both old and new formats for backward compatibility
                            if "iran" in value and isinstance(value["iran"], dict):
                                # New format - use as is
                                result[str(proxy)] = value
                            else:
                                # Old format - migrate to new format
                                main_count = int(value.get("main", 0))
                                iran_count = int(value.get("iran", 0))
                                consecutive_failures = int(value.get("consecutive_failures", 0))

                                result[str(proxy)] = {
                                    "global": main_count,
                                    "iran": {
                                        "total": iran_count,
                                        "operators": {
                                            "mci": 0,
                                            "irancell": 0,
                                            "tci": 0,
                                            "others": iran_count
                                        }
                                    },
                                    "consecutive_failures": consecutive_failures
                                }
                        else:
                            # Very old format - single integer
                            main_count = int(value) if isinstance(value, (int, str)) else 0

                            result[str(proxy)] = {
                                "global": main_count,
                                "iran": {
                                    "total": 0,
                                    "operators": {
                                        "mci": 0,
                                        "irancell": 0,
                                        "tci": 0,
                                        "others": 0
                                    }
                                },
                                "consecutive_failures": 0
                            }
                    return result
    except Exception as e:
        log(f"Failed to load check counts: {e}")
    return {}


def _cleanup_check_counts(active_proxies: List[str]) -> None:
    """Remove check counts for proxies that are no longer active."""
    if not active_proxies:
        return

    counts = _load_check_counts()
    active_set = set(active_proxies)

    # Filter counts to only include active proxies
    cleaned_counts = {proxy: counts for proxy, counts in counts.items() if proxy in active_set}

    # Only save if there are changes
    if len(cleaned_counts) != len(counts):
        removed_count = len(counts) - len(cleaned_counts)
        log(f"Cleaned up check counts: removed {removed_count} stale proxies from state (not in current input list)")
        _save_check_counts(cleaned_counts)


def _save_check_counts(counts: Dict[str, Dict[str, int]]) -> None:
    try:
        ensure_dirs()
        os.makedirs(os.path.dirname(CHECK_COUNTS_FILE), exist_ok=True)
        tmp = CHECK_COUNTS_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8', errors='ignore') as f:
            json.dump(counts, f, ensure_ascii=False, indent=2)
        os.replace(tmp, CHECK_COUNTS_FILE)
    except Exception as e:
        log(f"Failed to save check counts: {e}")


def _update_check_counts_for_proxies(proxies: List[str], active_proxies: List[str] = None, operator: str = "others") -> None:
    """Update check counts for successfully validated proxies with operator tracking."""
    if not proxies:
        return
    counts = _load_check_counts()

    # If active_proxies is provided, only update counts for active proxies
    active_set = set(active_proxies) if active_proxies else None

    # Deduplicate proxies using custom OpenRay dedup key
    from .common import get_openray_dedup_key
    seen_keys: set = set()
    unique_proxies: List[str] = []

    for p in proxies:
        if not p:
            continue
        # Skip if proxy is not in active list (when provided)
        if active_set is not None and p not in active_set:
            continue

        # Deduplicate using custom OpenRay dedup key
        conn_key = get_openray_dedup_key(p)
        if conn_key not in seen_keys:
            seen_keys.add(conn_key)
            unique_proxies.append(p)

    # Update counts for all unique successfully validated proxies
    updated_count = 0
    for p in unique_proxies:
        if p not in counts:
            counts[p] = {
                "global": 0,
                "iran": {
                    "total": 0,
                    "operators": {
                        "mci": 0,
                        "irancell": 0,
                        "tci": 0,
                        "others": 0
                    }
                },
                "consecutive_failures": 0
            }

        # Update the specific operator count
        counts[p]["iran"]["operators"][operator] = counts[p]["iran"]["operators"].get(operator, 0) + 1

        # Update the total Iran count (sum of all operators)
        total = sum(counts[p]["iran"]["operators"].values())
        counts[p]["iran"]["total"] = total

        counts[p]["consecutive_failures"] = 0  # Reset consecutive failures on success
        updated_count += 1

    if updated_count > 0:
        _save_check_counts(counts)
        log(f"📈 Updated {operator} operator check counts for {updated_count} successfully validated proxies")


def _write_operator_ranking(active_proxies: List[str], operator: str = None, filename: str = None) -> None:
    """Write top 100 proxies based on specific operator or overall Iran ranking."""
    try:
        counts = _load_check_counts()

        if not active_proxies:
            log("⚠️ No active proxies to rank")
            return

        # Score each active proxy based on operator or total Iran count
        scored = []
        for idx, p in enumerate(active_proxies):
            proxy_counts = counts.get(p, {
                "global": 0,
                "iran": {"total": 0, "operators": {"mci": 0, "irancell": 0, "tci": 0, "others": 0}},
                "consecutive_failures": 0
            })

            if operator is None:
                # Overall Iran ranking - prioritize total Iran count, then global
                iran_total = proxy_counts["iran"]["total"] if isinstance(proxy_counts["iran"], dict) else proxy_counts.get("iran", 0)
                global_count = proxy_counts.get("global", 0)
                scored.append((iran_total, global_count, idx, p))
            elif operator in ["mci", "irancell", "tci", "others"]:
                # Operator-specific ranking - prioritize operator count, then total Iran, then global
                operator_count = proxy_counts["iran"]["operators"].get(operator, 0) if isinstance(proxy_counts["iran"], dict) else 0
                iran_total = proxy_counts["iran"]["total"] if isinstance(proxy_counts["iran"], dict) else proxy_counts.get("iran", 0)
                global_count = proxy_counts.get("global", 0)
                scored.append((operator_count, iran_total, global_count, idx, p))
            else:
                # Fallback to global ranking
                global_count = proxy_counts.get("global", 0)
                iran_total = proxy_counts["iran"]["total"] if isinstance(proxy_counts["iran"], dict) else proxy_counts.get("iran", 0)
                scored.append((global_count, iran_total, idx, p))

        # Sort based on ranking criteria
        if operator is None:
            # Overall Iran ranking: Iran total desc, then global desc, then original order
            scored.sort(key=lambda t: (-t[0], -t[1], t[2]))
        elif operator in ["mci", "irancell", "tci", "others"]:
            # Operator ranking: operator count desc, then total Iran desc, then global desc, then original order
            scored.sort(key=lambda t: (-t[0], -t[1], -t[2], t[3]))
        else:
            # Global ranking: global desc, then Iran total desc, then original order
            scored.sort(key=lambda t: (-t[0], -t[1], t[2]))

        # Get top 100
        if operator is None:
            top = [p for _, _, _, p in scored[:100]]
        else:
            top = [p for _, _, _, _, p in scored[:100]]

        # Determine output file
        if filename:
            output_file = os.path.join(os.path.dirname(TOP100_FILE), filename)
        else:
            output_file = TOP100_FILE

        write_text_file_atomic(output_file, top)
        log(f"🏆 Wrote top {len(top)} most reliable proxies to {output_file}")

        # Show top 5 for verification
        if top and operator is None:  # Only show for main Iran ranking to avoid spam
            log("🥇 Top 5 most reliable proxies:")
            for i, proxy in enumerate(top[:5], 1):
                proxy_counts = counts.get(proxy, {
                    "global": 0,
                    "iran": {"total": 0, "operators": {"mci": 0, "irancell": 0, "tci": 0, "others": 0}},
                    "consecutive_failures": 0
                })
                iran_total = proxy_counts["iran"]["total"] if isinstance(proxy_counts["iran"], dict) else proxy_counts.get("iran", 0)
                global_count = proxy_counts.get("global", 0)
                log(f"  {i}. [Iran:{iran_total}, Global:{global_count}] {proxy[:60]}...")

    except Exception as e:
        log(f"❌ Failed to write operator ranking: {e}")


def _write_top100_by_checks(active_proxies: List[str]) -> None:
    """Write top 100 most frequently checked proxies to iran_top100_checked.txt.
    Prioritizes iran total scores, then global scores as tiebreaker."""
    _write_operator_ranking(active_proxies, operator=None, filename='iran_top100_checked.txt')


def _write_all_operator_rankings(active_proxies: List[str]) -> None:
    """Generate all operator-specific ranking files."""
    operators = ["mci", "irancell", "tci", "others"]

    for operator in operators:
        filename = f"{operator}_top100.txt"
        _write_operator_ranking(active_proxies, operator=operator, filename=filename)


def _write_iran_overall_ranking(active_proxies: List[str]) -> None:
    """Write top 100 most frequently checked proxies for overall Iran ranking."""
    _write_operator_ranking(active_proxies, operator=None, filename='iran_top100_checked.txt')


def _validate_proxies_directly(proxies: List[str]) -> List[str]:
    """Validate proxies directly (no pipeline, no rewriting). Returns successes."""
    try:
        from . import net as net_module
    except Exception as e:
        log(f"❌ Failed to import net module: {e}")
        return []

    successful_proxies: List[str] = []
    total_proxies = len(proxies)

    log(f"🔍 Starting direct validation of {total_proxies} proxies...")

    # Concurrency level (tunable via env var)
    # Align concurrency with main pipeline's Stage 3 default
    try:
        from . import constants as C
        default_workers = int(getattr(C, 'STAGE3_WORKERS', 32))
    except Exception:
        default_workers = 32
    try:
        max_workers = max(1, int(os.environ.get('OPENRAY_IRAN_CONCURRENCY', str(default_workers))))
    except Exception:
        max_workers = default_workers

    if total_proxies == 0:
        return successful_proxies

    progress = tqdm(total=total_proxies, desc="Checking", unit="proxy") if tqdm else None

    def _update_progress(n: int = 1):
        if progress is not None:
            try:
                progress.update(n)
            except Exception:
                pass

    # Load check counts for tracking consecutive failures
    counts = _load_check_counts()

    from .stage3.engine import get_engine
    stage3_results = get_engine().validate_many([p for p in proxies if p], timeout_s=12)
    for proxy in proxies:
        if not proxy:
            _update_progress()
            continue
        ok = stage3_results.get(proxy) is True
        if ok:
            successful_proxies.append(proxy)
            if proxy in counts:
                counts[proxy]["consecutive_failures"] = 0
        else:
            if proxy not in counts:
                counts[proxy] = {"main": 0, "iran": 0, "consecutive_failures": 0}
            if counts[proxy]["consecutive_failures"] >= int(getattr(C, 'EXISTING_PROXY_FAILURE_LIMIT', 24)):
                log(f"Proxy {proxy[:50]}... reached failure limit ({counts[proxy]['consecutive_failures']}) in Iran.")
        _update_progress()

    # Save updated check counts
    _save_check_counts(counts)

    if progress is not None:
        try:
            progress.close()
        except Exception:
            pass

    log(f"🎯 Direct validation complete: {len(successful_proxies)}/{total_proxies} proxies are working")
    return successful_proxies


def check_internet_socket(host="8.8.8.8", port=53, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except Exception:
        return False


def _check_all_proxies_from_input() -> List[str]:
    """Load all proxies from all_valid_proxies.txt (no rewriting)."""
    # Load all proxies from the input file
    all_proxies: List[str] = []
    if os.path.exists(INPUT_FILE):
        all_proxies = [ln.strip() for ln in read_lines(INPUT_FILE) if ln.strip()]
        log(f"📋 Loaded {len(all_proxies)} proxies from {INPUT_FILE}")
    else:
        log(f"❌ Input file not found: {INPUT_FILE}")
        return []
    
    if not all_proxies:
        log("⚠️ No proxies to check")
        return []
    return all_proxies

def main() -> int:
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Iran proxy validation with operator tracking')
    parser.add_argument('--mci', action='store_true', help='Increment MCI operator counter')
    parser.add_argument('--irancell', action='store_true', help='Increment Irancell operator counter')
    parser.add_argument('--tci', action='store_true', help='Increment TCI operator counter')
    args = parser.parse_args()

    # Determine which operator to increment
    if args.mci:
        operator = "mci"
    elif args.irancell:
        operator = "irancell"
    elif args.tci:
        operator = "tci"
    else:
        operator = "others"  # Default when no flag is specified

    _seed_available_from_input()

    # Simple connectivity pre-check (no patching, no monitoring to avoid scope issues)
    if not _robust_internet_check():
        log("❌ No internet connection available")
        return 1

    try:
        log(f"🚀 Starting Iran proxy validation (direct, no rewriting) for operator: {operator.upper()}")

        # Load proxies from main list without rewriting
        all_proxies = _check_all_proxies_from_input()
        if not all_proxies:
            log("❌ No proxies to check")
            return 1

        # First, drop stale entries not in current list
        _cleanup_check_counts(all_proxies)

        # Validate directly and count only successes
        successful_proxies = _validate_proxies_directly(all_proxies)
        if not successful_proxies:
            log("⚠️ No working proxies found this run")

        # Update counts only for successful proxies with the specified operator
        _update_check_counts_for_proxies(successful_proxies, all_proxies, operator)

        # Generate all operator-specific ranking files
        _write_top100_by_checks(all_proxies)  # iran_top100_checked.txt
        _write_iran_overall_ranking(all_proxies)  # iran_top100.txt
        _write_all_operator_rankings(all_proxies)  # mci_top100.txt, irancell_top100.txt, etc.

        log("✅ Completed: counts updated and all ranking files generated (no file rewrites)")
        return 0

    except Exception as e:
        log(f"❌ Proxy validation failed: {e}")
        return 1


if __name__ == '__main__':
    if _robust_internet_check():
        print("✅ Internet connection is available")
        raise SystemExit(main())
    else:
        print("❌ No internet connection")
