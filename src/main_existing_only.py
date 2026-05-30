from __future__ import annotations

import concurrent.futures
import os
import time
from typing import Dict, List, Optional, Set

from .common import log, progress, sha1_hex, get_proxy_connection_hash, get_v2rayn_connection_key
from .constants import (
    AVAILABLE_FILE,
    PING_WORKERS,
    ENABLE_STAGE3,
    STAGE3_MAX,
    STAGE3_TCP_PREFILTER,
    EXISTING_PROXY_FAILURE_LIMIT,
)
from .grouping import write_grouped_outputs
from .io_ops import (
    ensure_dirs,
    load_streaks,
    read_lines,
    save_streaks,
)
from .net import ping_host, connect_host_port
from .stage3.engine import get_engine
from .stage3.prefilter import tcp_prefilter_existing
from .parsing import extract_host

def _sync_check_counts_with_available_file() -> None:
    """Lazy import and call sync function from main.py to avoid circular imports."""
    try:
        # Lazy import to avoid circular dependency
        from .main import _sync_check_counts_with_available_file as sync_func
        sync_func()
    except (ImportError, AttributeError):
        # Silently fail if import is not available (e.g., during circular import)
        pass


def _has_connectivity() -> bool:
    """Best-effort Internet connectivity check using IP-only probes to avoid DNS dependency."""
    try:
        probes = [('1.1.1.1', 443), ('8.8.8.8', 53)]
        for ip, port in probes:
            try:
                if ping_host(ip):
                    return True
            except Exception:
                pass
            try:
                if connect_host_port(ip, port):
                    return True
            except Exception:
                pass
    except Exception:
        return False
    return False


def main() -> int:
    ensure_dirs()
    
    # Pre-flight connectivity check to avoid destructive actions during outages
    if not _has_connectivity():
        log("No Internet connectivity detected; skipping network operations and leaving existing outputs unchanged.")
        return 2

    # Load streaks persistence
    streaks: Dict[str, Dict[str, int]] = load_streaks()

    # Re-validate current available proxies to drop broken ones
    host_success_run: Dict[str, bool] = {}
    alive: List[str] = []
    deduplicated_alive: List[str] = []
    host_map_existing: Dict[str, Optional[str]] = {}
    
    if os.path.exists(AVAILABLE_FILE):
        existing_lines = [ln.strip() for ln in read_lines(AVAILABLE_FILE) if ln.strip()]
        if existing_lines:
            from .parsing import extract_host as _extract_host_for_existing

            # Deduplicate existing proxies using V2RayN-style connection-based uniqueness
            seen_connection_keys = set()
            deduplicated_existing = []
            for u in existing_lines:
                conn_key = get_v2rayn_connection_key(u)
                if conn_key not in seen_connection_keys:
                    seen_connection_keys.add(conn_key)
                    deduplicated_existing.append(u)
            
            log(f"Deduplicated existing proxies: {len(deduplicated_existing)} unique out of {len(existing_lines)} total")
            existing_lines = deduplicated_existing

            host_map_existing = {u: _extract_host_for_existing(u) for u in existing_lines}

            # Keep all existing proxies without Stage 2 revalidation
            for u in existing_lines:
                alive.append(u)
                h = host_map_existing.get(u)
                if h:
                    host_success_run[h] = True

            # Optional Stage 3: validate a subset of revalidated existing proxies with V2Ray core (if configured)
            if int(ENABLE_STAGE3) == 1 and alive:
                core_path = ''
                try:
                    from .constants import V2RAY_CORE_PATH  # local import to avoid circulars in some contexts
                    core_path = (V2RAY_CORE_PATH or '').strip()
                except Exception:
                    core_path = ''
                if not core_path:
                    log("Stage 3 enabled, but V2Ray/Xray core not found or OPENRAY_V2RAY_CORE is not set; skipping core validation for existing proxies.")
                else:
                    subset = alive[: int(STAGE3_MAX)]
                    kept_subset: List[str] = []

                    tcp_pass = subset
                    tcp_fail_set: Set[str] = set()
                    if int(STAGE3_TCP_PREFILTER) == 1:
                        tcp_pass, tcp_fail = tcp_prefilter_existing(
                            subset, host_map_existing, max_workers=PING_WORKERS
                        )
                        tcp_fail_set = set(tcp_fail)
                        log(f"Stage 3 TCP prefilter: pass={len(tcp_pass)} fail={len(tcp_fail)}")

                    print("Start Stage 3 for existing proxies")
                    stage3_results = get_engine().validate_many(tcp_pass, timeout_s=12)
                    for u in progress(subset, total=len(subset)):
                        if u in tcp_fail_set:
                            success = False
                        else:
                            success = stage3_results.get(u) is True
                        h = host_map_existing.get(u)
                        if success:
                            kept_subset.append(u)
                            if h:
                                if h not in streaks:
                                    streaks[h] = {'streak': 0, 'last_test': 0, 'last_success': 0, 'failure_count': 0}
                                streaks[h]['failure_count'] = 0
                        else:
                            if h:
                                if h not in streaks:
                                    streaks[h] = {'streak': 0, 'last_test': 0, 'last_success': 0, 'failure_count': 0}
                                
                                curr_fails = streaks[h].get('failure_count', 0)
                                streaks[h]['failure_count'] = curr_fails + 1
                                
                                if streaks[h]['failure_count'] < int(EXISTING_PROXY_FAILURE_LIMIT):
                                    kept_subset.append(u)
                                else:
                                    log(f"Proxy {h} reached failure limit ({EXISTING_PROXY_FAILURE_LIMIT}). Removing it.")

                    # Save updated streaks after revalidation
                    save_streaks(streaks)

                    # Merge: replace subset portion with validated ones
                    alive = kept_subset + alive[len(subset):]

            # Deduplicate alive proxies using V2RayN-style connection-based uniqueness
            seen_keys: Set[str] = set()
            deduplicated_alive: List[str] = []
            for u in alive:
                conn_key = get_v2rayn_connection_key(u)
                if conn_key not in seen_keys:
                    seen_keys.add(conn_key)
                    deduplicated_alive.append(u)
            
            if len(deduplicated_alive) != len(existing_lines):
                # Outage-safe guard: avoid purging available file if connectivity appears down
                if len(existing_lines) > 0 and len(deduplicated_alive) == 0 and not _has_connectivity():
                    log("Suspected Internet outage during revalidation; keeping existing available proxies file unchanged.")
                else:
                    tmp_path = AVAILABLE_FILE + '.tmp'
                    with open(tmp_path, 'w', encoding='utf-8', errors='ignore') as f:
                        for u in deduplicated_alive:
                            f.write(u)
                            f.write('\n')
                    os.replace(tmp_path, AVAILABLE_FILE)
                    log(f"Revalidated existing available proxies: kept {len(deduplicated_alive)} of {len(existing_lines)} (deduplicated from {len(alive)})")
                    _sync_check_counts_with_available_file()
            else:
                log("Revalidated existing available proxies: all still reachable")
    else:
        log(f"No existing proxies file found: {AVAILABLE_FILE}")
        return 0

    # Update streaks for hosts that were successfully tested
    for host, success in host_success_run.items():
        if host not in streaks:
            streaks[host] = {}
        if success:
            streaks[host]['consecutive'] = streaks[host].get('consecutive', 0) + 1
            streaks[host]['last_success'] = int(time.time())
        else:
            streaks[host]['consecutive'] = 0

    save_streaks(streaks)

    # Group and write outputs
    if deduplicated_alive:
        # Write grouped outputs (this will read from AVAILABLE_FILE which we just updated)
        write_grouped_outputs()
        
        log(f"Successfully processed {len(deduplicated_alive)} existing proxies")
    else:
        log("No existing proxies found to process")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
