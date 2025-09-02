from __future__ import annotations

import concurrent.futures
import os
import time
from typing import Dict, List, Optional, Set, Tuple

from .common import log, progress, sha1_hex
from .constants import (
    AVAILABLE_FILE,
    PING_WORKERS,
    ENABLE_STAGE2,
    ENABLE_STAGE3,
    STAGE3_MAX,
    STAGE3_WORKERS,
)
from .grouping import write_grouped_outputs
from .io_ops import (
    ensure_dirs,
    load_streaks,
    read_lines,
    save_streaks,
)
from .net import ping_host, connect_host_port, quick_protocol_probe, validate_with_v2ray_core
from .parsing import (
    extract_host,
    extract_port,
)


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
    host_map_existing: Dict[str, Optional[str]] = {}
    
    if os.path.exists(AVAILABLE_FILE):
        existing_lines = [ln.strip() for ln in read_lines(AVAILABLE_FILE) if ln.strip()]
        if existing_lines:
            from .parsing import extract_host as _extract_host_for_existing

            host_map_existing = {u: _extract_host_for_existing(u) for u in existing_lines}
            items = [(u, h) for u, h in host_map_existing.items() if h]
            # initialize to False for tested hosts
            for _, h in items:
                if h not in host_success_run:
                    host_success_run[h] = False

            def check_existing(item: Tuple[str, str]) -> Optional[str]:
                u, h = item
                try:
                    if not ping_host(h):
                        return None
                    scheme = u.split('://', 1)[0].lower()
                    if scheme in ('vmess', 'vless', 'trojan', 'ss', 'ssr'):
                        p = extract_port(u)
                        if p is not None:
                            ok = connect_host_port(h, int(p))
                            if not ok:
                                return None
                            if int(ENABLE_STAGE2) == 1:
                                return u if quick_protocol_probe(u, h, int(p)) else None
                            return u
                    return u
                except Exception:
                    return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=PING_WORKERS) as pool:
                print("Start Stage 2 for existing proxies")
                for res in progress(pool.map(check_existing, items), total=len(items)):
                    if res is not None:
                        alive.append(res)
                        h = host_map_existing.get(res)
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
                    subset = alive # [:int(STAGE3_MAX)]
                    kept_subset: List[str] = []

                    def _core_check(u: str) -> Optional[str]:
                        try:
                            res = validate_with_v2ray_core(u, timeout_s=12)
                        except Exception:
                            return None
                        return u if res is True else None

                    workers = int(STAGE3_WORKERS)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool2:
                        print("Start Stage 3 for existing proxies")
                        for r in progress(pool2.map(_core_check, subset), total=len(subset)):
                            if r is not None:
                                kept_subset.append(r)
                    # Merge: replace subset portion with validated ones
                    alive = kept_subset + alive[len(subset):]

            if len(alive) != len(existing_lines):
                # Outage-safe guard: avoid purging available file if connectivity appears down
                if len(existing_lines) > 0 and len(alive) == 0 and not _has_connectivity():
                    log("Suspected Internet outage during revalidation; keeping existing available proxies file unchanged.")
                else:
                    tmp_path = AVAILABLE_FILE + '.tmp'
                    with open(tmp_path, 'w', encoding='utf-8', errors='ignore') as f:
                        for u in alive:
                            f.write(u)
                            f.write('\n')
                    os.replace(tmp_path, AVAILABLE_FILE)
                    log(f"Revalidated existing available proxies: kept {len(alive)} of {len(existing_lines)}")
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
    if alive:
        # Write grouped outputs (this will read from AVAILABLE_FILE which we just updated)
        write_grouped_outputs()
        
        log(f"Successfully processed {len(alive)} existing proxies")
    else:
        log("No existing proxies found to process")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
