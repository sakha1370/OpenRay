from __future__ import annotations

import concurrent.futures
import os
from typing import List, Optional, Tuple

# Use package-relative imports to support `python -m src.main_local`
from .constants import AVAILABLE_FILE, OUTPUT_DIR, PING_WORKERS, ENABLE_STAGE2, ENABLE_STAGE3, STAGE3_MAX  # type: ignore
from .io_ops import ensure_dirs, read_lines, write_text_file_atomic  # type: ignore
from .parsing import extract_host, extract_port  # type: ignore
from .net import ping_host, connect_host_port, quick_protocol_probe, validate_with_v2ray_core  # type: ignore
from .common import log, progress  # type: ignore


OUT_FILE = os.path.join(OUTPUT_DIR, 'Iran_valid_proxies.txt')


def _check_one(item: Tuple[str, str]) -> Optional[str]:
    """Return URI if alive, else None."""
    uri, host = item
    try:
        if not host:
            return None
        # First, ensure host is reachable (ICMP/TCP fallback)
        if not ping_host(host):
            return None
        # Then, for TCP-based schemes, also ensure we can connect to the specific port
        scheme = uri.split('://', 1)[0].lower()
        if scheme in ('vmess', 'vless', 'trojan', 'ss', 'ssr'):
            p = extract_port(uri)
            if p is not None:
                ok = connect_host_port(host, int(p))
                if not ok:
                    return None
                if int(ENABLE_STAGE2) == 1:
                    return uri if quick_protocol_probe(uri, host, int(p)) else None
                return uri
        return uri
    except Exception:
        return None


def main() -> int:
    ensure_dirs()

    if not os.path.exists(AVAILABLE_FILE):
        log(f"Input not found: {AVAILABLE_FILE}")
        return 1

    lines = [ln.strip() for ln in read_lines(AVAILABLE_FILE) if ln.strip()]
    if not lines:
        log("No proxies to validate.")
        write_text_file_atomic(OUT_FILE, [])
        return 0

    # Build (uri, host) pairs
    items: List[Tuple[str, str]] = []
    for u in lines:
        h = extract_host(u)
        if h:
            items.append((u, h))

    if not items:
        log("No resolvable hosts found among proxies.")
        write_text_file_atomic(OUT_FILE, [])
        return 0

    log(f"Checking {len(items)} proxies from {AVAILABLE_FILE} ...")

    alive: List[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=PING_WORKERS) as pool:
        print("Start Stage 2 for existing proxies")
        for res in progress(pool.map(_check_one, items), total=len(items)):
            if res is not None:
                alive.append(res)

    # Optional Stage 3: validate a subset with V2Ray core (if configured)
    if int(ENABLE_STAGE3) == 1 and alive:
        core_path = ''
        try:
            from .constants import V2RAY_CORE_PATH
            core_path = (V2RAY_CORE_PATH or '').strip()
        except Exception:
            core_path = ''
        if not core_path:
            log("Stage 3 enabled, but V2Ray/Xray core not found or OPENRAY_V2RAY_CORE is not set; skipping core validation.")
        else:
            subset = alive # [:int(STAGE3_MAX)]
            kept_subset: List[str] = []

            def _core_check(u: str) -> Optional[str]:
                try:
                    res = validate_with_v2ray_core(u, timeout_s=12)
                except Exception:
                    return None
                return u if res is True else None

            workers = min(int(PING_WORKERS), 16)
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                print("Start Stage 3 for existing proxies")
                for r in progress(pool.map(_core_check, subset), total=len(subset)):
                    if r is not None:
                        kept_subset.append(r)
            # Merge: replace subset portion with validated ones
            alive = kept_subset + alive[len(subset):]

    # Optional: export v2ray/xray JSON configs for alive proxies
    try:
        exp_flag = os.environ.get('OPENRAY_EXPORT_V2RAY', '').strip().lower()
        if exp_flag in ('1', 'true', 'yes', 'on'):
            try:
                from .v2ray import export_v2ray_configs
                written = export_v2ray_configs(alive)
                if written > 0:
                    log(f"Exported {written} v2ray/xray JSON configs to {os.path.join(OUTPUT_DIR, 'v2ray_configs')}")
                else:
                    log("V2Ray export requested, but no configs were generated (unsupported schemes?)")
            except Exception as e:
                log(f"V2Ray config export failed: {e}")
    except Exception:
        pass

    write_text_file_atomic(OUT_FILE, alive)
    log(f"Validated proxies: {len(alive)} of {len(items)} saved to {OUT_FILE}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
