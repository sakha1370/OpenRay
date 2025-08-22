from __future__ import annotations

import concurrent.futures
import os
import time
from typing import Dict, List, Optional, Set, Tuple

from .common import log, progress, sha1_hex
from .constants import (
    AVAILABLE_FILE,
    CONSECUTIVE_REQUIRED,
    FETCH_WORKERS,
    PING_WORKERS,
    SOURCES_FILE,
    ENABLE_STAGE2,
    ENABLE_STAGE3,
    STAGE3_MAX,
    OUTPUT_DIR,
    STAGE3_WORKERS,
    NEW_URIS_LIMIT_ENABLED,
    NEW_URIS_LIMIT,
)
from .geo import _build_country_counters, _country_flag
from .grouping import regroup_available_by_country, write_grouped_outputs
from .io_ops import (
    append_lines,
    ensure_dirs,
    load_existing_available,
    load_streaks,
    load_tested_hashes,
    read_lines,
    save_streaks,
)
from .net import _get_country_code_for_host, fetch_url, ping_host, connect_host_port, quick_protocol_probe, validate_with_v2ray_core
from .parsing import (
    _set_remark,
    extract_host,
    extract_port,
    extract_uris,
    maybe_decode_subscription,
    parse_source_line,
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
        pass
        # return False

    # Internet appears broken, raise error to stop program
    raise RuntimeError("No Internet connectivity detected")
    # return False


def main() -> int:
    ensure_dirs()
    if not os.path.exists(SOURCES_FILE):
        log(f"Sources file not found: {SOURCES_FILE}")
        return 1

    source_lines = [ln.strip() for ln in read_lines(SOURCES_FILE) if ln.strip() and not ln.strip().startswith('#')]
    log(f"Loaded {len(source_lines)} sources")

    # Pre-flight connectivity check to avoid destructive actions during outages
    if not _has_connectivity():
        log("No Internet connectivity detected; skipping network operations and leaving existing outputs unchanged.")
        return 2

    # Load streaks persistence
    streaks: Dict[str, Dict[str, int]] = load_streaks()

    # Optionally re-validate current available proxies to drop broken ones
    host_success_run: Dict[str, bool] = {}
    recheck_env = os.environ.get('OPENRAY_RECHECK_EXISTING', '1').strip().lower()
    do_recheck = recheck_env not in ('0', 'false', 'no')
    alive: List[str] = []
    host_map_existing: Dict[str, Optional[str]] = {}
    if do_recheck and os.path.exists(AVAILABLE_FILE):
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
                    subset = alive[:int(STAGE3_MAX)]
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

    # Load persistence early to filter as we parse
    tested_hashes = load_tested_hashes()
    existing_available = load_existing_available()

    # Fetch and process sources concurrently; deduplicate URIs and collect only new ones
    seen_uri: Set[str] = set()
    new_uris: List[str] = []
    new_hashes: List[str] = []
    fetched_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
        future_to_src = {}
        for line in source_lines:
            url, flags = parse_source_line(line)
            if not url:
                continue
            future = pool.submit(fetch_url, url)
            future_to_src[future] = (url, flags)
        for fut in concurrent.futures.as_completed(future_to_src):
            url, flags = future_to_src[fut]
            content = None
            try:
                content = fut.result()
            except Exception as e:
                log(f"Fetch future error: {url} -> {e}")
            if content is None:
                continue
            fetched_count += 1
            decoded = maybe_decode_subscription(content, hinted_base64=flags.get('base64', False))
            for u in extract_uris(decoded):
                if u in seen_uri:
                    continue
                seen_uri.add(u)
                h = sha1_hex(u)
                if h not in tested_hashes:
                    new_uris.append(u)
                    new_hashes.append(h)

    log(f"Fetched {fetched_count} contents")
    log(f"Extracted {len(seen_uri)} unique proxy URIs; new to test: {len(new_uris)}")

    # Optionally limit the number of new URIs processed per run
    try:
        if int(NEW_URIS_LIMIT_ENABLED) == 1:
            _limit = int(NEW_URIS_LIMIT)
            if _limit > 0 and len(new_uris) > _limit:
                pre = len(new_uris)
                new_uris = new_uris[:_limit]
                new_hashes = new_hashes[:_limit]
                log(f"Limiting new URIs to {_limit} of {pre} due to NEW_URIS_LIMIT")
    except Exception:
        # On any misconfiguration, proceed without limiting
        pass

    # Extract hosts for new proxies
    host_map: Dict[str, Optional[str]] = {}
    for u in new_uris:
        host_map[u] = extract_host(u)
    to_test = [(u, host) for u, host in host_map.items() if host]
    log(f"New proxies with resolvable hosts: {len(to_test)}")

    # Ping concurrently
    available_to_add: List[str] = []

    def check_one(item: Tuple[str, str]) -> Tuple[str, str, bool]:
        uri, host = item
        try:
            # First, ensure host is reachable (ICMP/TCP fallback)
            if not ping_host(host):
                return (uri, host, False)
            # Then, for TCP-based schemes, also ensure we can connect to the specific port
            scheme = uri.split('://', 1)[0].lower()
            if scheme in ('vmess', 'vless', 'trojan', 'ss', 'ssr'):
                p = extract_port(uri)
                if p is not None:
                    ok2 = connect_host_port(host, int(p))
                    if ok2 and int(ENABLE_STAGE2) == 1:
                        ok2 = quick_protocol_probe(uri, host, int(p))
                    return (uri, host, ok2)
            return (uri, host, True)
        except Exception:
            return (uri, host, False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=PING_WORKERS) as pool:
        print("Start Stage 2 for new proxies")
        for uri, host, ok in progress(pool.map(check_one, to_test), total=len(to_test)):
            # Mark host as tested this run
            if host not in host_success_run:
                host_success_run[host] = False
            if ok:
                host_success_run[host] = True
                available_to_add.append(uri)

    log(f"Available proxies found this run (ping/connect ok): {len(available_to_add)}")

    # Optional Stage 3: validate a subset with V2Ray core (if configured)
    if int(ENABLE_STAGE3) == 1 and available_to_add:
        core_path = ''
        try:
            from .constants import V2RAY_CORE_PATH  # local import to avoid circulars in some contexts
            core_path = (V2RAY_CORE_PATH or '').strip()
        except Exception:
            core_path = ''
        if not core_path:
            log("Stage 3 enabled, but V2Ray/Xray core not found or OPENRAY_V2RAY_CORE is not set; skipping core validation.")
        else:
            subset = available_to_add[:int(STAGE3_MAX)]
            kept_subset: List[str] = []

            def _core_check(u: str) -> Optional[str]:
                try:
                    res = validate_with_v2ray_core(u, timeout_s=12)
                except Exception:
                    return None
                return u if res is True else None

            workers = int(STAGE3_WORKERS)
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool2:
                print("Start Stage 3 for new proxies")
                for r in progress(pool2.map(_core_check, subset), total=len(subset)):
                    if r is not None:
                        kept_subset.append(r)
            # Merge: replace subset portion with validated ones
            available_to_add = kept_subset + available_to_add[len(subset):]

    # Deduplicate against existing available file and write
    new_available_unique: List[str] = []
    exists_set = set(existing_available)
    for u in available_to_add:
        if u not in exists_set:
            exists_set.add(u)
            new_available_unique.append(u)

    if new_available_unique:
        # Build per-country counters from existing entries
        counters = _build_country_counters(existing_available)
        cc_cache: Dict[str, Optional[str]] = {}
        formatted_to_append: List[str] = []
        print("Start formatting new available proxies")
        for u in progress(new_available_unique, total=len(new_available_unique)):
            host = host_map.get(u)
            cc = None
            if host:
                if host in cc_cache:
                    cc = cc_cache[host]
                else:
                    cc = _get_country_code_for_host(host)
                    cc_cache[host] = cc
            if not cc:
                cc = 'XX'
            flag = _country_flag(cc)
            next_num = counters.get(cc, 0) + 1
            counters[cc] = next_num
            remark = f"[OpenRay] {flag} {cc}-{next_num}"
            new_u = _set_remark(u, remark)
            formatted_to_append.append(new_u)
        append_lines(AVAILABLE_FILE, formatted_to_append)
        log(f"Appended {len(formatted_to_append)} new available proxies to {AVAILABLE_FILE} with formatted remarks")
    else:
        log("No new available proxies to append (all duplicates)")

    # Regroup available proxies by country
    regroup_available_by_country()

    # Optional: export v2ray/xray JSON configs for available proxies
    try:
        exp_flag = os.environ.get('OPENRAY_EXPORT_V2RAY', '').strip().lower()
        if exp_flag in ('1', 'true', 'yes', 'on'):
            try:
                from .v2ray import export_v2ray_configs
                lines_for_export = [ln.strip() for ln in read_lines(AVAILABLE_FILE) if ln.strip()]
                written = export_v2ray_configs(lines_for_export)
                if written > 0:
                    log(f"Exported {written} v2ray/xray JSON configs to {os.path.join(OUTPUT_DIR, 'v2ray_configs')}")
                else:
                    log("V2Ray export requested, but no configs were generated (unsupported schemes?)")
            except Exception as e:
                log(f"V2Ray config export failed: {e}")
    except Exception:
        pass

    # Persist tested hashes (append all newly tested regardless of success)
    from .constants import TESTED_FILE

    append_lines(TESTED_FILE, new_hashes)
    log(f"Recorded {len(new_hashes)} newly tested proxies to {TESTED_FILE}")

    # Update streaks based on this run's host successes
    try:
        total_successes = sum(1 for v in host_success_run.values() if v)
        if total_successes == 0 and not _has_connectivity():
            log("Suspected Internet outage affected tests; skipping streaks update to avoid false resets.")
        else:
            now_ts = int(time.time())
            for host, success in host_success_run.items():
                rec = streaks.get(host, {'streak': 0, 'last_test': 0, 'last_success': 0})
                rec['last_test'] = now_ts
                if success:
                    rec['streak'] = int(rec.get('streak', 0)) + 1
                    rec['last_success'] = now_ts
                else:
                    rec['streak'] = 0
                streaks[host] = rec
            save_streaks(streaks)
    except Exception as e:
        log(f"Streaks update failed: {e}")

    # Generate grouped outputs by kind and country
    try:
        write_grouped_outputs()
    except Exception as e:
        log(f"Grouped outputs step failed: {e}")

    return 0


if __name__ == '__main__':
    import sys
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
