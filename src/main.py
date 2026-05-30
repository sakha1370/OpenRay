from __future__ import annotations

import concurrent.futures
import os
import time
from typing import Dict, List, Optional, Set, Tuple

from .common import log, progress, sha1_hex, get_proxy_connection_hash, get_v2rayn_connection_key, get_openray_dedup_key
import json
from .constants import (
    AVAILABLE_FILE,
    CONSECUTIVE_REQUIRED,
    FETCH_WORKERS,
    FETCH_TIMEOUT,
    PING_WORKERS,
    SOURCES_FILE,
    ENABLE_STAGE2,
    ENABLE_STAGE3,
    STAGE3_MAX,
    OUTPUT_DIR,
    STATE_DIR,
    STAGE3_WORKERS,
    STAGE3_EXISTING_TIMEOUT_S,
    STAGE3_NEW_TIMEOUT_S,
    STAGE3_TCP_PREFILTER,
    NEW_URIS_LIMIT_ENABLED,
    NEW_URIS_LIMIT,
    EXISTING_PROXY_FAILURE_LIMIT,
)
from .geo import _build_country_counters, _country_flag
from .grouping import regroup_available_by_country, write_grouped_outputs
from .io_ops import (
    append_lines,
    ensure_dirs,
    load_existing_available,
    load_tested_hashes,
    load_tested_hashes_optimized,
    append_tested_hashes_optimized,
    read_lines,
    write_text_file_atomic,
)
from .net import _get_country_code_for_host, ping_host, connect_host_port, quick_protocol_probe, validate_with_v2ray_core, fetch_urls_async_batch, get_country_codes_batch, check_one_sync, is_dynamic_host, check_pair
from .stage3.engine import get_engine
from .stage3.prefilter import tcp_prefilter_existing
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
        return False
    return False


def _deduplicate_proxies(proxies: List[str]) -> List[str]:
    """Deduplicate proxies using OpenRay dedup key, preserving first occurrence."""
    seen_keys: Set[str] = set()
    deduplicated: List[str] = []
    for u in proxies:
        if not u:
            continue
        conn_key = get_openray_dedup_key(u)
        if conn_key not in seen_keys:
            seen_keys.add(conn_key)
            deduplicated.append(u)
    return deduplicated


# Check counts functionality for main.py
CHECK_COUNTS_FILE = os.path.join(STATE_DIR, 'check_counts.json')
TOP100_FILE = os.path.join(os.path.dirname(AVAILABLE_FILE), 'main_top100_checked.txt')


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


def _update_check_counts_for_proxies(proxies: List[str], counter_type: str = "global") -> None:
    """Update check counts for successfully validated proxies."""
    if not proxies:
        return
    counts = _load_check_counts()

    # Deduplicate proxies using custom OpenRay dedup key
    seen_keys: set = set()
    unique_proxies: List[str] = []

    for p in proxies:
        if not p:
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

        # Update the global counter
        if counter_type == "global":
            old_count = counts[p].get("global", 0)
            counts[p]["global"] = old_count + 1
        elif counter_type == "iran":
            # For backward compatibility, increment the "others" operator when using "iran" counter
            old_count = counts[p]["iran"]["operators"].get("others", 0)
            counts[p]["iran"]["operators"]["others"] = old_count + 1
            # Update total
            total = sum(counts[p]["iran"]["operators"].values())
            counts[p]["iran"]["total"] = total
        else:
            # For any other counter type, treat as global
            old_count = counts[p].get("global", 0)
            counts[p]["global"] = old_count + 1

        counts[p]["consecutive_failures"] = 0  # Reset consecutive failures on success
        updated_count += 1

    if updated_count > 0:
        _save_check_counts(counts)
        log(f"📈 Updated {counter_type} check counts for {updated_count} successfully validated proxies")


def _sync_check_counts_with_available_file() -> None:
    """Sync check_counts.json with all_valid_proxies.txt: remove entries for proxies no longer in file, add entries for new proxies."""
    try:
        if not os.path.exists(AVAILABLE_FILE):
            return

        # Read all proxies from all_valid_proxies.txt
        current_proxies = set()
        for line in read_lines(AVAILABLE_FILE):
            proxy = line.strip()
            if proxy:
                current_proxies.add(proxy)

        if not current_proxies:
            return

        # Load current check counts
        counts = _load_check_counts()

        # Track changes
        removed_count = 0
        added_count = 0

        # Remove entries for proxies no longer in the file
        proxies_to_remove = []
        for proxy in counts.keys():
            if proxy not in current_proxies:
                proxies_to_remove.append(proxy)
                removed_count += 1

        for proxy in proxies_to_remove:
            del counts[proxy]

        # Add entries for new proxies (with 0 counts)
        for proxy in current_proxies:
            if proxy not in counts:
                counts[proxy] = {
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
                added_count += 1

        # Save if there were changes
        if removed_count > 0 or added_count > 0:
            _save_check_counts(counts)
            if removed_count > 0:
                log(f"🧹 Removed {removed_count} stale proxy entries from check_counts.json")
            if added_count > 0:
                log(f"➕ Added {added_count} new proxy entries to check_counts.json")
    except Exception as e:
        log(f"⚠️ Failed to sync check_counts.json with all_valid_proxies.txt: {e}")


def _write_top100_by_checks(active_proxies: List[str]) -> None:
    """Write top 100 most frequently checked proxies to main_top100_checked.txt.
    Prioritizes global scores, then iran total scores as tiebreaker."""
    try:
        counts = _load_check_counts()

        if not active_proxies:
            log("⚠️ No active proxies to rank")
            return

        # Score each active proxy by global count first, then iran total count as tiebreaker
        scored = []
        for idx, p in enumerate(active_proxies):
            proxy_counts = counts.get(p, {
                "global": 0,
                "iran": {"total": 0, "operators": {"mci": 0, "irancell": 0, "tci": 0, "others": 0}},
                "consecutive_failures": 0
            })
            global_count = proxy_counts.get("global", 0)
            iran_total = proxy_counts["iran"]["total"] if isinstance(proxy_counts["iran"], dict) else proxy_counts.get("iran", 0)
            scored.append((global_count, iran_total, idx, p))

        # Sort by global count desc, then iran total count desc, then original order asc (stable tie-break)
        scored.sort(key=lambda t: (-t[0], -t[1], t[2]))

        # Get top 100
        top = [p for _, _, _, p in scored[:100]]

        # Log some statistics
        if scored:
            max_global = scored[0][0] if scored else 0
            max_iran = max(t[1] for t in scored) if scored else 0
            avg_global = sum(t[0] for t in scored) / len(scored) if scored else 0
            avg_iran = sum(t[1] for t in scored) / len(scored) if scored else 0

            log(f"📊 Global check stats: max={max_global}, avg={avg_global:.1f}")
            log(f"📊 Iran check stats: max={max_iran}, avg={avg_iran:.1f}")

        write_text_file_atomic(TOP100_FILE, top)
        log(f"🏆 Wrote top {len(top)} most reliable proxies to {TOP100_FILE}")

        # Show top 5 for verification
        if top:
            log("🥇 Top 5 most reliable proxies:")
            for i, proxy in enumerate(top[:5], 1):
                proxy_counts = counts.get(proxy, {
                    "global": 0,
                    "iran": {"total": 0, "operators": {"mci": 0, "irancell": 0, "tci": 0, "others": 0}},
                    "consecutive_failures": 0
                })
                global_count = proxy_counts.get("global", 0)
                iran_total = proxy_counts["iran"]["total"] if isinstance(proxy_counts["iran"], dict) else proxy_counts.get("iran", 0)
                log(f"  {i}. [Global:{global_count}, Iran:{iran_total}] {proxy[:60]}...")

    except Exception as e:
        log(f"❌ Failed to write top100 checked proxies: {e}")


def _write_iran_top100_by_checks(active_proxies: List[str]) -> None:
    """Write top 100 most frequently checked proxies for Iran.
    Prioritizes iran total scores, then global scores as tiebreaker."""
    try:
        # Iran-specific output directory (same level as output directory)
        iran_output_dir = os.path.join(os.path.dirname(OUTPUT_DIR), 'output_iran')
        iran_top100_file = os.path.join(iran_output_dir, 'iran_top100_checked.txt')

        # Ensure directory exists
        os.makedirs(iran_output_dir, exist_ok=True)

        counts = _load_check_counts()

        if not active_proxies:
            log("⚠️ No active proxies to rank for Iran")
            return

        # Score each active proxy by iran total count first, then global count as tiebreaker
        scored = []
        for idx, p in enumerate(active_proxies):
            proxy_counts = counts.get(p, {
                "global": 0,
                "iran": {"total": 0, "operators": {"mci": 0, "irancell": 0, "tci": 0, "others": 0}},
                "consecutive_failures": 0
            })
            iran_total = proxy_counts["iran"]["total"] if isinstance(proxy_counts["iran"], dict) else proxy_counts.get("iran", 0)
            global_count = proxy_counts.get("global", 0)
            scored.append((iran_total, global_count, idx, p))

        # Sort by iran total count desc, then global count desc, then original order asc (stable tie-break)
        scored.sort(key=lambda t: (-t[0], -t[1], t[2]))

        # Get top 100
        top = [p for _, _, _, p in scored[:100]]

        # Log Iran-specific statistics only
        if scored:
            max_iran = scored[0][0] if scored else 0
            avg_iran = sum(t[0] for t in scored) / len(scored) if scored else 0

            log(f"📊 Iran check stats: max={max_iran}, avg={avg_iran:.1f}")

        write_text_file_atomic(iran_top100_file, top)
        log(f"🏆 Wrote top {len(top)} most reliable Iran proxies to {iran_top100_file}")

        # Show top 5 for verification
        if top:
            log("🥇 Top 5 most reliable Iran proxies:")
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
        log(f"❌ Failed to write Iran top100 checked proxies: {e}")


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

    # Remove streaks.json if it still exists
    try:
        streaks_file = os.path.join(STATE_DIR, 'streaks.json')
        if os.path.exists(streaks_file):
            os.remove(streaks_file)
            log("🧹 Removed legacy streaks.json file")
    except Exception:
        pass

    # Optionally re-validate current available proxies to drop broken ones
    recheck_env = os.environ.get('OPENRAY_RECHECK_EXISTING', '1').strip().lower()
    do_recheck = recheck_env not in ('0', 'false', 'no')
    alive: List[str] = []
    # Track which proxies successfully passed validation this run
    successful_this_run: List[str] = []
    host_map_existing: Dict[str, Optional[str]] = {}
    host_success_run: Dict[str, bool] = {}
    if do_recheck and os.path.exists(AVAILABLE_FILE):
        # Reset successful_this_run if we are doing a recheck, as we will populate it during checking
        successful_this_run = []
        existing_lines = [ln.strip() for ln in read_lines(AVAILABLE_FILE) if ln.strip()]
        if existing_lines:
            from .parsing import extract_host as _extract_host_for_existing

            # Deduplicate existing proxies using custom OpenRay dedup rules
            seen_connection_keys = set()
            deduplicated_existing = []
            for u in existing_lines:
                conn_key = get_openray_dedup_key(u)
                if conn_key not in seen_connection_keys:
                    seen_connection_keys.add(conn_key)
                    deduplicated_existing.append(u)
            
            log(f"Deduplicated existing proxies: {len(deduplicated_existing)} unique out of {len(existing_lines)} total")
            existing_lines = deduplicated_existing

            host_map_existing = {u: _extract_host_for_existing(u) for u in existing_lines}
            # Keep all existing proxies without Stage 2 revalidation
            for u in existing_lines:
                alive.append(u)
                if int(ENABLE_STAGE3) != 1:
                    successful_this_run.append(u)

            # Optional Stage 3: validate revalidated existing proxies with V2Ray core (if configured)
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
                    
                    # Load check counts for tracking consecutive failures
                    counts = _load_check_counts()

                    tcp_pass = subset
                    tcp_fail_set: Set[str] = set()
                    if int(STAGE3_TCP_PREFILTER) == 1:
                        tcp_pass, tcp_fail = tcp_prefilter_existing(
                            subset, host_map_existing, max_workers=PING_WORKERS
                        )
                        tcp_fail_set = set(tcp_fail)
                        log(f"Stage 3 TCP prefilter: pass={len(tcp_pass)} fail={len(tcp_fail)}")

                    print("Start Stage 3 (with retries) for existing proxies")
                    stage3_results = get_engine().validate_many(
                        tcp_pass, timeout_s=int(STAGE3_EXISTING_TIMEOUT_S)
                    )
                    for u in progress(subset, total=len(subset)):
                        if u in tcp_fail_set:
                            success = False
                        else:
                            success = stage3_results.get(u) is True
                        if success:
                            kept_subset.append(u)
                            successful_this_run.append(u)
                            if u in counts:
                                counts[u]["consecutive_failures"] = 0
                        else:
                            if u not in counts:
                                counts[u] = {"main": 0, "iran": 0, "consecutive_failures": 0}
                            
                            counts[u]["consecutive_failures"] += 1
                            
                            if counts[u]["consecutive_failures"] < int(EXISTING_PROXY_FAILURE_LIMIT):
                                kept_subset.append(u)
                            else:
                                log(f"Proxy {u[:50]}... reached failure limit ({EXISTING_PROXY_FAILURE_LIMIT}). Removing it.")

                    # Save updated check counts after revalidation
                    _save_check_counts(counts)

                    # Merge: replace subset portion with validated ones
                    alive = kept_subset + alive[len(subset):]

            # Deduplicate alive list before saving to ensure no duplicates
            alive_deduplicated = _deduplicate_proxies(alive)
            if len(alive_deduplicated) != len(alive):
                log(f"Deduplicated alive proxies: {len(alive_deduplicated)} unique out of {len(alive)} total")
            
            if len(alive_deduplicated) != len(existing_lines):
                # Outage-safe guard: avoid purging available file if connectivity appears down
                if len(existing_lines) > 0 and len(alive_deduplicated) == 0 and not _has_connectivity():
                    log("Suspected Internet outage during revalidation; keeping existing available proxies file unchanged.")
                else:
                    tmp_path = AVAILABLE_FILE + '.tmp'
                    with open(tmp_path, 'w', encoding='utf-8', errors='ignore') as f:
                        for u in alive_deduplicated:
                            f.write(u)
                            f.write('\n')
                    os.replace(tmp_path, AVAILABLE_FILE)
                    log(f"Revalidated existing available proxies: kept {len(alive_deduplicated)} of {len(existing_lines)}")
            else:
                log("Revalidated existing available proxies: all still reachable")

    # Load persistence early to filter as we parse
    tested_hashes = load_tested_hashes_optimized()
    existing_available = load_existing_available()

    # Fetch and process sources concurrently; deduplicate URIs and collect only new ones
    seen_connection_keys: Set[str] = set()
    new_uris: List[str] = []
    new_hashes: List[str] = []
    fetched_count = 0
    total_extracted = 0  # Track total URIs extracted from all sources
    # Parse sources and fetch asynchronously using aiohttp (fallbacks built-in)
    parsed_sources = []
    for line in source_lines:
        url, flags = parse_source_line(line)
        if not url:
            continue
        parsed_sources.append((url, flags))
    urls_only = [u for (u, _) in parsed_sources]
    content_map = {}
    log("Start fetching sources...")
    try:
        import asyncio  # type: ignore
        content_map = asyncio.run(fetch_urls_async_batch(urls_only, concurrency=int(FETCH_WORKERS), timeout=int(FETCH_TIMEOUT)))
    except Exception as e:
        log(f"Async fetch failed to run event loop; falling back to sequential urllib: {e}")
        # Fallback: sequential
        from .net import fetch_url as _fetch_url_sync  # local import to avoid circulars
        from .common import progress as _progress
        for u in _progress(urls_only, total=len(urls_only)):
            content_map[u] = _fetch_url_sync(u)

    for (url, flags) in parsed_sources:
        content = content_map.get(url)
        if content is None:
            continue
        fetched_count += 1
        decoded = maybe_decode_subscription(content, hinted_base64=flags.get('base64', False))
        for u in extract_uris(decoded):
            total_extracted += 1  # Count all URIs extracted from all sources
            # Use custom OpenRay dedup key for deduplication
            conn_key = get_openray_dedup_key(u)
            if conn_key not in seen_connection_keys:
                seen_connection_keys.add(conn_key)
                h = get_proxy_connection_hash(u)  # Still use original hash for tested_hashes
                if h not in tested_hashes:
                    new_uris.append(u)
                    new_hashes.append(h)

    log(f"Fetched {fetched_count} contents")
    log(f"Extracted: {total_extracted} proxy URIs; Unique: {len(seen_connection_keys)} proxy URIs; New for testing: {len(new_uris)}")

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

    # Stage 2 for new proxies: prefilter via fast batch ping, then connect/probe using asyncio or multiprocessing for large sets
    available_to_add: List[str] = []

    def check_one(item: Tuple[str, str]) -> Tuple[str, str, bool]:
        uri, host = item

        def _check_new_proxy_operation():
            try:
                # Step 1: Fast ICMP/TCP fallback check (speed boost)
                ping_ok = ping_host(host)
                
                # Step 2: Specific port check (hard gate)
                # For TCP-based schemes, we ensure we can connect to the specific port.
                # We try this even if ping_host failed, because some hosts block ICMP/fallback ports.
                scheme = uri.split('://', 1)[0].lower()
                if scheme in ('vmess', 'vless', 'trojan', 'ss', 'ssr', 'hysteria', 'hysteria2', 'hy2', 'tuic', 'juicity', 'wireguard'):
                    p = extract_port(uri)
                    if p is not None:
                        ok2 = connect_host_port(host, int(p))
                        if ok2 and int(ENABLE_STAGE2) == 1:
                            ok2 = quick_protocol_probe(uri, host, int(p))
                        return (uri, host, ok2)
                
                # If not a recognized TCP scheme or port extraction failed, fallback to ping result
                return (uri, host, ping_ok)
            except Exception:
                return (uri, host, False)

        # Use timeout wrapper with hard 10-second limit per proxy
        import threading
        result = [None]
        exception = [None]

        def target():
            try:
                result[0] = _check_new_proxy_operation()
            except Exception as e:
                exception[0] = e

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(10.0)  # Hard 10-second timeout per proxy

        if thread.is_alive():
            print(f"Warning: New proxy {host} timed out after 10 seconds", flush=True)
            return (uri, host, False)

        if exception[0]:
            return (uri, host, False)

        return result[0] if result[0] else (uri, host, False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=PING_WORKERS) as pool:
        print("Start Stage 2 for new proxies")
        for uri, host, ok in progress(pool.map(check_one, to_test), total=len(to_test)):
            # Mark host as tested this run
            if host not in host_success_run:
                host_success_run[host] = False
            if ok:
                host_success_run[host] = True
                available_to_add.append(uri)
                if int(ENABLE_STAGE3) != 1:
                    successful_this_run.append(uri)
    
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
            subset = available_to_add[: int(STAGE3_MAX)]
            kept_subset: List[str] = []

            print("Start Stage 3 for new proxies")
            stage3_results = get_engine().validate_many(subset, timeout_s=int(STAGE3_NEW_TIMEOUT_S))
            for u in progress(subset, total=len(subset)):
                if stage3_results.get(u) is True:
                    kept_subset.append(u)
                    successful_this_run.append(u)
            # Merge: replace subset portion with validated ones
            available_to_add = kept_subset + available_to_add[len(subset):]

    # First, deduplicate within the new proxy list itself (custom OpenRay dedup rules)
    seen_new_keys: Set[str] = set()
    deduplicated_new: List[str] = []
    for u in available_to_add:
        conn_key = get_openray_dedup_key(u)
        if conn_key not in seen_new_keys:
            seen_new_keys.add(conn_key)
            deduplicated_new.append(u)
    
    if len(deduplicated_new) != len(available_to_add):
        log(f"Deduplicated new proxies: {len(deduplicated_new)} unique out of {len(available_to_add)} total")
    available_to_add = deduplicated_new

    # Then, deduplicate against existing available file and write (custom OpenRay dedup rules)
    new_available_unique: List[str] = []
    existing_connection_keys = {get_openray_dedup_key(u) for u in existing_available}
    for u in available_to_add:
        conn_key = get_openray_dedup_key(u)
        if conn_key not in existing_connection_keys:
            existing_connection_keys.add(conn_key)
            new_available_unique.append(u)

    if new_available_unique:
        # Build per-country counters from existing entries
        counters = _build_country_counters(existing_available)
        formatted_to_append: List[str] = []
        print("Start formatting new available proxies")
        # Batch resolve country codes for hosts of new entries
        hosts_to_resolve: List[str] = []
        for u in new_available_unique:
            h = host_map.get(u)
            if h:
                hosts_to_resolve.append(h)
        # Deduplicate while preserving order
        hosts_to_resolve = list(dict.fromkeys(hosts_to_resolve))
        cc_map: Dict[str, Optional[str]] = {}
        try:
            cc_map = get_country_codes_batch(hosts_to_resolve)
        except Exception as e:
            log(f"Batch geolocation failed; falling back per-host: {e}")
            for h in hosts_to_resolve:
                try:
                    cc_map[h] = _get_country_code_for_host(h)
                except Exception:
                    cc_map[h] = None
        for u in progress(new_available_unique, total=len(new_available_unique)):
            host = host_map.get(u)
            cc = cc_map.get(host) if host else None
            if not cc:
                cc = 'XX'
            flag = _country_flag(cc)
            next_num = counters.get(cc, 0) + 1
            counters[cc] = next_num
            # Determine dynamic status using DNS heuristic (no streaks used)
            is_dynamic = True if not host else is_dynamic_host(host)
            if is_dynamic:
                remark = f"[OpenRay] Dynamic-{next_num}"
            else:
                remark = f"[OpenRay] {flag} {cc}-{next_num}"
            new_u = _set_remark(u, remark)
            formatted_to_append.append(new_u)
        append_lines(AVAILABLE_FILE, formatted_to_append)
        log(f"Appended {len(formatted_to_append)} new available proxies to {AVAILABLE_FILE} with formatted remarks")
        
        # Deduplicate entire file after appending to ensure no duplicates exist
        all_lines = [ln.strip() for ln in read_lines(AVAILABLE_FILE) if ln.strip()]
        all_deduplicated = _deduplicate_proxies(all_lines)
        if len(all_deduplicated) != len(all_lines):
            log(f"Deduplicated entire file: {len(all_deduplicated)} unique out of {len(all_lines)} total")
            tmp_path = AVAILABLE_FILE + '.tmp'
            with open(tmp_path, 'w', encoding='utf-8', errors='ignore') as f:
                for u in all_deduplicated:
                    f.write(u)
                    f.write('\n')
            os.replace(tmp_path, AVAILABLE_FILE)
            log(f"Saved deduplicated file with {len(all_deduplicated)} unique proxies")
        
        _sync_check_counts_with_available_file()
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

    append_tested_hashes_optimized(new_hashes)
    log(f"Recorded {len(new_hashes)} newly tested proxies to optimized storage")

    # Update check counts for successfully validated proxies
    try:
        if successful_this_run:
            _update_check_counts_for_proxies(successful_this_run, "main")
        
        # Load current available proxies for top100 ranking
        current_available = load_existing_available()
        if current_available:
            _write_top100_by_checks(list(current_available))
            
            # Generate Iran top100 ranking (without updating iran counter)
            _write_iran_top100_by_checks(list(current_available))
    except Exception as e:
        log(f"Check counts update failed: {e}")

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
