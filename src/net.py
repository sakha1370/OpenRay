from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import ssl
import shutil
import tempfile
from typing import List, Optional, Dict, Set, Tuple
from urllib.request import Request, urlopen

from .constants import USER_AGENT, PING_TIMEOUT_MS, TCP_FALLBACK_PORTS, FETCH_TIMEOUT, CONNECT_TIMEOUT_MS, PROBE_TIMEOUT_MS, V2RAY_CORE_PATH, ENABLE_STAGE2, FETCH_WORKERS, PING_WORKERS
from .common import log, progress


def _idna(host: str) -> str:
    try:
        return host.encode('idna').decode('ascii')
    except Exception:
        return host


def fetch_url(url: str, timeout: int = FETCH_TIMEOUT) -> Optional[str]:
    try:
        req = Request(url, headers={'User-Agent': USER_AGENT, 'Accept': '*/*'})
        with urlopen(req, timeout=timeout) as resp:
            # limit size to 10 MB to avoid memory blowups
            max_bytes = 10 * 1024 * 1024
            data = resp.read(max_bytes + 1)
            if len(data) > max_bytes:
                data = data[:max_bytes]
            return data.decode('utf-8', errors='ignore')
    except Exception as e:
        log(f"Fetch failed: {url} -> {e}")
        return None


def ping_host(host: str) -> bool:
    """Check host reachability via ICMP or TCP fallback."""
    host_ascii = _idna(host)
    timeout_ms = int(PING_TIMEOUT_MS)
    is_windows = os.name == 'nt' or sys.platform.startswith('win')

    # If running in GitHub Actions, skip ICMP and go straight to TCP fallback to avoid CAP_NET_RAW issues.
    force_tcp = os.environ.get('GITHUB_ACTIONS', '').lower() == 'true'

    if not force_tcp:
        # Build candidate commands depending on platform
        cmds: List[List[str]] = []
        if is_windows:
            # Windows: -n (count), -w (timeout in ms), -4/-6 to force family
            cmds = [
                ["ping", "-n", "1", "-w", str(timeout_ms), "-4", host_ascii],
                ["ping", "-n", "1", "-w", str(timeout_ms), "-6", host_ascii],
            ]
        else:
            is_darwin = sys.platform == 'darwin'
            if is_darwin:
                # macOS/BSD: -c (count), -W timeout in ms. BSD ping typically lacks -4/-6; use ping then ping6.
                cmds = [
                    ["ping", "-c", "1", "-W", str(timeout_ms), host_ascii],
                    ["ping6", "-c", "1", "-W", str(timeout_ms), host_ascii],
                ]
            else:
                # Linux: -c (count), -W timeout in seconds. Use -4/-6 to force family.
                timeout_sec = max(1, int(round(timeout_ms / 1000.0)))
                cmds = [
                    ["ping", "-c", "1", "-W", str(timeout_sec), "-4", host_ascii],
                    ["ping", "-c", "1", "-W", str(timeout_sec), "-6", host_ascii],
                ]

        py_timeout = (timeout_ms / 1000.0) + 1.0
        for cmd in cmds:
            try:
                res = subprocess.run(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=py_timeout,
                    creationflags=(subprocess.CREATE_NO_WINDOW if is_windows and hasattr(subprocess, 'CREATE_NO_WINDOW') else 0),
                )
                if res.returncode == 0:
                    return True
            except FileNotFoundError:
                # e.g., ping6 not present
                continue
            except Exception:
                continue

    # TCP fallback: try to connect to a few common ports with a short timeout
    try:
        # Resolve host (prefer IPv4 first)
        infos = socket.getaddrinfo(host_ascii, None, proto=socket.IPPROTO_TCP)
        # Order: IPv4 first, then others
        addrs: List[str] = []
        for fam, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if fam == socket.AF_INET:
                addrs.append(ip)
        for fam, _, _, _, sockaddr in infos:
            if fam != socket.AF_INET:
                addrs.append(sockaddr[0])
        timeout_sec = max(0.2, min(2.0, timeout_ms / 1000.0))
        for ip in addrs:
            for port in TCP_FALLBACK_PORTS:
                try:
                    with socket.create_connection((ip, port), timeout=timeout_sec):
                        return True
                except Exception:
                    continue
    except Exception:
        pass

    return False


def connect_host_port(host: str, port: int, timeout_ms: int = CONNECT_TIMEOUT_MS) -> bool:
    """Attempt a TCP connection to host:port within timeout. Returns True on success."""
    if not host or not isinstance(port, int):
        return False
    if port < 1 or port > 65535:
        return False
    host_ascii = _idna(host)
    try:
        timeout_sec = max(0.1, min(10.0, timeout_ms / 1000.0))
    except Exception:
        timeout_sec = 1.5
    try:
        # Resolve both IPv4/IPv6; prefer IPv4 order like in ping_host
        infos = socket.getaddrinfo(host_ascii, port, proto=socket.IPPROTO_TCP)
        addrs = []
        for fam, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if fam == socket.AF_INET:
                addrs.append((ip, port))
        for fam, _, _, _, sockaddr in infos:
            if fam != socket.AF_INET:
                addrs.append((sockaddr[0], port))
        for addr in addrs:
            try:
                with socket.create_connection(addr, timeout=timeout_sec):
                    return True
            except Exception:
                continue
    except Exception:
        pass
    return False


def _is_ip_address(host: str) -> bool:
    try:
        import ipaddress
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False

# Cache for dynamic classification to avoid repeated DNS lookups in a run
_dynamic_cache: Dict[str, bool] = {}

def is_dynamic_host(host: str) -> bool:
    """Heuristic to decide if a proxy host should be labeled Dynamic.

    Rules:
      - Literal IPs are treated as Static (return False).
      - Domain names are resolved; if they map to multiple distinct IPs, treat as Dynamic.
      - If resolution fails or yields no IPs, treat as Dynamic (conservative).
    """
    try:
        if not host:
            return True
        if _is_ip_address(host):
            return False
        key = host.lower()
        if key in _dynamic_cache:
            return _dynamic_cache[key]
        host_ascii = _idna(host)
        # Resolve without specific port, prefer TCP info for consistency
        infos = socket.getaddrinfo(host_ascii, None, proto=socket.IPPROTO_TCP)
        ips: Set[str] = set()
        for _, _, _, _, sockaddr in infos:
            try:
                ip = sockaddr[0]
                if ip:
                    ips.add(ip)
            except Exception:
                continue
        # Heuristic decision
        result = True if len(ips) != 1 else False
        _dynamic_cache[key] = result
        return result
    except Exception:
        return True


def _get_country_code_for_host(host: str, timeout: int = 5) -> Optional[str]:
    try:
        if _is_ip_address(host):
            ip = host
        else:
            try:
                # Prefer IPv4 if available
                infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
                ip = None
                for fam, _, _, _, sockaddr in infos:
                    if fam == socket.AF_INET:
                        ip = sockaddr[0]
                        break
                if not ip and infos:
                    ip = infos[0][4][0]
            except Exception:
                ip = host
        url = f"http://ip-api.com/json/{ip}?fields=countryCode"
        with urlopen(url, timeout=timeout) as resp:
            data = resp.read(1024)
            obj = json.loads(data.decode('utf-8', errors='ignore') or '{}')
            cc = obj.get('countryCode')
            if isinstance(cc, str) and len(cc) == 2:
                return cc.upper()
    except Exception:
        return None
    return None


# ---------- Stage 2: Lightweight protocol probe ----------
_tls_ports = {443, 8443, 2053, 2083, 2087, 2096, 444, 10443}

def _is_tls_likely(uri: str, port: int) -> bool:
    lc = (uri or '').lower()
    if 'security=tls' in lc or 'tls=1' in lc or 'tls=true' in lc:
        return True
    if port in _tls_ports:
        return True
    return False


def quick_protocol_probe(uri: str, host: str, port: int, timeout_ms: int = PROBE_TIMEOUT_MS) -> bool:
    """Fast protocol-level validation.

    Currently performs a TLS handshake probe when the proxy looks TLS-based.
    If not TLS-likely, returns True to avoid false negatives.
    """
    try:
        if not host or not isinstance(port, int) or port < 1 or port > 65535:
            return False
        if not _is_tls_likely(uri, port):
            return True
        host_ascii = _idna(host)
        timeout_sec = max(0.1, min(10.0, timeout_ms / 1000.0))
        # Create TCP socket
        with socket.create_connection((host_ascii, port), timeout=timeout_sec) as raw_sock:
            ctx = ssl.create_default_context()
            # Do not fail on certificate issues; we only care about TLS capability
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            server_name = None if _is_ip_address(host_ascii) else host_ascii
            with ctx.wrap_socket(raw_sock, server_hostname=server_name) as ssock:
                # If handshake completes, it's good
                return True
    except Exception:
        return False


# ---------- Stage 3: V2Ray core validation (stub) ----------

def validate_with_v2ray_core(uri: str, timeout_s: int = 10) -> Optional[bool]:
    """Validate proxy by spinning up Xray and fetching via a local HTTP proxy.

    Returns:
      True  -> validated by core (actual HTTP(S) fetch succeeded)
      False -> core executed but fetch failed (treat as invalid)
      None  -> core not configured/available or unsupported URI
    """
    try:
        path = (V2RAY_CORE_PATH or '').strip()
        if not path or not os.path.exists(path):
            return None

        # Import here to avoid a hard dependency when Stage 3 is disabled
        try:
            from .v2ray import build_config_for_uri  # type: ignore
        except Exception:
            return None

        built = build_config_for_uri(uri)
        if not built:
            return None
        tag, cfg = built
        # Add a temporary HTTP inbound on a free port
        import socket as _sock
        import tempfile
        import time
        import json as _json

        http_port = None
        s = None
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.bind(('127.0.0.1', 0))
            http_port = s.getsockname()[1]
        except Exception:
            http_port = 10809
        finally:
            try:
                if s:
                    s.close()
            except Exception:
                pass

        try:
            inb = cfg.get('inbounds') or []
        except Exception:
            inb = []
        # Ensure list
        if not isinstance(inb, list):
            inb = []
        inb.append({
            'listen': '127.0.0.1',
            'port': int(http_port),
            'protocol': 'http',
            'settings': {}
        })
        cfg['inbounds'] = inb

        # Write temp config file
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        tmp_path = tmp.name
        try:
            tmp.write(_json.dumps(cfg).encode('utf-8'))
            tmp.flush()
        finally:
            tmp.close()

        # Start Xray
        creation = (subprocess.CREATE_NO_WINDOW if os.name == 'nt' and hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
        proc = subprocess.Popen([path, '-config', tmp_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creation)

        # Give it a brief moment to start
        start = time.time()
        time.sleep(0.25)

        # Prepare proxy opener
        try:
            from urllib.request import build_opener, ProxyHandler
        except Exception:
            build_opener = None
            ProxyHandler = None
        if build_opener is None or ProxyHandler is None:
            # Cannot construct proxy opener; abort and cleanup
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            return None

        # Try a small set of endpoints
        test_urls = [
            'https://www.google.com/generate_204',
            'https://cp.cloudflare.com/generate_204',
        ]
        ok = False
        # Time budget
        deadline = start + max(2.0, float(timeout_s))
        for url in test_urls:
            if time.time() >= deadline:
                break
            try:
                opener = build_opener(ProxyHandler({
                    'http': f'http://127.0.0.1:{http_port}',
                    'https': f'http://127.0.0.1:{http_port}',
                }))
                req = Request(url, headers={'User-Agent': USER_AGENT, 'Accept': '*/*'})
                rem = max(0.5, deadline - time.time())
                with opener.open(req, timeout=rem) as resp:
                    code = getattr(resp, 'status', None) or getattr(resp, 'code', None)
                    if isinstance(code, int) and code in (200, 204):
                        ok = True
                        break
            except Exception:
                continue

        # Cleanup
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            # If still alive, kill
            try:
                proc.wait(timeout=0.2)
            except Exception:
                if hasattr(proc, 'kill'):
                    proc.kill()
        except Exception:
            pass
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

        return True if ok else False
    except Exception:
        return None


# ------------------ Async and Batch Helpers ------------------
import asyncio

async def fetch_urls_async_batch(urls: List[str], concurrency: int = None, timeout: int = FETCH_TIMEOUT) -> Dict[str, Optional[str]]:
    """Fetch multiple URLs concurrently using aiohttp when available.
    Falls back to sequential urllib if aiohttp is not installed.
    Returns mapping url -> content (str) or None on failure.
    Uses a bounded worker-queue to avoid creating a task per URL for very large lists.
    Includes simple retries with exponential backoff.
    """
    results: Dict[str, Optional[str]] = {u: None for u in urls}
    if not urls:
        return results
    if concurrency is None:
        try:
            concurrency = int(os.environ.get('OPENRAY_FETCH_WORKERS', '0')) or int(FETCH_WORKERS)
        except Exception:
            concurrency = 16
    try:
        import aiohttp  # type: ignore
    except Exception as e:
        print(f"fail to import aiohttp: {e}")
        # Fallback: sequential (to avoid new threads here)
        for u in progress(urls, total=len(urls)):
            results[u] = fetch_url(u, timeout=timeout)
        return results

    # Read optional retry and size limits from env
    try:
        max_retries = int(os.environ.get('OPENRAY_FETCH_RETRIES', '2'))
    except Exception:
        max_retries = 2
    max_bytes = 10 * 1024 * 1024  # 10 MB hard cap

    client_timeout = aiohttp.ClientTimeout(total=max(1, int(timeout)))
    connector = aiohttp.TCPConnector(limit=max(1, int(concurrency)))

    import random  # local to avoid module import cost if not needed

    async def _fetch_one(session: "aiohttp.ClientSession", url: str) -> None:
        # retry with exponential backoff
        attempt = 0
        backoff = 0.4
        while True:
            try:
                headers = {'User-Agent': USER_AGENT, 'Accept': '*/*'}
                async with session.get(url, headers=headers, timeout=client_timeout) as resp:
                    # limit size to 10 MB
                    if resp.content_length and resp.content_length > max_bytes:
                        data = await resp.content.readexactly(max_bytes)
                    else:
                        data = await resp.content.read()
                    if len(data) > max_bytes:
                        data = data[:max_bytes]
                    results[url] = data.decode('utf-8', errors='ignore')
                    return
            except asyncio.IncompleteReadError as e:
                try:
                    partial = e.partial
                    results[url] = partial.decode('utf-8', errors='ignore') if partial else None
                    return
                except Exception:
                    pass
            except Exception as e:
                if attempt >= max_retries:
                    log(f"Async fetch failed: {url} -> {e}")
                    results[url] = None
                    return
                # backoff with jitter
                await asyncio.sleep(backoff + random.random() * 0.3)
                attempt += 1
                backoff *= 2.0

    # Bounded worker queue
    queue: "asyncio.Queue[str]" = asyncio.Queue()
    for u in urls:
        queue.put_nowait(u)

    done_q: "asyncio.Queue[int]" = asyncio.Queue()

    async def _worker(session: "aiohttp.ClientSession") -> None:
        while True:
            try:
                u = queue.get_nowait()
            except Exception:
                break
            try:
                await _fetch_one(session, u)
            finally:
                try:
                    queue.task_done()
                except Exception:
                    pass
                try:
                    done_q.put_nowait(1)
                except Exception:
                    pass

    async def _progress_consumer(total: int) -> None:
        # Advance a progress bar as each URL is processed
        for _ in progress(range(total), total=total):
            try:
                await done_q.get()
            finally:
                try:
                    done_q.task_done()
                except Exception:
                    pass

    async with aiohttp.ClientSession(connector=connector) as session:
        workers = [asyncio.create_task(_worker(session)) for _ in range(max(1, int(concurrency)))]
        p_task = asyncio.create_task(_progress_consumer(len(urls)))
        await asyncio.gather(*workers, return_exceptions=True)
        try:
            await done_q.join()
        except Exception:
            pass
        try:
            await p_task
        except Exception:
            pass
    return results


def ping_hosts_batch(hosts: List[str], timeout_ms: int = None) -> Set[str]:
    """Batch ping using fping if available; fallback to per-host ping_host.
    Returns a set of reachable hosts.
    """
    if not hosts:
        return set()
    uniq = list(dict.fromkeys([_idna(h) for h in hosts if h]))
    if timeout_ms is None:
        try:
            timeout_ms = int(PING_TIMEOUT_MS)
        except Exception:
            timeout_ms = 1000

    # Detect fping
    try:
        env_fp = os.environ.get('OPENRAY_FPING', '').strip()
    except Exception:
        env_fp = ''
    if env_fp and os.path.exists(env_fp):
        fping_path = env_fp
    else:
        fping_path = shutil.which('fping') or shutil.which('fping.exe')

    if fping_path:
        print(f"fping found at: {fping_path}")
        # Read tuning knobs from environment (optional)
        try:
            target_batch_secs = float(os.environ.get('OPENRAY_FPING_BATCH_SECS', '12'))
        except Exception:
            target_batch_secs = 12.0
        target_batch_secs = max(3.0, min(60.0, target_batch_secs))
        try:
            min_interval_ms = int(os.environ.get('OPENRAY_FPING_MIN_INTERVAL_MS', '20'))
        except Exception:
            min_interval_ms = 20
        min_interval_ms = max(10, min(200, int(min_interval_ms)))
        try:
            retries = int(os.environ.get('OPENRAY_FPING_RETRIES', '0'))
        except Exception:
            retries = 0
        retries = max(0, min(3, int(retries)))

        # Clamp timeout per probe
        timeout_ms_clamped = max(300, min(timeout_ms, 2000))  # 0.3s to 2s

        # Compute dynamic batch size (but cap at 300 for safety)
        budget_ms = int(target_batch_secs * 1000)
        est_overhead_ms = (retries + 1) * timeout_ms_clamped
        if budget_ms <= est_overhead_ms + 50:
            allowed_n = 50
        else:
            allowed_n = max(1, (budget_ms - est_overhead_ms) // max(1, min_interval_ms))

        batch_size = int(min(100, max(1, allowed_n), len(uniq)))  # Hard cap = 300
        all_alive: Set[str] = set()

        for i in range(0, len(uniq), batch_size):
            batch = uniq[i:i + batch_size]
            try:
                # Write hosts into a temporary file
                with tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8') as tf:
                    for h in batch:
                        tf.write(h + "\n")
                    tf_path = tf.name

                # Build fping command
                cmd = [
                    fping_path, '-a',
                    '-r', str(retries),
                    '-t', str(timeout_ms_clamped),
                    '-i', str(min_interval_ms),
                    '-f', tf_path
                ]

                # Estimate subprocess runtime
                est_secs = (len(batch) * min_interval_ms) / 1000.0 + ((retries + 1) * timeout_ms_clamped) / 1000.0
                subprocess_timeout = max(60.0, est_secs * 4.0)  # Always allow at least 60s

                print(f"[DEBUG] fping batch {i // batch_size + 1}/{(len(uniq)+batch_size-1)//batch_size}, "
                      f"hosts={len(batch)}, timeout={subprocess_timeout:.1f}s")

                creation = (
                    subprocess.CREATE_NO_WINDOW if os.name == 'nt' and hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                )
                res = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=subprocess_timeout,
                    creationflags=creation,
                    encoding='utf-8',
                    errors='ignore'
                )

                try:
                    os.unlink(tf_path)
                except Exception as e:
                    print(f"[WARN] Could not delete temp file {tf_path}: {e}")

                if res.returncode in (0, 1):
                    for line in (res.stdout or '').splitlines():
                        h = line.strip()
                        if h:
                            all_alive.add(h)
                else:
                    print(f"[ERROR] fping batch {i // batch_size + 1} exited with code {res.returncode}")
                    if hasattr(res, 'stderr') and res.stderr:
                        print(f"[stderr] {res.stderr.strip()}")

            except Exception as e:
                try:
                    os.unlink(tf_path)
                except Exception:
                    pass
                print(f"[EXCEPTION] fping batch {i // batch_size + 1} failed: {e}")
                continue

        if all_alive:
            return all_alive
        else:
            print("[WARN] fping batches produced no results, falling back to individual ping")

    # Fallback: per-host ping
    alive: Set[str] = set()
    for h in progress(uniq, total=len(uniq)):
        try:
            if ping_host(h):
                alive.add(h)
        except Exception:
            continue
    return alive


def get_country_codes_batch(hosts: List[str], timeout: int = 5, batch_size: int = 100) -> Dict[str, Optional[str]]:
    """Resolve country codes for many hosts using ip-api.com batch endpoint.
    Fallback to per-host _get_country_code_for_host on errors.
    Returns host -> country code (2 letters) or None.
    """
    result: Dict[str, Optional[str]] = {h: None for h in hosts}
    if not hosts:
        return result

    # Resolve to IPs first
    ip_to_hosts: Dict[str, List[str]] = {}
    for host in hosts:
        if not host:
            continue
        try:
            if _is_ip_address(host):
                ip = host
            else:
                infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
                ip = None
                for fam, _, _, _, sockaddr in infos:
                    if fam == socket.AF_INET:
                        ip = sockaddr[0]
                        break
                if not ip and infos:
                    ip = infos[0][4][0]
            if ip:
                ip_to_hosts.setdefault(ip, []).append(host)
        except Exception:
            # leave as None
            pass

    ips = list(ip_to_hosts.keys())
    if not ips:
        # Fallback to per-host method
        for h in hosts:
            try:
                result[h] = _get_country_code_for_host(h, timeout=timeout)
            except Exception:
                result[h] = None
        return result

    # Query in batches
    try:
        endpoint = f"http://ip-api.com/batch?fields=countryCode"
        headers = {'Content-Type': 'application/json'}
        for i in range(0, len(ips), max(1, int(batch_size))):
            chunk = ips[i:i+batch_size]
            body = json.dumps([{'query': ip} for ip in chunk]).encode('utf-8')
            req = Request(endpoint, data=body, headers=headers, method='POST')
            with urlopen(req, timeout=timeout) as resp:
                data = resp.read()
                arr = json.loads(data.decode('utf-8', errors='ignore') or '[]')
                if isinstance(arr, list):
                    for idx, obj in enumerate(arr):
                        try:
                            ip = chunk[idx]
                        except Exception:
                            continue
                        cc = None
                        if isinstance(obj, dict):
                            c = obj.get('countryCode')
                            if isinstance(c, str) and len(c) == 2:
                                cc = c.upper()
                        if ip in ip_to_hosts:
                            for h in ip_to_hosts[ip]:
                                result[h] = cc
    except Exception as e:
        # Fallback to per-host
        for h in hosts:
            try:
                result[h] = _get_country_code_for_host(h, timeout=timeout)
            except Exception:
                result[h] = None
    return result


def check_one_sync(uri: str, host: str) -> Tuple[str, str, bool]:
    """Synchronous checker used for multiprocessing. Mirrors main.check_one logic."""
    try:
        if not ping_host(host):
            return (uri, host, False)
        scheme = (uri.split('://', 1)[0] or '').lower()
        if scheme in ('vmess', 'vless', 'trojan', 'ss', 'ssr'):
            try:
                from .parsing import extract_port  # local import to avoid cycles at module load
                p = extract_port(uri)
            except Exception:
                p = None
            if p is not None:
                ok2 = connect_host_port(host, int(p))
                if ok2 and int(ENABLE_STAGE2) == 1:
                    ok2 = quick_protocol_probe(uri, host, int(p))
                return (uri, host, ok2)
        return (uri, host, True)
    except Exception:
        return (uri, host, False)


def check_pair(item: Tuple[str, str]) -> Tuple[str, str, bool]:
    """Helper for multiprocessing.imap_unordered: accepts (uri, host)."""
    try:
        uri, host = item
    except Exception:
        return ("", "", False)
    return check_one_sync(uri, host)
