from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import ssl
from typing import List, Optional
from urllib.request import Request, urlopen

from .constants import USER_AGENT, PING_TIMEOUT_MS, TCP_FALLBACK_PORTS, FETCH_TIMEOUT, CONNECT_TIMEOUT_MS, PROBE_TIMEOUT_MS, V2RAY_CORE_PATH
from .common import log


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
