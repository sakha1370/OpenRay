#!/usr/bin/env python3
"""
Proxy Collector and Availability Checker (Windows)

Purpose:
- Read a list of source URLs from sources.txt.
- Each URL returns content containing multiple proxy links (vmess, vless, trojan, ss, ssr, hysteria/hysteria2/hy2, tuic, juicity, etc.).
- Some sources return base64-encoded subscription content. The script supports per-source hints (",base64,") and auto-detection.
- Extract all proxies from fetched contents.
- For each NEW proxy (not seen in previous runs), extract its target host and ping it to test reachability.
- Save only available proxies to output\\available.txt.
- Persist tested proxies' hashes in .state\\tested.txt to avoid retesting in subsequent hourly runs.

How to run hourly on Windows:
- Run once manually:  python proxy_checker.py
- Schedule hourly: Use Windows Task Scheduler to create a basic task that runs the above command every hour. Ensure the Start in directory is set to this repository folder.

Notes:
- Pinging is not a perfect availability test for application-level proxies, but it's a fast heuristic. It reduces load by only pinging hosts.
- This script uses only the Python standard library.
"""
from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import io
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
try:
    from tqdm import tqdm as _tqdm  # type: ignore
    def progress(iterable, total=None):
        return _tqdm(iterable, total=total)
except Exception:
    def progress(iterable, total=None):
        return iterable
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit, parse_qs, unquote, urlparse, quote
from urllib.request import Request, urlopen

# ------------------- Configuration -------------------
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.path.join(REPO_ROOT, '.state')
OUTPUT_DIR = os.path.join(REPO_ROOT, 'output')
TESTED_FILE = os.path.join(STATE_DIR, 'tested.txt')  # stores SHA1 per tested proxy URI
AVAILABLE_FILE = os.path.join(OUTPUT_DIR, 'all_valid_proxies.txt')
STREAKS_FILE = os.path.join(STATE_DIR, 'streaks.json')
LAST24H_FILE = os.path.join(OUTPUT_DIR, 'proxies_last24h.txt')
KIND_DIR = os.path.join(OUTPUT_DIR, 'kind')
COUNTERY_DIR = os.path.join(OUTPUT_DIR, 'countery')

# Helpers to read environment configuration with sane bounds

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

# Tuning (overridable by environment)
FETCH_TIMEOUT = _env_int('OPENRAY_FETCH_TIMEOUT', 20, 1, 120)  # seconds per source fetch
FETCH_WORKERS = _env_int('OPENRAY_FETCH_WORKERS', 24, 1, 256)
PING_WORKERS = _env_int('OPENRAY_PING_WORKERS', 64, 1, 1024)
PING_TIMEOUT_MS = _env_int('OPENRAY_PING_TIMEOUT_MS', 1000, 100, 10000)  # per ping attempt
# Ports to try for TCP connectivity fallback (when ICMP ping is blocked, e.g., in CI)
TCP_FALLBACK_PORTS: List[int] = [80, 443, 8080, 8443, 2052, 2082, 2086, 2095]
USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/122.0 Safari/537.36'
)

# Streak selection parameters (overridable)
CONSECUTIVE_REQUIRED = _env_int('OPENRAY_STREAK_REQUIRED', 5, 1, 100)
LAST24H_WINDOW_SECONDS = _env_int('OPENRAY_LAST24H_SECONDS', 24 * 3600, 60, 7 * 24 * 3600)

# Regex to find proxy URIs
SCHEMES = [
    'vmess', 'vless', 'trojan', 'ss', 'ssr', 'hysteria', 'hysteria2', 'hy2', 'tuic', 'juicity'
]
URI_REGEX = re.compile(r'(?i)\b(?:' + '|'.join(map(re.escape, SCHEMES)) + r')://[^\s<>"\']+')

# Fallback regex for host:port within strings
HOSTPORT_REGEX = re.compile(r'([A-Za-z0-9_.\-\[\]:]+):(\d{2,5})')

_print_lock = threading.Lock()

def log(msg: str) -> None:
    with _print_lock:
        print(msg, flush=True)

# ------------------- Utilities -------------------

def ensure_dirs() -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def read_lines(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.rstrip('\r\n') for line in f]


def append_lines(path: str, lines: Iterable[str]) -> None:
    if not lines:
        return
    with open(path, 'a', encoding='utf-8', errors='ignore') as f:
        for line in lines:
            f.write(line)
            if not line.endswith('\n'):
                f.write('\n')


def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode('utf-8', errors='ignore')).hexdigest()


def safe_b64decode_to_bytes(s: str) -> Optional[bytes]:
    """Try to base64-decode a string with leniency (padding, URL-safe). Returns None on failure."""
    if not s:
        return None
    # Remove whitespace
    compact = ''.join(s.split())
    # Convert URL-safe variants
    compact = compact.replace('-', '+').replace('_', '/')
    # Pad
    padding = (-len(compact)) % 4
    compact += '=' * padding
    try:
        return base64.b64decode(compact, validate=False)
    except Exception:
        return None


def maybe_decode_subscription(content: str, hinted_base64: bool = False) -> str:
    """Decode subscription content when required.

    Logic:
    - If hinted_base64 is True, attempt decode once; if result contains URIs, return lines; else fallback to original.
    - Else, if original content has no URI scheme patterns, try to base64-decode once or twice, stopping when URIs are found.
    """
    def contains_uri(txt: str) -> bool:
        return URI_REGEX.search(txt) is not None

    if hinted_base64:
        b = safe_b64decode_to_bytes(content)
        if b:
            text = b.decode('utf-8', errors='ignore')
            if contains_uri(text):
                return text
            # sometimes the decoded content still is base64 layer
            b2 = safe_b64decode_to_bytes(text)
            if b2:
                t2 = b2.decode('utf-8', errors='ignore')
                if contains_uri(t2):
                    return t2
        return content

    # Auto-detect: if already contains URIs, return as-is
    if contains_uri(content):
        return content

    # Try base64 decode once or twice
    b = safe_b64decode_to_bytes(content)
    if b:
        text = b.decode('utf-8', errors='ignore')
        if contains_uri(text):
            return text
        b2 = safe_b64decode_to_bytes(text)
        if b2:
            t2 = b2.decode('utf-8', errors='ignore')
            if contains_uri(t2):
                return t2
    return content


# ------------------- Fetching -------------------

def parse_source_line(line: str) -> Tuple[str, Dict[str, bool]]:
    """Return (url, flags). Flags currently supports {'base64': bool}.
    Lines may look like: 'https://example/path,base64,' or just URL.
    """
    parts = [p for p in line.split(',') if p]
    if not parts:
        return '', {}
    url = parts[0].strip()
    flags = {p.strip().lower(): True for p in parts[1:]}
    return url, {'base64': flags.get('base64', False)}


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


# ------------------- Extraction -------------------

def extract_uris(text: str) -> List[str]:
    if not text:
        return []
    found = set()
    uris = []
    for m in URI_REGEX.finditer(text):
        uri = m.group(0)
        # strip trailing punctuation that often follows links
        uri = uri.rstrip(')>,;\"\'\n\r')
        if uri not in found:
            found.add(uri)
            uris.append(uri)
    return uris


# ------------------- Host parsing -------------------

def _split_netloc_for_host(netloc: str) -> Optional[str]:
    # Remove userinfo if present
    if '@' in netloc:
        netloc = netloc.rsplit('@', 1)[-1]
    # If IPv6 in brackets
    if netloc.startswith('['):
        end = netloc.find(']')
        if end != -1:
            host = netloc[1:end]
            return host
    # Else split by colon for host:port
    if ':' in netloc:
        return netloc.split(':', 1)[0]
    return netloc or None


def _idna(host: str) -> str:
    try:
        return host.encode('idna').decode('ascii')
    except Exception:
        return host


def host_from_vmess(uri: str) -> Optional[str]:
    # vmess://<base64-json>
    try:
        payload_b64 = uri.split('://', 1)[1]
        b = safe_b64decode_to_bytes(payload_b64)
        if not b:
            return None
        obj = json.loads(b.decode('utf-8', errors='ignore') or '{}')
        host = obj.get('add') or obj.get('address') or obj.get('host')
        if isinstance(host, str) and host:
            return _idna(host.strip())
    except Exception:
        return None
    return None


def host_from_ss(uri: str) -> Optional[str]:
    # ss:// can be either base64(method:pass@host:port) or method:pass@host:port directly
    try:
        payload = uri.split('://', 1)[1]
        # If it looks like base64 up to a possible '#'
        main_part = payload.split('#', 1)[0]
        # strip plugin/query if present
        main_part = main_part.split('?', 1)[0]
        # Sometimes when it's not base64, urlparse can handle directly
        b = safe_b64decode_to_bytes(main_part)
        text = None
        if b:
            text = b.decode('utf-8', errors='ignore')
        else:
            # Not base64, try urlparse on full URI
            p = urlsplit(uri)
            host = p.hostname
            if host:
                return _idna(host)
        # Now parse method:pass@host:port
        if text:
            if '@' in text:
                right = text.rsplit('@', 1)[-1]
            else:
                # Some forms may be host:port (no creds)
                right = text
            # Remove plugin suffix if any
            right = right.split('?')[0]
            # IPv6 bracket handling
            if right.startswith('['):
                end = right.find(']')
                if end != -1:
                    return _idna(right[1:end])
            if ':' in right:
                return _idna(right.split(':', 1)[0])
            return _idna(right)
    except Exception:
        return None
    return None


def host_from_ssr(uri: str) -> Optional[str]:
    # ssr://base64(host:port:protocol:method:obfs:password_base64/?params)
    try:
        payload = uri.split('://', 1)[1]
        b = safe_b64decode_to_bytes(payload)
        if not b:
            return None
        text = b.decode('utf-8', errors='ignore')
        first = text.split('/', 1)[0]
        parts = first.split(':')
        if len(parts) >= 2:
            host = parts[0]
            return _idna(host)
    except Exception:
        return None
    return None


def host_from_generic(uri: str) -> Optional[str]:
    try:
        p = urlsplit(uri)
        host = p.hostname
        if host:
            return _idna(host)
        # some hysteria2 links embed host in query (server=)
        qs = parse_qs(p.query)
        server_vals = qs.get('server') or qs.get('sv')
        if server_vals:
            # server can be host:port
            m = HOSTPORT_REGEX.search(server_vals[0])
            if m:
                return _idna(m.group(1))
        # fallback: find host:port anywhere in the uri
        m = HOSTPORT_REGEX.search(uri)
        if m:
            return _idna(m.group(1))
    except Exception:
        return None
    return None


def extract_host(uri: str) -> Optional[str]:
    scheme = uri.split('://', 1)[0].lower()
    if scheme == 'vmess':
        return host_from_vmess(uri)
    if scheme == 'ss':
        return host_from_ss(uri)
    if scheme == 'ssr':
        return host_from_ssr(uri)
    # others via generic parsing
    return host_from_generic(uri)


# ------------------- Ping check -------------------

def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def ping_host(host: str) -> bool:
    """Check host reachability.

    Prefers ICMP ping (fast) when available. In restricted environments (e.g., GitHub Actions),
    ICMP may be blocked; in that case or on failure, fall back to a short TCP connect
    attempt to a small set of common ports.
    """
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


# ------------------- Remark formatting -------------------

def _country_flag(cc: Optional[str]) -> str:
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "🌐"
    cc = cc.upper()
    try:
        return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)
    except Exception:
        return "🌐"


def _get_country_code_for_host(host: str, timeout: int = 5) -> Optional[str]:
    try:
        if is_ip_address(host):
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


def _set_remark(uri: str, remark: str) -> str:
    scheme = uri.split('://', 1)[0].lower()
    if scheme == 'vmess':
        try:
            payload_b64 = uri.split('://', 1)[1]
            b = safe_b64decode_to_bytes(payload_b64)
            if b:
                obj = json.loads(b.decode('utf-8', errors='ignore') or '{}')
                if isinstance(obj, dict):
                    obj['ps'] = remark
                    new_json = json.dumps(obj, separators=(',', ':'), ensure_ascii=False)
                    new_b64 = base64.b64encode(new_json.encode('utf-8')).decode('ascii')
                    return 'vmess://' + new_b64
        except Exception:
            pass
        return uri
    # For non-vmess, set URL fragment
    try:
        base = uri.split('#', 1)[0]
        return base + '#' + quote(remark, safe='')
    except Exception:
        if '#' in uri:
            uri = uri.split('#', 1)[0]
        return uri + '#' + quote(remark, safe='')


def _extract_our_cc_and_num_from_uri(uri: str) -> Optional[Tuple[str, int]]:
    scheme = uri.split('://', 1)[0].lower()
    tag = None
    if scheme == 'vmess':
        try:
            payload_b64 = uri.split('://', 1)[1]
            b = safe_b64decode_to_bytes(payload_b64)
            if b:
                obj = json.loads(b.decode('utf-8', errors='ignore') or '{}')
                ps = obj.get('ps')
                if isinstance(ps, str):
                    tag = ps
        except Exception:
            tag = None
    else:
        try:
            frag = urlsplit(uri).fragment
            if frag:
                tag = unquote(frag)
        except Exception:
            tag = None
    if not tag:
        return None
    m = re.match(r'^\[OpenRay\]\s+.+\s+([A-Z]{2})-(\d+)$', tag)
    if not m:
        return None
    try:
        cc = m.group(1)
        num = int(m.group(2))
        return cc, num
    except Exception:
        return None


def _build_country_counters(existing: Iterable[str]) -> Dict[str, int]:
    counters: Dict[str, int] = {}
    for line in existing:
        parsed = _extract_our_cc_and_num_from_uri(line)
        if parsed:
            cc, num = parsed
            prev = counters.get(cc, 0)
            if num > prev:
                counters[cc] = num
    return counters


# ------------------- Grouping -------------------

def _write_text_file_atomic(path: str, lines: List[str]) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except Exception:
        pass
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8', errors='ignore') as f:
        for ln in lines:
            f.write(ln)
            f.write('\n')
    os.replace(tmp, path)


def write_grouped_outputs() -> None:
    """Generate per-kind and per-country files from AVAILABLE_FILE.

    - output\\kind\\<scheme>.txt
    - output\\countery\\<CC>.txt (uses existing remark format; falls back to XX)
    """
    try:
        lines = [ln.strip() for ln in read_lines(AVAILABLE_FILE) if ln.strip()]
        if not lines:
            return

        # Group by scheme (kind)
        kind_order: List[str] = []
        kind_groups: Dict[str, List[str]] = {}
        for s in lines:
            scheme = s.split('://', 1)[0].lower() if '://' in s else 'unknown'
            if not scheme:
                scheme = 'unknown'
            if scheme not in kind_groups:
                kind_groups[scheme] = []
                kind_order.append(scheme)
            kind_groups[scheme].append(s)

        os.makedirs(KIND_DIR, exist_ok=True)
        produced_kind: Set[str] = set()
        for scheme in kind_order:
            out_path = os.path.join(KIND_DIR, f'{scheme}.txt')
            _write_text_file_atomic(out_path, kind_groups[scheme])
            produced_kind.add(f'{scheme}.txt')
        # Remove stale kind txt files
        try:
            for name in os.listdir(KIND_DIR):
                p = os.path.join(KIND_DIR, name)
                if os.path.isfile(p) and name.lower().endswith('.txt') and name not in produced_kind:
                    try:
                        os.remove(p)
                    except Exception:
                        pass
        except Exception:
            pass

        # Group by country code (from our remark); fallback to XX
        cc_order: List[str] = []
        cc_groups: Dict[str, List[str]] = {}
        for s in lines:
            parsed = _extract_our_cc_and_num_from_uri(s)
            cc = parsed[0] if parsed else 'XX'
            if cc not in cc_groups:
                cc_groups[cc] = []
                cc_order.append(cc)
            cc_groups[cc].append(s)

        os.makedirs(COUNTERY_DIR, exist_ok=True)
        produced_cc: Set[str] = set()
        for cc in cc_order:
            out_path = os.path.join(COUNTERY_DIR, f'{cc}.txt')
            _write_text_file_atomic(out_path, cc_groups[cc])
            produced_cc.add(f'{cc}.txt')
        # Remove stale country txt files
        try:
            for name in os.listdir(COUNTERY_DIR):
                p = os.path.join(COUNTERY_DIR, name)
                if os.path.isfile(p) and name.lower().endswith('.txt') and name not in produced_cc:
                    try:
                        os.remove(p)
                    except Exception:
                        pass
        except Exception:
            pass

    except Exception as e:
        log(f"Writing grouped outputs failed: {e}")

def regroup_available_by_country() -> None:
    try:
        lines = read_lines(AVAILABLE_FILE)
        if not lines:
            return
        order: List[str] = []
        groups: Dict[str, List[str]] = {}
        for line in lines:
            s = line.strip()
            if not s:
                continue
            parsed = _extract_our_cc_and_num_from_uri(s)
            cc = parsed[0] if parsed else 'XX'
            if cc not in groups:
                groups[cc] = []
                order.append(cc)
            groups[cc].append(s)
        tmp_path = AVAILABLE_FILE + '.tmp'
        with open(tmp_path, 'w', encoding='utf-8', errors='ignore') as f:
            for cc in order:
                for item in groups[cc]:
                    f.write(item)
                    f.write('\n')
        os.replace(tmp_path, AVAILABLE_FILE)
        log(f"Regrouped available proxies by country into {len(order)} groups")
    except Exception as e:
        log(f"Regroup failed: {e}")

# ------------------- Main processing -------------------

def load_tested_hashes() -> Set[str]:
    tested: Set[str] = set()
    for line in read_lines(TESTED_FILE):
        h = line.strip()
        if h:
            tested.add(h)
    return tested


def load_existing_available() -> Set[str]:
    existing: Set[str] = set()
    for line in read_lines(AVAILABLE_FILE):
        s = line.strip()
        if s:
            existing.add(s)
    return existing


# ------------------- Streaks persistence -------------------

def load_streaks() -> Dict[str, Dict[str, int]]:
    try:
        if not os.path.exists(STREAKS_FILE):
            return {}
        with open(STREAKS_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
            if isinstance(data, dict):
                # Ensure numeric fields are ints
                cleaned: Dict[str, Dict[str, int]] = {}
                for host, obj in data.items():
                    if not isinstance(obj, dict):
                        continue
                    streak = int(obj.get('streak', 0))
                    last_test = int(obj.get('last_test', 0))
                    last_success = int(obj.get('last_success', 0))
                    cleaned[host] = {'streak': streak, 'last_test': last_test, 'last_success': last_success}
                return cleaned
    except Exception:
        pass
    return {}


def save_streaks(streaks: Dict[str, Dict[str, int]]) -> None:
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = STREAKS_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8', errors='ignore') as f:
            json.dump(streaks, f, ensure_ascii=False)
        os.replace(tmp, STREAKS_FILE)
    except Exception:
        # best-effort; ignore
        pass


def main() -> int:
    ensure_dirs()
    if not os.path.exists(SOURCES_FILE):
        log(f"Sources file not found: {SOURCES_FILE}")
        return 1

    source_lines = [ln.strip() for ln in read_lines(SOURCES_FILE) if ln.strip() and not ln.strip().startswith('#')]
    log(f"Loaded {len(source_lines)} sources")

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
            host_map_existing = {u: extract_host(u) for u in existing_lines}
            items = [(u, h) for u, h in host_map_existing.items() if h]
            # initialize to False for tested hosts
            for _, h in items:
                if h not in host_success_run:
                    host_success_run[h] = False
            def check_existing(item: Tuple[str, str]) -> Optional[str]:
                u, h = item
                try:
                    return u if ping_host(h) else None
                except Exception:
                    return None
            with concurrent.futures.ThreadPoolExecutor(max_workers=PING_WORKERS) as pool:
                for res in progress(pool.map(check_existing, items), total=len(items)):
                    if res is not None:
                        alive.append(res)
                        h = host_map_existing.get(res)
                        if h:
                            host_success_run[h] = True
            if len(alive) != len(existing_lines):
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
            ok = ping_host(host)
            return (uri, host, ok)
        except Exception:
            return (uri, host, False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=PING_WORKERS) as pool:
        for uri, host, ok in progress(pool.map(check_one, to_test), total=len(to_test)):
            # Mark host as tested this run
            if host not in host_success_run:
                host_success_run[host] = False
            if ok:
                host_success_run[host] = True
                available_to_add.append(uri)

    log(f"Available proxies found this run (ping ok): {len(available_to_add)}")

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

    # Persist tested hashes (append all newly tested regardless of success)
    append_lines(TESTED_FILE, new_hashes)
    log(f"Recorded {len(new_hashes)} newly tested proxies to {TESTED_FILE}")

    # Update streaks based on this run's host successes
    try:
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

    # Build proxies_last24h.txt: proxies whose host passed {CONSECUTIVE_REQUIRED} consecutive tests within last 24h and are alive now
    try:
        now_ts2 = int(time.time())
        lines = [ln.strip() for ln in read_lines(AVAILABLE_FILE) if ln.strip()]
        winners: List[str] = []
        cutoff = now_ts2 - int(LAST24H_WINDOW_SECONDS)
        for u in lines:
            h = extract_host(u)
            if not h:
                continue
            rec = streaks.get(h)
            if not rec:
                continue
            if int(rec.get('streak', 0)) >= int(CONSECUTIVE_REQUIRED) and int(rec.get('last_success', 0)) >= cutoff and host_success_run.get(h, False):
                winners.append(u)
        tmp_out = LAST24H_FILE + '.tmp'
        with open(tmp_out, 'w', encoding='utf-8', errors='ignore') as f:
            for u in winners:
                f.write(u)
                f.write('\n')
        os.replace(tmp_out, LAST24H_FILE)
        log(f"Wrote {len(winners)} proxies to {LAST24H_FILE}")
    except Exception as e:
        log(f"Writing {LAST24H_FILE} failed: {e}")

    # Generate grouped outputs by kind and country
    try:
        write_grouped_outputs()
    except Exception as e:
        log(f"Grouped outputs step failed: {e}")

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
