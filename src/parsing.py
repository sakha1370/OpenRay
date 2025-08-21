from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, parse_qs, unquote, quote

from .common import safe_b64decode_to_bytes

# Regex and schemes
SCHEMES = [
    'vmess', 'vless', 'trojan', 'ss', 'ssr', 'hysteria', 'hysteria2', 'hy2', 'tuic', 'juicity'
]
URI_REGEX = re.compile(r'(?i)\b(?:' + '|'.join(map(re.escape, SCHEMES)) + r')://[^\s<>"\']+')
HOSTPORT_REGEX = re.compile(r'([A-Za-z0-9_.\-\[\]:]+):(\d{2,5})')


def _idna(host: str) -> str:
    try:
        return host.encode('idna').decode('ascii')
    except Exception:
        return host


def parse_source_line(line: str) -> Tuple[str, Dict[str, bool]]:
    """Return (url, flags). Flags currently supports {'base64': bool}."""
    parts = [p for p in line.split(',') if p]
    if not parts:
        return '', {}
    url = parts[0].strip()
    flags = {p.strip().lower(): True for p in parts[1:]}
    return url, {'base64': flags.get('base64', False)}


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


def extract_uris(text: str) -> List[str]:
    if not text:
        return []
    found = set()
    uris: List[str] = []
    for m in URI_REGEX.finditer(text):
        uri = m.group(0)
        # strip trailing punctuation that often follows links
        uri = uri.rstrip(')>,;"\'\n\r')
        if uri not in found:
            found.add(uri)
            uris.append(uri)
    return uris


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


def port_from_vmess(uri: str) -> Optional[int]:
    try:
        payload_b64 = uri.split('://', 1)[1]
        b = safe_b64decode_to_bytes(payload_b64)
        if not b:
            return None
        obj = json.loads(b.decode('utf-8', errors='ignore') or '{}')
        port = obj.get('port') or obj.get('portNumber')
        if isinstance(port, str) and port.isdigit():
            n = int(port)
            return n if 1 <= n <= 65535 else None
        if isinstance(port, int):
            return port if 1 <= port <= 65535 else None
    except Exception:
        return None
    return None


def port_from_ss(uri: str) -> Optional[int]:
    try:
        payload = uri.split('://', 1)[1]
        main_part = payload.split('#', 1)[0]
        main_part = main_part.split('?', 1)[0]
        b = safe_b64decode_to_bytes(main_part)
        text = None
        if b:
            text = b.decode('utf-8', errors='ignore')
        else:
            p = urlsplit(uri)
            if p.port:
                return int(p.port)
        if text:
            right = text.rsplit('@', 1)[-1] if '@' in text else text
            right = right.split('?', 1)[0]
            # IPv6 bracket handling already done for host; for port, split last ':'
            if right.startswith('['):
                # [ipv6]:port or [ipv6]
                end = right.find(']')
                if end != -1:
                    rest = right[end + 1:]
                    if rest.startswith(':'):
                        rest = rest[1:]
                        if rest.split(':')[0].isdigit():
                            n = int(rest.split(':')[0])
                            return n if 1 <= n <= 65535 else None
                    return None
            if ':' in right:
                port_str = right.split(':', 1)[1]
                if port_str and port_str.split(':')[0].isdigit():
                    n = int(port_str.split(':')[0])
                    return n if 1 <= n <= 65535 else None
    except Exception:
        return None
    return None


def port_from_ssr(uri: str) -> Optional[int]:
    try:
        payload = uri.split('://', 1)[1]
        b = safe_b64decode_to_bytes(payload)
        if not b:
            return None
        text = b.decode('utf-8', errors='ignore')
        first = text.split('/', 1)[0]
        parts = first.split(':')
        if len(parts) >= 2 and parts[1].isdigit():
            n = int(parts[1])
            return n if 1 <= n <= 65535 else None
    except Exception:
        return None
    return None


def port_from_generic(uri: str) -> Optional[int]:
    try:
        p = urlsplit(uri)
        try:
            if p.port:
                return int(p.port)
        except Exception:
            pass
        # some hysteria2 links embed host:port in query server= or sv=
        qs = parse_qs(p.query)
        server_vals = qs.get('server') or qs.get('sv')
        if server_vals:
            m = HOSTPORT_REGEX.search(server_vals[0])
            if m:
                port_str = m.group(2)
                if port_str.isdigit():
                    n = int(port_str)
                    return n if 1 <= n <= 65535 else None
        # fallback: scan anywhere
        m2 = HOSTPORT_REGEX.search(uri)
        if m2:
            port_str = m2.group(2)
            if port_str.isdigit():
                n = int(port_str)
                return n if 1 <= n <= 65535 else None
    except Exception:
        return None
    return None


def extract_port(uri: str) -> Optional[int]:
    scheme = uri.split('://', 1)[0].lower()
    if scheme == 'vmess':
        return port_from_vmess(uri)
    if scheme == 'ss':
        return port_from_ss(uri)
    if scheme == 'ssr':
        return port_from_ssr(uri)
    return port_from_generic(uri)


def is_ip_address(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


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
                    import base64 as _b64
                    new_b64 = _b64.b64encode(new_json.encode('utf-8')).decode('ascii')
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
