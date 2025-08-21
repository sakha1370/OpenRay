from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, parse_qs, unquote

from .common import safe_b64decode_to_bytes, sha1_hex
from .constants import OUTPUT_DIR


def _ensure_dir(path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass


def _sanitize_filename(name: str) -> str:
    # Remove unsafe characters
    name = re.sub(r"[\\/:*?\"<>|]", "_", name)
    name = re.sub(r"\s+", "_", name).strip("._ ")
    if not name:
        name = "config"
    return name[:120]


def _parse_vmess(uri: str) -> Optional[Dict]:
    # vmess://<base64-json>
    try:
        b64 = uri.split('://', 1)[1]
        raw = safe_b64decode_to_bytes(b64)
        if not raw:
            return None
        obj = json.loads(raw.decode('utf-8', errors='ignore') or '{}')
        if not isinstance(obj, dict):
            return None
        return obj
    except Exception:
        return None


def _stream_settings_from_query(parsed, q: Dict[str, List[str]], default_sni: Optional[str]) -> Dict:
    # Build Xray streamSettings for common transports and security
    st: Dict = {}

    typ = (q.get('type', [''])[0] or q.get('network', [''])[0] or '').lower()
    if typ == 'ws':
        path = q.get('path', [''])[0]
        if path:
            path = unquote(path)
        host_header = q.get('host', [''])[0]
        st['network'] = 'ws'
        st['wsSettings'] = {
            'path': path or '/',
            'headers': ({'Host': host_header} if host_header else {})
        }
    elif typ == 'grpc' or typ == 'gun':
        # Minimal gRPC support (a.k.a gun in some links)
        service = q.get('serviceName', [''])[0] or q.get('service', [''])[0]
        st['network'] = 'grpc'
        st['grpcSettings'] = {'serviceName': service} if service else {'serviceName': ''}

    # Security
    sec = (q.get('security', [''])[0] or '').lower()
    sni = q.get('sni', [''])[0] or default_sni
    alpn = q.get('alpn', [])
    fp = q.get('fp', [''])[0] or q.get('fingerprint', [''])[0]

    if sec == 'tls':
        st['security'] = 'tls'
        tls = {'serverName': sni} if sni else {}
        if alpn:
            # alpn may be comma-separated or repeated
            val = alpn[0]
            if isinstance(val, str) and ',' in val:
                tls['alpn'] = [x.strip() for x in val.split(',') if x.strip()]
            else:
                tls['alpn'] = [x for x in alpn if x]
        if fp:
            tls['fingerprint'] = fp
        if tls:
            st['tlsSettings'] = tls
    elif sec == 'reality':
        st['security'] = 'reality'
        reality: Dict = {}
        if sni:
            reality['serverName'] = sni
        pbk = q.get('pbk', [''])[0]
        sid = q.get('sid', [''])[0]
        spx = q.get('spx', [''])[0]
        if pbk:
            reality['publicKey'] = pbk
        if sid:
            reality['shortId'] = sid
        if spx:
            reality['spiderX'] = spx
        if fp:
            reality['fingerprint'] = fp
        # Default show=false to mimic V2RayN typical behavior
        reality['show'] = False
        st['realitySettings'] = reality

    return st


def build_vless_config(uri: str) -> Optional[Tuple[str, Dict]]:
    try:
        p = urlsplit(uri)
        if p.scheme.lower() != 'vless':
            return None
        user = unquote(p.username or '')
        host = p.hostname
        port = p.port or 443
        if not user or not host or not port:
            return None
        q = parse_qs(p.query or '')
        flow = q.get('flow', [''])[0]
        remark = unquote(p.fragment or '')
        st = _stream_settings_from_query(p, q, q.get('sni', [''])[0])
        outbound = {
            'protocol': 'vless',
            'settings': {
                'vnext': [{
                    'address': host,
                    'port': port,
                    'users': [{
                        'id': user,
                        'encryption': (q.get('encryption', ['none'])[0] or 'none'),
                        'flow': flow
                    }]
                }]
            },
            'streamSettings': st
        }
        cfg = {
            'log': {'loglevel': 'warning'},
            'inbounds': [{
                'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
                'settings': {'udp': True}
            }],
            'outbounds': [outbound]
        }
        tag = remark or f"VLESS_{host}_{port}"
        return (tag, cfg)
    except Exception:
        return None


def build_vmess_config(uri: str) -> Optional[Tuple[str, Dict]]:
    try:
        obj = _parse_vmess(uri)
        if not obj:
            return None
        host = obj.get('add') or obj.get('host')
        port = int(obj.get('port') or 443)
        uuid = obj.get('id')
        aid = int(obj.get('aid') or obj.get('alterId') or 0)
        netw = (obj.get('net') or obj.get('network') or '').lower()
        path = obj.get('path') or '/'
        host_header = obj.get('host') or obj.get('sni')
        tls = (obj.get('tls') or '').lower() in ('tls', '1', 'true', 'on')
        remark = obj.get('ps') or ''
        if not host or not port or not uuid:
            return None
        st: Dict = {}
        if netw == 'ws':
            st['network'] = 'ws'
            st['wsSettings'] = {
                'path': path,
                'headers': ({'Host': host_header} if host_header else {})
            }
        if tls:
            st['security'] = 'tls'
            if host_header:
                st['tlsSettings'] = {'serverName': host_header}
        outbound = {
            'protocol': 'vmess',
            'settings': {
                'vnext': [{
                    'address': host,
                    'port': port,
                    'users': [{
                        'id': uuid,
                        'alterId': aid,
                        'security': obj.get('scy') or 'auto'
                    }]
                }]
            },
            'streamSettings': st
        }
        cfg = {
            'log': {'loglevel': 'warning'},
            'inbounds': [{
                'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
                'settings': {'udp': True}
            }],
            'outbounds': [outbound]
        }
        tag = remark or f"VMESS_{host}_{port}"
        return (tag, cfg)
    except Exception:
        return None


def build_trojan_config(uri: str) -> Optional[Tuple[str, Dict]]:
    try:
        p = urlsplit(uri)
        if p.scheme.lower() != 'trojan':
            return None
        password = unquote(p.username or '')
        host = p.hostname
        port = p.port or 443
        if not password or not host or not port:
            return None
        q = parse_qs(p.query or '')
        remark = unquote(p.fragment or '')
        st = _stream_settings_from_query(p, q, q.get('sni', [''])[0])
        # Minimal trojan outbound
        outbound = {
            'protocol': 'trojan',
            'settings': {
                'servers': [{
                    'address': host,
                    'port': port,
                    'password': password
                }]
            },
            'streamSettings': st
        }
        cfg = {
            'log': {'loglevel': 'warning'},
            'inbounds': [{
                'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
                'settings': {'udp': True}
            }],
            'outbounds': [outbound]
        }
        tag = remark or f"TROJAN_{host}_{port}"
        return (tag, cfg)
    except Exception:
        return None


def build_config_for_uri(uri: str) -> Optional[Tuple[str, Dict]]:
    scheme = (uri.split('://', 1)[0] if '://' in uri else '').lower()
    if scheme == 'vless':
        return build_vless_config(uri)
    if scheme == 'vmess':
        return build_vmess_config(uri)
    if scheme == 'trojan':
        return build_trojan_config(uri)
    return None


def export_v2ray_configs(uris: List[str], out_dir: Optional[str] = None) -> int:
    """
    Export per-proxy v2ray/xray JSON configs for provided URIs.
    Returns number of files written.
    """
    target_dir = os.path.join(OUTPUT_DIR, 'v2ray_configs') if not out_dir else out_dir
    _ensure_dir(target_dir)
    count = 0
    for uri in uris:
        u = (uri or '').strip()
        if not u:
            continue
        built = build_config_for_uri(u)
        if not built:
            continue
        tag, cfg = built
        # Prefer fragment remark; else use short SHA1 suffix
        if not tag:
            tag = sha1_hex(u)[:10]
        fname = _sanitize_filename(f"{tag}.json")
        path = os.path.join(target_dir, fname)
        try:
            with open(path, 'w', encoding='utf-8', errors='ignore') as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
            count += 1
        except Exception:
            # best-effort: skip failures
            continue
    return count
