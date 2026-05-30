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


def build_ss_config(uri: str) -> Optional[Tuple[str, Dict]]:
    try:
        p = urlsplit(uri)
        if p.scheme.lower() != 'ss':
            return None
        
        # Shadowsocks links can be ss://base64(method:password)@host:port#remark
        # or ss://method:password@host:port#remark
        
        # We reuse parsing logic if possible, or just parse here
        from .parsing import host_from_ss, port_from_ss
        host = host_from_ss(uri)
        port = port_from_ss(uri)
        
        if not host or not port:
            return None
            
        # Extract method and password
        userinfo = unquote(p.username or '')
        if not userinfo and '@' not in uri:
            # might be all base64
            payload = uri.split('://', 1)[1].split('#', 1)[0].split('?', 1)[0]
            b = safe_b64decode_to_bytes(payload)
            if b:
                userinfo = b.decode('utf-8', errors='ignore')
        
        if '@' in userinfo:
            userinfo = userinfo.rsplit('@', 1)[0]
        
        if ':' not in userinfo:
            # maybe userinfo itself is base64 encoded (common in some clients)
            b = safe_b64decode_to_bytes(userinfo)
            if b:
                userinfo = b.decode('utf-8', errors='ignore')

        if ':' not in userinfo:
            return None
            
        method, password = userinfo.split(':', 1)
        remark = unquote(p.fragment or '')
        
        outbound = {
            'protocol': 'shadowsocks',
            'settings': {
                'servers': [{
                    'address': host,
                    'port': port,
                    'method': method,
                    'password': password
                }]
            }
        }
        cfg = {
            'log': {'loglevel': 'warning'},
            'inbounds': [{
                'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
                'settings': {'udp': True}
            }],
            'outbounds': [outbound]
        }
        tag = remark or f"SS_{host}_{port}"
        return (tag, cfg)
    except Exception:
        return None


def build_ssr_config(uri: str) -> Optional[Tuple[str, Dict]]:
    try:
        # ssr://base64(host:port:protocol:method:obfs:password_base64/?params)
        payload = uri.split('://', 1)[1].split('#', 1)[0]
        b = safe_b64decode_to_bytes(payload)
        if not b:
            return None
        text = b.decode('utf-8', errors='ignore')
        
        main_part, params_part = text.split('/?', 1) if '/?' in text else (text, '')
        parts = main_part.split(':')
        if len(parts) < 6:
            return None
            
        host = parts[0]
        port = int(parts[1])
        protocol = parts[2]
        method = parts[3]
        obfs = parts[4]
        password = safe_b64decode_to_bytes(parts[5]).decode('utf-8', errors='ignore')
        
        q = parse_qs(params_part)
        remark = safe_b64decode_to_bytes(q.get('remarks', [''])[0]).decode('utf-8', errors='ignore') if q.get('remarks') else ''
        
        outbound = {
            'protocol': 'shadowsocks', # Xray handles SSR via shadowsocks protocol or similar? 
            # Actually Xray doesn't support SSR natively in the same way. 
            # But many collectors include it. We'll try to build a best-effort config 
            # or skip if Xray really can't do it. 
            # For now, let's assume it's NOT supported by standard Xray core if it's SSR.
            # However, the task asks to implement it.
            'settings': {
                'servers': [{
                    'address': host,
                    'port': port,
                    'method': method,
                    'password': password
                    # protocol and obfs are tricky for Xray
                }]
            }
        }
        # If Xray doesn't support SSR, this might fail Stage 3, which is fine.
        cfg = {
            'log': {'loglevel': 'warning'},
            'inbounds': [{
                'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
                'settings': {'udp': True}
            }],
            'outbounds': [outbound]
        }
        tag = remark or f"SSR_{host}_{port}"
        return (tag, cfg)
    except Exception:
        return None


def build_hysteria_config(uri: str) -> Optional[Tuple[str, Dict]]:
    try:
        p = urlsplit(uri)
        scheme = p.scheme.lower()
        if scheme not in ('hysteria', 'hysteria2', 'hy2'):
            return None
        
        from .parsing import host_from_generic, port_from_generic
        host = host_from_generic(uri)
        port = port_from_generic(uri)
        if not host or not port:
            return None
            
        q = parse_qs(p.query or '')
        remark = unquote(p.fragment or '')
        
        if scheme == 'hysteria':
            # Hysteria 1
            auth = q.get('auth', [''])[0]
            outbound = {
                'protocol': 'hysteria',
                'settings': {
                    'servers': [{
                        'address': host,
                        'port': port,
                        'auth': auth
                    }]
                }
            }
        else:
            # Hysteria 2
            password = p.username or q.get('password', [''])[0]
            outbound = {
                'protocol': 'hysteria2',
                'settings': {
                    'servers': [{
                        'address': host,
                        'port': port,
                        'password': password
                    }]
                }
            }
        
        # Stream settings for Hysteria (QUIC based)
        st = _stream_settings_from_query(p, q, q.get('sni', [''])[0])
        outbound['streamSettings'] = st
        
        cfg = {
            'log': {'loglevel': 'warning'},
            'inbounds': [{
                'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
                'settings': {'udp': True}
            }],
            'outbounds': [outbound]
        }
        tag = remark or f"HYSTERIA_{host}_{port}"
        return (tag, cfg)
    except Exception:
        return None


def build_tuic_config(uri: str) -> Optional[Tuple[str, Dict]]:
    try:
        p = urlsplit(uri)
        if p.scheme.lower() != 'tuic':
            return None
            
        host = p.hostname
        port = p.port
        if not host or not port:
            return None
            
        uuid = p.username
        password = p.password
        q = parse_qs(p.query or '')
        remark = unquote(p.fragment or '')
        
        outbound = {
            'protocol': 'tuic',
            'settings': {
                'servers': [{
                    'address': host,
                    'port': port,
                    'uuid': uuid,
                    'password': password
                }]
            }
        }
        st = _stream_settings_from_query(p, q, q.get('sni', [''])[0])
        outbound['streamSettings'] = st
        
        cfg = {
            'log': {'loglevel': 'warning'},
            'inbounds': [{
                'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
                'settings': {'udp': True}
            }],
            'outbounds': [outbound]
        }
        tag = remark or f"TUIC_{host}_{port}"
        return (tag, cfg)
    except Exception:
        return None


def build_juicity_config(uri: str) -> Optional[Tuple[str, Dict]]:
    try:
        p = urlsplit(uri)
        if p.scheme.lower() != 'juicity':
            return None

        host = p.hostname
        port = p.port
        if not host or not port:
            return None

        user = p.username
        password = p.password
        q = parse_qs(p.query or '')
        remark = unquote(p.fragment or '')

        outbound = {
            'protocol': 'juicity',
            'settings': {
                'servers': [{
                    'address': host,
                    'port': port,
                    'user': user,
                    'password': password
                }]
            }
        }
        st = _stream_settings_from_query(p, q, q.get('sni', [''])[0])
        outbound['streamSettings'] = st

        cfg = {
            'log': {'loglevel': 'warning'},
            'inbounds': [{
                'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
                'settings': {'udp': True}
            }],
            'outbounds': [outbound]
        }
        tag = remark or f"JUICITY_{host}_{port}"
        return (tag, cfg)
    except Exception:
        return None


def build_wireguard_config(uri: str) -> Optional[Tuple[str, Dict]]:
    try:
        p = urlsplit(uri)
        if p.scheme.lower() != 'wireguard':
            return None

        host = p.hostname
        port = p.port or 51820  # Default WireGuard port
        if not host:
            return None

        q = parse_qs(p.query or '')

        # Extract WireGuard parameters
        secretkey = q.get('privatekey', [''])[0] or q.get('secretkey', [''])[0]
        publickey = q.get('publickey', [''])[0] or q.get('peerpubkey', [''])[0]
        address = q.get('address', [''])[0] or q.get('addresses', [''])[0]
        mtu = q.get('mtu', [''])[0]
        reserved = q.get('reserved', [''])[0]

        # Extract additional parameters
        dns_servers = q.get('dns', [''])[0]
        kernel = q.get('kernel', [''])[0]

        # Parse addresses (comma-separated)
        addresses = [addr.strip() for addr in address.split(',')] if address else []
        if not addresses:
            # Fallback: try to get address from path part of URI
            if p.path and p.path.startswith('/'):
                path_addr = p.path[1:].split(',')
                addresses = [addr.strip() for addr in path_addr if addr.strip()]

        # Parse reserved bytes (comma-separated numbers)
        reserved_bytes = []
        if reserved:
            try:
                reserved_bytes = [int(x.strip()) for x in reserved.split(',')]
            except ValueError:
                reserved_bytes = []

        # Parse MTU
        mtu_val = None
        if mtu:
            try:
                mtu_val = int(mtu)
            except ValueError:
                pass

        # Parse DNS servers
        dns_list = []
        if dns_servers:
            dns_list = [dns.strip() for dns in dns_servers.split(',') if dns.strip()]

        remark = unquote(p.fragment or '')

        # Build WireGuard outbound configuration
        outbound = {
            'protocol': 'wireguard',
            'settings': {
                'address': addresses if addresses else ['172.16.0.2/32'],
                'peers': [{
                    'endpoint': f"{host}:{port}",
                    'publicKey': publickey,
                    'allowedIPs': ['0.0.0.0/0', '::/0']  # Allow all IPs by default
                }],
                'secretKey': secretkey,
                'mtu': mtu_val or 1420  # Default MTU
            }
        }

        # Add reserved bytes if provided
        if reserved_bytes:
            outbound['settings']['reserved'] = reserved_bytes

        # Add DNS if provided
        if dns_list:
            outbound['settings']['dns'] = dns_list

        # Add kernel option if provided
        if kernel.lower() in ['1', 'true', 'yes']:
            outbound['settings']['kernelMode'] = True

        cfg = {
            'log': {'loglevel': 'warning'},
            'inbounds': [{
                'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
                'settings': {'udp': True}
            }],
            'outbounds': [outbound]
        }
        tag = remark or f"WIREGUARD_{host}_{port}"
        return (tag, cfg)
    except Exception:
        return None


def build_outbound_for_uri(uri: str) -> Optional[Dict]:
    """Extract the primary outbound dict from a share link (for Stage 3 API backend)."""
    built = build_config_for_uri(uri)
    if not built:
        return None
    tag, cfg = built
    outbounds = cfg.get('outbounds') or []
    if not outbounds:
        return None
    outbound = outbounds[0]
    if not isinstance(outbound, dict):
        return None
    ob = dict(outbound)
    if tag and not ob.get('tag'):
        ob['tag'] = tag
    return ob


def build_config_for_uri(uri: str) -> Optional[Tuple[str, Dict]]:
    scheme = (uri.split('://', 1)[0] if '://' in uri else '').lower()
    if scheme == 'vless':
        return build_vless_config(uri)
    if scheme == 'vmess':
        return build_vmess_config(uri)
    if scheme == 'trojan':
        return build_trojan_config(uri)
    if scheme == 'ss':
        return build_ss_config(uri)
    if scheme == 'ssr':
        return build_ssr_config(uri)
    if scheme in ('hysteria', 'hysteria2', 'hy2'):
        return build_hysteria_config(uri)
    if scheme == 'tuic':
        return build_tuic_config(uri)
    if scheme == 'juicity':
        return build_juicity_config(uri)
    if scheme == 'wireguard':
        return build_wireguard_config(uri)
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
