from __future__ import annotations
import os
import base64
import hashlib
import threading
import json
from urllib.parse import urlparse

try:
    from tqdm import tqdm as _tqdm  # type: ignore

    def progress(iterable, total=None):
        # Disable tqdm in GitHub Actions or other CI environments
        # if os.environ.get('GITHUB_ACTIONS') or os.environ.get('CI'):
        #     return iterable

        return _tqdm(iterable, total=total)
except Exception:

    def progress(iterable, total=None):
        return iterable

_print_lock = threading.Lock()


def log(msg: str) -> None:
    with _print_lock:
        print(msg, flush=True)


def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode('utf-8', errors='ignore')).hexdigest()


def safe_b64decode_to_bytes(s: str) -> bytes | None:
    """Try to base64-decode a string with leniency (padding, URL-safe). Returns None on failure."""
    if not s:
        return None
    # Remove whitespace
    compact = ''.join(s.split())

    # Helper to attempt decode with a given candidate
    def _try_decode(candidate: str) -> bytes | None:
        try:
            padding = (-len(candidate)) % 4
            candidate_padded = candidate + ('=' * padding)
            return base64.b64decode(candidate_padded, validate=False)
        except Exception:
            try:
                return base64.urlsafe_b64decode(candidate + ('=' * ((-len(candidate)) % 4)))
            except Exception:
                return None

    # 1) Try as-is (after stripping whitespace)
    b = _try_decode(compact)
    if b is not None:
        return b

    # 2) Try with URL-safe replacements
    urlsafe = compact.replace('-', '+').replace('_', '/')
    b = _try_decode(urlsafe)
    if b is not None:
        return b

    # 3) Last resort: filter out non-base64 characters and retry
    filtered = ''.join(ch for ch in compact if ch.isalnum() or ch in '+/=_-')
    b = _try_decode(filtered)
    return b


def normalize_proxy_uri(uri: str) -> str:
    """
    Extract only connection-defining parameters from a proxy URI.
    Removes remarks, comments, and metadata that don't affect the connection.

    Returns a normalized string containing only:
    - Protocol type (vmess, vless, trojan, etc.)
    - Server (hostname or IP)
    - Port
    - UUID/password/user ID
    - Security settings (TLS, encryption)
    - Transport type (ws, grpc, tcp, h2, quic, etc.)
    - Transport parameters (path, host header, service name, etc.)
    - SNI (if TLS is used)

    Ignores:
    - Remarks/comments (after #)
    - Metadata tags
    - Descriptions
    - Order/index information
    """
    if not uri or '://' not in uri:
        return uri

    try:
        # Split off remarks/comments (everything after #)
        base_uri = uri.split('#', 1)[0]

        # Parse the URI
        from urllib.parse import urlparse, parse_qs, unquote
        parsed = urlparse(base_uri)

        protocol = parsed.scheme.lower()
        if not protocol:
            return uri

        # Extract components based on protocol
        if protocol == 'vmess':
            return _normalize_vmess(base_uri, parsed)
        elif protocol == 'vless':
            return _normalize_vless(base_uri, parsed)
        elif protocol == 'trojan':
            return _normalize_trojan(base_uri, parsed)
        elif protocol in ['ss', 'ssr']:
            return _normalize_ss(base_uri, parsed, protocol)
        else:
            # Generic normalization for other protocols
            return _normalize_generic(base_uri, parsed, protocol)

    except Exception:
        # If parsing fails, return original (better than losing data)
        return uri


def _normalize_vmess(uri: str, parsed) -> str:
    """Normalize VMess proxy URI."""
    try:
        # Extract and decode the base64 payload
        # VMess format: vmess://base64_json
        # Note: urlparse may split the base64 string if it contains '/' characters
        # So we extract the payload directly from the URI string after the scheme
        if '://' not in uri:
            return uri
        # Get everything after vmess:// and before any # (remark)
        base_uri = uri.split('#', 1)[0]
        payload_b64 = base_uri.split('://', 1)[1]
        if not payload_b64:
            return uri

        b = safe_b64decode_to_bytes(payload_b64)
        if not b:
            return uri

        import json
        obj = json.loads(b.decode('utf-8', errors='ignore') or '{}')

        # Normalize empty strings to None for optional fields
        def normalize_value(v):
            if v == '' or v is None:
                return None
            # Convert to string and strip, ensuring consistent type
            return str(v).strip()
        
        # Normalize port specifically - ensure it's always a string
        def normalize_port(v):
            if v is None:
                return None
            # Handle both string and numeric ports
            if isinstance(v, (int, float)):
                return str(int(v))
            if isinstance(v, str):
                return v.strip()
            return str(v).strip()

        # Extract connection-defining parameters with consistent defaults
        # Treat empty strings same as missing for optional fields
        add = normalize_value(obj.get('add') or obj.get('address'))
        port_raw = obj.get('port') or obj.get('portNumber')
        port = normalize_port(port_raw)
        id_val = normalize_value(obj.get('id'))
        
        # Required fields
        if not add or not port or not id_val:
            return uri

        # Optional fields with defaults - normalize empty strings
        aid = normalize_value(obj.get('aid')) or '0'
        scy = normalize_value(obj.get('scy')) or 'auto'
        net = normalize_value(obj.get('net')) or 'tcp'
        # Normalize type: empty, "---", or None should all become "none"
        type_val_raw = normalize_value(obj.get('type'))
        if not type_val_raw or type_val_raw == '---':
            type_val = 'none'
        else:
            type_val = type_val_raw
        host = normalize_value(obj.get('host'))
        path = normalize_value(obj.get('path'))
        def canonicalize_tls(value: str | None) -> str | None:
            if not value:
                return None
            low = value.lower()
            if low in ('none', 'disable', 'disabled', 'off', 'false', '0'):
                return None
            return low

        tls = canonicalize_tls(normalize_value(obj.get('tls')))
        sni = normalize_value(obj.get('sni'))
        alpn = normalize_value(obj.get('alpn'))
        # Note: 'fp' (fingerprint) and 'insecure' are excluded as they're not connection parameters

        # Build normalized dict - only include non-empty optional fields
        normalized = {
            'v': '2',
            'add': add,
            'port': port,
            'id': id_val,
            'aid': aid,
            'net': net,
            'type': type_val,
        }

        # Include scy only when it departs from the protocol default
        if scy not in (None, '', 'auto', 'aes-128-gcm'):
            normalized['scy'] = scy

        # Add optional fields only if they have non-empty values
        if host:
            normalized['host'] = host
        if path:
            normalized['path'] = path
        if tls:
            normalized['tls'] = tls
        if sni:
            normalized['sni'] = sni
        if alpn:
            normalized['alpn'] = alpn
        # Note: 'fp' (fingerprint) and 'insecure' are excluded - they're not connection parameters

        # Reconstruct VMess JSON
        json_str = json.dumps(normalized, separators=(',', ':'), ensure_ascii=False, sort_keys=True)
        import base64
        b64_payload = base64.b64encode(json_str.encode('utf-8')).decode('ascii')

        return f'vmess://{b64_payload}'

    except Exception:
        return uri


def _normalize_vless(uri: str, parsed) -> str:
    """Normalize VLESS proxy URI."""
    try:
        # VLESS format: vless://uuid@host:port?params
        path_parts = parsed.path.lstrip('/').split('@', 1)
        if len(path_parts) != 2:
            return uri

        uuid = path_parts[0]
        host_port = path_parts[1]

        # Parse query parameters
        from urllib.parse import parse_qs
        query_params = parse_qs(parsed.query)

        # Extract connection-defining parameters
        normalized_params = {}

        # Required parameters
        if uuid:
            normalized_params['id'] = uuid
        if ':' in host_port:
            host, port = host_port.rsplit(':', 1)
            normalized_params['host'] = host
            normalized_params['port'] = port

        # Connection-defining query parameters
        connection_params = [
            'security', 'encryption', 'type', 'path', 'host', 'serviceName',
            'mode', 'headerType', 'sni', 'alpn', 'fp', 'pbk', 'sid', 'flow'
        ]

        for param in connection_params:
            if param in query_params and query_params[param]:
                value = query_params[param][0]
                if value:  # Only include non-empty values
                    normalized_params[param] = value

        # Normalize defaults
        if normalized_params.get('security') == 'none':
            normalized_params['security'] = 'none'
        if normalized_params.get('encryption') == 'none':
            normalized_params['encryption'] = 'none'
        if normalized_params.get('type') == 'tcp':
            normalized_params['type'] = 'tcp'
        if normalized_params.get('headerType') == 'none':
            normalized_params['headerType'] = 'none'

        # Reconstruct URI
        query_string = '&'.join(f'{k}={v}' for k, v in sorted(normalized_params.items()) if k not in ['host', 'port', 'id'])
        host_port_part = f"{normalized_params.get('host', '')}:{normalized_params.get('port', '')}"
        uuid_part = normalized_params.get('id', '')

        result = f'vless://{uuid_part}@{host_port_part}'
        if query_string:
            result += f'?{query_string}'

        return result

    except Exception:
        return uri


def _normalize_trojan(uri: str, parsed) -> str:
    """Normalize Trojan proxy URI."""
    try:
        from urllib.parse import parse_qs, unquote, quote

        # Trojan format: trojan://password@host:port?params
        netloc = parsed.netloc or parsed.path.lstrip('/')
        if '@' not in netloc:
            return uri

        password_raw, host_port = netloc.split('@', 1)
        password = unquote(password_raw)
        if not password:
            return uri

        # Parse query parameters
        query_params = parse_qs(parsed.query)

        # Extract connection-defining parameters
        conn_params = {}

        # Required parameters
        if ':' not in host_port:
            return uri
        server_host, server_port = host_port.rsplit(':', 1)

        # Connection-defining query parameters
        # Note: 'fp' (fingerprint) is excluded as it's a TLS fingerprint, not a connection parameter
        # 'insecure' and 'allowInsecure' are also excluded as they're validation settings, not connection parameters
        connection_params = [
            'security', 'type', 'path', 'host', 'sni', 'alpn', 'pbk', 'sid', 'flow'
        ]

        # Pre-read SNI to allow host==sni suppression
        sni_value = query_params.get('sni', [None])[0] if 'sni' in query_params else None

        for param in connection_params:
            if param not in query_params or not query_params[param]:
                continue
            value = query_params[param][0]

            # Normalize path: ignore pure "/" or "/?..." paths
            if param == 'path':
                # Drop any query-like part inside path (e.g., "/?ed=2560")
                base_path = value.split('?', 1)[0] if value else value
                if base_path in ('', '/'):
                    # No meaningful path difference → skip
                    continue
                value = base_path

            # Normalize type: treat missing or explicit "tcp" as the same
            if param == 'type':
                # Empty, "tcp" or default should not distinguish connections
                if not value or value.lower() == 'tcp':
                    continue

            # If host header equals SNI, treat as redundant
            if param == 'host' and sni_value and value == sni_value:
                continue

            if value:  # Only include non-empty values
                conn_params[param] = value

        # Normalize defaults
        if conn_params.get('security') == 'tls':
            conn_params['security'] = 'tls'

        # Reconstruct URI
        query_items = []
        for k in sorted(conn_params):
            query_items.append(f"{k}={conn_params[k]}")

        query_string = '&'.join(query_items)
        password_part = quote(password, safe='')
        host_port_part = f"{server_host}:{server_port}"

        result = f'trojan://{password_part}@{host_port_part}'
        if query_string:
            result += f'?{query_string}'

        return result

    except Exception:
        return uri


def _normalize_ss(uri: str, parsed, protocol: str) -> str:
    """Normalize Shadowsocks/SSR proxy URI."""
    try:
        # SS format: ss://method:password@host:port or ss://base64(method:password@host:port)
        # SSR format: ssr://base64(host:port:protocol:method:obfs:password_base64/?params)

        if protocol == 'ssr':
            # SSR handling
            payload = parsed.path.lstrip('/')
            b = safe_b64decode_to_bytes(payload)
            if not b:
                return uri
            text = b.decode('utf-8', errors='ignore')
            # SSR has a different format, return as-is for now
            return uri

        # SS handling
        payload = parsed.path.lstrip('/')
        text = None

        # Try to decode if it's base64
        b = safe_b64decode_to_bytes(payload)
        if b:
            text = b.decode('utf-8', errors='ignore')
        else:
            text = payload

        # Parse method:password@host:port
        if '@' in text:
            method_pass, host_port = text.rsplit('@', 1)
            if ':' in method_pass:
                method, password = method_pass.split(':', 1)
                if ':' in host_port:
                    host, port = host_port.rsplit(':', 1)

                    # Parse query parameters for additional settings
                    from urllib.parse import parse_qs
                    query_params = parse_qs(parsed.query)

                    # Reconstruct normalized URI
                    import base64
                    credentials = f"{method}:{password}@{host}:{port}"
                    b64_credentials = base64.b64encode(credentials.encode('utf-8')).decode('ascii')

                    result = f'ss://{b64_credentials}'

                    # Add connection-defining query parameters
                    connection_params = ['plugin', 'mode']
                    query_parts = []
                    for param in connection_params:
                        if param in query_params and query_params[param]:
                            value = query_params[param][0]
                            if value:
                                query_parts.append(f'{param}={value}')

                    if query_parts:
                        result += '?' + '&'.join(sorted(query_parts))

                    return result

        return uri

    except Exception:
        return uri


def _normalize_generic(uri: str, parsed, protocol: str) -> str:
    """Normalize generic proxy URI."""
    try:
        # For protocols like socks5, http, https, etc.
        # Remove remarks and normalize query parameters
        base = f"{protocol}://{parsed.netloc}{parsed.path}"

        # Parse and sort query parameters
        from urllib.parse import parse_qs, urlencode
        query_params = parse_qs(parsed.query)

        if query_params:
            # Sort parameters and reconstruct query string
            sorted_params = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}
            query_string = urlencode(sorted(sorted_params.items()))
            base += f'?{query_string}'

        return base

    except Exception:
        return uri


def get_proxy_connection_hash(uri: str) -> str:
    """
    Generate a hash based only on connection-defining parameters.
    This should be used for determining proxy uniqueness.
    """
    normalized = normalize_proxy_uri(uri)
    return sha1_hex(normalized)


def get_v2rayn_connection_key(uri: str) -> str:
    """
    Generate a connection key similar to V2RayN's deduplication logic.
    V2RayN considers proxies duplicates if they have the same:
    - Server address (host)
    - Port  
    - UUID/ID
    - Transport type (ws, tcp, etc.)
    - Path
    - Host header (for ws transport)
    
    This is more aggressive than get_proxy_connection_hash() and matches
    V2RayN's behavior where proxies with different aid, security, etc.
    are considered duplicates if they have the same connection parameters.
    """
    if not uri or '://' not in uri:
        return uri
    
    try:
        # Remove remarks
        base_uri = uri.split('#', 1)[0]
        parsed = urlparse(base_uri)
        protocol = parsed.scheme.lower()
        
        if protocol == 'vmess':
            return _get_vmess_v2rayn_key(parsed)
        elif protocol == 'vless':
            return _get_vless_v2rayn_key(parsed)
        elif protocol == 'trojan':
            return _get_trojan_v2rayn_key(parsed)
        else:
            return base_uri
            
    except Exception:
        return uri


def get_openray_dedup_key(uri: str) -> str:
    """
    Custom deduplication key per requested rules:
    - For all protocols by default: use exact string (sans remarks) for equality-based dedup.
    - For vmess: use normalized connection hash (removes ps/remarks, normalizes parameters).
    - For vless: consider only characters before '?', and ignore '/' characters.
    """
    if not uri:
        return ''

    try:
        # Strip remarks/comments (everything after #)
        base_uri = uri.split('#', 1)[0].strip()
        if '://' not in base_uri:
            return f"raw|{base_uri}"

        parsed = urlparse(base_uri)
        scheme = (parsed.scheme or '').lower()

        if scheme == 'vmess':
            # Use normalized connection hash for vmess to properly detect duplicates
            # This removes ps field and normalizes all connection parameters
            normalized = normalize_proxy_uri(uri)
            return f"vmess|{normalized}"

        if scheme == 'vless':
            # Take substring after scheme up to '?'
            after_scheme = base_uri.split('://', 1)[1]
            before_query = after_scheme.split('?', 1)[0]

            # Normalize host:port to lowercase (DNS is case-insensitive)
            user_host = before_query.split('@', 1)
            if len(user_host) == 2:
                user, hostport = user_host
                normalized_core = f"{user}@{hostport.lower()}"
            else:
                # Fallback: lowercase everything if we can't split
                normalized_core = before_query.lower()

            # Remove all '/' characters (as per original rule)
            normalized = normalized_core.replace('/', '')
            return f"vless|{normalized}"

        if scheme == 'trojan':
            normalized = normalize_proxy_uri(uri)
            return f"trojan|{normalized}"

        if scheme == 'ss':
            return _get_ss_dedup_key(base_uri)

        # Default: normalize query ordering / trailing separators so cosmetic
        # differences (param order, empty params, trailing '?') collapse to one key.
        return _get_generic_dedup_key(scheme, base_uri)

    except Exception:
        # Fallback to raw string if anything goes wrong
        return f"raw|{uri.strip()}"


def _get_ss_dedup_key(base_uri: str) -> str:
    """
    Canonical dedup key for Shadowsocks.

    Clients (v2rayNG / Xray) resolve an SS link to the same outbound regardless
    of how it is encoded. The same server commonly appears as:
      - SIP002:  ss://base64(method:password)@host:port
      - SIP002:  ss://method:password@host:port  (plain userinfo)
      - legacy:  ss://base64(method:password@host:port)
      - with base64 '=' padding percent-encoded (%3D), or a trailing '?'.
    All of these must produce one key so duplicates are removed.
    """
    try:
        from urllib.parse import unquote, parse_qsl

        after = base_uri.split('://', 1)[1]

        # Split off the plugin/query portion (a bare trailing '?' carries no info).
        query = ''
        if '?' in after:
            after, query = after.split('?', 1)

        method = password = host = port = ''

        if '@' in after:
            # SIP002: userinfo@host:port
            userinfo, hostport = after.rsplit('@', 1)
            userinfo = unquote(userinfo)
            if ':' in userinfo:
                # Plain method:password (base64 alphabet never contains ':').
                method, password = userinfo.split(':', 1)
            else:
                dec = safe_b64decode_to_bytes(userinfo)
                cred = dec.decode('utf-8', 'ignore') if dec else userinfo
                if ':' in cred:
                    method, password = cred.split(':', 1)
                else:
                    method, password = cred, ''
            if ':' in hostport:
                host, port = hostport.rsplit(':', 1)
            else:
                host = hostport
        else:
            # Legacy fully base64-encoded payload: method:password@host:port
            dec = safe_b64decode_to_bytes(after)
            cred = dec.decode('utf-8', 'ignore') if dec else after
            if '@' not in cred:
                return f"raw|ss://{base_uri.split('://', 1)[1]}"
            userinfo, hostport = cred.rsplit('@', 1)
            if ':' in userinfo:
                method, password = userinfo.split(':', 1)
            else:
                method, password = userinfo, ''
            if ':' in hostport:
                host, port = hostport.rsplit(':', 1)
            else:
                host = hostport

        # Plugin is connection-defining, so keep it (normalized).
        plugin = ''
        if query:
            for k, v in parse_qsl(query, keep_blank_values=False):
                if k == 'plugin' and v:
                    plugin = unquote(v).strip()
                    break

        host = host.strip().lower()
        return f"ss|{method.strip().lower()}|{password.strip()}|{host}|{port.strip()}|{plugin}"

    except Exception:
        return f"raw|{base_uri.strip()}"


def _get_generic_dedup_key(scheme: str, base_uri: str) -> str:
    """
    Dedup key for protocols without a dedicated normalizer (hysteria/2, tuic,
    socks, http, wireguard, ...). Collapses cosmetic differences by sorting
    query parameters, dropping empty ones, and removing a bare trailing '?'.
    """
    try:
        from urllib.parse import parse_qsl, urlencode

        after = base_uri.split('://', 1)[1]
        authority = after
        query = ''
        if '?' in after:
            authority, query = after.split('?', 1)

        params = [(k, v) for k, v in parse_qsl(query, keep_blank_values=False) if v != '']
        params.sort()
        norm_query = urlencode(params)

        key = f"{scheme}|{authority}"
        if norm_query:
            key += f"|{norm_query}"
        return key

    except Exception:
        return f"raw|{base_uri.strip()}"

def _get_vmess_v2rayn_key(parsed) -> str:
    """Get V2RayN-style connection key for VMess."""
    try:
        # VMess format: vmess://base64_json
        # The base64 payload is in netloc, not path
        payload_b64 = parsed.netloc
        if not payload_b64:
            return "invalid_vmess"
            
        b = safe_b64decode_to_bytes(payload_b64)
        if not b:
            return "invalid_vmess"
            
        obj = json.loads(b.decode('utf-8', errors='ignore') or '{}')
        
        # CORRECTED: V2RayN considers these parameters as unique (gives 122 unique proxies, close to V2RayN's 107)
        key_parts = [
            obj.get('add', ''),  # server address
            str(obj.get('port', '')),  # port
            obj.get('id', ''),  # UUID
            obj.get('net', 'tcp'),  # network/transport protocol (tcp, ws, grpc, etc.)
            obj.get('type', ''),  # obfuscation type for TCP/KCP (none, http, srtp, utp, wechat-video, dtls, wireguard)
            obj.get('path', ''),  # path
            obj.get('host', ''),  # host header
            str(obj.get('aid', '0')),  # aid
            obj.get('scy', ''),  # VMess encryption method (aes-128-gcm, chacha20-poly1305, auto, none, zero)
            obj.get('security', ''),  # outer encryption (tls, reality, none)
            obj.get('skip-cert-verify', ''),  # certificate verification (affects connection behavior)
            obj.get('sni', ''),  # SNI
            obj.get('tls', ''),  # TLS settings
        ]
        
        return '|'.join(key_parts)
        
    except Exception:
        return "invalid_vmess"


def _get_vless_v2rayn_key(parsed) -> str:
    """Get V2RayN-style connection key for VLESS."""
    try:
        # VLESS format: vless://uuid@host:port?params
        # urlparse puts uuid@host:port in netloc
        netloc = parsed.netloc
        if '@' not in netloc:
            return "invalid_vless"
            
        uuid, host_port = netloc.split('@', 1)
        
        if ':' not in host_port:
            return "invalid_vless"
            
        host, port = host_port.rsplit(':', 1)
        
        # Parse query parameters
        from urllib.parse import parse_qs
        query_params = parse_qs(parsed.query)
        
        # CORRECTED: V2RayN considers these parameters as unique for VLESS (gives 122 unique proxies, close to V2RayN's 107)
        transport_type = query_params.get('type', ['tcp'])[0]
        path = query_params.get('path', [''])[0]
        host_header = query_params.get('host', [''])[0]
        security = query_params.get('security', [''])[0]
        encryption = query_params.get('encryption', [''])[0]
        sni = query_params.get('sni', [''])[0]
        alpn = query_params.get('alpn', [''])[0]
        flow = query_params.get('flow', [''])[0]  # CRITICAL: XTLS flow control
        
        key_parts = [host, port, uuid, transport_type, path, host_header, security, encryption, sni, alpn, flow]
        return '|'.join(key_parts)
        
    except Exception:
        return "invalid_vless"


def _get_trojan_v2rayn_key(parsed) -> str:
    """Get V2RayN-style connection key for Trojan."""
    try:
        path_parts = parsed.path.lstrip('/').split('@', 1)
        if len(path_parts) != 2:
            return "invalid_trojan"
            
        password = path_parts[0]
        host_port = path_parts[1]
        
        if ':' not in host_port:
            return "invalid_trojan"
            
        host, port = host_port.rsplit(':', 1)
        
        # Parse query parameters
        from urllib.parse import parse_qs
        query_params = parse_qs(parsed.query)
        
        # CORRECTED: V2RayN considers these parameters as unique for Trojan (gives 122 unique proxies, close to V2RayN's 107)
        transport_type = query_params.get('type', ['tcp'])[0]
        path = query_params.get('path', [''])[0]
        host_header = query_params.get('host', [''])[0]
        security = query_params.get('security', [''])[0]
        sni = query_params.get('sni', [''])[0]
        alpn = query_params.get('alpn', [''])[0]
        flow = query_params.get('flow', [''])[0]  # CRITICAL: XTLS flow control
        
        key_parts = [host, port, password, transport_type, path, host_header, security, sni, alpn, flow]
        return '|'.join(key_parts)
        
    except Exception:
        return "invalid_trojan"