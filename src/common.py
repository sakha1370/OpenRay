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


def _canonicalize_vmess_header_type(header_type: str | None) -> str | None:
    """Treat empty / none / --- as the same VMess header type (v2rayNG default)."""
    if header_type is None:
        return None
    low = str(header_type).strip().lower()
    if low in ('', '---', 'none'):
        return None
    return low


def _canonicalize_vmess_transport(net: str | None, header_type: str | None) -> tuple[str, str | None]:
    """
    Unify VMess share-link variants of the same transport.

    The same server is often published as net=tcp with an empty type, or net=raw
    with type=none — clients treat these as equivalent plain TCP VMess.
    """
    net_norm = (str(net).strip().lower() if net else '') or 'tcp'
    ht = _canonicalize_vmess_header_type(header_type)
    if net_norm == 'raw' and ht is None:
        net_norm = 'tcp'
    return net_norm, ht


def _canonicalize_vmess_security(tls: str | None) -> str | None:
    """Match v2rayNG: only tls/reality are connection-defining security values."""
    if not tls:
        return None
    low = str(tls).strip().lower()
    if low in ('none', 'disable', 'disabled', 'off', 'false', '0'):
        return None
    if low in ('tls', 'reality'):
        return low
    return low


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
        net, header_type = _canonicalize_vmess_transport(
            normalize_value(obj.get('net')),
            normalize_value(obj.get('type')),
        )
        type_val = header_type if header_type else 'none'
        host = normalize_value(obj.get('host'))
        path = normalize_value(obj.get('path'))
        tls = _canonicalize_vmess_security(normalize_value(obj.get('tls')))
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

        # SS handling — use the raw segment after ss://; urlparse breaks legacy
        # ss://base64(...) links (especially with a trailing '/' path separator).
        after = _strip_ss_uri_artifacts(uri.split('://', 1)[1])
        query = ''
        payload = after
        if '?' in after:
            payload, query = after.split('?', 1)

        text = None
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
                    port = _normalize_ss_port(port)

                    from urllib.parse import parse_qsl, unquote
                    import base64

                    credentials = f"{method}:{password}@{host}:{port}"
                    b64_credentials = base64.b64encode(credentials.encode('utf-8')).decode('ascii')
                    result = f'ss://{b64_credentials}'

                    connection_params = ['plugin', 'mode']
                    query_parts = []
                    if query:
                        for k, v in parse_qsl(query, keep_blank_values=False):
                            if k in connection_params and v:
                                query_parts.append(f'{k}={unquote(v)}')

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


# Connection-defining ProfileItem fields compared by v2rayNG's
# ProfileItem.equals() (remarks, alterId, encryption-as-method-for-vmess,
# insecure, spiderX, etc. are intentionally excluded — see v2rayNG dto/ProfileItem.kt).
_V2RAY_DEDUP_FIELDS = (
    'server', 'serverPort', 'password', 'method', 'flow',
    'network', 'headerType', 'host', 'path', 'seed', 'quicSecurity', 'quicKey',
    'mode', 'serviceName', 'authority', 'xhttpMode',
    'security', 'sni', 'alpn', 'fingerPrint', 'publicKey', 'shortId',
    'obfsPassword', 'portHopping', 'portHoppingInterval', 'pinnedCA256',
)


def _v2ray_query_params(query: str) -> dict:
    """Decode a raw URI query string the way v2rayNG's getQueryParam does."""
    params: dict = {}
    for part in query.split('&'):
        if not part:
            continue
        if '=' in part:
            k, v = part.split('=', 1)
        else:
            k, v = part, ''
        from urllib.parse import unquote
        params[k] = unquote(v)
    return params


def _v2ray_fields_from_query(fields: dict, q: dict) -> None:
    """Populate transport/TLS fields from query params (mirrors FmtBase.getItemFormQuery)."""
    fields['network'] = q.get('type') or 'tcp'
    fields['headerType'] = q.get('headerType')
    fields['host'] = q.get('host')
    fields['path'] = q.get('path')
    fields['seed'] = q.get('seed')
    fields['quicSecurity'] = q.get('quicSecurity')
    fields['quicKey'] = q.get('key')
    fields['mode'] = q.get('mode')
    fields['serviceName'] = q.get('serviceName')
    fields['authority'] = q.get('authority')
    fields['xhttpMode'] = q.get('mode')
    sec = q.get('security')
    fields['security'] = sec if sec in ('tls', 'reality') else None
    fields['sni'] = q.get('sni')
    fields['fingerPrint'] = q.get('fp')
    fields['alpn'] = q.get('alpn')
    fields['pinnedCA256'] = q.get('pcs')
    fields['publicKey'] = q.get('pbk')
    fields['shortId'] = q.get('sid')
    fields['flow'] = q.get('flow')


def get_openray_dedup_key(uri: str) -> str:
    """
    Deduplication key that mirrors v2rayNG's notion of a duplicate server.

    v2rayNG parses each share link into a ProfileItem and treats two servers as
    duplicates when their connection-defining fields are equal (ignoring the
    remark/name, vmess alterId, vless encryption, allowInsecure, fingerprint
    spider-x, etc.). We replicate that parsing + field set here so that proxies
    surviving our dedup also survive v2rayNG's "remove duplicate" with no leftovers.

    Falls back to a stable normalized key for protocols without a dedicated
    parser (hysteria2, tuic, socks, ...).
    """
    if not uri:
        return ''

    try:
        from urllib.parse import unquote

        base_uri = uri.split('#', 1)[0].strip()
        if '://' not in base_uri:
            return f"raw|{base_uri}"

        scheme = base_uri.split('://', 1)[0].lower()
        fields = {f: None for f in _V2RAY_DEDUP_FIELDS}

        if scheme == 'vmess':
            # vmess-std (vless-like with query) vs legacy base64 JSON.
            if '?' in uri and '&' in uri:
                parsed = urlparse(base_uri)
                fields['server'] = (parsed.hostname or '').lower()
                fields['serverPort'] = str(parsed.port) if parsed.port else '-1'
                fields['password'] = unquote(parsed.username) if parsed.username else None
                fields['method'] = 'auto'
                _v2ray_fields_from_query(fields, _v2ray_query_params(parsed.query))
            else:
                b = safe_b64decode_to_bytes(base_uri.split('://', 1)[1])
                if not b:
                    return f"raw|{base_uri}"
                obj = json.loads(b.decode('utf-8', errors='ignore') or '{}')
                net, header_type = _canonicalize_vmess_transport(
                    obj.get('net'),
                    obj.get('type'),
                )
                fields['server'] = str(obj.get('add') or '').lower()
                fields['serverPort'] = str(obj.get('port') or '')
                fields['password'] = obj.get('id') or None
                scy = obj.get('scy')
                fields['method'] = scy if scy not in (None, '') else 'auto'
                fields['network'] = net
                fields['headerType'] = header_type
                fields['host'] = obj.get('host') or None
                fields['path'] = obj.get('path') or None
                if net == 'grpc':
                    fields['mode'] = obj.get('type') or None
                    fields['serviceName'] = obj.get('path') or None
                    fields['authority'] = obj.get('host') or None
                elif net == 'kcp':
                    fields['seed'] = obj.get('path') or None
                fields['security'] = _canonicalize_vmess_security(obj.get('tls'))
                fields['sni'] = obj.get('sni') or None
                fields['fingerPrint'] = obj.get('fp') or None
                fields['alpn'] = obj.get('alpn') or None

        elif scheme == 'vless':
            parsed = urlparse(base_uri)
            fields['server'] = (parsed.hostname or '').lower()
            fields['serverPort'] = str(parsed.port) if parsed.port else '-1'
            fields['password'] = unquote(parsed.username) if parsed.username else None
            q = _v2ray_query_params(parsed.query)
            fields['method'] = q.get('encryption') or 'none'
            _v2ray_fields_from_query(fields, q)

        elif scheme == 'trojan':
            parsed = urlparse(base_uri)
            fields['server'] = (parsed.hostname or '').lower()
            fields['serverPort'] = str(parsed.port) if parsed.port else '-1'
            fields['password'] = unquote(parsed.username) if parsed.username else None
            if not parsed.query:
                fields['network'] = 'tcp'
                fields['security'] = 'tls'
            else:
                q = _v2ray_query_params(parsed.query)
                _v2ray_fields_from_query(fields, q)
                # Trojan overrides security with the raw value (default tls).
                fields['security'] = q.get('security') or 'tls'

        elif scheme == 'ss':
            return _get_ss_dedup_key(base_uri)

        else:
            # No dedicated v2rayNG-style parser: collapse cosmetic differences only.
            return _get_generic_dedup_key(scheme, base_uri)

        return scheme + '|' + '|'.join(
            (fields[f] if fields[f] is not None else '') for f in _V2RAY_DEDUP_FIELDS
        )

    except Exception:
        # Fallback to raw string if anything goes wrong
        return f"raw|{uri.strip()}"


def _strip_ss_uri_artifacts(payload: str) -> str:
    """
    Strip cosmetic trailing URL characters from an SS authority/payload segment.

    Legacy ss://base64(...) links are often published with a trailing '/' (treated
    as a URL path) or '?' (empty query). '/' is in the base64 alphabet, so leaving
    it in place corrupts the decoded method:password@host:port string.
    """
    s = payload.strip()
    while s.endswith('?'):
        s = s[:-1].rstrip()
    # Legacy fully-encoded payloads never contain '@' before decoding.
    if '@' not in s:
        s = s.rstrip('/')
    return s


def _normalize_ss_port(port: str) -> str:
    """Drop decode artifacts from a parsed SS port (e.g. '50099?')."""
    return port.strip().rstrip('?/')


def _get_ss_dedup_key(base_uri: str) -> str:
    """
    Canonical dedup key for Shadowsocks.

    Clients (v2rayNG / Xray) resolve an SS link to the same outbound regardless
    of how it is encoded. The same server commonly appears as:
      - SIP002:  ss://base64(method:password)@host:port
      - SIP002:  ss://method:password@host:port  (plain userinfo)
      - legacy:  ss://base64(method:password@host:port)
      - with base64 '=' padding percent-encoded (%3D), or a trailing '?'.
      - with a mistaken trailing '/' after the base64 blob.
    All of these must produce one key so duplicates are removed.
    """
    try:
        from urllib.parse import unquote, parse_qsl

        after = _strip_ss_uri_artifacts(base_uri.split('://', 1)[1])

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
                port = _normalize_ss_port(port)
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
                port = _normalize_ss_port(port)
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
        return f"ss|{method.strip().lower()}|{password.strip()}|{host}|{_normalize_ss_port(port)}|{plugin}"

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