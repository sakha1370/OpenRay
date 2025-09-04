import sys
import requests
import base64
import json
import yaml

try:
    from ruamel.yaml import YAML
except ImportError:
    try:
        import ruamel.yaml

        YAML = ruamel.yaml.YAML
    except Exception as e:
        print('Error: ruamel.yaml not installed. Please install it with: pip install ruamel.yaml')
        raise e
from urllib.parse import urlparse, parse_qs, unquote
from collections import OrderedDict
import re


def is_valid_ws_path(path):
    # All '%' must be followed by exactly two hex digits
    # Regex: '%' not followed by two hex digits is invalid
    invalid = re.search(r'%($|[^0-9A-Fa-f]{0,2}|[0-9A-Fa-f]($|[^0-9A-Fa-f]))', path)
    return not invalid


# ---------- UTILITIES ----------
def download_subscription(sub_url):
    resp = requests.get(sub_url)
    resp.raise_for_status()
    text = resp.text.strip()
    # meta: some sub files are base64 encoded!
    try:
        if all(ord(c) < 128 for c in text) and not text.startswith(
                ('vmess://', 'vless://', 'trojan://', 'ss://', 'socks://', 'hy2://', 'hysteria2://', 'tuic://',
                 'wg://')):
            # Try decode base64 whole (often for SSR/SS)
            dec = base64.b64decode(text).decode('utf-8', errors='ignore')
            if dec.count('\n') > text.count('\n'):
                text = dec
    except Exception:
        pass
    return [line.strip() for line in text.splitlines() if line.strip()]


def read_local_subscription(file_path):
    """Read proxy subscription from local file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            text = f.read().strip()
        # Handle base64 encoded content
        try:
            if all(ord(c) < 128 for c in text) and not text.startswith(
                    ('vmess://', 'vless://', 'trojan://', 'ss://', 'socks://', 'hy2://', 'hysteria2://', 'tuic://',
                     'wg://')):
                # Try decode base64 whole (often for SSR/SS)
                dec = base64.b64decode(text).decode('utf-8', errors='ignore')
                if dec.count('\n') > text.count('\n'):
                    text = dec
        except Exception:
            pass
        return [line.strip() for line in text.splitlines() if line.strip()]
    except FileNotFoundError:
        print(f'[FATAL] File not found: {file_path}')
        sys.exit(1)
    except Exception as e:
        print(f'[FATAL] Error reading file {file_path}: {e}')
        sys.exit(1)


# --- PROTOCOL PARSERS ---
def parse_vmess(uri):
    # vmess://<base64json>
    payload = uri[8:]
    try:
        raw = base64.b64decode(payload + '=' * ((4 - len(payload) % 4) % 4)).decode('utf-8')
        data = json.loads(raw)
        cipher = data.get('cipher')
        # Fix: always set a valid cipher (Meta: chacha20-poly1305 or auto is safest)
        if not cipher or cipher.lower() not in ["auto", "chacha20-poly1305", "aes-128-gcm", "none"]:
            cipher = 'auto'

        net = data.get('net') or data.get('network', 'tcp')
        ws_opts = None
        tls_opts = None

        # Handle WebSocket transport
        if net in ['ws', 'wss']:
            path = data.get('path', '/')
            host = None
            try:
                addh = data.get('add', None)
                host = data.get('host', None) or data.get('Host', None)
                if host:
                    if isinstance(host, list):
                        host = host[0]
                else:
                    if addh:
                        host = addh
            except Exception:
                host = None
            ws_opts = {'type': 'ws', 'path': path if path else '/', 'host': host if host else None}

        # Handle TLS
        tls_enabled = (data.get('tls', 'none') == 'tls')
        if tls_enabled:
            sni = data.get('sni') or data.get('host') or data.get('add')
            tls_opts = {'server_name': sni} if sni else {}

        proxy = {
            'type': 'vmess',
            'server': data.get('add'),
            'port': int(data.get('port', 0)),
            'uuid': data.get('id'),
            'alterId': data.get('aid', '0'),
            'cipher': cipher,
            'network': net,
            'transport': ws_opts,
            'tls': tls_enabled,
            'tls_opts': tls_opts,
            'name': data.get('ps') or f"vmess_{data.get('add')}",
        }
        return proxy
    except Exception:
        return None


def parse_vless(uri):
    # vless://[uuid]@[host]:[port]?params#remark
    try:
        url = urlparse(uri)
        user = url.username
        server = url.hostname
        port = url.port
        params = parse_qs(url.query)
        tag = unquote(url.fragment) if url.fragment else f"vless_{server}"

        if not port or not user or not server:
            return None

        encryption = params.get('encryption', [None])[0]
        if encryption in (None, '', 'none'):
            encryption = None

        net = params.get('type', ['tcp'])[0]
        path = params.get('path', ['/'])[0]
        host = params.get('host', [server])[0]
        sni = params.get('sni', [None])[0]

        # Transport options
        ws_opts = None
        if net in ['ws', 'wss']:
            ws_opts = {'type': 'ws', 'path': path, 'host': host or server}

        # TLS options
        security = params.get('security', ['none'])[0]
        tls_enabled = security in ['tls', 'reality']
        tls_opts = None
        if tls_enabled:
            tls_opts = {}
            if sni:
                tls_opts['server_name'] = sni
            if security == 'reality':
                # Reality specific parameters
                public_key = params.get('pbk', [None])[0]
                short_id = params.get('sid', [None])[0]
                fp = params.get('fp', [None])[0]
                if public_key:
                    tls_opts['reality'] = {
                        'public_key': public_key,
                        'short_id': short_id or '',
                        'fingerprint': fp or 'chrome'
                    }

        return {
            'type': 'vless',
            'server': server,
            'port': int(port),
            'uuid': user,
            'encryption': encryption,
            'flow': params.get('flow', [''])[0],
            'network': net,
            'transport': ws_opts,
            'tls': tls_enabled,
            'tls_opts': tls_opts,
            'name': tag,
        }
    except Exception:
        return None


def parse_trojan(uri):
    # trojan://password@host:port?params#remark
    try:
        url = urlparse(uri)
        server = url.hostname
        port = url.port
        password = url.username
        tag = unquote(url.fragment) if url.fragment else f"trojan_{server}"

        if not port or not password or not server:
            return None

        params = parse_qs(url.query)
        sni = params.get('sni', [None])[0]

        # TLS options for Hysteria2
        tls_opts = None
        if sni:
            tls_opts = {'server_name': sni}

        return {
            'type': 'trojan',
            'server': server,
            'port': int(port),
            'password': password,
            'tls_opts': tls_opts,
            'name': tag
        }
    except Exception:
        return None


def parse_ss(uri):
    # ss://[method:pass@host:port] or ss://base64#remark
    try:
        rest = uri[5:]
        if '@' in rest:
            if '#' in rest:
                rest, tag = rest.split('#', 1)
                tag = unquote(tag)
            else:
                tag = None
            auth, host_port = rest.split('@', 1)
            method, password = auth.split(':', 1)
            host, port = host_port.split(':', 1)
            if not port:
                return None
        else:
            if '#' in rest:
                main, tag = rest.split('#', 1)
                tag = unquote(tag)
            else:
                main = rest
                tag = None
            raw = base64.b64decode(main.split('?')[0] + '===').decode('utf-8')
            userinfo, host_port = raw.rsplit('@', 1)
            method, password = userinfo.split(':', 1)
            host, port = host_port.split(':', 1)
            if not port:
                return None
        return {
            'type': 'ss',
            'server': host,
            'port': int(port),
            'method': method,
            'password': password,
            'name': tag or f"ss_{host}"
        }
    except Exception:
        return None


def parse_socks(uri):
    # socks://[username:password@]host:port
    try:
        url = urlparse(uri)
        username = url.username or ''
        password = url.password or ''
        server = url.hostname
        port = url.port
        tag = unquote(url.fragment) if url.fragment else f"socks_{server}"
        if not port or not server:
            return None
        return {
            'type': 'socks',
            'server': server,
            'port': int(port),
            'username': username,
            'password': password,
            'name': tag
        }
    except Exception:
        return None


def parse_hysteria2(uri):
    # hy2://password@host:port?params#remark or hysteria2://password@host:port?params#remark
    try:
        if uri.startswith('hy2://'):
            uri = 'hysteria2://' + uri[6:]

        url = urlparse(uri)
        server = url.hostname
        port = url.port
        password = url.username
        tag = unquote(url.fragment) if url.fragment else f"hysteria2_{server}"

        if not port or not password or not server:
            return None

        params = parse_qs(url.query)
        sni = params.get('sni', [None])[0]

        # TLS options for Hysteria2
        tls_opts = None
        if sni:
            tls_opts = {'server_name': sni}

        return {
            'type': 'hysteria2',
            'server': server,
            'port': int(port),
            'password': password,
            'tls_opts': tls_opts,
            'name': tag
        }
    except Exception:
        return None


def parse_tuic(uri):
    # tuic://uuid:password@host:port?params#remark
    try:
        url = urlparse(uri)
        server = url.hostname
        port = url.port
        user_info = url.username
        tag = unquote(url.fragment) if url.fragment else f"tuic_{server}"

        if not port or not user_info or not server:
            return None

        # Parse uuid:password
        if ':' in user_info:
            uuid, password = user_info.split(':', 1)
        else:
            uuid = user_info
            password = ''

        params = parse_qs(url.query)
        sni = params.get('sni', [None])[0]

        # TLS options for TUIC
        tls_opts = None
        if sni:
            tls_opts = {'server_name': sni}

        return {
            'type': 'tuic',
            'server': server,
            'port': int(port),
            'uuid': uuid,
            'password': password,
            'tls_opts': tls_opts,
            'name': tag
        }
    except Exception:
        return None


def parse_wireguard(uri):
    # wg://... (basic support)
    try:
        # This is a simplified parser for WireGuard
        # Real WireGuard configs are usually much more complex
        url = urlparse(uri)
        server = url.hostname
        port = url.port or 51820
        tag = unquote(url.fragment) if url.fragment else f"wireguard_{server}"

        if not server:
            return None

        params = parse_qs(url.query)
        private_key = params.get('privatekey', [None])[0]
        public_key = params.get('publickey', [None])[0]

        if not private_key or not public_key:
            return None

        return {
            'type': 'wireguard',
            'server': server,
            'port': int(port),
            'private_key': private_key,
            'public_key': public_key,
            'name': tag
        }
    except Exception:
        return None


def parse_proxy_line(line):
    if line.startswith('vmess://'):
        return parse_vmess(line)
    elif line.startswith('vless://'):
        return parse_vless(line)
    elif line.startswith('trojan://'):
        return parse_trojan(line)
    elif line.startswith('ss://'):
        return parse_ss(line)
    elif line.startswith('socks://'):
        return parse_socks(line)
    elif line.startswith(('hy2://', 'hysteria2://')):
        return parse_hysteria2(line)
    elif line.startswith('tuic://'):
        return parse_tuic(line)
    elif line.startswith('wg://'):
        return parse_wireguard(line)
    elif line.startswith(('reality://', 'anytls://')):
        print(f'[!] WARNING: New or future protocol detected in link: {line[:32]}...')
        return None  # Not yet implemented -- print warning
    else:
        if line.strip():
            print(f'[!] WARNING: Unknown v2ray/vless/protocol line skipped: {line[:48]}...')
        return None


def validate_proxy(p):
    # Block injection if domain is well-known public web service or parameters are missing
    if not p:
        return False
    if not p.get('server') or not p.get('port') or not p.get('uuid', ''):
        return False
    # Block known public domains (e.g. speedtest.net, npmjs.com, google.com, etc.)
    public_domains = {
        'www.speedtest.net', 'speedtest.net', 'npmjs.com', 'google.com', 'github.com', 'cloudflare.com',
        'facebook.com', 'twitter.com', 'spotify.com', 'youtube.com', 'apple.com', 'microsoft.com', 'instagram.com'
    }
    server_l = p['server'].lower()
    if any(domain in server_l for domain in public_domains):
        return False
    # Optionally block .ir endpoints (for Iran direct/dns leaks)
    if server_l.endswith('.ir'):
        return False
    # You may add extra filters here if needed
    return True


# --- CONFIG PARSING/RENDER ---
def read_yaml_file(yaml_path):
    with open(yaml_path, 'r', encoding='utf-8') as f:
        yaml_ = YAML()
        content = yaml_.load(f)
    return content


def write_yaml_file(yaml_obj, yaml_path):
    with open(yaml_path, 'w', encoding='utf-8') as f:
        yaml_ = YAML()
        yaml_.default_flow_style = False
        yaml_.dump(yaml_obj, f)


def read_json_file(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def write_json_file(obj, path):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


# ---- INJECTION LOGIC ----
def ascii_name(name):
    # Remove all characters except ASCII letters, numbers, dash, underscore, and spaces
    n = re.sub(r'[^A-Za-z0-9 \-_]', '', name)
    return n.strip()


def update_clash_proxies(clash_cfg, proxies):
    yaml_proxies = []
    name_registry = {}
    for p in proxies:
        clash_proxy = proxy_to_clash(p)
        if clash_proxy:
            orig_name = ascii_name(clash_proxy['name'])
            # Ensure unique names for Clash
            name = orig_name
            i = 2
            while name in name_registry:
                name = f"{orig_name} #{i}"
                i += 1
            clash_proxy['name'] = name
            name_registry[name] = True
            yaml_proxies.append(clash_proxy)
    proxy_names = [p['name'] for p in yaml_proxies]
    # ... (rest unchanged)
    for p in yaml_proxies:
        p['name'] = p['name']
    # ... (rest unchanged)
    clash_cfg['proxies'] = yaml_proxies
    clash_cfg['proxy-groups'] = []
    auto_group = {
        "name": "AUTO",
        "type": "url-test",
        "url": "https://www.gstatic.com/generate_204",
        "interval": 300,
        "tolerance": 50,
        "proxies": proxy_names
    }

    proxy_group = {
        "name": "PROXY",
        "type": "select",
        "proxies": ["AUTO"] + proxy_names
    }

    clash_cfg['proxy-groups'] = [auto_group, proxy_group]

    # Update rules to ensure consistent formatting (fix the spacing issues)
    if 'rules' in clash_cfg:
        new_rules = []
        for rule in clash_cfg['rules']:
            # Ensure proper formatting without extra spaces
            if isinstance(rule, str):
                # Split and rejoin to fix spacing
                parts = [part.strip() for part in rule.split(',')]
                new_rules.append(','.join(parts))
            else:
                new_rules.append(rule)
        clash_cfg['rules'] = new_rules

    return clash_cfg


def proxy_to_clash(proxy):
    # Map internal proxy to Clash Meta format
    if proxy['type'] == 'vmess':
        clash_proxy = {
            'name': proxy['name'],
            'type': 'vmess',
            'server': proxy['server'],
            'port': proxy['port'],
            'uuid': proxy['uuid'],
            'alterId': int(proxy.get('alterId', '0')),
            'cipher': proxy.get('cipher', 'auto'),
            'network': proxy.get('network', 'tcp'),
        }

        if proxy.get('tls'):
            clash_proxy['tls'] = True
            if proxy.get('tls_opts', {}).get('server_name'):
                clash_proxy['servername'] = proxy['tls_opts']['server_name']

        # WebSocket options
        if proxy.get('transport'):
            clash_proxy['ws-opts'] = {
                'path': proxy['transport'].get('path', '/'),
                'headers': {}
            }
            if proxy['transport'].get('host'):
                clash_proxy['ws-opts']['headers']['Host'] = proxy['transport']['host']

        return clash_proxy

    elif proxy['type'] == 'vless':
        clash_proxy = {
            'name': proxy['name'],
            'type': 'vless',
            'server': proxy['server'],
            'port': proxy['port'],
            'uuid': proxy['uuid'],
            'network': proxy.get('network', 'tcp'),
        }

        if proxy.get('flow'):
            clash_proxy['flow'] = proxy['flow']
        if proxy.get('encryption'):
            clash_proxy['encryption'] = proxy['encryption']

        if proxy.get('tls'):
            clash_proxy['tls'] = True
            if proxy.get('tls_opts', {}).get('server_name'):
                clash_proxy['servername'] = proxy['tls_opts']['server_name']

            # Reality support
            if proxy.get('tls_opts', {}).get('reality'):
                reality = proxy['tls_opts']['reality']
                clash_proxy['reality-opts'] = {
                    'public-key': reality['public_key'],
                    'short-id': reality.get('short_id', '')
                }
                if reality.get('fingerprint'):
                    clash_proxy['client-fingerprint'] = reality['fingerprint']

        # WebSocket options
        if proxy.get('transport'):
            clash_proxy['ws-opts'] = {
                'path': proxy['transport'].get('path', '/'),
                'headers': {}
            }
            if proxy['transport'].get('host'):
                clash_proxy['ws-opts']['headers']['Host'] = proxy['transport']['host']

        return clash_proxy

    elif proxy['type'] == 'trojan':
        clash_proxy = {
            'name': proxy['name'],
            'type': 'trojan',
            'server': proxy['server'],
            'port': proxy['port'],
            'password': proxy['password'],
        }

        if proxy.get('tls_opts', {}).get('server_name'):
            clash_proxy['servername'] = proxy['tls_opts']['server_name']

        return clash_proxy

    elif proxy['type'] == 'ss':
        return {
            'name': proxy['name'],
            'type': 'ss',
            'server': proxy['server'],
            'port': proxy['port'],
            'cipher': proxy['method'],
            'password': proxy['password']
        }

    elif proxy['type'] == 'socks':
        clash_proxy = {
            'name': proxy['name'],
            'type': 'socks5',
            'server': proxy['server'],
            'port': proxy['port'],
        }
        if proxy['username']:
            clash_proxy['username'] = proxy['username']
        if proxy['password']:
            clash_proxy['password'] = proxy['password']
        return clash_proxy

    elif proxy['type'] == 'hysteria2':
        clash_proxy = {
            'name': proxy['name'],
            'type': 'hysteria2',
            'server': proxy['server'],
            'port': proxy['port'],
            'password': proxy['password'],
        }

        if proxy.get('tls_opts', {}).get('server_name'):
            clash_proxy['sni'] = proxy['tls_opts']['server_name']

        return clash_proxy

    else:
        # Unsupported protocol for Clash
        return None


def update_singbox_outbounds(sj, proxies):
    new_outbounds = []
    tagset = set()

    for p in proxies:
        sbo = proxy_to_singbox(p)
        if not sbo:
            continue
        if sbo['tag'] in tagset:
            continue
        new_outbounds.append(sbo)
        tagset.add(sbo['tag'])

    # Find existing system outbounds to preserve
    system_outbounds = []
    for o in sj.get('outbounds', []):
        if o.get('type') in ['direct', 'block']:
            system_outbounds.append(o)
        elif o.get('type') in ['selector', 'urltest']:
            # Keep the system selector/urltest outbounds but update their proxy lists
            system_outbounds.append(o)

    # Replace all outbounds but keep system ones and add new ones
    sj['outbounds'] = system_outbounds + new_outbounds

    # Update selector and urltest outbounds with new proxy tags
    proxy_tags = list(tagset)
    for o in sj['outbounds']:
        if o['type'] == 'selector' and o.get('tag') == 'proxy':
            # Replace any placeholder with auto + all proxies
            o['outbounds'] = ['auto'] + proxy_tags
            o['default'] = 'auto'
        elif o['type'] == 'urltest' and o.get('tag') == 'auto':
            # Replace any placeholder with all proxies
            o['outbounds'] = proxy_tags

    return sj


def proxy_to_singbox(proxy):
    tag = ascii_name(proxy['name'])

    net = proxy.get('network', 'tcp')
    # If grpc network, change to tcp and add transport block if possible
    if net == 'grpc':
        net = 'tcp'
        transport = {'type': 'grpc'}
        if 'serviceName' in proxy:
            transport['serviceName'] = proxy['serviceName']
        proxy['transport'] = transport
    if net not in ('tcp', 'ws', 'wss', 'grpc'):
        print(f"[!] Skipping proxy with unsupported network type for sing-box: {net} ({proxy['name']})")
        return None
    # Now do ws path validation on path fields
    if net in ('ws', 'wss') and proxy.get('transport') and proxy['transport'].get('path'):
        path = str(proxy['transport'].get('path'))
        if not is_valid_ws_path(path):
            print(f"[FATAL] Skipping proxy with invalid WebSocket path: {path} ({proxy['name']})")
            return None
    if proxy['type'] == 'vmess':
        ws = net in ('ws', 'wss')
        out = OrderedDict([
            ('type', 'vmess'),
            ('tag', tag),
            ('server', proxy['server']),
            ('server_port', proxy['port']),
            ('uuid', proxy['uuid']),
            ('alter_id', int(proxy.get('alterId', '0'))),
            ('network', 'tcp' if ws else net)
        ])

        # TLS configuration
        if proxy.get('tls'):
            tls_config = {}
            if proxy.get('tls_opts', {}).get('server_name'):
                tls_config['server_name'] = proxy['tls_opts']['server_name']
            out['tls'] = tls_config

        # Transport configuration
        if ws and proxy.get('transport'):
            transport = {}
            if proxy['transport'].get('type'):
                transport['type'] = proxy['transport']['type']
            if proxy['transport'].get('path'):
                transport['path'] = proxy['transport']['path']
            if transport:
                out['transport'] = transport
        return out
    elif proxy['type'] == 'vless':
        ws = net in ('ws', 'wss')
        out = OrderedDict([
            ('type', 'vless'),
            ('tag', tag),
            ('server', proxy['server']),
            ('server_port', proxy['port']),
            ('uuid', proxy['uuid']),
            ('network', 'tcp' if ws else net)
        ])
        if proxy.get('flow'):
            out['flow'] = proxy['flow']
        if proxy.get('encryption'):
            out['encryption'] = proxy['encryption']
        # TLS configuration
        if proxy.get('tls'):
            tls_config = {}
            if proxy.get('tls_opts', {}).get('server_name'):
                tls_config['server_name'] = proxy['tls_opts']['server_name']
            if proxy.get('tls_opts', {}).get('reality'):
                reality = proxy['tls_opts']['reality']
                tls_config['reality'] = {
                    'enabled': True,
                    'public_key': reality['public_key'],
                    'short_id': reality.get('short_id', '')
                }
            out['tls'] = tls_config
        # Transport configuration
        if ws and proxy.get('transport'):
            transport = {}
            if proxy['transport'].get('type'):
                transport['type'] = proxy['transport']['type']
            if proxy['transport'].get('path'):
                transport['path'] = proxy['transport']['path']
            if transport:
                out['transport'] = transport

        return out

    elif proxy['type'] == 'trojan':
        out = {
            'type': 'trojan',
            'tag': tag,
            'server': proxy['server'],
            'server_port': proxy['port'],
            'password': proxy['password'],
        }

        # TLS configuration
        if proxy.get('tls_opts', {}).get('server_name'):
            out['tls'] = {
                'server_name': proxy['tls_opts']['server_name']
            }

        return out

    elif proxy['type'] == 'ss':
        return {
            'type': 'shadowsocks',
            'tag': tag,
            'server': proxy['server'],
            'server_port': proxy['port'],
            'method': proxy['method'],
            'password': proxy['password'],
        }

    elif proxy['type'] == 'socks':
        out = {
            'type': 'socks',
            'tag': tag,
            'server': proxy['server'],
            'server_port': proxy['port'],
            'version': '5',
        }
        if proxy['username']:
            out['username'] = proxy['username']
        if proxy['password']:
            out['password'] = proxy['password']
        return out

    elif proxy['type'] == 'hysteria2':
        out = {
            'type': 'hysteria2',
            'tag': tag,
            'server': proxy['server'],
            'server_port': proxy['port'],
            'password': proxy['password'],
        }

        # TLS configuration
        if proxy.get('tls_opts', {}).get('server_name'):
            out['tls'] = {
                'server_name': proxy['tls_opts']['server_name']
            }

        return out

    elif proxy['type'] == 'tuic':
        out = {
            'type': 'tuic',
            'tag': tag,
            'server': proxy['server'],
            'server_port': proxy['port'],
            'uuid': proxy['uuid'],
            'password': proxy['password'],
        }

        # TLS configuration
        if proxy.get('tls_opts', {}).get('server_name'):
            out['tls'] = {
                'server_name': proxy['tls_opts']['server_name']
            }

        return out

    else:
        # Unsupported protocol for sing-box or skip
        return None


# ------ MAIN ENTRYPOINT ------
if __name__ == '__main__':
    if len(sys.argv) != 6:
        print(
            "Usage: python sub2clash_singbox.py <sub_url_or_file> <clash_template.yaml> <singbox_template.json> <output_clash.yaml> <output_singbox.json>")
        print("       <sub_url_or_file> can be a URL (https://...) or local file path")
        sys.exit(1)
    (input_source, clash_tmpl, singbox_tmpl, out_clash, out_sb) = sys.argv[1:]

    # Determine if input is URL or local file
    if input_source.startswith(('http://', 'https://', 'ftp://')):
        print(f"[+] Download: {input_source}")
        lines = download_subscription(input_source)
    else:
        print(f"[+] Read local file: {input_source}")
        lines = read_local_subscription(input_source)
    print(f"[+] {len(lines)} lines found in sub...")

    proxies = []
    for line in lines:
        px = parse_proxy_line(line)
        if validate_proxy(px):
            proxies.append(px)

    # NEW: Warn and halt if no valid proxies!
    if not proxies:
        print('[FATAL] No valid proxies remain after filtering subscription. Check your sub or filtering policy!')
        sys.exit(2)

    print(f"[+] Parsed proxies: {len(proxies)}")

    # Show protocol distribution
    protocol_count = {}
    for proxy in proxies:
        protocol = proxy['type']
        protocol_count[protocol] = protocol_count.get(protocol, 0) + 1

    print(f"[+] Protocol distribution: {protocol_count}")

    # --- Handle Clash Meta YAML ---
    print(f"[~] Processing Clash...")
    clash_cfg = read_yaml_file(clash_tmpl)
    clash_cfg = update_clash_proxies(clash_cfg, proxies)
    write_yaml_file(clash_cfg, out_clash)
    print(f"[✓] Output Clash config: {out_clash}")

    # --- Handle Singbox JSON ---
    print(f"[~] Processing Singbox...")
    singbox_cfg = read_json_file(singbox_tmpl)
    singbox_cfg = update_singbox_outbounds(singbox_cfg, proxies)
    write_json_file(singbox_cfg, out_sb)
    print(f"[✓] Output Singbox config: {out_sb}")
    print("Done!")
