from __future__ import annotations

import copy
import json
import re
from pathlib import Path

from .domain import QUERY_ALIASES, Proxy


class Unsupported(ValueError):
    pass


FINGERPRINTS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}
# Equivalent Shadowsocks cipher spellings. Each pinned core accepts only the method
# sets below (verified with its own config checker); others make the core exit at startup.
SS_ALIASES = {
    "chacha20-poly1305": "chacha20-ietf-poly1305",
    "xchacha20-poly1305": "xchacha20-ietf-poly1305",
    "aead_aes_128_gcm": "aes-128-gcm",
    "aead_aes_256_gcm": "aes-256-gcm",
    "aead_chacha20_poly1305": "chacha20-ietf-poly1305",
    "aead_xchacha20_poly1305": "xchacha20-ietf-poly1305",
}
XRAY_SS_METHODS = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
SINGBOX_SS_METHODS = XRAY_SS_METHODS | {
    "none",
    "aes-192-gcm",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
}
MIHOMO_SS_METHODS = SINGBOX_SS_METHODS | {"chacha20"}
# Xray rejects REALITY over other transports; sing-box can still represent them.
XRAY_REALITY_NETWORKS = {"raw", "xhttp", "grpc"}
COMMON_PARAMS = {
    "type",
    "path",
    "host",
    "security",
    "sni",
    "peer",
    "fp",
    "fingerprint",
    "alpn",
    "allowinsecure",
    "insecure",
    "pbk",
    "sid",
    "flow",
    "encryption",
    "cipher",
    "aid",
    "servicename",
    "service",
    "headerType".lower(),
    "packetencoding",
    "ed",
    "eh",
    "max_early_data",
    "early_data_header_name",
    "plugin",
    "auth",
    "upmbps",
    "downmbps",
    "obfs",
    "obfs-password",
    "obfspassword",
    "congestion_control",
    "udp_relay_mode",
    "zero_rtt_handshake",
    "protocol",
    "method",
    "protoparam",
    "obfsparam",
    "privatekey",
    "secretkey",
    "publickey",
    "public-key",
    "presharedkey",
    "address",
    "localaddress",
    "reserved",
    "telegram",
    "descriptions",
    "_t",
}


PROTOCOL_FIELDS = {
    "flow": {"vless"},
    "encryption": {"vless"},
    "cipher": {"vmess"},
    "aid": {"vmess"},
    "packetencoding": {"vless", "vmess"},
    "plugin": {"ss"},
    "auth": {"hysteria"},
    "upmbps": {"hysteria"},
    "downmbps": {"hysteria"},
    "obfs": {"ssr", "hysteria", "hysteria2"},
    "obfs-password": {"hysteria2"},
    "obfspassword": {"hysteria2"},
    "congestion_control": {"tuic"},
    "udp_relay_mode": {"tuic"},
    "zero_rtt_handshake": {"tuic"},
    "protocol": {"ssr", "hysteria"},
    "method": {"ssr"},
    "protoparam": {"ssr"},
    "obfsparam": {"ssr"},
    **{
        key: {"wireguard"}
        for key in (
            "privatekey",
            "secretkey",
            "publickey",
            "public-key",
            "presharedkey",
            "address",
            "localaddress",
            "reserved",
        )
    },
}


def supported_params(p: Proxy, extra: set[str] = frozenset()):
    keys = {QUERY_ALIASES.get(k.lower(), k.lower()) for k, v in p.params if v}
    if p.scheme == "vmess":
        keys |= {
            QUERY_ALIASES.get(k.lower(), k.lower())
            for k, v in p.metadata_fields.items()
            if v is not None and v != "" and k.lower() not in {"net", "tls", "scy", "type"}
        }
    if keys - COMMON_PARAMS - extra:
        # Do not echo unknown names/values: inputs can put credentials in either.
        raise Unsupported("connection has parameters not representable by this profile")
    if p.scheme == "hysteria" and p.get("protocol", "udp").lower() != "udp":
        raise Unsupported("Hysteria transport requires a different client profile")
    if any(p.scheme not in PROTOCOL_FIELDS[key] for key in keys & PROTOCOL_FIELDS.keys()):
        raise Unsupported("connection includes options belonging to a different protocol")


def _bool(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "on"}


def vmess_security(p: Proxy) -> str:
    # JSON null was stored as the string "None"; unset means auto. Every pinned core accepts only these.
    fields = p.metadata_fields
    value = p.get("cipher", "auto").lower()
    if fields.get("scy", fields.get("cipher", "")) is None or value in {"", "null"}:
        value = "auto"
    if value not in {"auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"}:
        raise Unsupported("VMess security unsupported")
    return value


def ss_method(p: Proxy, supported: set[str]) -> str:
    method = p.username.lower()
    method = SS_ALIASES.get(method, method)
    if method not in supported:
        raise Unsupported("Shadowsocks cipher unsupported by this core")
    if method.startswith("2022-blake3-"):
        from .domain import b64decode

        size = 16 if "aes-128" in method else 32
        # Every client refuses a 2022 key of the wrong size; "server:user" keys are checked separately.
        try:
            valid = all(len(b64decode(key)) == size for key in p.password.split(":"))
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("invalid Shadowsocks 2022 key")
    return method


def tls_options(p: Proxy) -> dict | None:
    security = p.get(
        "security",
        "tls"
        if p.scheme in {"trojan", "hysteria", "hysteria2", "tuic", "https"} or p.transport == "wss"
        else "none",
    ).lower()
    if security not in {"tls", "reality", "none", ""}:
        raise Unsupported("unknown transport security mode")
    if security not in {"tls", "reality"}:
        return None
    tls = {
        "enabled": True,
        "server_name": p.get("sni", p.get("peer", p.server)),
        "insecure": _bool(p.get("allowInsecure", p.get("insecure", "false"))),
    }
    if p.get("alpn"):
        tls["alpn"] = p.get("alpn").split(",")
    fp = p.get("fp", p.get("fingerprint"))
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    if security == "reality":
        if not p.get("pbk"):
            raise Unsupported("Reality public key missing")
        from .domain import b64decode

        if len(b64decode(p.get("pbk"))) != 32:
            raise ValueError("invalid Reality public key")
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", p.get("sid")):
            raise Unsupported("Reality short ID must be at most eight hexadecimal bytes")
        tls["reality"] = {"enabled": True, "public_key": p.get("pbk"), "short_id": p.get("sid")}
        tls.setdefault("utls", {"enabled": True, "fingerprint": "chrome"})
    return tls


def singbox_outbound(p: Proxy) -> dict:
    supported_params(p)
    kind = {"ss": "shadowsocks", "socks": "socks", "https": "http", "wireguard": "wireguard"}.get(
        p.scheme, p.scheme
    )
    if kind in {"ssr", "juicity", "wireguard"}:
        raise Unsupported(f"{kind} requires another core or an endpoint profile")
    ob = {"type": kind, "tag": "p-" + p.identity[:16], "server": p.server, "server_port": p.port}
    if p.scheme in {"vless", "vmess", "tuic"}:
        ob["uuid"] = p.username
    if p.scheme == "vless":
        if p.get("encryption", "none") != "none":
            raise Unsupported("sing-box cannot represent VLESS encryption")
        if p.get("flow"):
            if p.get("flow") != "xtls-rprx-vision":
                raise Unsupported("sing-box VLESS flow unsupported")
            ob["flow"] = p.get("flow")
        if p.get("packetEncoding"):
            if p.get("packetEncoding") not in {"xudp", "packetaddr", "none"}:
                raise Unsupported("sing-box packet encoding unsupported")
            ob["packet_encoding"] = "" if p.get("packetEncoding") == "none" else p.get("packetEncoding")
    elif p.scheme == "vmess":
        if p.get("packetEncoding"):
            raise Unsupported("VMess packet encoding requires the Xray profile")
        ob.update(security=vmess_security(p), alter_id=int(p.get("aid", "0")))
    elif p.scheme == "trojan":
        ob["password"] = p.username + ((":" + p.password) if p.password else "")
    elif p.scheme == "ss":
        ob.update(method=ss_method(p, SINGBOX_SS_METHODS), password=p.password)
        if p.get("plugin"):
            plugin, _, options = p.get("plugin").partition(";")
            # sing-box knows obfs only as obfs-local and rejects empty option items.
            plugin = {"simple-obfs": "obfs-local", "obfs": "obfs-local"}.get(plugin, plugin)
            ob.update(plugin=plugin, plugin_opts=";".join(item for item in options.split(";") if item))
    elif p.scheme in {"socks", "http", "https"}:
        if p.username:
            ob.update(username=p.username, password=p.password)
        if p.scheme == "socks":
            ob["version"] = "5"
    elif p.scheme == "hysteria2":
        ob["password"] = p.username + ((":" + p.password) if p.password else "")
        if p.get("obfs"):
            if not p.get("obfs-password", p.get("obfsPassword")):
                raise Unsupported("Hysteria2 obfs requires a password")
            ob["obfs"] = {"type": p.get("obfs"), "password": p.get("obfs-password", p.get("obfsPassword"))}
    elif p.scheme == "hysteria":
        ob.update(
            auth_str=p.get("auth", p.username),
            up_mbps=int(p.get("upmbps", "100")),
            down_mbps=int(p.get("downmbps", "100")),
        )
        if p.get("obfs"):
            ob["obfs"] = p.get("obfs")
    elif p.scheme == "tuic":
        ob.update(
            password=p.password,
            congestion_control=p.get("congestion_control", "cubic"),
            udp_relay_mode=p.get("udp_relay_mode", "native"),
            zero_rtt_handshake=_bool(p.get("zero_rtt_handshake", "false")),
        )
    else:
        if p.scheme not in {"vless", "vmess"}:
            raise Unsupported("unimplemented sing-box protocol")
    tls = tls_options(p)
    if tls:
        if tls.get("utls", {}).get("fingerprint") not in FINGERPRINTS | {None}:
            raise Unsupported("sing-box fingerprint profile unsupported")
        ob["tls"] = tls
    if p.scheme in {"vless", "vmess", "trojan"}:
        network = p.transport
        # Xray accepts a path with a stray '%', sing-box rejects the whole configuration file.
        if network in {"ws", "wss", "httpupgrade"} and re.search(r"%(?![0-9A-Fa-f]{2})", p.get("path")):
            raise Unsupported("sing-box rejects malformed path escapes")
        if network in {"ws", "wss"}:
            ob["transport"] = {"type": "ws", "path": p.get("path", "/") or "/"}
            if p.get("host"):
                ob["transport"]["headers"] = {"Host": p.get("host")}
            if p.get("ed", p.get("max_early_data")):
                ob["transport"]["max_early_data"] = int(p.get("ed", p.get("max_early_data")))
                ob["transport"]["early_data_header_name"] = p.get(
                    "eh", p.get("early_data_header_name", "Sec-WebSocket-Protocol")
                )
        elif network == "grpc":
            ob["transport"] = {"type": "grpc", "service_name": p.get("serviceName", p.get("service"))}
        elif network == "httpupgrade":
            ob["transport"] = {"type": "httpupgrade", "path": p.get("path", "/"), "host": p.get("host")}
        elif network in {"http", "h2"}:
            ob["transport"] = {
                "type": "http",
                "path": p.get("path", "/"),
                "host": p.get("host", p.server).split(","),
            }
        elif network not in {"tcp", "raw", ""}:
            raise Unsupported("sing-box transport unsupported")
        elif p.get("headerType", "none") != "none":
            raise Unsupported("TCP HTTP camouflage unsupported by sing-box")
    return ob


def wireguard_endpoint(p: Proxy) -> dict:
    supported_params(p)
    private = p.get("privatekey", p.get("secretkey", p.username))
    public = p.get("publickey", p.get("public-key"))
    if not private or not public:
        raise Unsupported("WireGuard keys missing")
    from .domain import b64decode

    for key in (private, public, p.get("presharedkey")):
        if key and len(b64decode(key)) != 32:
            raise ValueError("WireGuard keys must contain 32 bytes")
    peer = {"address": p.server, "port": p.port, "public_key": public, "allowed_ips": ["0.0.0.0/0", "::/0"]}
    if p.get("presharedkey"):
        peer["pre_shared_key"] = p.get("presharedkey")
    if p.get("reserved"):
        peer["reserved"] = [int(x) for x in p.get("reserved").split(",")]
        if len(peer["reserved"]) != 3 or any(not 0 <= b <= 255 for b in peer["reserved"]):
            raise ValueError("invalid WireGuard reserved bytes")
    return {
        "type": "wireguard",
        "tag": "p-" + p.identity[:16],
        "system": False,
        "workers": 2,
        "address": p.get("address", p.get("localAddress", "10.0.0.2/32")).split(","),
        "private_key": private,
        "peers": [peer],
    }


def xray_outbound(p: Proxy) -> dict:
    supported_params(p, {"spx", "mode", "extra", "authority", "multimode"})
    if p.scheme not in {"vless", "vmess", "trojan", "ss", "socks", "http", "https"}:
        raise Unsupported("protocol requires complementary core")
    if p.scheme == "ss" and p.get("plugin"):
        raise Unsupported("Shadowsocks plugin requires complementary core")
    ob = {"protocol": {"ss": "shadowsocks", "https": "http"}.get(p.scheme, p.scheme), "tag": "candidate"}
    if p.scheme in {"vless", "vmess"}:
        user = {"id": p.username}
        if p.scheme == "vless":
            user.update(encryption=p.get("encryption", "none"))
            if p.get("flow"):
                if p.get("flow") not in {"xtls-rprx-vision", "xtls-rprx-vision-udp443"}:
                    raise Unsupported("Xray VLESS flow unsupported")
                user["flow"] = p.get("flow")
        else:
            user.update(alterId=int(p.get("aid", "0")), security=vmess_security(p))
        ob["settings"] = {"vnext": [{"address": p.server, "port": p.port, "users": [user]}]}
        if p.get("packetEncoding"):
            ob["settings"]["packetEncoding"] = p.get("packetEncoding")
    else:
        server = {"address": p.server, "port": p.port}
        if p.scheme == "trojan":
            server["password"] = p.username + ((":" + p.password) if p.password else "")
        elif p.scheme == "ss":
            server.update(method=ss_method(p, XRAY_SS_METHODS), password=p.password)
        elif p.username:
            server["users"] = [{"user": p.username, "pass": p.password}]
        ob["settings"] = {"servers": [server]}
    network = p.transport
    stream = {"network": "raw" if network in {"tcp", "raw", ""} else network}
    if network in {"ws", "wss"}:
        stream["network"] = "ws"
        stream["wsSettings"] = {
            "path": p.get("path", "/") or "/",
            "headers": {"Host": p.get("host")} if p.get("host") else {},
        }
        if p.get("ed", p.get("max_early_data")):
            stream["wsSettings"]["maxEarlyData"] = int(p.get("ed", p.get("max_early_data")))
            stream["wsSettings"]["earlyDataHeaderName"] = p.get(
                "eh", p.get("early_data_header_name", "Sec-WebSocket-Protocol")
            )
    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": p.get("serviceName", p.get("service")),
            "multiMode": _bool(p.get("multiMode", "false")),
        }
        if p.get("authority"):
            stream["grpcSettings"]["authority"] = p.get("authority")
    elif network in {"xhttp", "splithttp"}:
        stream["network"] = "xhttp"
        settings = {"path": p.get("path", "/"), "host": p.get("host"), "mode": p.get("mode", "auto")}
        if p.get("extra"):
            settings["extra"] = json.loads(p.get("extra"))
        stream["xhttpSettings"] = settings
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": p.get("path", "/"), "host": p.get("host")}
    elif network in {"tcp", "raw", ""}:
        if p.get("headerType", "none") == "http":
            stream["rawSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "path": [p.get("path", "/")],
                        "headers": {"Host": p.get("host", p.server).split(",")},
                    },
                }
            }
        elif p.get("headerType", "none") != "none":
            raise Unsupported("unknown TCP header type")
    else:
        raise Unsupported("Xray transport unsupported")
    tls = tls_options(p)
    if tls:
        if tls.get("insecure"):
            raise Unsupported("pinned Xray removed allowInsecure; use sing-box for this connection")
        reality = tls.get("reality")
        if reality and stream["network"] not in XRAY_REALITY_NETWORKS:
            raise Unsupported("Xray REALITY transport unsupported")
        stream["security"] = "reality" if reality else "tls"
        settings = {
            "serverName": tls["server_name"],
            "fingerprint": tls.get("utls", {}).get("fingerprint", "chrome"),
        }
        if reality:
            settings.update(
                publicKey=reality["public_key"], shortId=reality["short_id"], spiderX=p.get("spx"), show=False
            )
        else:
            if "alpn" in tls:
                settings["alpn"] = tls["alpn"]
        stream["realitySettings" if reality else "tlsSettings"] = settings
    ob["streamSettings"] = stream
    return ob


def clash_plugin(value: str) -> dict:
    # SIP003 option names differ from mihomo's typed plugin-opts; mihomo rejects the whole file otherwise.
    plugin, _, options = value.partition(";")
    opts = dict(item.split("=", 1) if "=" in item else (item, "true") for item in options.split(";") if item)
    if plugin in {"obfs-local", "simple-obfs", "obfs"}:
        mode = opts.get("obfs", opts.get("mode"))
        if mode not in {"http", "tls"}:
            raise Unsupported("obfs plugin mode missing")
        host = opts.get("obfs-host", opts.get("host"))
        return {"plugin": "obfs", "plugin-opts": {"mode": mode, **({"host": host} if host else {})}}
    if plugin == "v2ray-plugin":
        if opts.get("mode", "websocket") != "websocket":
            raise Unsupported("mihomo v2ray-plugin supports WebSocket only")
        if opts.get("sni", opts.get("host")) != opts.get("host"):
            raise Unsupported("v2ray-plugin SNI differs from host")
        result = {"mode": "websocket"}
        for key in ("host", "path"):
            if opts.get(key):
                result[key] = opts[key]
        for key in ("tls", "mux", "skip-cert-verify"):
            if key in opts:
                result[key] = opts[key].lower() not in {"0", "false", "no", "off"}
        return {"plugin": "v2ray-plugin", "plugin-opts": result}
    raise Unsupported("Shadowsocks plugin unsupported by mihomo profile")


def clash_proxy(p: Proxy) -> dict:
    supported_params(p)
    if (
        p.scheme in {"vless", "vmess", "trojan"}
        and p.transport in {"tcp", "raw", ""}
        and p.get("headerType", "none") != "none"
    ):
        raise Unsupported("TCP camouflage requires the Xray profile")
    if p.scheme == "juicity":
        raise Unsupported("Juicity unsupported by mihomo")
    if p.transport in {"xhttp", "splithttp"}:
        raise Unsupported("XHTTP unsupported by mihomo profile")
    name = (p.remark or f"{p.scheme}-{p.server}")[:100] + "-" + p.identity[:12]
    ob = {
        "name": name,
        "type": {"socks": "socks5", "https": "http"}.get(p.scheme, p.scheme),
        "server": p.server,
        "port": p.port,
    }
    if p.scheme in {"vless", "vmess", "tuic"}:
        ob["uuid"] = p.username
    if p.scheme == "vmess":
        if p.get("packetEncoding"):
            raise Unsupported("VMess packet encoding requires the Xray profile")
        ob.update(alterId=int(p.get("aid", "0")), cipher=vmess_security(p))
    elif p.scheme == "vless":
        if p.get("encryption", "none") != "none":
            raise Unsupported("mihomo VLESS encryption unsupported")
        if p.get("flow"):
            if p.get("flow").startswith(("xtls-rprx-direct", "xtls-rprx-origin", "xtls-rprx-splice")):
                raise Unsupported("mihomo removed legacy XTLS flows")
            ob["flow"] = p.get("flow")
        if p.get("packetEncoding"):
            ob["packet-encoding"] = p.get("packetEncoding")
    elif p.scheme in {"trojan", "hysteria2"}:
        ob["password"] = p.username + ((":" + p.password) if p.password else "")
    elif p.scheme in {"ss", "ssr"}:
        ob.update(
            cipher=ss_method(p, MIHOMO_SS_METHODS) if p.scheme == "ss" else p.get("method"),
            password=p.password,
        )
        if p.scheme == "ssr":
            ob.update(protocol=p.get("protocol"), obfs=p.get("obfs"))
            for key in ("protoparam", "obfsparam"):
                if p.get(key):
                    from .domain import b64decode

                    ob["protocol-param" if key == "protoparam" else "obfs-param"] = b64decode(
                        p.get(key)
                    ).decode()
        if p.get("plugin"):
            ob.update(clash_plugin(p.get("plugin")))
    elif p.scheme in {"socks", "http", "https"}:
        if p.username:
            ob.update(username=p.username, password=p.password)
    elif p.scheme == "tuic":
        if _bool(p.get("zero_rtt_handshake", "false")):
            raise Unsupported("TUIC zero-RTT requires the sing-box profile")
        ob.update(
            password=p.password,
            **{
                "congestion-controller": p.get("congestion_control", "cubic"),
                "udp-relay-mode": p.get("udp_relay_mode", "native"),
            },
        )
    elif p.scheme == "hysteria":
        ob.update(
            **{
                "auth-str": p.get("auth", p.username),
                "up": p.get("upmbps", "100"),
                "down": p.get("downmbps", "100"),
            }
        )
    elif p.scheme == "wireguard":
        import ipaddress

        endpoint = wireguard_endpoint(p)
        ob.update(
            **{
                "private-key": endpoint["private_key"],
                "public-key": endpoint["peers"][0]["public_key"],
                "udp": True,
            }
        )
        addresses = [ipaddress.ip_interface(value).ip for value in endpoint["address"]]
        for version, key in ((4, "ip"), (6, "ipv6")):
            values = [str(a) for a in addresses if a.version == version]
            if len(values) > 1:
                raise Unsupported("mihomo permits one WireGuard address per family")
            if values:
                ob[key] = values[0]
        if "reserved" in endpoint["peers"][0]:
            ob["reserved"] = endpoint["peers"][0]["reserved"]
        if "pre_shared_key" in endpoint["peers"][0]:
            ob["preshared-key"] = endpoint["peers"][0]["pre_shared_key"]
    tls = tls_options(p)
    if tls:
        if tls.get("utls", {}).get("fingerprint") not in FINGERPRINTS | {None}:
            raise Unsupported("mihomo fingerprint profile unsupported")
        ob.update(
            tls=True,
            **{
                "servername": tls["server_name"],
                "sni": tls["server_name"],
                "skip-cert-verify": tls.get("insecure", False),
            },
        )
        if "utls" in tls:
            ob["client-fingerprint"] = tls["utls"]["fingerprint"]
        if "alpn" in tls:
            ob["alpn"] = tls["alpn"]
        if "reality" in tls:
            ob["reality-opts"] = {
                "public-key": tls["reality"]["public_key"],
                "short-id": tls["reality"]["short_id"],
            }
    if p.scheme in {"vless", "vmess", "trojan"} and p.transport not in {"tcp", "raw", ""}:
        ob["network"] = p.transport
        if p.transport == "ws":
            ob["ws-opts"] = {
                "path": p.get("path", "/"),
                "headers": {"Host": p.get("host")} if p.get("host") else {},
            }
            if p.get("ed", p.get("max_early_data")):
                ob["ws-opts"]["max-early-data"] = int(p.get("ed", p.get("max_early_data")))
                ob["ws-opts"]["early-data-header-name"] = p.get(
                    "eh", p.get("early_data_header_name", "Sec-WebSocket-Protocol")
                )
        elif p.transport == "grpc":
            ob["grpc-opts"] = {"grpc-service-name": p.get("serviceName", p.get("service"))}
        elif p.transport == "httpupgrade":
            raise Unsupported("HTTPUpgrade unsupported by mihomo profile")
        else:
            raise Unsupported("mihomo transport unsupported")
    if p.scheme == "hysteria2" and p.get("obfs"):
        if not p.get("obfs-password", p.get("obfsPassword")):
            raise Unsupported("mihomo requires the Hysteria2 obfs password")
        ob.update(obfs=p.get("obfs"), **{"obfs-password": p.get("obfs-password", p.get("obfsPassword"))})
    return ob


def convert(
    proxies: list[Proxy],
    clash_template: dict | None = None,
    singbox_template: dict | None = None,
    *,
    portable: bool = True,
) -> tuple[dict, dict, list[dict]]:
    report: list[dict] = []
    clash = (
        copy.deepcopy(clash_template)
        if clash_template is not None
        else {"mixed-port": 7892, "mode": "rule", "rules": ["MATCH,PROXY"]}
    )
    sing = (
        copy.deepcopy(singbox_template)
        if singbox_template is not None
        else {
            "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7892}],
            "dns": {"servers": [{"type": "udp", "tag": "dns1", "server": "1.1.1.1"}]},
            "route": {"final": "proxy", "default_domain_resolver": "dns1"},
        }
    )
    clashes, outbounds, endpoints = [], [], []
    for p in sorted({p.identity: p for p in proxies}.values(), key=lambda p: p.identity):
        for format_name, renderer, target in (
            ("clash", clash_proxy, clashes),
            (
                "singbox",
                wireguard_endpoint if p.scheme == "wireguard" else singbox_outbound,
                endpoints if p.scheme == "wireguard" else outbounds,
            ),
        ):
            try:
                target.append(renderer(p))
            except (Unsupported, ValueError, KeyError) as exc:
                report.append(
                    {
                        "id": p.identity,
                        "scheme": p.scheme,
                        "format": format_name,
                        "reason": str(exc)
                        if isinstance(exc, Unsupported)
                        else "invalid protocol configuration",
                    }
                )
    clash.update(
        {
            "allow-lan": False,
            "bind-address": "127.0.0.1",
            "external-controller": "127.0.0.1:9090",
            "proxies": clashes,
        }
    )
    if portable and "tun" in clash:
        clash["tun"]["enable"] = False
    if "dns" in clash:
        clash["dns"]["listen"] = "127.0.0.1:1053"
    names = [p["name"] for p in clashes] or ["DIRECT"]
    clash["proxy-groups"] = [
        {
            "name": "AUTO",
            "type": "url-test",
            "url": "https://cp.cloudflare.com/generate_204",
            "interval": 300,
            "proxies": names,
        },
        {"name": "PROXY", "type": "select", "proxies": ["AUTO", "DIRECT"] + names},
    ]
    tags = [p["tag"] for p in outbounds + endpoints] or ["direct"]
    sing["outbounds"] = [
        {"type": "selector", "tag": "proxy", "outbounds": ["auto", "direct"] + tags},
        {
            "type": "urltest",
            "tag": "auto",
            "outbounds": tags,
            "url": "https://cp.cloudflare.com/generate_204",
            "interval": "5m",
        },
        {"type": "direct", "tag": "direct"},
    ] + outbounds
    sing["endpoints"] = endpoints
    for inbound in sing.get("inbounds", []):
        if inbound.get("type") != "tun":
            inbound["listen"] = "127.0.0.1"
        inbound.pop("sniff", None)
        inbound.pop("sniff_override_destination", None)
    # Portable default. The source template retains the explicit TUN preset.
    if portable:
        sing["inbounds"] = [i for i in sing.get("inbounds", []) if i.get("type") != "tun"]
    sing.get("dns", {}).pop("fakeip", None)
    lock_path = Path(__file__).with_name("assets") / "rules.lock.json"
    if lock_path.is_file():
        pins = json.loads(lock_path.read_text())
        for rule_set in sing.get("route", {}).get("rule_set", []):
            url = rule_set.get("url", "")
            for repository in ("sing-geoip", "sing-geosite"):
                old = f"https://raw.githubusercontent.com/SagerNet/{repository}/rule-set/"
                if url.startswith(old):
                    rule_set["url"] = url.replace(
                        old, f"https://raw.githubusercontent.com/SagerNet/{repository}/{pins[repository]}/"
                    )
        base = f"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/{pins['meta-rules-dat']}/"
        clash["geodata-url"] = {
            "geoip": base + "geoip.dat",
            "geosite": base + "geosite.dat",
            "mmdb": base + "country.mmdb",
            "asn": base + "GeoLite2-ASN.mmdb",
        }
    # Preserve routing policy using current reject action in place of removed block outbound.
    for rule in sing.get("route", {}).get("rules", []):
        if rule.get("outbound") == "block":
            rule.pop("outbound")
            rule["action"] = "reject"
    return clash, sing, report
