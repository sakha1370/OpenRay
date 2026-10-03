from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from functools import cached_property
from urllib.parse import parse_qsl, unquote, urlsplit

IDENTITY_VERSION = 2
SCHEMES = frozenset(
    {
        "vmess",
        "vless",
        "trojan",
        "ss",
        "ssr",
        "hysteria",
        "hysteria2",
        "hy2",
        "tuic",
        "juicity",
        "wireguard",
        "wg",
        "socks",
        "socks5",
        "http",
        "https",
    }
)
ALIASES = {"hy2": "hysteria2", "wg": "wireguard", "socks5": "socks"}
QUERY_ALIASES = {
    "network": "type",
    "servername": "sni",
    "allow_insecure": "allowinsecure",
    "packet-encoding": "packetencoding",
    "spiderx": "spx",
}
URI_PATTERN = re.compile(
    r"(?:" + "|".join(sorted(SCHEMES, key=len, reverse=True)) + r")://[^\s<>\"'`]+", re.I
)


class ParseError(ValueError):
    """Invalid input; messages deliberately do not contain credentials."""


class Outcome(StrEnum):
    SUCCESS = "success"
    PROXY_FAILURE = "proxy_failure"
    TIMEOUT = "timeout"
    UNSUPPORTED = "unsupported"
    INVALID_CONFIG = "invalid_config"
    CORE_FAILURE = "core_failure"
    SOURCE_FAILURE = "source_failure"
    TARGET_FAILURE = "target_failure"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class Observation:
    outcome: Outcome
    elapsed_ms: float = 0
    detail: str = ""
    status: int | None = None
    core: str = ""


def b64decode(value: str) -> bytes:
    try:
        raw = value.encode("ascii")
        return base64.b64decode(raw + b"=" * (-len(raw) % 4), altchars=b"-_", validate=True)
    except (ValueError, UnicodeError) as exc:
        raise ParseError("invalid base64") from exc


def _host(value: str) -> str:
    if not value or any(c.isspace() for c in value) or any(c in value for c in "/@?#"):
        raise ParseError("invalid server")
    try:
        return ipaddress.ip_address(value.strip("[]")).compressed
    except ValueError:
        try:
            return value.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ParseError("invalid hostname") from exc


def _port(value: object) -> int:
    try:
        n = int(str(value))
    except ValueError as exc:
        raise ParseError("invalid port") from exc
    if not 1 <= n <= 65535:
        raise ParseError("port outside 1..65535")
    return n


def xray_uuid(value: str) -> str:
    # Xray's documented short custom IDs use UUIDv5 with the nil namespace.
    try:
        return str(uuid.UUID(value))
    except ValueError:
        if 1 <= len(value.encode("utf-8")) <= 30:
            return str(uuid.uuid5(uuid.UUID(int=0), value))
        raise ParseError("invalid UUID/custom ID")


@dataclass(frozen=True)
class Proxy:
    uri: str = field(repr=False)
    scheme: str
    server: str
    port: int
    username: str = field(default="", repr=False)
    password: str = field(default="", repr=False)
    params: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    metadata: str = field(default="{}", repr=False)
    remark: str = ""

    def get(self, name: str, default: str = "") -> str:
        for key, value in self.params:
            if QUERY_ALIASES.get(key.lower(), key.lower()) == QUERY_ALIASES.get(name.lower(), name.lower()):
                return value
        if self.scheme == "vmess":
            for key, value in self.metadata_fields.items():
                mapped = (
                    "headertype" if key.lower() == "type" else QUERY_ALIASES.get(key.lower(), key.lower())
                )
                if mapped == QUERY_ALIASES.get(name.lower(), name.lower()):
                    return str(value)
        return default

    @cached_property
    def metadata_fields(self) -> dict:
        return json.loads(self.metadata)

    @property
    def transport(self) -> str:
        return self.get("type", self.get("network", "tcp")).lower().replace("gun", "grpc")

    @cached_property
    def identity(self) -> str:
        # JSON boundaries prevent delimiter collisions; repeat-value order is retained.
        grouped: dict[str, list[str]] = {}
        for key, value in self.params:
            grouped.setdefault(QUERY_ALIASES.get(key.lower(), key.lower()), []).append(value)
        data = [
            IDENTITY_VERSION,
            self.scheme,
            self.server,
            self.port,
            self.username,
            self.password,
            grouped,
            self.metadata_fields,
        ]
        encoded = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode()).hexdigest()

    @property
    def country(self) -> str:
        match = re.search(r"\[OpenRay\].*?\b([A-Z]{2})-\d+", self.remark)
        return match[1] if match else "XX"


def _parse_uri(uri: str) -> Proxy:
    uri = uri.strip()
    if len(uri) > 65536 or any(c.isspace() for c in uri.split("#", 1)[0]):
        raise ParseError("oversized URI or whitespace in connection")
    if "://" not in uri:
        raise ParseError("missing scheme")
    scheme, payload = uri.split("://", 1)
    scheme = ALIASES.get(scheme.lower(), scheme.lower())
    if scheme not in SCHEMES:
        raise ParseError("unknown protocol")
    if re.search(r"[a-z0-9]+://", payload.split("#", 1)[0], re.I):
        raise ParseError("concatenated connection URIs")
    if scheme == "vmess":
        try:
            data = json.loads(b64decode(payload.split("#", 1)[0]))
            server, port = _host(data["add"]), _port(data["port"])
            user = str(data["id"])
            user = xray_uuid(user)
            remark = str(data.get("ps", ""))
            extra = {k: v for k, v in data.items() if k not in {"ps", "add", "port", "id", "v"}}
            params = {
                "type": data.get("net", "tcp"),
                "path": data.get("path", ""),
                "host": data.get("host", ""),
                "sni": data.get("sni", ""),
                "security": "tls" if str(data.get("tls", "")).lower() in {"tls", "true", "1"} else "none",
                "serviceName": data.get(
                    "serviceName", data.get("path", "") if data.get("net") == "grpc" else ""
                ),
                "cipher": data.get("scy", data.get("cipher", "auto")),
                "aid": data.get("aid", "0"),
            }
            return Proxy(
                uri,
                scheme,
                server,
                port,
                user,
                params=tuple((k, str(v)) for k, v in params.items()),
                metadata=json.dumps(extra, sort_keys=True),
                remark=remark,
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise ParseError("invalid VMess JSON") from exc
    if scheme == "ssr":
        try:
            body = b64decode(payload.split("#", 1)[0]).decode()
            connection, _, query = body.partition("/?")
            server, port, protocol, method, obfs, password = connection.rsplit(":", 5)
            params = tuple(parse_qsl(query, keep_blank_values=True))
            # Remarks are presentation metadata, not part of SSR connection identity.
            remark = next((b64decode(v).decode() for k, v in params if k == "remarks"), "")
            params = tuple((k, v) for k, v in params if k not in {"remarks", "group"})
            params += (("protocol", protocol), ("method", method), ("obfs", obfs))
            return Proxy(
                uri,
                scheme,
                _host(server),
                _port(port),
                password=b64decode(password).decode(),
                params=params,
                remark=remark,
            )
        except (ValueError, UnicodeError) as exc:
            raise ParseError("invalid SSR connection") from exc
    if scheme == "ss":
        connection, _, remark = payload.partition("#")
        authority, _, query = connection.partition("?")
        authority = authority.rstrip("/")
        if "@" not in authority:
            authority = b64decode(authority).decode("utf-8")
        auth, separator, address = authority.rpartition("@")
        if not separator:
            raise ParseError("missing Shadowsocks endpoint")
        auth = unquote(auth)
        if ":" not in auth:
            auth = b64decode(auth).decode("utf-8")
        method, separator, password = auth.partition(":")
        if not separator or not method or not password:
            raise ParseError("missing Shadowsocks credentials")
        try:
            parsed = urlsplit("ss://" + address)
            return Proxy(
                uri,
                scheme,
                _host(parsed.hostname or ""),
                _port(parsed.port),
                method,
                password,
                tuple(parse_qsl(query, keep_blank_values=True)),
                remark=unquote(remark),
            )
        except ValueError as exc:
            raise ParseError("invalid Shadowsocks endpoint") from exc
    try:
        parsed = urlsplit(uri)
        default_port = {
            "trojan": 443,
            "hysteria2": 443,
            "hysteria": 443,
            "https": 443,
            "http": 80,
            "socks": 1080,
        }.get(scheme)
        port = _port(parsed.port if parsed.port is not None else default_port)
        user, password = unquote(parsed.username or ""), unquote(parsed.password or "")
        params = tuple(parse_qsl(parsed.query, keep_blank_values=True))
        if parsed.path and parsed.path != "/":
            params += (("uri_path", parsed.path),)
        if scheme == "vless":
            user = xray_uuid(user)
        elif scheme in {"tuic", "juicity"}:
            uuid.UUID(user)
        if scheme in {"trojan", "hysteria2", "juicity"} and not user:
            raise ParseError("missing authentication")
        if scheme == "tuic" and not password:
            raise ParseError("missing TUIC password")
        proxy = Proxy(
            uri,
            scheme,
            _host(parsed.hostname or ""),
            port,
            user,
            password,
            params,
            remark=unquote(parsed.fragment),
        )
        if scheme == "wireguard" and not (proxy.get("privatekey") or user):
            raise ParseError("missing WireGuard private key")
        return proxy
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, ParseError):
            raise
        raise ParseError("invalid connection authority") from exc


def parse_uri(uri: str) -> Proxy:
    try:
        return _parse_uri(uri)
    except ParseError:
        raise
    except (UnicodeError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ParseError("invalid protocol encoding or fields") from exc


def extract_uris(content: str, *, encoded: bool = False) -> list[str]:
    if len(content) > 10 * 1024 * 1024:
        raise ParseError("subscription exceeds decoded limit")
    if encoded or not URI_PATTERN.search(content):
        for _ in range(2):
            try:
                content = b64decode("".join(content.split())).decode("utf-8")
            except (ParseError, UnicodeError):
                break
            if URI_PATTERN.search(content):
                break
    return [m[0].rstrip(",;") for m in URI_PATTERN.finditer(content)]
