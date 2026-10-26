"""Iran-oriented triage of proxy share links: what to drop, what to repair and how to order the rest.

Everything here is pure (no network, no files) so tests can pin each rule; tools/iran_filter.py drives it
on a GitHub runner. A runner cannot observe Iranian ISPs, so each rule rests on published measurements and
names its source. Most sources are single anecdotal reports: the ordering is a heuristic, not a guarantee.
"""

from __future__ import annotations

import base64
import copy
import ipaddress
import json
import re
import uuid
from dataclasses import dataclass
from urllib.parse import quote, unquote

from .domain import TLS_BY_DEFAULT, ParseError, Proxy, b64decode, parse_uri
from .render import SS_ALIASES, XRAY_SS_METHODS, xray_outbound

# QUIC Initial packets are blocked on every ISP since 2025-06-17 (net4people/bbs#648), unidentified UDP is
# dropped on most (bbs#489) and WireGuard is blackholed (bbs#628).
UDP_SCHEMES = frozenset({"hysteria", "hysteria2", "tuic", "juicity", "wireguard"})
# Open relays with no authentication and a cleartext handshake: neither censorship resistant nor safe.
PLAINTEXT_SCHEMES = frozenset({"socks", "http", "https"})
# Xray, the default core of v2rayN and v2rayNG, cannot carry REALITY over other transports.
REALITY_NETWORKS = frozenset({"tcp", "raw", "grpc", "xhttp", "splithttp"})
# A TLS link with none of these sends Go's default ClientHello, which is easy to tell from a browser's.
SPOILED_FINGERPRINTS = frozenset({"", "none", "null", "unsafe"})
PLACEHOLDER_SNI = frozenset({"localhost", "vpn.local"})
ALPN_TOKENS = frozenset({"h2", "http/1.1", "h3"})
HEX_ID = re.compile(r"[0-9a-fA-F]{32}")
VLESS_HEX_ID = re.compile(r"^vless://([0-9a-fA-F]{32})(?=@)")
# Names a query parameter goes by; the first spelling is the one written back.
PARAM_SPELLINGS = {
    "type": ("type", "network"),
    "fp": ("fp", "fingerprint"),
    "sni": ("sni", "servername", "peer"),
    "alpn": ("alpn",),
}
# Probed on 2026-10-25 from six Iranian nodes, 127 endpoints that all pass from a US runner were reachable
# on 40% of port 443, 35% of the other usual web ports and only 10% of any other port.
WEB_PORTS = frozenset({80, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443})
# A probing node only counts a failure against an endpoint when it reaches this share of the sample.
CALIBRATED_RATE = 0.5


# The outbound a fragmenting config dials its proxy through (Xray's legacy freedom.fragment, still parsed by
# the pinned core). Fragmenting is client-side behaviour: no standard share link can carry it.
FRAGMENT_OUT = {
    "tag": "fragment-out",
    "protocol": "freedom",
    "settings": {"fragment": {"packets": "tlshello", "length": "10-20", "interval": "10-20"}},
    "streamSettings": {"sockopt": {"tcpNoDelay": True}},
}
SNIFFING = {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False}
PRIVATE_RANGES = ["10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"]


@dataclass(frozen=True)
class Repair:
    uri: str
    tags: tuple[str, ...]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return True


def _domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    usable = "." in value and not _is_ip(value) and not any(c in value for c in " /:@")
    return value if usable else ""


def _endpoint(p: Proxy) -> tuple:
    return p.scheme, p.server, p.port, p.username, p.password


def security(p: Proxy) -> str:
    default = "tls" if p.scheme in TLS_BY_DEFAULT or p.transport == "wss" else "none"
    return p.get("security", default).lower() or "none"


def drop_reason(p: Proxy) -> str | None:
    """Why a link cannot serve a client in Iran, or None when it may stay."""
    if p.scheme in UDP_SCHEMES:
        return "udp-quic"
    if p.scheme in PLAINTEXT_SCHEMES:
        return "plaintext-proxy"
    if security(p) == "reality" and p.transport not in REALITY_NETWORKS:
        return "reality-transport"
    return None


def _ascii(text: str) -> str:
    return "".join(c if ord(c) < 128 else quote(c) for c in text)


def _set_params(uri: str, updates: dict[str, str | None]) -> str:
    """Set or remove query parameters, leaving every other byte of the link as it was."""
    head, hash_mark, remark = uri.partition("#")
    base, question, query = head.partition("?")
    spellings = {spelling: name for name in updates for spelling in PARAM_SPELLINGS[name]}
    pieces: list[str] = []
    written: set[str] = set()
    for piece in query.split("&") if question else []:
        if not piece:
            continue
        name = spellings.get(unquote(piece.partition("=")[0]).lower())
        if name is None:
            pieces.append(piece)
        elif name not in written:
            written.add(name)
            if updates[name] is not None:
                pieces.append(f"{name}={quote(updates[name], safe=',')}")
    for name, value in updates.items():
        if name not in written and value is not None:
            pieces.append(f"{name}={quote(value, safe=',')}")
    return base + ("?" + "&".join(pieces) if pieces else "") + hash_mark + remark


def _vmess_data(p: Proxy) -> dict:
    return json.loads(b64decode(p.uri.split("://", 1)[1].split("#", 1)[0]))


def _vmess_uri(data: dict) -> str:
    body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
    return "vmess://" + base64.b64encode(body).decode()


def _verified(p: Proxy, edit: Repair, *, same_identity: bool) -> Repair | None:
    """Accept an edit only if it still parses to the same server and credentials."""
    try:
        edited = parse_uri(edit.uri)
    except ParseError:
        return None
    if _endpoint(edited) != _endpoint(p) or (edited.identity == p.identity) != same_identity:
        return None
    return edit


def normalize(p: Proxy) -> Repair | None:
    """Spelling fixes that leave the connection, and so its identity, unchanged."""
    tags: list[str] = []
    if p.scheme == "vmess":
        data = _vmess_data(p)
        if HEX_ID.fullmatch(str(data.get("id", ""))):
            data["id"] = str(uuid.UUID(data["id"]))
            tags.append("uuid")
        if str(data.get("net", "")).lower() == "raw":
            data["net"] = "tcp"
            tags.append("type")
        uri = _vmess_uri(data)
    elif p.scheme in {"vless", "trojan"}:
        uri = p.uri
        match = VLESS_HEX_ID.match(uri) if p.scheme == "vless" else None
        if match:
            uri = "vless://" + str(uuid.UUID(match[1])) + uri[match.end() :]
            tags.append("uuid")
        updates: dict[str, str | None] = {}
        if p.get("type").lower() == "raw":
            updates["type"] = "tcp"
            tags.append("type")
        if security(p) == "reality" and not p.get("fp", p.get("fingerprint")).strip():
            updates["fp"] = "chrome"
            tags.append("fp")
        if updates:
            uri = _set_params(uri, updates)
        if _ascii(uri) != uri:
            uri = _ascii(uri)
            tags.append("ascii")
    else:
        return None
    if not tags:
        return None
    return _verified(p, Repair(uri, tuple(tags)), same_identity=True)


def fix(p: Proxy) -> Repair | None:
    """Edits to the TLS ClientHello. They change the connection, so a runner has to re-test them."""
    kind = security(p)
    if p.scheme not in {"vless", "vmess", "trojan"} or kind not in {"tls", "reality"}:
        return None
    updates: dict[str, str | None] = {}
    if p.get("fp", p.get("fingerprint")).strip().lower() in SPOILED_FINGERPRINTS:
        updates["fp"] = "chrome"
    if kind == "tls":
        # A SNI-less or IP-literal ClientHello is anomalous, and a CDN cannot route it.
        current = p.get("sni", p.get("peer", p.server)).strip()
        if not current or current.lower() in PLACEHOLDER_SNI or _is_ip(current):
            name = _domain(p.get("host").split(",")[0]) or _domain(p.server)
            if name and name != current:
                updates["sni"] = name
    alpn = p.get("alpn")
    if alpn:
        kept = [t for t in (part.strip() for part in alpn.split(",")) if t.lower() in ALPN_TOKENS]
        if ",".join(kept) != alpn:
            updates["alpn"] = ",".join(kept) or None
    if not updates:
        return None
    if p.scheme == "vmess":
        data = _vmess_data(p)
        for key, value in updates.items():
            if value is None:
                data.pop(key, None)
            else:
                data[key] = value
        uri = _vmess_uri(data)
    else:
        uri = _set_params(p.uri, updates)
    return _verified(p, Repair(uri, tuple(updates)), same_identity=False)


def protocol_rank(p: Proxy) -> int:
    """2 (best) to 5 by protocol alone. Low-confidence ordering; see the sources named in this module.

    REALITY and TLS over tcp, grpc or xhttp come first. TLS over WebSocket follows because
    Cloudflare-fronted WebSocket configs died on every operator on 2026-09-28 (BPB-Worker-Panel#1458) and
    Xray flags WS as deprecated. Cleartext transports and legacy-cipher Shadowsocks, which Xray cannot
    run, come last.
    """
    if p.scheme == "ss":
        method = SS_ALIASES.get(p.username.lower(), p.username.lower())
        return 4 if method in XRAY_SS_METHODS else 5
    kind = security(p)
    if kind not in {"tls", "reality"}:
        return 5
    if kind == "reality" or p.transport in {"tcp", "raw", "grpc", "xhttp", "splithttp"}:
        return 2
    if p.transport in {"ws", "wss"}:
        return 3
    return 4


def port_rank(p: Proxy) -> int:
    """0 for 443, 1 for the other usual web ports, 2 for the rest, a tiebreaker inside a protocol tier."""
    return 0 if p.port == 443 else 1 if p.port in WEB_PORTS else 2


def bucket(p: Proxy, *, iran_evidence: bool = False) -> int:
    """Rank 1 (best) to 5. Evidence from Iran lifts a line to the top, but never out of the last tier."""
    rank = protocol_rank(p)
    return 1 if iran_evidence and rank < 5 else rank


def fragment_candidates(lines: list[str]) -> list[Proxy]:
    """Links Xray can run over TLS or REALITY, in order: the ones a ClientHello fragment can help."""
    found = []
    for line in lines:
        try:
            proxy = parse_uri(line.strip())
            xray_outbound(proxy)
        except (ValueError, KeyError):
            continue
        if proxy.scheme in {"vless", "vmess", "trojan"} and security(proxy) in {"tls", "reality"}:
            found.append(proxy)
    return found


def fragment_config(p: Proxy, index: int, *, packets: str = "tlshello") -> dict:
    """A complete Xray client config that sends the proxy's TLS ClientHello through a fragmenting outbound."""
    outbound = xray_outbound(p)
    outbound["tag"] = "proxy"
    sockopt = {"dialerProxy": "fragment-out", "tcpKeepAliveIdle": 100, "tcpNoDelay": True}
    outbound.setdefault("streamSettings", {}).setdefault("sockopt", {}).update(sockopt)
    fragment = copy.deepcopy(FRAGMENT_OUT)
    fragment["settings"]["fragment"]["packets"] = packets
    return {
        "remarks": f"{index:03d} - [Iran-Fragment] {p.remark}",
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": copy.deepcopy(SNIFFING),
            },
            {
                "tag": "http",
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "settings": {},
                "sniffing": copy.deepcopy(SNIFFING),
            },
        ],
        "outbounds": [
            outbound,
            fragment,
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "ip": PRIVATE_RANGES, "outboundTag": "direct"}],
        },
    }


def node_rates(probes: dict[str, dict[str, list[bool]]]) -> dict[str, float]:
    """Share of probed endpoints each node reached. probes[endpoint][node] holds its attempt results."""
    seen: dict[str, list[bool]] = {}
    for nodes in probes.values():
        for node, attempts in nodes.items():
            seen.setdefault(node, []).append(any(attempts))
    return {node: sum(reached) / len(reached) for node, reached in seen.items()}


def trusted_probes(controls: dict[str, dict[str, bool]]) -> set[str]:
    """Probes on subscriber networks that reached a control endpoint both before and after the run."""
    start, end = controls.get("start", {}), controls.get("end", {})
    return {probe for probe, reached in start.items() if reached and end.get(probe)}


def eyeball_verdict(nodes: dict[str, list[bool]], trusted: set[str]) -> str:
    """reachable: a probe connected. unreachable: none did and at least two trusted probes tried. unknown:
    anything else, which keeps the line, because one network's filtering is not another's: on 2026-10-26
    MCI and Rightel reached endpoints that TCI and most datacenter probes could not."""
    if any(any(attempts) for attempts in nodes.values()):
        return "reachable"
    tried = [probe for probe in trusted if nodes.get(probe)]
    return "unreachable" if len(tried) >= 2 else "unknown"


def probe_verdict(nodes: dict[str, list[bool]], rates: dict[str, float]) -> str:
    """reachable: an Iranian node connected. unreachable: nothing connected and at least two well
    calibrated nodes (every one, if fewer exist) failed both attempts. unknown: anything else, which
    keeps the line, because a node that reaches little of the sample is reporting its own restrictions."""
    if any(any(attempts) for attempts in nodes.values()):
        return "reachable"
    calibrated = [node for node, rate in rates.items() if rate >= CALIBRATED_RATE]
    failed = [node for node in calibrated if len(nodes.get(node, ())) >= 2]
    if failed and len(failed) >= min(2, len(calibrated)):
        return "unreachable"
    return "unknown"
