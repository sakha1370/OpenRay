from __future__ import annotations

import concurrent.futures
from typing import Dict, List, Optional, Tuple

from ..net import connect_host_port
from ..parsing import extract_port

_TCP_SCHEMES = frozenset({
    'vmess', 'vless', 'trojan', 'ss', 'ssr',
    'hysteria', 'hysteria2', 'hy2', 'tuic', 'juicity', 'wireguard',
})


def _tcp_reachable(uri: str, host: Optional[str]) -> bool:
    if not host:
        return False
    scheme = uri.split('://', 1)[0].lower()
    if scheme not in _TCP_SCHEMES:
        return True
    port = extract_port(uri)
    if port is None:
        return False
    try:
        return connect_host_port(host, int(port))
    except Exception:
        return False


def tcp_prefilter_existing(
    uris: List[str],
    host_map: Dict[str, Optional[str]],
    *,
    max_workers: int,
) -> Tuple[List[str], List[str]]:
    """Return (tcp_pass, tcp_fail). TCP connect to host:port only."""
    if not uris:
        return [], []

    tcp_pass: List[str] = []
    tcp_fail: List[str] = []
    workers = max(1, int(max_workers))

    def _check(u: str) -> Tuple[str, bool]:
        return u, _tcp_reachable(u, host_map.get(u))

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for u, ok in pool.map(_check, uris):
            if ok:
                tcp_pass.append(u)
            else:
                tcp_fail.append(u)

    return tcp_pass, tcp_fail
