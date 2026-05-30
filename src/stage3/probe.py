from __future__ import annotations

import time
from typing import Dict, List, Sequence, Tuple, TypedDict
from urllib.request import Request, build_opener, urlopen
from urllib.request import ProxyHandler

from ..constants import USER_AGENT

STAGE3_TEST_URLS: List[str] = [
    'https://cp.cloudflare.com/generate_204',
    # 'https://www.google.com/generate_204',
]


class SiteTarget(TypedDict):
    id: str
    url: str
    blocked_codes: Tuple[int, ...]


def _build_proxy_opener(http_port: int, user_agent: str = USER_AGENT):
    return build_opener(ProxyHandler({
        'http': f'http://127.0.0.1:{http_port}',
        'https': f'http://127.0.0.1:{http_port}',
    }))


def probe_url_not_blocked(
    http_port: int,
    url: str,
    deadline: float,
    blocked_codes: Sequence[int] = (403,),
    user_agent: str = USER_AGENT,
) -> bool:
    """HTTP(S) fetch via local HTTP inbound; True if response status is not blocked."""
    if time.time() >= deadline:
        return False
    try:
        opener = _build_proxy_opener(http_port, user_agent)
    except Exception:
        return False
    try:
        req = Request(url, headers={'User-Agent': user_agent, 'Accept': '*/*'})
        rem = max(2.0, deadline - time.time())
        with opener.open(req, timeout=rem) as resp:
            code = getattr(resp, 'status', None) or getattr(resp, 'code', None)
            if isinstance(code, int) and code not in blocked_codes:
                return True
    except Exception:
        pass
    return False


def probe_all_targets(
    http_port: int,
    deadline: float,
    targets: Sequence[SiteTarget],
    user_agent: str = USER_AGENT,
) -> Dict[str, bool]:
    """Test each target URL within the deadline; return {target_id: passed}."""
    results: Dict[str, bool] = {}
    for target in targets:
        if time.time() >= deadline:
            results[target['id']] = False
            continue
        per_target_deadline = deadline
        passed = probe_url_not_blocked(
            http_port,
            target['url'],
            per_target_deadline,
            blocked_codes=target.get('blocked_codes', (403,)),
            user_agent=user_agent,
        )
        results[target['id']] = passed
    return results


def probe_http_proxy(http_port: int, deadline: float, user_agent: str = USER_AGENT) -> bool:
    """HTTP(S) fetch via local HTTP inbound; True if 200/204 received."""
    try:
        opener = _build_proxy_opener(http_port, user_agent)
    except Exception:
        return False

    for url in STAGE3_TEST_URLS:
        if time.time() >= deadline:
            break
        try:
            req = Request(url, headers={'User-Agent': user_agent, 'Accept': '*/*'})
            rem = max(2.0, deadline - time.time())
            with opener.open(req, timeout=rem) as resp:
                code = getattr(resp, 'status', None) or getattr(resp, 'code', None)
                if isinstance(code, int) and code in (200, 204):
                    return True
        except Exception:
            continue
    return False
