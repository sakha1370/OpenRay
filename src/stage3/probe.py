from __future__ import annotations

import time
from typing import Dict, List, NotRequired, Sequence, Tuple, TypedDict
from urllib.request import Request, build_opener, urlopen
from urllib.request import ProxyHandler

from ..constants import USER_AGENT

STAGE3_TEST_URLS: List[str] = [
    'https://cp.cloudflare.com/generate_204',
    # 'https://www.google.com/generate_204',
]


class SiteTarget(TypedDict):
    id: str
    urls: Tuple[str, ...]
    blocked_codes: NotRequired[Tuple[int, ...]]
    allowed_codes: NotRequired[Tuple[int, ...]]
    output_file: NotRequired[str]


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
    allowed_codes: Sequence[int] | None = None,
    user_agent: str = USER_AGENT,
) -> bool:
    """HTTP(S) fetch via local HTTP inbound; True if response status passes the check."""
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
            if not isinstance(code, int):
                return False
            if allowed_codes is not None:
                return code in allowed_codes
            return code not in blocked_codes
    except Exception:
        pass
    return False


def probe_all_targets(
    http_port: int,
    deadline: float,
    targets: Sequence[SiteTarget],
    user_agent: str = USER_AGENT,
) -> Dict[str, bool]:
    """Test each target (all URLs must pass) within the deadline; return {target_id: passed}."""
    results: Dict[str, bool] = {}
    for target in targets:
        site_id = target['id']
        if time.time() >= deadline:
            results[site_id] = False
            continue
        blocked_codes = target.get('blocked_codes', (403,))
        allowed_codes = target.get('allowed_codes')
        passed = True
        for url in target['urls']:
            if time.time() >= deadline:
                passed = False
                break
            if not probe_url_not_blocked(
                http_port,
                url,
                deadline,
                blocked_codes=blocked_codes,
                allowed_codes=allowed_codes,
                user_agent=user_agent,
            ):
                passed = False
                break
        results[site_id] = passed
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
