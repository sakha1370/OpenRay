from __future__ import annotations

import time
from typing import List, Optional
from urllib.request import Request, build_opener, urlopen
from urllib.request import ProxyHandler

from ..constants import USER_AGENT

STAGE3_TEST_URLS: List[str] = [
    'https://www.google.com/generate_204',
    'https://cp.cloudflare.com/generate_204',
]


def probe_http_proxy(http_port: int, deadline: float, user_agent: str = USER_AGENT) -> bool:
    """HTTP(S) fetch via local HTTP inbound; True if 200/204 received."""
    try:
        opener = build_opener(ProxyHandler({
            'http': f'http://127.0.0.1:{http_port}',
            'https': f'http://127.0.0.1:{http_port}',
        }))
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
