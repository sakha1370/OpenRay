"""Deprecated synchronous probe helpers with strict proxy routing and deadlines."""

import time
from typing import NotRequired, TypedDict
import httpx
from ..constants import USER_AGENT

STAGE3_TEST_URLS = ["https://cp.cloudflare.com/generate_204"]


class SiteTarget(TypedDict):
    id: str
    urls: tuple[str, ...]
    blocked_codes: NotRequired[tuple[int, ...]]
    allowed_codes: NotRequired[tuple[int, ...]]
    output_file: NotRequired[str]


def probe_url_not_blocked(
    http_port, url, deadline, blocked_codes=(403,), allowed_codes=None, user_agent=USER_AGENT
):
    remaining = deadline - time.time()
    if remaining <= 0:
        return False
    try:
        with httpx.Client(
            proxy=f"http://127.0.0.1:{http_port}", trust_env=False, follow_redirects=False, timeout=remaining
        ) as client:
            with client.stream("GET", url, headers={"User-Agent": user_agent}) as response:
                status = response.status_code
                if status in blocked_codes or allowed_codes is not None and status not in allowed_codes:
                    return False
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > 1024 * 1024 or time.time() >= deadline:
                        return False
                return True
    except (httpx.HTTPError, OSError, ValueError):
        return False


def probe_all_targets(http_port, deadline, targets, user_agent=USER_AGENT):
    return {
        target["id"]: all(
            probe_url_not_blocked(
                http_port,
                url,
                deadline,
                target.get("blocked_codes", (403,)),
                target.get("allowed_codes"),
                user_agent,
            )
            for url in target["urls"]
        )
        for target in targets
    }


def probe_http_proxy(http_port, deadline, user_agent=USER_AGENT):
    return all(
        probe_url_not_blocked(http_port, url, deadline, allowed_codes=(204,), user_agent=user_agent)
        for url in STAGE3_TEST_URLS
    )
