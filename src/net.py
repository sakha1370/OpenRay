"""Deprecated networking facade. Production paths use openray.fetch and validation."""

import asyncio
import dataclasses
import ipaddress
import socket
from openray.config import Settings
from openray.domain import parse_uri
from openray.fetch import Fetcher, Source
from openray.geo import Geo
from openray.legacy_stage3 import get_engine
from openray.storage import Store


def connect_host_port(host, port, timeout_ms=1500):
    try:
        with socket.create_connection((host, port), timeout=timeout_ms / 1000):
            return True
    except OSError:
        return False


# A legacy reachability hint; never a validation result.
def ping_host(host):
    return connect_host_port(host, 443, 1000)


def is_dynamic_host(host):
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return True


def _get_country_code_for_host(host, timeout=5):
    geo = Geo(Settings.from_env().root)
    from openray.domain import Proxy

    try:
        return geo.country(Proxy("", "socks", host, 1))
    finally:
        geo.close()


def get_country_codes_batch(hosts, timeout=5, batch_size=100):
    geo = Geo(Settings.from_env().root)
    from openray.domain import Proxy

    try:
        return {host: geo.country(Proxy("", "socks", host, 1)) for host in hosts}
    finally:
        geo.close()


def validate_with_v2ray_core(uri, timeout_s=12):
    return get_engine().validate_one(uri, timeout_s)


def check_one_sync(uri, host):
    return uri, host, validate_with_v2ray_core(uri) is True


def check_pair(item):
    return check_one_sync(*item)


def quick_protocol_probe(uri, host, port, timeout_ms=1200):
    return validate_with_v2ray_core(uri, max(1, timeout_ms / 1000)) is True


async def fetch_urls_async_batch(urls, concurrency=None, timeout=15):
    settings = dataclasses.replace(Settings.from_env(), fetch_workers=concurrency or 8, fetch_timeout=timeout)
    queue = asyncio.Queue(settings.queue_size)
    results = {}
    with Store(":memory:") as store:
        async with Fetcher(settings, store) as fetcher:

            async def produce():
                for url in dict.fromkeys(urls):
                    await queue.put(url)
                for _ in range(settings.fetch_workers):
                    await queue.put(None)

            async def consume():
                while (url := await queue.get()) is not None:
                    try:
                        results[url] = (await fetcher._request(Source(url)))[0]
                    except (ValueError, OSError, TimeoutError):
                        results[url] = None

            async with asyncio.TaskGroup() as group:
                group.create_task(produce())
                for _ in range(settings.fetch_workers):
                    group.create_task(consume())
    return results


def fetch_url(url, timeout=15):
    return asyncio.run(fetch_urls_async_batch([url], 1, timeout)).get(url)
