"""Compatibility status/latency tester using the same supervised workers."""

import argparse
import asyncio
import dataclasses
from datetime import datetime
from pathlib import Path

from .config import Settings
from .domain import Outcome, ParseError, extract_uris, parse_uri
from .files import atomic_write
from .validation import Target, Validator


def main(argv=None, expected=True):
    p = argparse.ArgumentParser()
    p.add_argument("vless_url", nargs="?")
    p.add_argument("--batch", action="store_true")
    p.add_argument("--max", type=int)
    p.add_argument("--expected-status", type=int, default=404 if expected else None)
    p.add_argument("--output", type=Path, default=Path("working_proxies.txt"))
    p.add_argument("--workers", type=int, default=10)
    p.add_argument("--input", type=Path)
    p.add_argument(
        "--url", default="https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
    )
    a = p.parse_args(argv)
    settings = Settings.from_env()
    if not 1 <= a.workers <= 128 or a.max is not None and a.max < 1:
        p.error("invalid worker/count limit")
    settings = dataclasses.replace(settings, workers=min(settings.workers, a.workers))
    if a.vless_url and not a.batch:
        uris = [a.vless_url]
    else:
        candidates = (
            [a.input]
            if a.input
            else [
                settings.root / "output_iran/all_valid_proxies_for_iran.txt",
                settings.root / "output_iran/iran_top100_checked.txt",
                settings.root / "output_iran/test.txt",
            ]
        )
        path = next((x for x in candidates if x.is_file()), None)
        if path is None:
            p.error("no input subscription exists")
        uris = extract_uris(path.read_text(encoding="utf-8"))
    proxies = {}
    for uri in uris:
        try:
            proxy = parse_uri(uri)
            if proxy.scheme == "vless":
                proxies.setdefault(proxy.identity, proxy)
        except ParseError:
            continue
    values = list(proxies.values())[: a.max]
    target = Target(
        "custom", (a.url,), allowed=(a.expected_status,) if a.expected_status else tuple(range(100, 600))
    )

    async def run():
        queue = asyncio.Queue(settings.queue_size)
        results = []
        async with Validator(settings) as validator:

            async def producer():
                for proxy in values:
                    await queue.put(proxy)
                for _ in range(settings.workers):
                    await queue.put(None)

            async def consumer():
                while (proxy := await queue.get()) is not None:
                    results.append((proxy, await validator.check(proxy, target)))

            async with asyncio.TaskGroup() as group:
                group.create_task(producer())
                for _ in range(settings.workers):
                    group.create_task(consumer())
        return results

    results = asyncio.run(run())
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    content = f"# Working VLESS Proxies\n# Test Date: {stamp}\n# Test URL: {a.url}\n# Workers: {settings.workers}\n\n"
    passed = 0
    for proxy, result in sorted(results, key=lambda item: item[0].identity):
        if result.outcome == Outcome.SUCCESS:
            passed += 1
            content += f"# Status: {result.status} | Response Time: {round(result.elapsed_ms)}ms | Tested: {stamp}\n{proxy.uri}\n\n"
    if any(r.outcome == Outcome.CORE_FAILURE for _, r in results):
        print("Core unavailable or unhealthy; prior output preserved")
        return 2
    atomic_write(a.output, content)
    print(f"Checked {len(results)} connections; {passed} matched the response policy")
    return 0
