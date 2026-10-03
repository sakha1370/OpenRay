"""Reproducible wall-clock benchmarks; synthetic credentials and controlled endpoints only."""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import os
import platform
import statistics
import time
from pathlib import Path

from .domain import ParseError, parse_uri
from .files import atomic_write, json_text
from .render import convert
from .validation import Validator

UUID = "11111111-1111-4111-8111-111111111111"


def cpu_rss() -> dict:
    import psutil

    p = psutil.Process()
    cpu = p.cpu_times()
    return {
        "rss_bytes": p.memory_info().rss,
        "cpu_s": cpu.user + cpu.system,
        "children": len(p.children(recursive=True)),
        "handles": p.num_handles() if os.name == "nt" else p.num_fds(),
    }


def corpus(count: int, path: Path | None) -> dict:
    inputs = (
        path.read_text(encoding="utf-8").splitlines()
        if path
        else [f"vless://{UUID}@host{n}.test:443?type=ws&path=%2Fws%3Fx%3D{n}" for n in range(count)]
    )
    started, before = time.perf_counter(), cpu_rss()
    proxies, invalid = [], 0
    for uri in inputs:
        try:
            proxies.append(parse_uri(uri))
        except ParseError:
            invalid += 1
    identities = [p.identity for p in proxies]
    parse_wall = time.perf_counter() - started
    started = time.perf_counter()
    clash, sing, report = convert(proxies)
    payload = json_text([clash, sing, report]).encode()
    after = cpu_rss()
    return {
        "input_rows": len(inputs),
        "parsed": len(proxies),
        "invalid": invalid,
        "unique": len(set(identities)),
        "parse_identity_wall_s": parse_wall,
        "export_wall_s": time.perf_counter() - started,
        "export_bytes": len(payload),
        "export_sha256": hashlib.sha256(payload).hexdigest(),
        "omissions": len(report),
        "before": before,
        "after": after,
    }


async def core(
    count: int = 32,
    workers: int = 4,
    rounds: int = 3,
    timeout: float = 5,
    backends: tuple[str, ...] = ("subprocess", "pool", "prefilter"),
) -> dict:
    # The integration fixture includes a private-target allow rule constrained to its ephemeral port.
    from tests.test_validation import XRAY, CoreIntegrationTests

    if not Path(XRAY).is_file():
        return {"unavailable": "install pinned Xray"}
    fixture = CoreIntegrationTests()
    await fixture.asyncSetUp()
    try:
        results, reference = [], None
        for backend in backends:
            for round_index in range(rounds):
                settings = dataclasses.replace(
                    fixture.settings,
                    workers=workers,
                    timeout=timeout,
                    backend="subprocess" if backend == "prefilter" else backend,
                    tcp_prefilter=backend == "prefilter",
                )
                queue = asyncio.Queue(workers * 2)
                outcomes, timings = {}, []
                before, start = cpu_rss(), time.perf_counter()
                async with Validator(settings) as validator:

                    async def producer():
                        for i in range(count):
                            await queue.put(i)
                        for _ in range(workers):
                            await queue.put(None)

                    async def consumer():
                        while (i := await queue.get()) is not None:
                            # Refused endpoints produce controlled negative connections.
                            proxy = fixture.proxy if i % 4 else parse_uri(f"vless://{UUID}@127.0.0.1:1")
                            result = await validator.check(proxy)
                            outcomes[i] = result.outcome.value
                            timings.append(result.elapsed_ms)

                    async with asyncio.TaskGroup() as group:
                        group.create_task(producer())
                        for _ in range(workers):
                            group.create_task(consumer())
                wall, after = time.perf_counter() - start, cpu_rss()
                if reference is None:
                    reference = outcomes
                results.append(
                    {
                        "backend": backend,
                        "round": round_index,
                        "checked": count,
                        "wall_s": wall,
                        "checks_per_minute": count * 60 / wall,
                        "successes": sum(v == "success" for v in outcomes.values()),
                        "mismatches": sum(reference[k] != v for k, v in outcomes.items()),
                        "p50_ms": statistics.median(timings),
                        "p95_ms": sorted(timings)[int((len(timings) - 1) * 0.95)],
                        "before": before,
                        "after": after,
                    }
                )
        return {
            "workers": workers,
            "rounds": results,
            "median_wall_s": {
                b: statistics.median(r["wall_s"] for r in results if r["backend"] == b) for b in backends
            },
        }
    finally:
        await fixture.asyncTearDown()


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--count", type=int, default=100000)
    p.add_argument("--input", "-i", type=Path)
    p.add_argument("--core", action="store_true")
    p.add_argument("--core-count", "--limit", "-n", type=int, default=32)
    p.add_argument("--timeout", "-t", type=float, default=5)
    p.add_argument("--backends", default="subprocess,pool,prefilter")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument("--output", type=Path, default=Path("benchmark-results/benchmark.json"))
    a = p.parse_args(argv)
    backends = tuple(dict.fromkeys(a.backends.split(",")))
    if (
        not 1 <= a.count <= 1000000
        or not 1 <= a.workers <= 128
        or not 1 <= a.core_count <= 100000
        or not 1 <= a.rounds <= 100
        or not 0 < a.timeout <= 120
        or not backends
        or set(backends) - {"subprocess", "pool", "prefilter", "api", "xray_api"}
    ):
        p.error("invalid benchmark dimensions")
    report = {
        "schema": 1,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "corpus": corpus(a.count, a.input),
    }
    if a.core:
        report["core"] = asyncio.run(core(a.core_count, a.workers, a.rounds, a.timeout, backends))
    atomic_write(a.output, json_text(report))
    print(json_text(report), end="")
    return 1 if any(r["mismatches"] for r in report.get("core", {}).get("rounds", [])) else 0


if __name__ == "__main__":
    raise SystemExit(main())
