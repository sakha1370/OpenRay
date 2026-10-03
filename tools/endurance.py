"""Controlled lifecycle soak; use --seconds 86400 for the 24-hour acceptance gate."""

import argparse
import asyncio
import dataclasses
import gc
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from openray.benchmarks import cpu_rss
from openray.domain import Outcome
from openray.files import atomic_write, json_text
from openray.validation import Validator
from tests.test_validation import CoreIntegrationTests


async def soak(seconds, workers, backend):
    fixture = CoreIntegrationTests()
    await fixture.asyncSetUp()
    started, checked, samples = time.monotonic(), 0, []
    import psutil

    baseline = {p.pid for p in psutil.Process().children(recursive=True)}
    try:
        settings = dataclasses.replace(fixture.settings, workers=workers, backend=backend)
        while time.monotonic() - started < seconds:
            async with Validator(settings) as validator:
                results = await asyncio.gather(*(validator.check(fixture.proxy) for _ in range(workers * 4)))
                if any(r.outcome != Outcome.SUCCESS for r in results):
                    raise AssertionError("controlled positive failed during soak")
            gc.collect()
            sample = cpu_rss()
            children = {p.pid for p in psutil.Process().children(recursive=True)}
            if children - baseline:
                raise AssertionError(
                    "orphan child process after validator teardown: "
                    + str(
                        [
                            (p.pid, p.name())
                            for p in psutil.Process().children(recursive=True)
                            if p.pid not in baseline
                        ]
                    )
                )
            samples.append(sample)
            checked += len(results)
        warm = samples[min(2, len(samples) - 1)]
        if max(s["rss_bytes"] for s in samples) > 512 * 1024 * 1024:
            raise AssertionError("Python RSS exceeds controlled 512 MiB soak ceiling")
        if len(samples) > 3 and max(s["handles"] for s in samples[2:]) - warm["handles"] > 64:
            raise AssertionError("handles grow beyond bounded warmup allowance")
        return {
            "seconds": time.monotonic() - started,
            "requested_seconds": seconds,
            "workers": workers,
            "backend": backend,
            "checks": checked,
            "cycles": len(samples),
            "max_rss_bytes": max(s["rss_bytes"] for s in samples),
            "handle_growth_after_warmup": max(s["handles"] for s in samples[2:] or samples) - warm["handles"],
            "orphan_processes": 0,
            "samples": samples,
        }
    finally:
        await fixture.asyncTearDown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=86400)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--backend", choices=("subprocess", "pool"), default="subprocess")
    parser.add_argument("--output", type=Path, default=Path("benchmark-results/endurance.json"))
    args = parser.parse_args()
    if not 1 <= args.seconds <= 604800 or not 1 <= args.workers <= 128:
        parser.error("invalid soak dimensions")
    result = asyncio.run(soak(args.seconds, args.workers, args.backend))
    atomic_write(args.output, json_text(result))
    print(json_text({k: v for k, v in result.items() if k != "samples"}), end="")
