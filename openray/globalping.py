"""Globalping client: TCP connect tests from probes on Iranian subscriber networks.

Globalping runs measurements from volunteer probes. A ping with protocol TCP is a connect test to host:port,
and a few probes sit on subscriber networks in Iran (MCI, Rightel and TCI at the last survey). Unauthenticated
callers get 250 credits per hour per IP and a measurement costs one credit per probe, so each endpoint is
asked one probe at a time, in priority order, and stops at the first probe that connects. Everything degrades
to "no data": a missing probe, a spent allowance or an unreachable API never produces a verdict. The probes
are volunteers' devices and drop off for minutes or hours, so a probe the API cannot find is asked again later.
"""

from __future__ import annotations

import asyncio
import time
from collections import Counter

import httpx

API = "https://api.globalping.io"
HEADERS = {"User-Agent": "OpenRay-iran-probe/2 (+https://github.com/sakha1370/OpenRay)"}
# ASNs asked, in order: Hamrah-e Aval first, then the other operators the list is meant to serve.
TARGETS = {197207: "mci", 57218: "rightel", 58224: "tci", 12880: "tci", 44244: "irancell", 31549: "shatel"}
CONTROLS = ("8.8.8.8:443", "1.1.1.1:443")
LIMIT_HEADERS = frozenset({"x-ratelimit-remaining", "x-ratelimit-reset", "retry-after"})
# Credits kept back so that the closing controls can still run.
RESERVE = 8
CONCURRENCY = 3
# Seconds before a probe the API could not find is asked again, after its first, second and later misses.
OFFLINE_RETRY = (60, 120, 300)
# Seconds without a single answer from any probe after which the run stops and leaves the verdict to the gates.
GIVE_UP = 900


def now() -> float:
    return time.monotonic()


async def pause(seconds: float) -> None:
    await asyncio.sleep(seconds)


def seconds(value: str | None) -> float:
    try:
        return max(0.0, float(value or 0))
    except ValueError:
        return 0.0  # an HTTP date


class Budget:
    """The hourly allowance, as the API last reported it."""

    def __init__(self):
        self.remaining: int | None = None
        self.resets_at = 0.0

    def update(self, headers: dict) -> None:
        try:
            if "x-ratelimit-remaining" in headers:
                self.remaining = int(headers["x-ratelimit-remaining"])
            if "x-ratelimit-reset" in headers:
                self.resets_at = now() + float(headers["x-ratelimit-reset"])
        except ValueError:
            pass

    def exhaust(self, wait: float) -> None:
        self.remaining = 0
        self.resets_at = now() + wait

    async def afford(self, credits: int, deadline: float) -> bool:
        """Wait for the allowance to refill if needed; False when that would pass the deadline."""
        if now() >= deadline:
            return False
        if self.remaining is None or self.remaining >= credits:
            return True
        wait = self.resets_at - now()
        if wait > 0:
            if now() + wait >= deadline:
                return False
            await pause(wait + 1)
        self.remaining = None  # the window has rolled over; the next reply says by how much
        return True


async def online_targets(client: httpx.AsyncClient) -> dict[int, dict]:
    """Probes in Iran on the networks we want, in the order they should be asked."""
    response = await client.get(API + "/v1/probes")
    response.raise_for_status()
    found: dict[int, dict] = {}
    for probe in response.json():
        location = probe.get("location", {})
        asn = location.get("asn")
        if location.get("country") == "IR" and asn in TARGETS and asn not in found:
            city = location.get("city") or "?"
            found[asn] = {"asn": f"AS{asn}", "isp": TARGETS[asn], "location": ["ir", "Iran", city]}
    return {asn: found[asn] for asn in TARGETS if asn in found}


async def get_limits(client: httpx.AsyncClient, budget: Budget) -> None:
    response = await client.get(API + "/v1/limits")
    response.raise_for_status()
    create = response.json()["rateLimit"]["measurements"]["create"]
    budget.remaining = int(create["remaining"])
    budget.resets_at = now() + float(create.get("reset") or 0)


def error_type(response: httpx.Response) -> str:
    try:
        return str(response.json()["error"]["type"])
    except (ValueError, KeyError, TypeError):
        return "unparsable"


async def tcp_ping(
    client: httpx.AsyncClient, budget: Budget, endpoint: str, asn: int, reasons: Counter, wait: float = 45.0
) -> tuple[str, bool]:
    """('ok', reached), or ('limited' | 'offline' | 'failed', False) when there is no answer to use.

    'offline' is only the API saying no probe on that network is online, or the probe leaving mid-test. Any other
    refusal is 'failed' (the endpoint, not the probe, is the likely trouble). The refusals are tallied in reasons."""
    host, _, port = endpoint.rpartition(":")
    body = {
        "type": "ping",
        "target": host,
        "locations": [{"asn": asn, "limit": 1}],
        "measurementOptions": {"protocol": "TCP", "port": int(port), "packets": 3},
    }
    try:
        response = await client.post(API + "/v1/measurements", json=body)
        budget.update({k.lower(): v for k, v in response.headers.items() if k.lower() in LIMIT_HEADERS})
        if response.status_code == 429:
            budget.exhaust(seconds(response.headers.get("Retry-After")) or 60)
            return "limited", False
        if response.status_code == 422:
            kind = error_type(response)
            reasons[f"422 {kind}"] += 1
            return ("offline" if kind == "no_probes_found" else "failed"), False
        if response.status_code != 202:
            reasons[f"http {response.status_code}"] += 1
            return "failed", False
        ident = response.json()["id"]
    except (httpx.HTTPError, ValueError, KeyError):
        return "failed", False
    started = now()
    while now() - started < wait:
        await pause(1.5)
        try:
            poll = await client.get(f"{API}/v1/measurements/{ident}")
            data = poll.json() if poll.status_code == 200 else {"status": "in-progress"}
        except (httpx.HTTPError, ValueError):
            continue
        if data.get("status") == "in-progress":
            continue
        results = data.get("results") or []
        result = results[0].get("result", {}) if results else {}
        if result.get("status") != "finished":
            status = str(result.get("status"))
            reasons[f"result {status}"] += 1
            return ("offline" if status == "offline" else "failed"), False
        return "ok", bool((result.get("stats") or {}).get("rcv"))
    reasons["poll timeout"] += 1
    return "failed", False


async def run(
    endpoints: list[str], budget_minutes: float, transport: httpx.AsyncBaseTransport | None = None
) -> dict:
    """Ask each endpoint of the probes on target networks until one connects. Never raises on API trouble."""
    started = now()
    deadline = started + budget_minutes * 60
    report: dict = {"prober": "globalping", "status": "ok", "requested": len(endpoints), "endpoints": {}}
    report.update(budget_s=round(budget_minutes * 60), refused=0, offline=0, errors=0)
    async with httpx.AsyncClient(timeout=30, headers=HEADERS, transport=transport) as client:
        budget = Budget()
        try:
            targets = await online_targets(client)
            await get_limits(client, budget)
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            report.update(status="api-unavailable", error=type(exc).__name__)
            return report
        report["nodes"] = {f"AS{asn}": info for asn, info in targets.items()}
        if not targets:
            # One probe is enough: a connect is positive evidence, and a drop needs two trusted probes to fail.
            report["status"] = "no-probes"
            return report
        report["credits_at_start"] = budget.remaining
        report.update(recovered=0, gave_up=False)
        # Probes the API could not find: asn -> (when to ask again, consecutive misses).
        down: dict[int, tuple[float, int]] = {}
        reasons: Counter = Counter()
        heard = {"at": now()}  # when a probe last gave an answer
        stop = asyncio.Event()

        async def ask(
            endpoint: str, asn: int, *, reserve: int = RESERVE, until: float = deadline
        ) -> bool | None:
            """True or False when the probe answered, None when it could not be asked."""
            for _ in range(3):
                if down.get(asn, (0.0, 0))[0] > now():
                    return None
                if (reserve and stop.is_set()) or not await budget.afford(1 + reserve, until):
                    if reserve:
                        stop.set()
                    return None
                asked_at = now()
                state, reached = await tcp_ping(client, budget, endpoint, asn, reasons)
                if state == "ok":
                    heard["at"] = now()
                    if down.pop(asn, None):
                        report["recovered"] += 1
                    return reached
                if state == "limited":
                    report["refused"] += 1
                    continue
                if state == "offline":
                    report["offline"] += 1
                    retry_at, misses = down.get(asn, (0.0, 0))
                    if (
                        retry_at <= asked_at
                    ):  # a request already in flight when the probe went quiet is no new miss
                        misses += 1
                    down[asn] = (now() + OFFLINE_RETRY[min(misses, len(OFFLINE_RETRY)) - 1], misses)
                else:
                    report["errors"] += 1
                return None
            return None

        async def controls(label: str, **limits) -> None:
            seen: dict[str, bool] = {}
            report.setdefault("controls", {})[label] = seen
            for asn in targets:
                seen[f"AS{asn}"] = False
                for control in CONTROLS:
                    if await ask(control, asn, **limits):
                        seen[f"AS{asn}"] = True
                        break

        await controls("start")
        order = [asn for asn in targets if report["controls"]["start"][f"AS{asn}"]]
        results = report["endpoints"]
        gate = asyncio.Semaphore(CONCURRENCY)

        async def settle(endpoint: str) -> None:
            async with gate:
                while not stop.is_set():
                    for asn in order:
                        reached = await ask(endpoint, asn)
                        if reached is None:
                            if stop.is_set():
                                return
                            continue
                        results.setdefault(endpoint, {}).setdefault(f"AS{asn}", []).append(reached)
                        if reached:
                            return
                    if endpoint in results:
                        return
                    # No probe answered. If some are only quiet for now, wait for the first to be due again.
                    due = [down[asn][0] for asn in order if asn in down and down[asn][0] > now()]
                    if not due:
                        return  # refused or failed rather than missing: leave this endpoint unprobed
                    if now() >= deadline or now() - heard["at"] > GIVE_UP:
                        report["gave_up"] = now() < deadline
                        stop.set()
                        return
                    await pause(max(1.0, min(due) - now()))

        await asyncio.gather(*(settle(e) for e in endpoints))
        await controls("end", reserve=0, until=max(deadline, now()) + 600)
        report.update(probed=len(results), elapsed_s=round(now() - started), refusals=dict(reasons))
        report.update(stopped_early=stop.is_set(), credits_at_end=budget.remaining)
    return report
