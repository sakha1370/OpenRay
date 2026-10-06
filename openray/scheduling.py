"""Bounded work traversal with separate budgets for existing, new and site checks."""

from __future__ import annotations

import asyncio
import hashlib
import time

from .config import Settings
from .domain import Outcome
from .storage import Store
from .validation import Target


async def validate_batch(
    settings: Settings,
    store: Store,
    validator,
    target: Target,
    context: str,
    run_id: str,
    accepted: bool,
    results: list[dict],
    deadline: float,
    retests: bool = False,
):
    queue = asyncio.Queue(settings.queue_size)
    # TCP handshakes wait without a core, so extra consumers keep every core busy meanwhile.
    consumers = settings.workers + (settings.prefilter_slots if settings.tcp_prefilter else 0)

    async def producer():
        leased = 0
        while leased < settings.batch_size and time.monotonic() < deadline:
            batch = store.lease(
                context,
                target.id,
                run_id,
                min(max(settings.queue_size, 256), settings.batch_size - leased),
                settings.budget + settings.timeout + 5,
                accepted_only=accepted,
                source_only=not accepted,
                version=target.version,
                # Site results through a proxy that fails connectivity carry no information.
                alive_only=accepted and target.id != "connectivity",
                retests_only=retests,
            )
            if not batch:
                break
            leased += len(batch)
            for proxy in batch:
                await queue.put(proxy)
        for _ in range(consumers):
            await queue.put(None)

    async def consumer():
        while (proxy := await queue.get()) is not None:
            result = await validator.check(proxy, target)
            event = hashlib.sha256(
                f"{run_id}/{proxy.identity}/{context}/{target.id}/{target.version}".encode()
            ).hexdigest()
            stamp = time.time()
            if result.outcome not in {Outcome.PROXY_FAILURE, Outcome.TIMEOUT}:
                store.observe(
                    event,
                    run_id,
                    proxy,
                    context,
                    target.id,
                    result,
                    version=target.version,
                    now=stamp,
                    cooldown=settings.cooldown,
                    death_after=settings.death_after,
                )
            item = {
                "event_id": event,
                "uri": proxy.uri,
                "time": stamp,
                "target": target.id,
                "version": target.version,
                "outcome": result.outcome.value,
                "elapsed_ms": result.elapsed_ms,
                "detail": result.detail,
                "status": result.status,
                "core": result.core,
            }
            if result.outcome in {Outcome.PROXY_FAILURE, Outcome.TIMEOUT}:
                store.pending(event, run_id, context, item)
            results.append(item)

    async with asyncio.timeout_at(deadline):
        async with asyncio.TaskGroup() as group:
            group.create_task(producer())
            for _ in range(consumers):
                group.create_task(consumer())
