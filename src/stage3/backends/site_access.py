"""Legacy site backend facade; workers and deadlines use the supervised implementation."""

import asyncio
import dataclasses
from openray.config import Settings
from openray.domain import Outcome, parse_uri
from openray.validation import Target, Validator


class SiteAccessBackend:
    def __init__(self, targets, pool_size=None):
        self.targets = targets
        self.pool_size = pool_size

    def validate_many(self, uris, timeout_s=12, targets_by_uri=None):
        async def run():
            settings = dataclasses.replace(Settings.from_env(), timeout=timeout_s)
            if self.pool_size:
                settings = dataclasses.replace(settings, workers=min(settings.workers, self.pool_size))
            results = {}
            queue = asyncio.Queue(settings.queue_size)
            async with Validator(settings) as validator:

                async def produce():
                    for uri in dict.fromkeys(uris):
                        await queue.put(uri)
                    for _ in range(settings.workers):
                        await queue.put(None)

                async def consume():
                    while (uri := await queue.get()) is not None:
                        try:
                            proxy = parse_uri(uri)
                        except ValueError:
                            results[uri] = None
                            continue
                        values = {}
                        for raw in (targets_by_uri or {}).get(uri, self.targets):
                            target = Target(
                                raw["id"],
                                tuple(raw.get("urls") or (raw["url"],)),
                                raw.get("version", 1),
                                tuple(
                                    raw.get("allowed_codes")
                                    or tuple(
                                        c
                                        for c in range(200, 600)
                                        if c not in raw.get("blocked_codes", (403,))
                                    )
                                ),
                            )
                            result = await validator.check(proxy, target)
                            values[target.id] = (
                                result.outcome == Outcome.SUCCESS
                                if result.outcome
                                in {Outcome.SUCCESS, Outcome.BLOCKED, Outcome.PROXY_FAILURE, Outcome.TIMEOUT}
                                else None
                            )
                        results[uri] = values

                async with asyncio.TaskGroup() as group:
                    group.create_task(produce())
                    for _ in range(settings.workers):
                        group.create_task(consume())
            return results

        return asyncio.run(run())

    def validate_one(self, uri, timeout_s=12):
        return self.validate_many([uri], timeout_s).get(uri)

    def shutdown(self):
        pass
