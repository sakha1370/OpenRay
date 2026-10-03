"""Synchronous compatibility facade for the supervised asynchronous validator."""

import asyncio
import dataclasses
import threading
from enum import StrEnum

from .config import Settings
from .domain import Outcome, parse_uri
from .validation import Validator


class BackendKind(StrEnum):
    SUBPROCESS = "subprocess"
    POOL = "pool"
    API = "api"


class Stage3Engine:
    def __init__(self, backend=None, kind=None):
        self.backend_kind = BackendKind(kind or Settings.from_env().backend.replace("xray_api", "api"))
        self.backend = backend

    def validate_many(self, uris, timeout_s=12):
        if self.backend:
            return self.backend.validate_many(uris, timeout_s)

        async def run():
            settings = dataclasses.replace(
                Settings.from_env(), backend=self.backend_kind.value, timeout=timeout_s
            )
            queue = asyncio.Queue(settings.queue_size)
            results = {}
            async with Validator(settings) as validator:

                async def producer():
                    for uri in dict.fromkeys(uris):
                        if uri:
                            await queue.put(uri)
                    for _ in range(settings.workers):
                        await queue.put(None)

                async def consumer():
                    while (uri := await queue.get()) is not None:
                        try:
                            result = await validator.check(parse_uri(uri))
                            results[uri] = (
                                True
                                if result.outcome == Outcome.SUCCESS
                                else False
                                if result.outcome in {Outcome.PROXY_FAILURE, Outcome.TIMEOUT}
                                else None
                            )
                        except (ValueError, UnicodeError):
                            results[uri] = None

                async with asyncio.TaskGroup() as group:
                    group.create_task(producer())
                    for _ in range(settings.workers):
                        group.create_task(consumer())
            return results

        return asyncio.run(run())

    def validate_one(self, uri, timeout_s=12):
        return self.validate_many([uri], timeout_s).get(uri)

    def shutdown(self):
        if self.backend:
            self.backend.shutdown()


_lock = threading.Lock()
_engine = None


def get_engine(force_new=False):
    global _engine
    with _lock:
        if force_new or _engine is None:
            _engine = Stage3Engine()
        return _engine
