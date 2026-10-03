"""Keep pools keyed by real origin while connecting only to approved DNS results.

The HTTPX/httpcore bridge is version-pinned and tested with real TLS virtual hosts.
"""

import contextvars

import httpcore
from httpcore._backends.auto import AutoBackend


class PinnedBackend(httpcore.AsyncNetworkBackend):
    def __init__(self):
        self.pin = contextvars.ContextVar("openray_source_pin", default=None)
        self.backend = AutoBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        approved = self.pin.get()
        if not approved or host.lower().rstrip(".") != approved[0].lower().rstrip("."):
            raise ValueError("unapproved source connection")
        return await self.backend.connect_tcp(
            approved[1], port, timeout=timeout, local_address=local_address, socket_options=socket_options
        )

    async def connect_unix_socket(self, *args, **kwargs):
        raise ValueError("Unix sockets are not subscription sources")

    async def sleep(self, seconds):
        await self.backend.sleep(seconds)
