import asyncio
import ssl
import tempfile
import unittest
from pathlib import Path

import dns.message
import dns.rrset

from openray.config import Settings
from openray.fetch import Fetcher, Resolver, Source
from openray.storage import Store
from tests.test_domain import VLESS


class DnsTlsTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_dns_cache_and_cancellation(self):
        seen = []

        class Dns(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, address):
                query = dns.message.from_wire(data)
                seen.append(query)
                if str(query.question[0].name).startswith("blackhole"):
                    return
                answer = dns.message.make_response(query)
                if query.question[0].rdtype == 1:
                    answer.answer.append(
                        dns.rrset.from_text(query.question[0].name, 60, "IN", "A", "203.0.113.9")
                    )
                self.transport.sendto(answer.to_wire(), address)

        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            Dns, local_addr=("127.0.0.1", 0)
        )
        try:
            resolver = Resolver(2)
            resolver.dns.nameservers = ["127.0.0.1"]
            resolver.dns.port = transport.get_extra_info("sockname")[1]
            self.assertEqual(await resolver.resolve("example.test", 443), ["203.0.113.9"])
            count = len(seen)
            self.assertEqual(await resolver.resolve("example.test", 443), ["203.0.113.9"])
            self.assertEqual(len(seen), count)
            task = asyncio.create_task(resolver.resolve("blackhole.test", 443))
            await asyncio.sleep(0.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 0.5)
        finally:
            transport.close()

    async def test_dns_pinning_preserves_tls_sni_and_http_host(self):
        fixtures = Path(__file__).parent / "fixtures"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(fixtures / "test-cert.pem", fixtures / "test-key.pem")
        names, requests = [], []
        context.set_servername_callback(lambda sock, name, ctx: names.append(name))

        async def serve(reader, writer):
            try:
                while True:
                    requests.append(await reader.readuntil(b"\r\n\r\n"))
                    body = VLESS.encode()
                    writer.write(
                        b"HTTP/1.1 200 OK\r\n" + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
                    )
                    await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=context)
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                settings = Settings(
                    root, root / "state.sqlite3", root / "sources.txt", allow_private_sources=True
                )
                with Store(settings.database) as store:
                    async with Fetcher(settings, store) as fetcher:
                        fetcher.transport._pool._ssl_context = ssl.create_default_context(
                            cafile=str(fixtures / "test-cert.pem")
                        )
                        port = server.sockets[0].getsockname()[1]
                        self.assertEqual(await fetcher.fetch(Source(f"https://localhost:{port}/")), [VLESS])
                        self.assertEqual(names, ["localhost"])
                        self.assertIn(f"Host: localhost:{port}".encode(), requests[0])
                        # Same IP and port, distinct TLS origin: the second name must
                        # be verified independently, never reuse localhost's TLS pool.
                        fetcher.resolver.hosts["other.test"] = ["127.0.0.1"]
                        self.assertEqual(await fetcher.fetch(Source(f"https://other.test:{port}/")), [])
                        self.assertIn("other.test", names)
                        self.assertEqual(len(requests), 1)
        finally:
            server.close()
            await server.wait_closed()
