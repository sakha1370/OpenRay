import asyncio
import gzip
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from openray.config import Settings
from openray.fetch import Fetcher, Source
from openray.storage import Store
from tests.test_domain import VLESS


class FetchTests(unittest.IsolatedAsyncioTestCase):
    async def test_local_source_resolves_root_alias_and_rejects_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            real = parent / "real"
            real.mkdir()
            (real / "subscription.txt").write_text(VLESS + "\n")
            (parent / "outside.txt").write_text(VLESS + "\n")
            alias = parent / "alias"
            if os.name == "nt":
                subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(alias), str(real)],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                alias.symlink_to(real, target_is_directory=True)
            settings = Settings(alias, parent / "state.sqlite3", alias / "sources.txt")
            with Store(settings.database) as store:
                async with Fetcher(settings, store) as fetcher:
                    self.assertEqual(await fetcher.fetch(Source("subscription.txt")), [VLESS])
                    self.assertEqual(await fetcher.fetch(Source(str(real / "subscription.txt"))), [VLESS])
                    with self.assertRaisesRegex(ValueError, "outside configured root"):
                        await fetcher._request(Source("../outside.txt"))

    async def test_cache_gzip_size_and_status(self):
        seen = []

        async def handler(reader, writer):
            data = await reader.readuntil(b"\r\n\r\n")
            seen.append(data)
            path = data.split()[1]
            body = gzip.compress((VLESS + "\n").encode())
            headers = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nETag: test\r\n"
            if b"if-none-match: test" in data.lower():
                body, headers = b"", b"HTTP/1.1 304 Not Modified\r\n"
            if path == b"/oversize":
                body = gzip.compress(b"x" * 10000)
            if path == b"/bad":
                headers = b"HTTP/1.1 404 Not Found\r\n"
            writer.write(
                headers + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        url = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                settings = Settings(
                    root,
                    root / "state.sqlite3",
                    root / "sources.txt",
                    max_body=1000,
                    allow_private_sources=True,
                )
                with Store(settings.database) as store, self.subTest("fetch"):
                    async with Fetcher(settings, store) as fetcher:
                        self.assertEqual(await fetcher.fetch(Source(url + "/ok")), [VLESS])
                        self.assertEqual(await fetcher.fetch(Source(url + "/ok")), [VLESS])
                        self.assertIn(b"if-none-match: test", seen[-1].lower())
                        self.assertEqual(await fetcher.fetch(Source(url + "/oversize")), [])
                        self.assertEqual(await fetcher.fetch(Source(url + "/bad")), [])
                settings = Settings(root, root / "private.sqlite3", root / "sources.txt")
                with Store(settings.database) as store:
                    async with Fetcher(settings, store) as fetcher:
                        self.assertEqual(await fetcher.fetch(Source(url)), [])
        finally:
            server.close()
            await server.wait_closed()
