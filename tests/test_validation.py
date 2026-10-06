import asyncio
import base64
import dataclasses
import gzip
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import psutil

from openray.config import Settings
from openray.domain import Outcome, parse_uri
from openray.render import MIHOMO_SS_METHODS, SINGBOX_SS_METHODS, XRAY_SS_METHODS
from openray.validation import (
    REFERENCE,
    CoreWorker,
    Target,
    Validator,
    candidate_config,
    config_check,
    http_probe,
    reserve_port,
    tcp_handshake,
    tcp_only,
    terminate,
)
from tests.test_domain import UUID

ROOT = Path(__file__).resolve().parents[1]
XRAY = os.environ.get("OPENRAY_XRAY", str(ROOT / ".tools" / ("xray.exe" if os.name == "nt" else "xray")))
CORES = {
    "xray": XRAY,
    "singbox": str(ROOT / ".tools" / ("sing-box.exe" if os.name == "nt" else "sing-box")),
    "mihomo": str(ROOT / ".tools" / ("mihomo.exe" if os.name == "nt" else "mihomo")),
}


@unittest.skipUnless(all(Path(p).is_file() for p in CORES.values()), "pinned cores required")
class CoreCheckerTests(unittest.TestCase):
    def test_render_tables_match_pinned_core_checkers(self):
        # A core upgrade that drops a cipher would otherwise reappear as startup rejections.
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config = directory / "config.json"
            for kind, methods in (
                ("xray", XRAY_SS_METHODS),
                ("singbox", SINGBOX_SS_METHODS),
                ("mihomo", MIHOMO_SS_METHODS),
            ):
                for method in sorted(methods) + ["reference"]:
                    if method == "reference":
                        proxy = REFERENCE
                    else:
                        key = base64.b64encode(bytes(16 if "128" in method else 32)).decode()
                        auth = base64.urlsafe_b64encode(f"{method}:{key}".encode()).decode()
                        proxy = parse_uri(f"ss://{auth.rstrip('=')}@127.0.0.1:9")
                    config.write_text(json.dumps(candidate_config(proxy, kind, 18080, 18081, "token")))
                    check = subprocess.run(
                        config_check(kind, CORES[kind], directory, config), capture_output=True, timeout=30
                    )
                    with self.subTest(kind=kind, method=method):
                        self.assertEqual(check.returncode, 0)


@unittest.skipUnless(Path(XRAY).is_file(), "pinned Xray required: python tools/install_cores.py xray")
class CoreIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

        async def target(reader, writer):
            try:
                request = await reader.readuntil(b"\r\n\r\n")
                if b"/slow " in request:
                    await reader.read()
                    return
                if b"/compressed " in request:
                    body = gzip.compress(b"a" * (1024 * 1024 + 1))
                    writer.write(
                        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nConnection: close\r\n"
                        + f"Content-Length: {len(body)}\r\n\r\n".encode()
                        + body
                    )
                    await writer.drain()
                    return
                status = (
                    b"404 Not Found"
                    if b"/expected404 " in request
                    else b"302 Found"
                    if b"/redirect " in request
                    else b"204 No Content"
                )
                writer.write(b"HTTP/1.1 " + status + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        self.target = await asyncio.start_server(target, "127.0.0.1", 0)
        port = self.target.sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{port}/generate_204"
        reservation = reserve_port()
        self.server_port = reservation.getsockname()[1]
        config = {
            "log": {"loglevel": "none"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": self.server_port,
                    "protocol": "vless",
                    "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                }
            ],
            "outbounds": [
                {
                    "protocol": "freedom",
                    "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1"], "port": port}]},
                }
            ],
        }
        path = self.root / "server.json"
        path.write_text(json.dumps(config))
        reservation.close()
        self.server = await asyncio.create_subprocess_exec(
            XRAY,
            "run",
            "-c",
            str(path),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            creationflags=0x08000000 if os.name == "nt" else 0,
        )
        await asyncio.sleep(0.3)
        self.assertIsNone(self.server.returncode)
        self.settings = Settings(
            self.root,
            self.root / "state.sqlite3",
            self.root / "sources.txt",
            workers=2,
            timeout=10,
            xray=XRAY,
            test_url=self.url,
        )
        self.proxy = parse_uri(f"vless://{UUID}@127.0.0.1:{self.server_port}")

    async def asyncTearDown(self):
        await terminate(self.server)
        self.target.close()
        await self.target.wait_closed()
        self.tmp.cleanup()

    async def test_reference_and_pool_equivalence_no_orphans(self):
        outcomes = []
        for backend in ("subprocess", "pool"):
            settings = dataclasses.replace(self.settings, backend=backend)
            async with Validator(settings) as validator:
                results = await asyncio.gather(*(validator.check(self.proxy) for _ in range(6)))
                outcomes.append([r.outcome for r in results])
                pids = [w.process.pid for w in validator.workers if w.process]
                wrong = parse_uri(self.proxy.uri.replace(UUID, "22222222-2222-4222-8222-222222222222"))
                failed = await validator.check(wrong)
                self.assertNotEqual(failed.outcome, Outcome.SUCCESS)
            self.assertTrue(all(not psutil.pid_exists(pid) for pid in pids))
        self.assertEqual(outcomes[0], [Outcome.SUCCESS] * 6)
        self.assertEqual(outcomes[0], outcomes[1])

    async def test_deadline_and_cancel_cleanup(self):
        async with Validator(self.settings) as validator:
            start = asyncio.get_running_loop().time()
            task = asyncio.create_task(
                validator.check(self.proxy, Target("slow", ("http://10.255.255.1:81/",)))
            )
            await asyncio.sleep(0.3)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertLess(asyncio.get_running_loop().time() - start, 5)
            self.assertTrue(all(w.process is None for w in validator.workers))

    async def test_unknown_core_never_passes(self):
        async with Validator(dataclasses.replace(self.settings, xray="absent-xray")) as validator:
            self.assertEqual((await validator.check(self.proxy)).outcome, Outcome.CORE_FAILURE)

    async def test_core_rejection_is_invalid_config_not_infrastructure(self):
        async with Validator(self.settings) as validator:
            result = await validator.check(parse_uri(self.proxy.uri + "?encryption=garbage"))
            self.assertEqual((result.outcome, result.core), (Outcome.INVALID_CONFIG, "xray"))
            self.assertEqual((await validator.check(self.proxy)).outcome, Outcome.SUCCESS)
        # A "core" that exits for every configuration, known-good included, is infrastructure.
        async with Validator(dataclasses.replace(self.settings, xray=sys.executable)) as validator:
            self.assertEqual((await validator.check(self.proxy)).outcome, Outcome.CORE_FAILURE)

    async def test_mihomo_http_frontend_no_udp_or_direct_bypass(self):
        mihomo = ROOT / ".tools" / ("mihomo.exe" if os.name == "nt" else "mihomo")
        if not mihomo.is_file():
            self.skipTest("pinned mihomo required")
        settings = dataclasses.replace(self.settings, xray="", singbox="", mihomo=str(mihomo))
        worker = CoreWorker(settings, self.root / "mihomo-client")
        try:
            deadline = asyncio.get_running_loop().time() + 10
            await worker.start(self.proxy, "mihomo", str(mihomo), deadline, False)
            sockets = psutil.Process(worker.process.pid).net_connections(kind="all")
            self.assertFalse(
                any(c.type == socket.SOCK_DGRAM and c.laddr and c.laddr.port == worker.port for c in sockets)
            )
            result = await http_probe(
                worker.port, worker.token, Target("connectivity", (self.url,)), deadline
            )
            self.assertEqual(result.outcome, Outcome.SUCCESS)
        finally:
            await worker.stop()
        wrong = parse_uri(self.proxy.uri.replace(UUID, "22222222-2222-4222-8222-222222222222"))
        async with Validator(settings) as validator:
            self.assertNotEqual((await validator.check(wrong)).outcome, Outcome.SUCCESS)

    async def test_probe_policy_and_timeout_classification(self):
        async with Validator(self.settings) as validator:
            url = self.url.rsplit("/", 1)[0]
            result = await validator.check(
                self.proxy, Target("expected", (url + "/expected404",), allowed=(404,))
            )
            self.assertEqual((result.outcome, result.status), (Outcome.SUCCESS, 404))
            result = await validator.check(self.proxy, Target("redirect", (url + "/redirect",)))
            self.assertEqual(result.outcome, Outcome.TARGET_FAILURE)
            result = await validator.check(
                self.proxy, Target("compressed", (url + "/compressed",), allowed=(200,))
            )
            self.assertEqual(result.outcome, Outcome.TARGET_FAILURE)
            result = await validator.check(self.proxy, Target("body", (self.url,), body_sha256="0" * 64))
            self.assertEqual(result.outcome, Outcome.TARGET_FAILURE)
        async with Validator(dataclasses.replace(self.settings, timeout=1.5)) as validator:
            result = await validator.check(self.proxy, Target("slow", (url + "/slow",)))
            self.assertEqual(result.outcome, Outcome.TIMEOUT)
            self.assertTrue(all(w.process is None for w in validator.workers))


class TcpHandshakeTests(unittest.IsolatedAsyncioTestCase):
    async def test_handshake_is_negative_evidence_only(self):
        listener = await asyncio.start_server(lambda _, writer: writer.close(), "127.0.0.1", 0)
        proxy = parse_uri(f"vless://{UUID}@127.0.0.1:{listener.sockets[0].getsockname()[1]}")
        try:
            self.assertIsNone(await tcp_handshake(proxy, 5))
        finally:
            listener.close()
            await listener.wait_closed()
        self.assertEqual((await tcp_handshake(proxy, 5)).outcome, Outcome.PROXY_FAILURE)

        async def silent(*_):
            await asyncio.sleep(60)

        with unittest.mock.patch("asyncio.open_connection", silent):
            self.assertEqual((await tcp_handshake(proxy, 0.2)).outcome, Outcome.TIMEOUT)
        with unittest.mock.patch("asyncio.open_connection", side_effect=OSError("unreachable")):
            self.assertIsNone(await tcp_handshake(proxy, 5))
        self.assertTrue(tcp_only(proxy))
        for uri in (
            f"vless://{UUID}@example.com:443",
            "hy2://secret@127.0.0.1:443",
            f"vless://{UUID}@127.0.0.1:443?type=xhttp&alpn=h3",
            f"vless://{UUID}@127.0.0.1:443?type=kcp",
        ):
            self.assertFalse(tcp_only(parse_uri(uri)), uri)
