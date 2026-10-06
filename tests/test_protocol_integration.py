import asyncio
import base64
import dataclasses
import json
import os
import secrets
import socket
import ssl
import unittest
from pathlib import Path
from urllib.parse import urlencode

from openray.domain import Outcome, parse_uri
from openray.validation import Validator, terminate
from tests import test_validation as fixtures
from tests.test_domain import UUID

ROOT = fixtures.ROOT

SINGBOX = os.environ.get(
    "OPENRAY_SINGBOX", str(ROOT / ".tools" / ("sing-box.exe" if os.name == "nt" else "sing-box"))
)


def reserve_dual_port():
    # Windows TCP/UDP excluded ranges differ. Reserve both before a UDP-capable
    # fixture starts so an otherwise usable TCP ephemeral port cannot fail UDP.
    for _ in range(128):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if os.name == "nt":
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            # TCP's allocator can repeatedly choose a large UDP-excluded block.
            # Independent random proposals escape it while both binds prove availability.
            tcp.bind(("127.0.0.1", 20000 + secrets.randbelow(28000)))
            udp.bind(tcp.getsockname())
            return tcp, udp
        except OSError:
            tcp.close()
            udp.close()
    raise OSError("no available dual-transport fixture port")


@unittest.skipUnless(Path(SINGBOX).is_file(), "pinned sing-box required")
class ProtocolIntegrationTests(fixtures.CoreIntegrationTests):
    test_deadline_and_cancel_cleanup = None
    test_reference_and_pool_equivalence_no_orphans = None
    test_unknown_core_never_passes = None
    test_core_rejection_is_invalid_config_not_infrastructure = None
    test_probe_policy_and_timeout_classification = None
    test_mihomo_http_frontend_no_udp_or_direct_bypass = None

    async def test_reality_with_local_tls_handshake_server(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(ROOT / "tests/fixtures/test-cert.pem", ROOT / "tests/fixtures/test-key.pem")

        async def handshake(reader, writer):
            await reader.read()
            writer.close()
            await writer.wait_closed()

        origin = await asyncio.start_server(handshake, "127.0.0.1", 0, ssl=context)
        generated = await asyncio.create_subprocess_exec(
            SINGBOX,
            "generate",
            "reality-keypair",
            stdout=asyncio.subprocess.PIPE,
            creationflags=0x08000000 if os.name == "nt" else 0,
        )
        output, _ = await generated.communicate()
        keys = dict(line.split(": ", 1) for line in output.decode().splitlines())
        reservation, udp_reservation = reserve_dual_port()
        port = reservation.getsockname()[1]
        config = {
            "log": {"level": "debug", "output": str(self.root / "reality.log")},
            "inbounds": [
                {
                    "type": "vless",
                    "tag": "reality",
                    "listen": "127.0.0.1",
                    "listen_port": port,
                    "users": [{"uuid": UUID}],
                    "tls": {
                        "enabled": True,
                        "server_name": "localhost",
                        "reality": {
                            "enabled": True,
                            "private_key": keys["PrivateKey"],
                            "short_id": ["08"],
                            "handshake": {
                                "server": "127.0.0.1",
                                "server_port": origin.sockets[0].getsockname()[1],
                            },
                        },
                    },
                }
            ],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
        }
        path = self.root / "reality-server.json"
        path.write_text(json.dumps(config))
        reservation.close()
        udp_reservation.close()
        server = await asyncio.create_subprocess_exec(
            SINGBOX,
            "run",
            "-c",
            str(path),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            creationflags=0x08000000 if os.name == "nt" else 0,
        )
        try:
            await asyncio.sleep(0.3)
            self.assertIsNone(
                server.returncode,
                (await server.stderr.read()).decode() if server.returncode is not None else "",
            )
            query = urlencode(
                {
                    "security": "reality",
                    "sni": "localhost",
                    "sid": "08",
                    "pbk": keys["PublicKey"],
                    "fp": "chrome",
                }
            )
            proxy = parse_uri(f"vless://{UUID}@127.0.0.1:{port}?{query}")
            async with Validator(
                dataclasses.replace(self.settings, singbox=SINGBOX, timeout=10)
            ) as validator:
                result = await validator.check(proxy)
                self.assertEqual(
                    result.outcome,
                    Outcome.SUCCESS,
                    result.detail + (self.root / "reality.log").read_text()[-2000:],
                )
                self.assertEqual(result.core, "xray")
        finally:
            await terminate(server)
            origin.close()
            await origin.wait_closed()

    async def test_wireguard_userspace_endpoint(self):
        # A userspace WireGuard stack has its own loopback. Use the host's routed
        # address for this controlled local target, without changing OS routes.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
            route.connect(("192.0.2.1", 80))  # No packets are sent by UDP connect.
            address = route.getsockname()[0]

        async def handler(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        target = await asyncio.start_server(handler, address, 0)
        url = f"http://{address}:{target.sockets[0].getsockname()[1]}/"

        async def keys():
            process = await asyncio.create_subprocess_exec(
                SINGBOX,
                "generate",
                "wg-keypair",
                stdout=asyncio.subprocess.PIPE,
                creationflags=0x08000000 if os.name == "nt" else 0,
            )
            output, _ = await process.communicate()
            self.assertEqual(process.returncode, 0)
            return dict(line.split(": ", 1) for line in output.decode().splitlines())

        server_keys, client_keys = await keys(), await keys()
        reservation, udp_reservation = reserve_dual_port()
        port = reservation.getsockname()[1]
        config = {
            "log": {"level": "debug", "output": str(self.root / "wg.log")},
            "endpoints": [
                {
                    "type": "wireguard",
                    "tag": "wg",
                    "system": False,
                    "workers": 2,
                    "address": ["10.0.0.1/32"],
                    "private_key": server_keys["PrivateKey"],
                    "listen_port": port,
                    "peers": [{"public_key": client_keys["PublicKey"], "allowed_ips": ["10.0.0.2/32"]}],
                }
            ],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
        }
        path = self.root / "wg-server.json"
        path.write_text(json.dumps(config))
        reservation.close()
        udp_reservation.close()
        server = await asyncio.create_subprocess_exec(
            SINGBOX,
            "run",
            "-c",
            str(path),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            creationflags=0x08000000 if os.name == "nt" else 0,
        )
        try:
            await asyncio.sleep(0.3)
            self.assertIsNone(
                server.returncode,
                (await server.stderr.read()).decode() if server.returncode is not None else "",
            )
            query = urlencode(
                {
                    "privatekey": client_keys["PrivateKey"],
                    "publickey": server_keys["PublicKey"],
                    "address": "10.0.0.2/32",
                }
            )
            proxy = parse_uri(f"wireguard://127.0.0.1:{port}?{query}")
            async with Validator(
                dataclasses.replace(self.settings, singbox=SINGBOX, timeout=10, test_url=url)
            ) as validator:
                result = await validator.check(proxy)
                self.assertEqual(
                    result.outcome,
                    Outcome.SUCCESS,
                    result.detail + (self.root / "wg.log").read_text()[-2000:],
                )
        finally:
            await terminate(server)
            target.close()
            await target.wait_closed()

    async def test_protocols_through_real_servers(self):
        # Test keys are deliberately public fixtures; never used for production.
        ports = {}
        reservations = []
        for name in (
            "vmess",
            "trojan",
            "ss",
            "socks",
            "http",
            "https",
            "hysteria",
            "hysteria2",
            "tuic",
            "ws",
            "grpc",
        ):
            sock, udp = reserve_dual_port()
            ports[name] = sock.getsockname()[1]
            reservations.append(sock)
            reservations.append(udp)
        tls = {
            "enabled": True,
            "certificate_path": str(ROOT / "tests/fixtures/test-cert.pem"),
            "key_path": str(ROOT / "tests/fixtures/test-key.pem"),
        }
        inbounds = [
            {"type": "vmess", "users": [{"uuid": UUID, "alterId": 0}], "tag": "vmess"},
            {"type": "trojan", "users": [{"password": "test-secret"}], "tls": tls, "tag": "trojan"},
            {"type": "shadowsocks", "method": "aes-128-gcm", "password": "test-secret", "tag": "ss"},
            {"type": "socks", "users": [{"username": "user", "password": "test-secret"}], "tag": "socks"},
            {"type": "http", "users": [{"username": "user", "password": "test-secret"}], "tag": "http"},
            {
                "type": "http",
                "users": [{"username": "user", "password": "test-secret"}],
                "tls": tls,
                "tag": "https",
            },
            {
                "type": "hysteria",
                "users": [{"auth_str": "test-secret"}],
                "up_mbps": 100,
                "down_mbps": 100,
                "tls": tls,
                "tag": "hysteria",
            },
            {"type": "hysteria2", "users": [{"password": "test-secret"}], "tls": tls, "tag": "hysteria2"},
            {
                "type": "tuic",
                "users": [{"uuid": UUID, "password": "test-secret"}],
                "congestion_control": "cubic",
                "tls": dict(tls, alpn=["h3"]),
                "tag": "tuic",
            },
            {
                "type": "vless",
                "users": [{"uuid": UUID}],
                "transport": {
                    "type": "ws",
                    "path": "/ws",
                    "early_data_header_name": "Sec-WebSocket-Protocol",
                },
                "tag": "ws",
            },
            {
                "type": "vless",
                "users": [{"uuid": UUID}],
                "transport": {"type": "grpc", "service_name": "test-service"},
                "tag": "grpc",
            },
        ]
        for inbound in inbounds:
            inbound.update(listen="127.0.0.1", listen_port=ports[inbound["tag"]])
        config = {
            "log": {"level": "debug", "output": str(self.root / "protocol-server.log")},
            "inbounds": inbounds,
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
        }
        path = self.root / "sing-server.json"
        path.write_text(json.dumps(config))
        for reservation in reservations:
            reservation.close()
        server = await asyncio.create_subprocess_exec(
            SINGBOX,
            "run",
            "-c",
            str(path),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            creationflags=0x08000000 if os.name == "nt" else 0,
        )
        try:
            await asyncio.sleep(0.3)
            self.assertIsNone(
                server.returncode,
                (await server.stderr.read()).decode() if server.returncode is not None else "",
            )
            vmess = base64.b64encode(
                json.dumps({"add": "127.0.0.1", "port": ports["vmess"], "id": UUID, "scy": "auto"}).encode()
            ).decode()
            ss_auth = base64.urlsafe_b64encode(b"aes-128-gcm:test-secret").decode().rstrip("=")
            uris = {
                "vmess": "vmess://" + vmess,
                "trojan": f"trojan://test-secret@127.0.0.1:{ports['trojan']}?sni=localhost&allowInsecure=1",
                "ss": f"ss://{ss_auth}@127.0.0.1:{ports['ss']}",
                "socks": f"socks://user:test-secret@127.0.0.1:{ports['socks']}",
                "http": f"http://user:test-secret@127.0.0.1:{ports['http']}",
                "https": f"https://user:test-secret@127.0.0.1:{ports['https']}?sni=localhost&allowInsecure=1",
                "hysteria": f"hysteria://127.0.0.1:{ports['hysteria']}?auth=test-secret&insecure=1&sni=localhost",
                "hysteria2": f"hy2://test-secret@127.0.0.1:{ports['hysteria2']}?insecure=1&sni=localhost",
                "tuic": f"tuic://{UUID}:test-secret@127.0.0.1:{ports['tuic']}?insecure=1&sni=localhost&alpn=h3",
                "ws": f"vless://{UUID}@127.0.0.1:{ports['ws']}?type=ws&path=%2Fws%3Ftoken%3Da",
                "grpc": f"vless://{UUID}@127.0.0.1:{ports['grpc']}?type=grpc&serviceName=test-service",
            }
            settings = dataclasses.replace(self.settings, singbox=SINGBOX, timeout=10)
            async with Validator(settings) as validator:
                for name, uri in uris.items():
                    with self.subTest(protocol=name):
                        result = await validator.check(parse_uri(uri))
                        self.assertEqual(
                            result.outcome,
                            Outcome.SUCCESS,
                            f"{result.detail}; status={result.status}; core={result.core}; "
                            + (self.root / "protocol-server.log").read_text()[-2500:]
                            if result.outcome != Outcome.SUCCESS
                            else "",
                        )
        finally:
            await terminate(server)
