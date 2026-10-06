from __future__ import annotations

import asyncio
import contextlib
import errno
import hashlib
import ipaddress
import os
import secrets
import shutil
import socket
import ssl
import tempfile
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .config import Settings
from .domain import Observation, Outcome, Proxy
from .files import atomic_write, json_text
from .http_body import bounded_body
from .render import Unsupported, clash_proxy, singbox_outbound, wireguard_endpoint, xray_outbound

# Known-good outbound for every core; never probed, only checked offline.
REFERENCE = Proxy("socks://127.0.0.1:9", "socks", "127.0.0.1", 9)


class ConfigRejected(Exception):
    pass


class CoreExited(RuntimeError):
    """A core exit with a package-controlled reason, safe to record in observation details."""


def config_check(kind: str, path: str, directory: Path, config: Path) -> list[str]:
    return {
        "xray": [path, "run", "-test", "-c", str(config)],
        "singbox": [path, "check", "-c", str(config)],
        "mihomo": [path, "-t", "-d", str(directory), "-f", str(config)],
    }[kind]


@dataclass(frozen=True)
class Target:
    id: str
    urls: tuple[str, ...]
    version: int = 1
    allowed: tuple[int, ...] = (204,)
    blocked: tuple[int, ...] = ()
    body_sha256: str = ""


SITE_TARGETS = (
    Target(
        "aistudio",
        ("https://aistudio.google.com/welcome",),
        allowed=tuple(c for c in range(200, 600) if c != 403),
        blocked=(403,),
    ),
    Target(
        "jetbrain",
        ("https://analytics.services.jetbrains.com/",),
        allowed=tuple(c for c in range(200, 600) if c != 403),
        blocked=(403,),
    ),
    Target("cursor", ("https://agentn.global.api5.cursor.sh",), version=2, allowed=(200,), blocked=(403,)),
)


@lru_cache(maxsize=1)
def ssl_context():
    return ssl.create_default_context()


async def terminate(process: asyncio.subprocess.Process | None):
    if process is None:
        return
    if process.returncode is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
    try:
        await asyncio.wait_for(process.wait(), 0.5)
    except TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await asyncio.wait_for(process.wait(), 2)


async def spawn_owned(*args, **kwargs) -> asyncio.subprocess.Process:
    """Cancellation during process creation must still adopt and reap the child."""
    spawning = asyncio.create_task(asyncio.create_subprocess_exec(*args, **kwargs))
    try:
        return await asyncio.shield(spawning)
    except asyncio.CancelledError:
        process = await spawning
        await asyncio.shield(terminate(process))
        raise


def reserve_port() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if os.name == "nt":
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    sock.bind(("127.0.0.1", 0))
    return sock


def owned_listener(pid: int, port: int) -> bool:
    import psutil

    try:
        return any(
            c.status == psutil.CONN_LISTEN and c.laddr.port == port and c.laddr.ip in {"127.0.0.1", "::1"}
            for c in psutil.Process(pid).net_connections(kind="tcp")
        )
    except (psutil.Error, OSError):
        return False


async def http_probe(port: int, token: str, target: Target, deadline: float) -> Observation:
    import httpx

    start = time.monotonic()
    for url in target.urls:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return Observation(Outcome.TIMEOUT, detail="probe deadline")
        try:
            # trust_env=False prevents NO_PROXY or an ambient proxy from bypassing the candidate.
            async with httpx.AsyncClient(
                proxy=f"http://openray:{token}@127.0.0.1:{port}",
                trust_env=False,
                follow_redirects=False,
                timeout=remaining,
                verify=ssl_context(),
            ) as client:
                async with client.stream("GET", url, headers={"User-Agent": "OpenRay/2"}) as response:
                    status = response.status_code
                    if status in target.blocked:
                        return Observation(Outcome.BLOCKED, status=status, detail="target denied connection")
                    if status not in target.allowed:
                        return Observation(
                            Outcome.TARGET_FAILURE, status=status, detail="unexpected target response"
                        )
                    size, digest = 0, hashlib.sha256()
                    async for chunk in bounded_body(response, 1024 * 1024):
                        size += len(chunk)
                        digest.update(chunk)
                    if target.body_sha256 and digest.hexdigest() != target.body_sha256:
                        return Observation(
                            Outcome.TARGET_FAILURE, status=status, detail="probe body mismatch"
                        )
                    if status == 204 and size:
                        return Observation(
                            Outcome.TARGET_FAILURE, status=status, detail="204 response contains body"
                        )
        except httpx.TimeoutException:
            return Observation(Outcome.TIMEOUT, detail="proxy request timeout")
        except ValueError:
            return Observation(Outcome.TARGET_FAILURE, detail="invalid or excessive probe body")
        except (httpx.HTTPError, OSError):
            return Observation(Outcome.PROXY_FAILURE, detail="proxy request failed")
    return Observation(Outcome.SUCCESS, (time.monotonic() - start) * 1000, status=status)


def candidate_config(
    proxy: Proxy, kind: str, port: int, api_port: int, token: str, *, pool: bool = False
) -> dict:
    if kind == "xray":
        config = {
            "log": {"loglevel": "none"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": port,
                    "protocol": "http",
                    "tag": "test",
                    "settings": {"accounts": [{"user": "openray", "pass": token}]},
                }
            ],
            "outbounds": [xray_outbound(proxy)],
            "routing": {"rules": [{"inboundTag": ["test"], "outboundTag": "candidate"}]},
        }
        if pool:
            config["api"] = {"tag": "api", "services": ["HandlerService"]}
            config["inbounds"].append(
                {
                    "listen": "127.0.0.1",
                    "port": api_port,
                    "protocol": "dokodemo-door",
                    "tag": "api",
                    "settings": {"address": "127.0.0.1"},
                }
            )
            config["routing"]["rules"].insert(0, {"inboundTag": ["api"], "outboundTag": "api"})
        return config
    if kind == "singbox":
        endpoint = proxy.scheme == "wireguard"
        outbound = wireguard_endpoint(proxy) if endpoint else singbox_outbound(proxy)
        config = {
            "log": {"disabled": True},
            "inbounds": [
                {
                    "type": "http",
                    "listen": "127.0.0.1",
                    "listen_port": port,
                    "tag": "test",
                    "users": [{"username": "openray", "password": token}],
                }
            ],
            "outbounds": [] if endpoint else [outbound],
            "route": {"final": outbound["tag"]},
        }
        if endpoint:
            config["endpoints"] = [outbound]
        return config
    if kind == "mihomo":
        outbound = clash_proxy(proxy)
        return {
            "port": port,
            "bind-address": "127.0.0.1",
            "allow-lan": False,
            "authentication": [f"openray:{token}"],
            "log-level": "silent",
            "mode": "rule",
            "proxies": [outbound],
            "rules": [f"MATCH,{outbound['name']}"],
        }
    raise Unsupported("core adapter unavailable")


class CoreWorker:
    def __init__(self, settings: Settings, directory: Path):
        self.settings = settings
        self.directory = directory
        self.process: asyncio.subprocess.Process | None = None
        self.port = self.api_port = 0
        self.kind = ""
        self.token = secrets.token_hex(16)
        self.jobs = 0
        self.stderr = None
        self.stop_lock = asyncio.Lock()
        self.checkers: set[str] = set()

    def select(self, proxy: Proxy) -> tuple[str, str]:
        candidates = [
            ("xray", self.settings.xray, xray_outbound),
            (
                "singbox",
                self.settings.singbox,
                wireguard_endpoint if proxy.scheme == "wireguard" else singbox_outbound,
            ),
            ("mihomo", self.settings.mihomo, clash_proxy),
        ]
        representable = False
        for kind, path, renderer in candidates:
            try:
                renderer(proxy)
                representable = True
            except (Unsupported, ValueError, KeyError):
                continue
            if path and (Path(path).is_file() or shutil.which(path)):
                return kind, path
        if representable:
            raise FileNotFoundError("required validation core is unavailable")
        raise Unsupported("no faithful core adapter for protocol/transport")

    async def stop(self):
        async with self.stop_lock:
            try:
                await terminate(self.process)
            finally:
                self.process = None
                self.jobs = 0
                if self.stderr:
                    self.stderr.close()
                    self.stderr = None

    async def _command(self, args: list[str], deadline: float) -> bool:
        if deadline <= time.monotonic():
            return False
        process = await spawn_owned(
            *args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            creationflags=0x08000000 if os.name == "nt" else 0,
        )
        try:
            await asyncio.wait_for(process.wait(), max(0.001, deadline - time.monotonic()))
            return process.returncode == 0
        finally:
            await terminate(process)

    async def rejected(self, kind: str, path: str, config_path: Path, deadline: float) -> bool:
        # An early exit is blamed on the configuration only when the core's own checker
        # refuses it yet accepts a known-good one. Anything inconclusive stays a core failure.
        if await self._command(config_check(kind, path, self.directory, config_path), deadline):
            return False
        if time.monotonic() >= deadline:
            return False
        if kind not in self.checkers:
            reference = self.directory / "reference.json"
            config = candidate_config(REFERENCE, kind, self.port, self.api_port, self.token)
            atomic_write(reference, json_text(config))
            if not await self._command(config_check(kind, path, self.directory, reference), deadline):
                return False
            self.checkers.add(kind)
        return True

    async def start(self, proxy: Proxy, kind: str, path: str, deadline: float, reuse: bool):
        try:
            await self._start(proxy, kind, path, deadline, reuse)
        except CoreExited:
            # Its own checker accepted this configuration, so the exit belongs to the host,
            # such as a port taken between reservation and bind. Retry once on fresh ports.
            await self._start(proxy, kind, path, deadline, reuse)

    async def _start(self, proxy: Proxy, kind: str, path: str, deadline: float, reuse: bool):
        await self.stop()
        http, api = reserve_port(), reserve_port()
        self.port, self.api_port = http.getsockname()[1], api.getsockname()[1]
        try:
            config = candidate_config(proxy, kind, self.port, self.api_port, self.token, pool=reuse)
            self.directory.mkdir(parents=True, exist_ok=True)
            config_path = self.directory / "config.json"
            atomic_write(config_path, json_text(config))
            command = {
                "xray": [path, "run", "-c", str(config_path)],
                "singbox": [path, "run", "-c", str(config_path)],
                "mihomo": [path, "-d", str(self.directory), "-f", str(config_path)],
            }[kind]
            # Release immediately before spawn. Readiness checks ownership, never just an open port.
            http.close()
            api.close()
            self.stderr = (self.directory / "stderr.log").open("wb")
            self.process = await spawn_owned(
                *command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=self.stderr,
                creationflags=0x08000000 if os.name == "nt" else 0,
            )
            self.kind = kind
            while time.monotonic() < deadline:
                if self.process.returncode is not None:
                    if await self.rejected(kind, path, config_path, deadline):
                        raise ConfigRejected("core rejected configuration")
                    log = (self.directory / "stderr.log").read_bytes()[-4096:]
                    if b"address already in use" in log:
                        raise CoreExited("core exited during startup: port collision")
                    raise CoreExited("core exited during startup")
                if await asyncio.to_thread(owned_listener, self.process.pid, self.port):
                    if not reuse or await asyncio.to_thread(owned_listener, self.process.pid, self.api_port):
                        return
                await asyncio.sleep(0.02)
            raise TimeoutError("core readiness deadline")
        finally:
            http.close()
            api.close()

    async def check(self, proxy: Proxy, target: Target, deadline: float) -> Observation:
        start = time.monotonic()
        keep = False
        probing = False
        try:
            kind, path = self.select(proxy)
            reuse = self.settings.backend in {"pool", "api", "xray_api"} and kind == "xray"
            async with asyncio.timeout_at(deadline):
                if (
                    reuse
                    and self.kind == kind
                    and self.process
                    and self.process.returncode is None
                    and self.jobs < 100
                ):
                    outbound_path = self.directory / "outbound.json"
                    atomic_write(outbound_path, json_text({"outbounds": [xray_outbound(proxy)]}))
                    api = f"-server=127.0.0.1:{self.api_port}"
                    if not await self._command([path, "api", "rmo", api, "candidate"], deadline):
                        raise RuntimeError("candidate removal failed")
                    if not await self._command([path, "api", "ado", api, str(outbound_path)], deadline):
                        raise RuntimeError("candidate installation failed")
                else:
                    await self.start(proxy, kind, path, deadline, reuse)
                probing = True
                result = await http_probe(self.port, self.token, target, deadline)
                if self.process.returncode is not None:
                    raise CoreExited("core exited during probe")
                self.jobs += 1
                keep = reuse and result.outcome not in {Outcome.CORE_FAILURE, Outcome.CANCELLED}
                return Observation(
                    result.outcome, (time.monotonic() - start) * 1000, result.detail, result.status, kind
                )
        except Unsupported:
            return Observation(Outcome.UNSUPPORTED, detail="no faithful core adapter")
        except ConfigRejected:
            return Observation(
                Outcome.INVALID_CONFIG,
                (time.monotonic() - start) * 1000,
                "core rejected configuration",
                core=kind,
            )
        except FileNotFoundError:
            return Observation(Outcome.CORE_FAILURE, detail="required core unavailable")
        except (ValueError, KeyError):
            return Observation(Outcome.INVALID_CONFIG, detail="invalid protocol configuration")
        except TimeoutError:
            return Observation(
                Outcome.TIMEOUT if probing else Outcome.CORE_FAILURE,
                (time.monotonic() - start) * 1000,
                "validation deadline",
            )
        except (OSError, RuntimeError) as exc:
            if isinstance(exc, CoreExited):
                reason = str(exc)
            elif isinstance(exc, OSError) and exc.errno in errno.errorcode:
                reason = errno.errorcode[exc.errno]
            else:
                reason = type(exc).__name__
            return Observation(
                Outcome.CORE_FAILURE,
                (time.monotonic() - start) * 1000,
                "core startup/swap/lifecycle failed: " + reason,
            )
        finally:
            if not keep:
                await asyncio.shield(self.stop())


class Validator:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.closed = False
        self.checks = set()
        self.temporary = tempfile.TemporaryDirectory(prefix="openray-")
        self.workers = [
            CoreWorker(settings, Path(self.temporary.name) / str(i)) for i in range(settings.workers)
        ]
        self.available: asyncio.Queue[CoreWorker] = asyncio.Queue(settings.workers)
        for worker in self.workers:
            self.available.put_nowait(worker)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.close()

    async def close(self):
        if self.closed:
            return
        self.closed = True
        active = list(self.checks)
        for task in active:
            task.cancel()
        await asyncio.gather(*active, return_exceptions=True)
        await asyncio.gather(*(w.stop() for w in self.workers))
        self.temporary.cleanup()

    async def check(self, proxy: Proxy, target: Target | None = None) -> Observation:
        if self.closed:
            raise RuntimeError("validator is closed")
        task = asyncio.current_task()
        self.checks.add(task)
        try:
            return await self._check(proxy, target)
        finally:
            self.checks.discard(task)

    async def _check(self, proxy: Proxy, target: Target | None = None) -> Observation:
        target = target or Target(
            "connectivity",
            (self.settings.test_url,),
            allowed=(self.settings.test_status,),
            body_sha256=self.settings.body_sha256,
        )
        if self.settings.tcp_prefilter and tcp_only(proxy):
            rejected = await tcp_handshake(proxy, self.settings.timeout)
            if rejected:
                return rejected
        # Waiting for a free core is not the candidate's time: its full timeout starts with the core.
        worker = await self.available.get()
        try:
            # The worker owns its deadline and bounded teardown. An outer timeout here
            # would overwrite a completed probe timeout while its child is being reaped.
            return await worker.check(proxy, target, time.monotonic() + self.settings.timeout)
        finally:
            self.available.put_nowait(worker)


def tcp_only(proxy: Proxy) -> bool:
    # Domains may resolve differently inside a core; UDP transports have no TCP handshake.
    try:
        ipaddress.ip_address(proxy.server)
    except ValueError:
        return False
    return (
        proxy.scheme in {"vless", "vmess", "trojan", "ss", "http", "https", "socks"}
        and proxy.transport not in {"kcp", "quic"}
        and "h3" not in proxy.get("alpn").lower().split(",")
        and not proxy.get("plugin")
    )


async def tcp_handshake(proxy: Proxy, timeout: float) -> Observation | None:
    """Negative evidence only. An endpoint that refuses, or does not complete a TCP handshake
    within the full validation timeout, cannot pass the core check over the same network."""
    started = time.monotonic()
    try:
        async with asyncio.timeout(timeout):
            _, writer = await asyncio.open_connection(proxy.server, proxy.port)
    except ConnectionRefusedError:
        return Observation(
            Outcome.PROXY_FAILURE, (time.monotonic() - started) * 1000, "TCP endpoint refused connection"
        )
    except TimeoutError:
        return Observation(Outcome.TIMEOUT, (time.monotonic() - started) * 1000, "TCP handshake deadline")
    except OSError:
        return None  # Inconclusive: the protocol core decides.
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()
    return None
