from __future__ import annotations

import asyncio
import ipaddress
import os
import random
import socket
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .config import Settings
from .domain import ParseError, extract_uris
from .http_body import bounded_body
from .source_transport import PinnedBackend
from .storage import Store


@dataclass(frozen=True)
class Source:
    url: str
    encoded: bool = False


def source_lines(path: Path) -> list[Source]:
    result = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        url, _, flag = line.rpartition(",")
        if flag.lower().strip() in {"1", "true", "base64", "0", "false"}:
            result.append(Source(url.strip(), flag.lower().strip() in {"1", "true", "base64"}))
        else:
            result.append(Source(line))
    return list(dict.fromkeys(result))


class Resolver:
    def __init__(self, concurrency: int = 8, ttl: float = 60):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.cache: OrderedDict[str, tuple[float, list[str]]] = OrderedDict()
        self.ttl = ttl
        import dns.asyncresolver

        try:
            self.dns = dns.asyncresolver.Resolver()
        except dns.resolver.NoResolverConfiguration:
            # Literal addresses, hosts entries and local files still work offline.
            self.dns = dns.asyncresolver.Resolver(configure=False)
        self.dns.timeout = 2
        self.hosts = {"localhost": ["127.0.0.1", "::1"]}
        path = (
            Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/drivers/etc/hosts"
            if os.name == "nt"
            else Path("/etc/hosts")
        )
        if path.is_file():
            with path.open(encoding="utf-8", errors="replace") as host_file:
                host_lines = host_file.read(1024 * 1024).splitlines()
            for line in host_lines:
                values = line.split("#", 1)[0].split()
                if len(values) > 1:
                    try:
                        address = str(ipaddress.ip_address(values[0]))
                    except ValueError:
                        continue
                    for alias in values[1:]:
                        self.hosts.setdefault(alias.lower(), []).append(address)

    async def resolve(self, host: str, port: int) -> list[str]:
        try:
            return [str(ipaddress.ip_address(host))]
        except ValueError:
            pass
        host = host.lower().rstrip(".")
        if host in self.hosts:
            return sorted(set(self.hosts[host]))
        cached = self.cache.get(host)
        if cached and cached[0] > time.monotonic():
            self.cache.move_to_end(host)
            return cached[1]
        async with self.semaphore:
            import dns.exception

            try:
                async with asyncio.timeout(5):
                    answers = await self.dns.resolve_name(host, lifetime=5, search=False)
                    result = sorted(
                        set(answers.addresses()), key=lambda ip: (ipaddress.ip_address(ip).version, ip)
                    )
            except dns.exception.DNSException as exc:
                raise socket.gaierror("asynchronous source DNS failed") from exc
        self.cache[host] = (time.monotonic() + self.ttl, result)
        if len(self.cache) > 4096:
            self.cache.popitem(last=False)
        return result


class Fetcher:
    def __init__(self, settings: Settings, store: Store):
        self.settings, self.store = settings, store
        self.resolver = Resolver(settings.fetch_workers)
        self.client = None

    async def __aenter__(self):
        import httpx

        self.network = PinnedBackend()
        self.transport = httpx.AsyncHTTPTransport(
            trust_env=False,
            limits=httpx.Limits(
                max_connections=self.settings.fetch_workers,
                max_keepalive_connections=self.settings.fetch_workers,
            ),
        )
        self.transport._pool._network_backend = self.network
        self.client = httpx.AsyncClient(
            transport=self.transport,
            trust_env=False,
            follow_redirects=False,
            limits=httpx.Limits(
                max_connections=self.settings.fetch_workers,
                max_keepalive_connections=self.settings.fetch_workers,
            ),
            timeout=self.settings.fetch_timeout,
        )
        return self

    async def __aexit__(self, *_):
        await self.client.aclose()

    async def _request(self, source: Source, address_index: int = 0) -> tuple[str, str, str]:
        import httpx

        parsed = urlsplit(source.url)
        if parsed.scheme not in {"http", "https"}:
            local = Path(parsed.path if parsed.scheme == "file" else source.url)
            if not local.is_absolute():
                local = self.settings.root / local
            local = local.resolve()
            if not local.is_relative_to(self.settings.root) and not self.settings.allow_private_sources:
                raise ValueError("local source outside configured root")
            if not local.is_file():
                raise ValueError("local source must be a regular file")

            def read():
                with local.open("rb") as f:
                    body = f.read(self.settings.max_body + 1)
                if len(body) > self.settings.max_body:
                    raise ValueError("source body exceeds limit")
                return body.decode("utf-8-sig")

            return await asyncio.to_thread(read), "", ""
        row = self.store.db.execute("SELECT * FROM source WHERE url=?", (source.url,)).fetchone()
        headers = {"User-Agent": "OpenRay/2", "Accept-Encoding": "gzip, deflate"}
        if row:
            if row["etag"]:
                headers["If-None-Match"] = row["etag"]
            if row["modified"]:
                headers["If-Modified-Since"] = row["modified"]
        url = source.url
        async with asyncio.timeout(self.settings.fetch_timeout):
            for _ in range(6):
                original = httpx.URL(url)
                if original.scheme not in {"http", "https"} or original.userinfo:
                    raise ValueError("unsafe source URL")
                addresses = await self.resolver.resolve(
                    original.host, original.port or (443 if original.scheme == "https" else 80)
                )
                if not addresses:
                    raise ValueError("source DNS returned no addresses")
                if not self.settings.allow_private_sources and any(
                    not ipaddress.ip_address(a).is_global for a in addresses
                ):
                    raise ValueError("private source address denied")
                # Pin the checked DNS result while retaining HTTP Host and TLS SNI.
                self.network.pin.set((original.host, addresses[address_index % len(addresses)]))
                request_headers = dict(headers, Host=original.netloc.decode("ascii"))
                async with self.client.stream("GET", original, headers=request_headers) as response:
                    if response.status_code == 304 and row and row["body"] is not None:
                        return bytes(row["body"]).decode("utf-8"), row["etag"] or "", row["modified"] or ""
                    if response.is_redirect:
                        url = urljoin(url, response.headers.get("location", ""))
                        headers.pop("If-None-Match", None)
                        headers.pop("If-Modified-Since", None)
                        continue
                    response.raise_for_status()
                    body = bytearray()
                    async for chunk in bounded_body(response, self.settings.max_body):
                        body.extend(chunk)
                    return (
                        body.decode("utf-8-sig"),
                        response.headers.get("etag", ""),
                        response.headers.get("last-modified", ""),
                    )
        raise ValueError("source redirect limit")

    async def fetch(self, source: Source) -> list[str]:
        import httpx

        row = self.store.db.execute("SELECT next_due FROM source WHERE url=?", (source.url,)).fetchone()
        if row and row[0] > time.time():
            return []
        for attempt in range(3):
            try:
                content, etag, modified = await self._request(source, attempt)
                uris = extract_uris(content, encoded=source.encoded)
                with self.store.transaction() as db:
                    db.execute(
                        "INSERT INTO source(url,etag,modified,body,fetched,outcome) VALUES(?,?,?,?,?,'success') "
                        "ON CONFLICT(url) DO UPDATE SET etag=excluded.etag,modified=excluded.modified,body=excluded.body,"
                        "fetched=excluded.fetched,outcome='success',failures=0,next_due=0",
                        (source.url, etag, modified, content.encode("utf-8"), time.time()),
                    )
                    cached_bytes = db.execute("SELECT COALESCE(sum(length(body)),0) FROM source").fetchone()[
                        0
                    ]
                    maximum = self.settings.source_cache_mb * 1024 * 1024
                    if cached_bytes > maximum:
                        for entry in db.execute(
                            "SELECT url,length(body) FROM source WHERE body IS NOT NULL ORDER BY fetched,url"
                        ).fetchall():
                            if cached_bytes <= maximum:
                                break
                            db.execute(
                                "UPDATE source SET body=NULL,etag=NULL,modified=NULL WHERE url=?", (entry[0],)
                            )
                            cached_bytes -= entry[1]
                return uris
            except httpx.HTTPStatusError as exc:
                retry = exc.response.status_code in {408, 429} or exc.response.status_code >= 500
            except (httpx.TransportError, TimeoutError, socket.gaierror):
                retry = True
            except (ValueError, OSError, ParseError, UnicodeError):
                retry = False
            if not retry or attempt == 2:
                break
            await asyncio.sleep((2**attempt) * 0.2 + random.uniform(0, 0.1))
        with self.store.transaction() as db:
            db.execute(
                "INSERT INTO source(url,fetched,outcome,failures,next_due) VALUES(?,?,'source_failure',1,?) "
                "ON CONFLICT(url) DO UPDATE SET fetched=excluded.fetched,outcome='source_failure',"
                "failures=failures+1,next_due=excluded.next_due",
                (source.url, time.time(), time.time() + 300),
            )
        return []


async def discover(settings: Settings, store: Store) -> dict:
    from .domain import parse_uri

    queue: asyncio.Queue = asyncio.Queue(settings.queue_size)
    stats = {"sources": 0, "new": 0, "invalid": 0}
    async with Fetcher(settings, store) as fetcher:

        async def producer():
            fetched = dict(store.db.execute("SELECT url,COALESCE(fetched,0) FROM source"))
            # Persisted oldest-first traversal prevents late sources from starving
            # when the discovery budget expires on each scheduled invocation.
            for source in sorted(
                source_lines(settings.sources), key=lambda s: (fetched.get(s.url, 0), s.url)
            ):
                await queue.put(source)
            for _ in range(settings.fetch_workers):
                await queue.put(None)

        async def consumer():
            while (source := await queue.get()) is not None:
                uris = await fetcher.fetch(source)
                stats["sources"] += 1
                with store.transaction() as db:
                    for uri in sorted(set(uris)):
                        try:
                            stats["new"] += store.add(parse_uri(uri), source.url, db=db)
                        except (ParseError, UnicodeError):
                            stats["invalid"] += 1

        async with asyncio.TaskGroup() as group:
            group.create_task(producer())
            for _ in range(settings.fetch_workers):
                group.create_task(consumer())
    return stats
