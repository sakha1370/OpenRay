"""Build output/site_access/aistudio_iran.txt from aistudio.txt on a GitHub runner.

Stages, driven by .github/workflows/aistudio-iran.yml: prepare, check (sharded), probe, assemble. The rules
live in openray/iran.py. Nothing here touches the SQLite state or the original aistudio.txt.
"""

import argparse
import asyncio
import hashlib
import ipaddress
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

import httpx

from openray import iran
from openray.config import Settings
from openray.domain import Outcome, ParseError, Proxy, parse_uri
from openray.files import atomic_write, json_text, lines_text
from openray.validation import SITE_TARGETS, Validator

RETRYABLE = frozenset({Outcome.PROXY_FAILURE, Outcome.TIMEOUT, Outcome.TARGET_FAILURE, Outcome.CORE_FAILURE})
CORE_FAILURE_LIMIT = 0.05
CALIBRATION_SAMPLE = 150
CHECK_HOST = "https://check-host.net"
# Reachable from any Iranian node that has a path abroad at all; recorded for the report, never used to drop.
CONTROLS = ("1.1.1.1:443", "8.8.8.8:443", "140.82.112.3:443")
ISP_BY_ASN = {
    "AS197207": "mci",
    "AS58224": "tci",
    "AS12880": "tci",
    "AS44244": "irancell",
    "AS57218": "rightel",
    "AS31549": "shatel",
}


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").split("\n") if line.strip()]


def jsonl_text(rows) -> str:
    return lines_text(json.dumps(row, ensure_ascii=False, sort_keys=True) for row in rows)


def load_candidates(work: Path) -> list[dict]:
    return [row for path in sorted(work.glob("candidates-*.jsonl")) for row in load_jsonl(path)]


def load_results(directory: Path) -> dict[str, dict]:
    return {row["id"]: row for path in sorted(directory.glob("results-*.jsonl")) for row in load_jsonl(path)}


def candidate(index: int, kind: str, uri: str, tags) -> dict:
    return {"id": f"{index}.{kind[0]}", "of": index, "kind": kind, "uri": uri, "tags": list(tags)}


def endpoint_key(proxy: Proxy) -> str | None:
    """host:port for IPv4 literals only; a name would be resolved by Iranian DNS, which poisons answers."""
    try:
        address = ipaddress.ip_address(proxy.server)
    except ValueError:
        return None
    return f"{proxy.server}:{proxy.port}" if address.version == 4 else None


def choose(candidates: list[dict], results: dict[str, dict]) -> dict[int, tuple[dict, dict]]:
    """Per source line, the candidate to publish: the repaired link if it passes, else the original."""
    chosen: dict[int, tuple[dict, dict]] = {}
    for item in sorted(candidates, key=lambda c: (c["of"], c["kind"] != "fix")):
        result = results.get(item["id"])
        if result and result["outcome"] == Outcome.SUCCESS and item["of"] not in chosen:
            chosen[item["of"]] = (item, result)
    return chosen


def prepare(args) -> int:
    lines = [line.strip() for line in args.source.read_text(encoding="utf-8").split("\n") if line.strip()]
    if args.limit and len(lines) > args.limit:
        lines = lines[:: len(lines) // args.limit][: args.limit]
    dropped: list[tuple[str, str]] = []
    seen: set[str] = set()
    entries: list[dict] = []
    candidates: list[dict] = []
    normalized: Counter = Counter()
    fixes: Counter = Counter()
    schemes: Counter = Counter()
    for line in lines:
        try:
            proxy = parse_uri(line)
        except ParseError:
            dropped.append(("unparseable", line))
            continue
        if reason := iran.drop_reason(proxy):
            dropped.append((reason, line))
            continue
        tags: tuple[str, ...] = ()
        if edit := iran.normalize(proxy):
            proxy, tags = parse_uri(edit.uri), edit.tags
            normalized.update(tags)
        if proxy.identity in seen:
            dropped.append(("duplicate", line))
            continue
        seen.add(proxy.identity)
        schemes[proxy.scheme] += 1
        index = len(entries)
        entries.append({"index": index, "source": line, "uri": proxy.uri, "tags": list(tags)})
        candidates.append(candidate(index, "orig", proxy.uri, ()))
        if edit := iran.fix(proxy):
            fixes.update(edit.tags)
            candidates.append(candidate(index, "fix", edit.uri, edit.tags))
    shards: list[list[dict]] = [[] for _ in range(args.shards)]
    for item in candidates:
        shards[item["of"] % args.shards].append(item)
    for number, rows in enumerate(shards):
        atomic_write(args.work / f"candidates-{number}.jsonl", jsonl_text(rows))
    atomic_write(args.work / "entries.jsonl", jsonl_text(entries))
    atomic_write(args.work / "dropped.tsv", "".join(f"{reason}\t{line}\n" for reason, line in dropped))
    report = {
        "source": {"sha": args.source_sha, "blob": args.source_blob, "sampled": bool(args.limit)},
        "input_lines": len(lines),
        "kept": len(entries),
        "dropped": dict(Counter(reason for reason, _ in dropped)),
        "normalized": dict(normalized),
        "fixes_offered": dict(fixes),
        "candidates": len(candidates),
        "shards": args.shards,
        "kept_by_scheme": dict(schemes),
    }
    atomic_write(args.work / "prepare.json", json_text(report))
    print(json_text(report), end="")
    return 0


def check(args) -> int:
    settings = Settings.from_env()
    items = load_jsonl(args.candidates)
    target = SITE_TARGETS[0]

    async def test(validator: Validator, item: dict) -> dict:
        try:
            proxy = parse_uri(item["uri"])
        except ParseError:
            return {"id": item["id"], "outcome": Outcome.INVALID_CONFIG.value, "ms": 0, "attempts": 0}
        for attempt in (1, 2):
            observation = await validator.check(proxy, target)
            if observation.outcome not in RETRYABLE:
                break
            if attempt == 1:
                await asyncio.sleep(2)
        return {
            "id": item["id"],
            "outcome": str(observation.outcome),
            "status": observation.status,
            "ms": round(observation.elapsed_ms),
            "core": observation.core,
            "attempts": attempt,
        }

    async def run() -> list[dict]:
        queue: asyncio.Queue = asyncio.Queue(settings.queue_size)
        results: list[dict] = []
        async with Validator(settings) as validator:

            async def producer():
                for item in items:
                    await queue.put(item)
                for _ in range(settings.workers):
                    await queue.put(None)

            async def consumer():
                while (item := await queue.get()) is not None:
                    results.append(await test(validator, item))

            async with asyncio.TaskGroup() as group:
                group.create_task(producer())
                for _ in range(settings.workers):
                    group.create_task(consumer())
        return results

    results = asyncio.run(run())
    atomic_write(args.output, jsonl_text(sorted(results, key=lambda r: r["id"])))
    outcomes = Counter(r["outcome"] for r in results)
    print(json_text(dict(outcomes)), end="")
    if outcomes[Outcome.CORE_FAILURE.value] > CORE_FAILURE_LIMIT * max(1, len(results)):
        print("too many core failures; the results are not trustworthy", file=sys.stderr)
        return 2
    return 0


class RateLimited(Exception):
    def __init__(self, message: str, retry_after: float = 0, headers: dict | None = None):
        super().__init__(message)
        self.retry_after = retry_after
        self.headers = headers or {}


def seconds(value: str | None) -> float:
    try:
        return max(0.0, float(value or 0))
    except ValueError:
        return 0.0  # an HTTP date; the caller falls back to its own backoff


async def check_host(client: httpx.AsyncClient, path: str, params=None):
    response = await client.get(CHECK_HOST + path, params=params, headers={"Accept": "application/json"})
    if response.status_code == 429:
        hints = {k: v for k, v in response.headers.items() if k.lower().startswith(("retry", "x-rate"))}
        raise RateLimited(path, seconds(response.headers.get("Retry-After")), hints)
    response.raise_for_status()
    data = response.json()
    if isinstance(data, dict) and data.get("ok") == 0:
        message = str(data.get("error", "check-host rejected the request"))[:80]
        raise RateLimited(message) if "limit" in message else RuntimeError(message)
    return data


def iranian_nodes(listing) -> dict[str, dict]:
    nodes = listing.get("nodes", listing) if isinstance(listing, dict) else listing
    if isinstance(nodes, list):
        nodes = {name: {} for name in nodes}
    found = {}
    for name, info in nodes.items():
        if re.fullmatch(r"ir\d+", name.split(".")[0].lower()):
            found[name] = info if isinstance(info, dict) else {"raw": info}
    return found


async def tcp_check(client: httpx.AsyncClient, endpoint: str, nodes: list[str], samples: list) -> dict:
    params = [("host", endpoint)] + [("node", node) for node in nodes]
    started = await check_host(client, "/check-tcp", params)
    request_id = started["request_id"]
    result: dict = {}
    await asyncio.sleep(4)
    for _ in range(12):
        result = await check_host(client, f"/check-result/{request_id}")
        if all(result.get(node) is not None for node in nodes):
            break
        await asyncio.sleep(2)
    if len(samples) < 6:
        samples.append({"endpoint": endpoint, "started": started, "result": result})
    outcome = {}
    for node in nodes:
        value = result.get(node)
        if value is None:
            continue
        first = value[0] if isinstance(value, list) and value else None
        outcome[node] = isinstance(first, dict) and "time" in first and "error" not in first
    return outcome


async def globalping_iran(client: httpx.AsyncClient) -> dict:
    try:
        response = await client.get("https://api.globalping.io/v1/probes")
        response.raise_for_status()
        probes = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        return {"status": type(exc).__name__}
    found: Counter = Counter()
    for probe in probes:
        location = probe.get("location", {}) if isinstance(probe, dict) else {}
        if location.get("country") == "IR":
            found[f"AS{location.get('asn')} {location.get('network', '')}".strip()] += 1
    return {"status": "ok", "total_probes": len(probes), "iran": dict(found)}


async def run_probe(endpoints: list[str], budget_minutes: float) -> dict:
    started = time.monotonic()
    budget = budget_minutes * 60
    report: dict = {"status": "ok", "budget_s": round(budget), "requested": len(endpoints)}
    report.update(rate_limited=0, errors=0, rate_limit_hints=[])
    samples: list[dict] = []
    async with httpx.AsyncClient(timeout=20, headers={"User-Agent": "OpenRay-iran-probe/1"}) as client:
        report["globalping"] = await globalping_iran(client)
        try:
            nodes = iranian_nodes(await check_host(client, "/nodes/hosts"))
        except (httpx.HTTPError, ValueError, RateLimited, RuntimeError) as exc:
            report.update(status="nodes-unavailable", error=type(exc).__name__, endpoints={})
            return report
        if not nodes:
            report.update(status="no-iranian-nodes", endpoints={})
            return report
        names = sorted(nodes)
        report["nodes"] = {
            name: {**nodes[name], "isp": ISP_BY_ASN.get(str(nodes[name].get("asn", "")).upper(), "other")}
            for name in names
        }
        state = {"limited_since": 0.0, "pause_until": 0.0}
        stop = asyncio.Event()
        limiter = asyncio.Semaphore(3)

        async def one(endpoint: str, until: float, record: dict):
            async with limiter:
                for _ in range(3):
                    if stop.is_set() or time.monotonic() >= until:
                        return
                    if (wait := state["pause_until"] - time.monotonic()) > 0:
                        await asyncio.sleep(wait)
                    try:
                        outcome = await tcp_check(client, endpoint, names, samples)
                    except RateLimited as exc:
                        report["rate_limited"] = report.get("rate_limited", 0) + 1
                        if exc.headers and len(report["rate_limit_hints"]) < 3:
                            report["rate_limit_hints"].append(exc.headers)
                        # The service gives no Retry-After and stayed closed to runners for hours once spent.
                        now = time.monotonic()
                        state["limited_since"] = state["limited_since"] or now
                        state["pause_until"] = now + min(900, exc.retry_after or 300)
                        if now - state["limited_since"] > 1200:
                            stop.set()
                        continue
                    except (httpx.HTTPError, ValueError, RuntimeError, KeyError):
                        report["errors"] = report.get("errors", 0) + 1
                        return
                    state["limited_since"] = 0.0
                    for node, reached in outcome.items():
                        record.setdefault(endpoint, {}).setdefault(node, []).append(reached)
                    return

        controls: dict = {}
        for endpoint in CONTROLS:
            await one(endpoint, started + budget, controls)
        results: dict = {}
        head, tail = endpoints[:CALIBRATION_SAMPLE], endpoints[CALIBRATION_SAMPLE:]
        await asyncio.gather(*(one(e, started + budget, results) for e in head))
        # A second attempt only matters where some node reaches most endpoints; otherwise no failure counts.
        calibrated = any(rate >= iran.CALIBRATED_RATE for rate in iran.node_rates(results).values())
        first_until = started + budget * (0.7 if calibrated else 1)
        await asyncio.gather(*(one(e, first_until, results) for e in tail))
        if calibrated:
            retry = [e for e, seen in results.items() if not any(any(a) for a in seen.values())]
            await asyncio.gather(*(one(e, started + budget, results) for e in retry))
        report["retry_pass"] = calibrated
        if stop.is_set():
            report["status"] = "rate-limited"
        report.update(
            controls=controls,
            endpoints=results,
            probed=len(results),
            elapsed_s=round(time.monotonic() - started),
            samples=samples,
        )
    return report


def probe(args) -> int:
    chosen = choose(load_candidates(args.work), load_results(args.results))
    best: dict[str, int] = {}
    for item, _ in chosen.values():
        proxy = parse_uri(item["uri"])
        rank = iran.protocol_rank(proxy)
        # Evidence cannot lift the last tier, so probing it would only spend the service's goodwill.
        if (key := endpoint_key(proxy)) and rank < 5:
            best[key] = min(rank, best.get(key, rank))
    # Best protocols first, each tier in a fixed shuffle, so that a budget that runs out samples it evenly.
    ordered = sorted(best, key=lambda k: (best[k], hashlib.sha256(k.encode()).hexdigest()))
    report = asyncio.run(run_probe(ordered, args.budget_minutes))
    atomic_write(args.output, json_text(report))
    brief = {k: v for k, v in report.items() if k not in {"endpoints", "samples", "controls"}}
    print(json_text(brief), end="")
    return 0


def has_iran_evidence(entry) -> bool:
    return bool(isinstance(entry, dict) and entry.get("iran", {}).get("total"))


def probe_stats(endpoints: dict, rates: dict) -> dict:
    reached = {key: [any(attempts) for attempts in nodes.values()] for key, nodes in endpoints.items()}
    stats = {
        "endpoints probed": len(reached),
        "reached by every node": sum(all(v) for v in reached.values()),
        "reached by some nodes": sum(any(v) and not all(v) for v in reached.values()),
        "reached by no node": sum(not any(v) for v in reached.values()),
    }
    for node, rate in sorted(rates.items()):
        stats[f"share of endpoints reached by {node.split('.')[0]}"] = f"{rate:.0%}"
    return stats


def describe_node(info: dict) -> str:
    location = info.get("location") or []
    return f"{info.get('asn', '?')}, {location[-1] if location else '?'}, {info.get('isp', 'other')}"


def table(title: str, mapping: dict) -> list[str]:
    if not mapping:
        return []
    body = (f"| {key} | {value} |" for key, value in mapping.items())
    return ["", f"### {title}", "", "| Item | Count |", "|---|---|", *body]


def summary_markdown(report: dict) -> str:
    lines = ["## aistudio_iran.txt", ""]
    source = report["source"]
    lines.append(f"Source commit `{str(source['sha'])[:12]}`, {report['input_lines']} input lines.")
    lines.append(f"Published lines: **{report['published']}**. Gates: {report['gates']}.")
    probing = report["probe"]
    status, probed = probing.get("status", "not run"), probing.get("probed", 0)
    limited = probing.get("rate_limited", 0)
    lines.append(f"Iran probes: `{status}`, {probed} endpoints, {limited} rate-limit responses.")
    for title, key in (
        ("Dropped before testing", "dropped"),
        ("Normalised (identity unchanged)", "normalized"),
        ("Repairs offered", "fixes_offered"),
        ("Repair outcomes on the runner", "repairs"),
        ("Runner re-test, originals", "retest_originals"),
        ("Runner re-test, repaired links", "retest_fixes"),
        ("Dropped after testing", "dropped_after"),
        ("Probes from Iranian nodes", "probe_stats"),
        ("Probing nodes in Iran (ASN, city, ISP label)", "probe_nodes"),
        ("Globalping probes in Iran (inventory only, not used)", "globalping_iran"),
        ("Probe verdicts", "verdicts"),
        ("Published, by rank bucket", "buckets"),
        ("Published, by protocol and security", "mix"),
    ):
        lines += table(title, report.get(key, {}))
    return lines_text(lines)


def assemble(args) -> int:
    prepared = json.loads((args.work / "prepare.json").read_text(encoding="utf-8"))
    entries = load_jsonl(args.work / "entries.jsonl")
    candidates = load_candidates(args.work)
    results = load_results(args.results)
    chosen = choose(candidates, results)
    probing: dict = {}
    if args.probe and args.probe.is_file():
        probing = json.loads(args.probe.read_text(encoding="utf-8"))
    endpoints = probing.get("endpoints", {})
    rates = iran.node_rates(endpoints)
    counts = {}
    if args.check_counts and args.check_counts.is_file():
        counts = json.loads(args.check_counts.read_text(encoding="utf-8"))

    repairs: Counter = Counter()
    for item in candidates:
        if item["kind"] != "fix":
            continue
        original = results.get(f"{item['of']}.o", {}).get("outcome")
        fixed = results.get(item["id"], {}).get("outcome")
        for tag in item["tags"]:
            repairs[f"{tag}: tested"] += 1
            if fixed == Outcome.SUCCESS:
                repairs[f"{tag}: passes"] += 1
                if original != Outcome.SUCCESS:
                    repairs[f"{tag}: rescued (original fails)"] += 1

    dropped_after: Counter = Counter()
    verdicts: Counter = Counter()
    rows = []
    for entry in entries:
        pair = chosen.get(entry["index"])
        if pair is None:
            original = results.get(f"{entry['index']}.o", {}).get("outcome", "missing")
            dropped_after[f"retest: {original}"] += 1
            continue
        item, result = pair
        proxy = parse_uri(item["uri"])
        key = endpoint_key(proxy)
        verdict = iran.probe_verdict(endpoints[key], rates) if key in endpoints else "unprobed"
        verdicts[verdict] += 1
        if verdict == "unreachable":
            dropped_after["probe: unreachable from Iranian nodes"] += 1
            continue
        evidence = verdict == "reachable" or has_iran_evidence(counts.get(entry["source"]))
        rank = iran.bucket(proxy, iran_evidence=evidence)
        order = (rank, iran.protocol_rank(proxy), iran.port_rank(proxy), result["ms"], proxy.uri)
        rows.append((order, proxy))
    rows.sort(key=lambda row: row[0])

    output: list[str] = []
    identities: set[str] = set()
    buckets: Counter = Counter()
    mix: Counter = Counter()
    for (rank, *_), proxy in rows:
        if proxy.identity in identities:
            dropped_after["duplicate after repair"] += 1
            continue
        identities.add(proxy.identity)
        output.append(proxy.uri)
        buckets[f"{rank}"] += 1
        mix[f"{proxy.scheme} / {proxy.transport} / {iran.security(proxy)}"] += 1

    reparsed = [parse_uri(line) for line in output]
    floor = max(args.min_lines, args.min_share * prepared["input_lines"])
    gates = {
        "enough lines": len(output) >= floor,
        "all parse and unique": len({p.identity for p in reparsed}) == len(output),
        "no dropped scheme": all(iran.drop_reason(p) is None for p in reparsed),
    }
    failed = [name for name, ok in gates.items() if not ok]
    nodes = {name.split(".")[0]: describe_node(info) for name, info in probing.get("nodes", {}).items()}
    report = {
        **prepared,
        "published": len(output),
        "gates": "pass" if not failed else "FAIL: " + ", ".join(failed),
        "probe": {k: v for k, v in probing.items() if k not in {"endpoints", "samples", "controls"}},
        "repairs": dict(sorted(repairs.items())),
        "retest_originals": dict(Counter(r["outcome"] for i, r in results.items() if i.endswith(".o"))),
        "retest_fixes": dict(Counter(r["outcome"] for i, r in results.items() if i.endswith(".f"))),
        "dropped_after": dict(dropped_after),
        "probe_stats": probe_stats(endpoints, rates) if endpoints else {},
        "probe_nodes": nodes,
        "globalping_iran": probing.get("globalping", {}).get("iran", {}),
        "verdicts": dict(verdicts),
        "buckets": dict(sorted(buckets.items())),
        "mix": dict(mix.most_common()),
    }
    atomic_write(args.report, json_text(report))
    atomic_write(args.summary, summary_markdown(report))
    print(args.summary.read_text(encoding="utf-8"), end="")
    if failed:
        return 3
    atomic_write(args.output, lines_text(output))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    p = commands.add_parser("prepare")
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--shards", type=int, default=4)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--source-sha", default="")
    p.add_argument("--source-blob", default="")
    p.set_defaults(run=prepare)

    p = commands.add_parser("check")
    p.add_argument("--candidates", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.set_defaults(run=check)

    p = commands.add_parser("probe")
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--results", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--budget-minutes", type=float, default=120)
    p.set_defaults(run=probe)

    p = commands.add_parser("assemble")
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--results", type=Path, required=True)
    p.add_argument("--probe", type=Path)
    p.add_argument("--check-counts", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--summary", type=Path, required=True)
    p.add_argument("--min-lines", type=int, default=300)
    p.add_argument("--min-share", type=float, default=0.25)
    p.set_defaults(run=assemble)

    args = parser.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
