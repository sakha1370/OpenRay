"""A ledger of which endpoints a probe on an Iranian subscriber network reached, kept between runs.

A Globalping probe is a volunteer device: it drops out partway through a run, so a run often covers only part
of the endpoints. Each result is therefore stamped and kept for a day. The verified list is then what was
reached in this run plus what was reached recently and not missed since, so a short run adds to the list
instead of replacing it, and the next run asks about the endpoints that were checked longest ago first.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

VERSION = 1
STAMP = "%Y-%m-%dT%H:%M:%SZ"
# How long a connect counts as evidence, and how long an endpoint is remembered at all.
TTL = timedelta(hours=24)
RETENTION = timedelta(days=7)

Ledger = dict[str, dict[str, str]]


def stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime(STAMP)


def parse_stamp(value) -> datetime | None:
    try:
        return datetime.strptime(value, STAMP).replace(tzinfo=UTC)
    except (TypeError, ValueError):
        return None


def newest(entry: dict) -> datetime | None:
    times = (parse_stamp(entry.get("reached")), parse_stamp(entry.get("missed")))
    return max(filter(None, times), default=None)


def well_formed(entry: dict) -> bool:
    times = [entry[field] for field in ("reached", "missed") if field in entry]
    return bool(times) and all(map(parse_stamp, times)) and set(entry) <= {"asn", "reached", "missed"}


def load(path: Path | None) -> Ledger:
    """No file is an empty ledger. A file that cannot be read is an error, so that damage cannot quietly
    turn into a thin verified list."""
    if path is None or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data["version"] != VERSION:
            raise ValueError(f"version {data['version']!r}")
        ledger = {str(key): dict(entry) for key, entry in data["endpoints"].items()}
        if not all(map(well_formed, ledger.values())):
            raise ValueError("a malformed entry")
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ValueError(f"unreadable evidence ledger {path}: {exc}") from exc
    return ledger


def dump(ledger: Ledger) -> str:
    """One endpoint per line in a fixed order, so that an unchanged ledger is an unchanged file."""
    if not ledger:
        return '{"version":1,"endpoints":{}}\n'
    rows = ",\n".join(
        f"{json.dumps(key)}:{json.dumps(entry, sort_keys=True, separators=(',', ':'))}"
        for key, entry in sorted(ledger.items())
    )
    return f'{{"version":{VERSION},"endpoints":{{\n{rows}\n}}}}\n'


def merge(
    ledger: Ledger, results: dict[str, dict[str, list[bool]]], trusted: set[str], at: datetime
) -> tuple[Ledger, Counter]:
    """Fold one run's results (results[endpoint][probe] holds that probe's attempts) into a new ledger.

    A connect is evidence whichever probe made it. A miss counts only when a trusted probe (one whose controls
    connected before and after the run) made it, because a probe that is dropping out fails everything. An
    endpoint the ledger has seen more recently than `at` is left alone, so that re-assembling an old run
    cannot overwrite newer evidence.
    """
    moment = stamp(at)
    when = parse_stamp(moment)
    merged = {key: dict(entry) for key, entry in ledger.items()}
    counts: Counter = Counter()
    for key, nodes in results.items():
        entry = merged.get(key, {})
        if (latest := newest(entry)) and when < latest:
            counts["older than the ledger"] += 1
        elif reached := next((node for node, attempts in nodes.items() if any(attempts)), None):
            merged[key] = {"asn": reached, "reached": moment}
            counts["reached"] += 1
        elif any(attempts for node, attempts in nodes.items() if node in trusted):
            merged[key] = {**entry, "missed": moment}
            counts["missed by a trusted probe"] += 1
        else:
            counts["missed, not counted (probe not trusted)"] += 1
    return merged, counts


def recent(ledger: Ledger, now: datetime, ttl: timedelta = TTL) -> set[str]:
    """Endpoints reached within `ttl` of `now` and not missed since."""
    found = set()
    for key, entry in ledger.items():
        reached, missed = parse_stamp(entry.get("reached")), parse_stamp(entry.get("missed"))
        if reached and now - reached <= ttl and not (missed and missed >= reached):
            found.add(key)
    return found


def last_checked(ledger: Ledger, key: str) -> str:
    """When a probe last gave an answer for this endpoint, or '' if it never has. Sorts as time does."""
    entry = ledger.get(key, {})
    return max(entry.get("reached", ""), entry.get("missed", ""))


def prune(ledger: Ledger, now: datetime, retention: timedelta = RETENTION) -> Ledger:
    return {
        key: entry for key, entry in ledger.items() if (seen := newest(entry)) and now - seen <= retention
    }
