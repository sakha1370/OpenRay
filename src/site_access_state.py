"""Deprecated site-state facade backed by expiring, transactional SQLite health."""

from __future__ import annotations

import time
import uuid
from contextlib import contextmanager

from openray.config import Settings
from openray.domain import Observation, Outcome, ParseError, parse_uri
from openray.pipeline import initialize
from openray.storage import Store


@contextmanager
def _store():
    settings = Settings.from_env()
    with Store(settings.database) as store:
        initialize(store, settings.root)
        yield settings, store


def load_blocked_state() -> dict[str, set[str]]:
    result = {}
    with _store() as (_, store):
        for row in store.db.execute(
            "SELECT p.uri,h.target FROM health h JOIN proxy p ON p.id=h.proxy_id "
            "WHERE h.context='global' AND h.target!='connectivity' "
            "AND h.outcome='blocked' AND h.next_due>?",
            (time.time(),),
        ):
            result.setdefault(row["uri"], set()).add(row["target"])
    return result


def save_blocked_state(state: dict[str, set[str]], target_versions: dict[str, int]) -> None:
    run = "legacy-site-" + uuid.uuid4().hex
    with _store() as (settings, store), store.transaction() as db:
        requested = set()
        for uri, sites in state.items():
            try:
                proxy = parse_uri(uri)
            except ParseError:
                continue
            for site in sites:
                requested.add((proxy.identity, site))
                store.observe(
                    uuid.uuid4().hex,
                    run,
                    proxy,
                    "global",
                    site,
                    Observation(Outcome.BLOCKED),
                    version=target_versions.get(site, 1),
                    cooldown=settings.cooldown,
                    db=db,
                )
        for row in db.execute("SELECT * FROM health WHERE context='global' AND outcome='blocked'").fetchall():
            if (row["proxy_id"], row["target"]) not in requested:
                db.execute(
                    "UPDATE health SET outcome=NULL,next_due=0 WHERE proxy_id=? AND context='global' AND target=?",
                    (row["proxy_id"], row["target"]),
                )


def sync_blocked_state(active_proxies: list[str], target_versions: dict[str, int]) -> dict[str, set[str]]:
    aliases = {}
    for uri in active_proxies:
        try:
            aliases[uri] = parse_uri(uri).identity
        except ParseError:
            continue
    with _store() as (_, store), store.transaction() as db:
        for row in db.execute(
            "SELECT * FROM health WHERE context='global' AND target!='connectivity'"
        ).fetchall():
            version = target_versions.get(row["target"], row["version"])
            if row["proxy_id"] not in aliases.values() or version > row["version"]:
                db.execute(
                    "UPDATE health SET version=?,outcome=NULL,next_due=0,observed_at=0 "
                    "WHERE proxy_id=? AND context='global' AND target=?",
                    (max(version, row["version"]), row["proxy_id"], row["target"]),
                )
    by_id = {parse_uri(uri).identity: sites for uri, sites in load_blocked_state().items()}
    return {uri: by_id[identity] for uri, identity in aliases.items() if identity in by_id}


def mark_site_blocked(state: dict[str, set[str]], uri: str, site_id: str) -> None:
    state.setdefault(uri, set()).add(site_id)


def sites_to_test(uri: str, all_site_ids: list[str], blocked_state: dict[str, set[str]]) -> list[str]:
    return [site for site in all_site_ids if site not in blocked_state.get(uri, set())]
