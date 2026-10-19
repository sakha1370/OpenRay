import json
import sqlite3
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path

from openray.domain import Observation, Outcome, parse_uri
from openray.maintenance import maintain
from openray.storage import RETIRED, SCHEMA, SCHEMA_VERSION, Store, migrate
from tests.test_domain import VLESS


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / "state.sqlite3")
        self.proxy = parse_uri(VLESS)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_exactly_once_and_infrastructure(self):
        self.store.observe(
            "event", "run", self.proxy, "global", "connectivity", Observation(Outcome.SUCCESS), now=100
        )
        self.assertFalse(
            self.store.observe(
                "event", "run", self.proxy, "global", "connectivity", Observation(Outcome.SUCCESS), now=100
            )
        )
        self.store.observe(
            "infra", "run", self.proxy, "global", "connectivity", Observation(Outcome.CORE_FAILURE), now=200
        )
        proxies, scores, health = self.store.view()
        self.assertEqual(scores[self.proxy.identity]["global"], 1)
        self.assertEqual(health[0]["failures"], 0)
        self.assertEqual(len(proxies), 1)

    def test_leases_fairness_expiry_and_backup(self):
        for n in range(5):
            self.store.add(parse_uri(VLESS.replace("example.com", f"host{n}.test")))
        first = self.store.lease("global", "connectivity", "one", 2, 10, now=0)
        second = self.store.lease("global", "connectivity", "two", 5, 10, now=0)
        self.assertEqual(len(first), 2)
        self.assertEqual(len(second), 3)
        self.assertEqual(len(self.store.lease("global", "connectivity", "three", 5, 10, now=11)), 5)
        self.store.backup(self.root / "backup.sqlite3")
        with Store(self.root / "backup.sqlite3") as backup:
            self.assertEqual(backup.status(), self.store.status())

    def test_never_checked_newest_first_then_due_retests(self):
        old, mid, new = (parse_uri(VLESS.replace("example.com", f"{n}.test")) for n in ("old", "mid", "new"))
        self.store.add(old)
        failure = Observation(Outcome.PROXY_FAILURE)
        self.store.observe("e", "earlier", old, "global", "connectivity", failure, now=0, cooldown=10)
        self.store.add(mid)
        self.assertEqual(
            self.store.lease("global", "connectivity", "a", 1, 5, now=1, source_only=True), [mid]
        )
        self.store.release("a")
        self.store.add(new)
        leased = self.store.lease("global", "connectivity", "b", 5, 5, now=20, source_only=True)
        self.assertEqual(leased, [new, mid, old])

    def test_unaccepted_candidates_retire_after_repeated_failures(self):
        accepted = parse_uri(VLESS.replace("example.com", "accepted.test"))
        self.store.add(accepted, accepted=True)
        brief = parse_uri(VLESS.replace("example.com", "brief.test"))
        for n, now in enumerate((0, 10, 20)):
            for proxy in (self.proxy, accepted):
                timeout = Observation(Outcome.TIMEOUT)
                self.store.observe(
                    f"{proxy.server}{n}",
                    f"r{n}",
                    proxy,
                    "global",
                    "connectivity",
                    timeout,
                    now=now,
                    cooldown=10,
                )
            # Three failures within two cooldowns are not enough evidence.
            self.store.observe(
                f"b{n}",
                f"r{n}",
                brief,
                "global",
                "connectivity",
                Observation(Outcome.TIMEOUT),
                now=n,
                cooldown=10,
            )
        due = {h["proxy_id"]: h["next_due"] for h in self.store.view()[2]}
        self.assertEqual(due[self.proxy.identity], RETIRED)
        self.assertEqual((due[accepted.identity], due[brief.identity]), (30, 12))
        self.assertEqual(self.store.due("global", now=100)["retired"], 1)
        self.assertEqual(
            self.store.lease("global", "connectivity", "late", 5, 5, now=10**9, source_only=True), [brief]
        )

    def test_site_leases_need_current_connectivity_and_mid_run_candidates_are_leased(self):
        alive, dead = (parse_uri(VLESS.replace("example.com", f"{n}.test")) for n in ("alive", "dead"))
        for proxy, outcome in ((alive, Outcome.SUCCESS), (dead, Outcome.PROXY_FAILURE)):
            self.store.add(proxy, accepted=True)
            self.store.observe(
                proxy.server, "r", proxy, "global", "connectivity", Observation(outcome), now=0
            )
        site = self.store.lease("global", "aistudio", "s", 5, 5, now=1, accepted_only=True, alive_only=True)
        self.assertEqual(site, [alive])
        self.assertEqual(self.store.lease("global", "connectivity", "c", 5, 5, now=1, source_only=True), [])
        self.store.add(self.proxy)
        self.assertEqual(
            self.store.lease("global", "connectivity", "c", 5, 5, now=1, source_only=True), [self.proxy]
        )

    def test_maintenance_drops_only_empty_unleasable_placeholders(self):
        member, candidate = (
            parse_uri(VLESS.replace("example.com", f"{n}.test")) for n in ("member", "candidate")
        )
        self.store.add(member, accepted=True)
        self.store.add(candidate)
        for target in ("connectivity", "aistudio"):
            self.store.lease("global", target, "r", 5, 5, now=0)
            self.store.release("r")
        self.store.observe("seen", "r", candidate, "global", "cursor", Observation(Outcome.BLOCKED), now=1)
        report = maintain(self.store, apply=False)
        self.assertEqual((report["placeholders_to_drop"], report["dropped_target_rows"]), (1, 2))
        self.assertEqual(maintain(self.store, apply=True)["placeholders_to_drop"], 1)
        rows = {(h["proxy_id"], h["target"]) for h in self.store.view()[2]}
        # A placeholder and every row of a target no longer checked are gone.
        self.assertNotIn((candidate.identity, "aistudio"), rows)
        self.assertNotIn((candidate.identity, "cursor"), rows)
        for kept in ((candidate.identity, "connectivity"), (member.identity, "aistudio")):
            self.assertIn(kept, rows)
        report = maintain(self.store)
        self.assertEqual((report["placeholders_to_drop"], report["dropped_target_rows"]), (0, 0))

    def test_repeatable_migration_and_alias_counts(self):
        (self.root / "output").mkdir()
        (self.root / ".state").mkdir()
        (self.root / "output/all_valid_proxies.txt").write_text(VLESS + "#name\n", encoding="utf-8")
        (self.root / ".state/check_counts.json").write_text(
            json.dumps(
                {
                    VLESS: {"global": 5, "iran": {"total": 3, "operators": {"mci": 2, "tci": 1}}},
                    VLESS + "#name": {"global": 7},
                }
            )
        )
        migrate(self.store, self.root)
        first = self.store.status()
        migrate(self.store, self.root)
        self.assertEqual(first, self.store.status())
        self.assertEqual(self.store.view()[1][self.proxy.identity]["global"], 7)
        self.assertEqual(self.store.view()[1][self.proxy.identity]["mci"], 2)
        self.assertEqual(self.store.view()[1][self.proxy.identity]["iran"], 3)
        self.assertEqual(self.store.view()[1][self.proxy.identity]["tci"], 1)

    def test_atomic_bundle_and_rollback(self):
        bundle = {
            "schema": 1,
            "id": "b",
            "context": "mci",
            "observations": [{"uri": VLESS, "event_id": "e", "time": 100, "outcome": "success"}],
        }
        self.assertEqual(self.store.import_bundle(bundle), 1)
        self.assertEqual(self.store.import_bundle(bundle), 0)
        bundle["id"] = "bad"
        bundle["observations"].append({"uri": "bad", "event_id": "bad", "time": 100, "outcome": "success"})
        with self.assertRaises(ValueError):
            self.store.import_bundle(bundle)
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM bundle").fetchone()[0], 1)

    def test_recovery_skips_active_run_and_preserves_health(self):
        self.store.add(self.proxy, accepted=True)
        self.store.observe("success", "old", self.proxy, "global", "aistudio", Observation(Outcome.SUCCESS))
        self.store.lease("global", "connectivity", "active", 1, 1000)
        payload = {
            "uri": VLESS,
            "target": "connectivity",
            "version": 1,
            "elapsed_ms": 10,
            "time": time.time(),
        }
        self.store.pending("pending", "active", "global", payload)
        self.assertEqual(self.store.recover_pending(), 0)
        self.store.release("active")
        self.assertEqual(self.store.recover_pending(), 1)
        self.assertEqual(self.store.recover_pending(), 0)
        self.store.observe(
            "infra", "new", self.proxy, "global", "aistudio", Observation(Outcome.TARGET_FAILURE)
        )
        site = self.store.db.execute("SELECT * FROM health WHERE target='aistudio'").fetchone()
        self.assertEqual(site["outcome"], "success")
        self.assertEqual(site["failures"], 0)

    def test_cooldown_death_window_and_context_isolation(self):
        self.store.observe(
            "ok", "r", self.proxy, "global", "connectivity", Observation(Outcome.SUCCESS), now=100
        )
        self.assertFalse(self.store.lease("global", "connectivity", "r", 1, 10, now=101))
        self.store.observe(
            "regional", "r", self.proxy, "mci", "connectivity", Observation(Outcome.SUCCESS), now=101
        )
        self.assertEqual(self.store.view()[1][self.proxy.identity]["iran"], 1)
        self.store.observe(
            "fail1", "r", self.proxy, "global", "connectivity", Observation(Outcome.PROXY_FAILURE), now=1000
        )
        self.store.observe(
            "fail2", "r", self.proxy, "global", "connectivity", Observation(Outcome.PROXY_FAILURE), now=2000
        )
        self.assertEqual(len(self.store.view()[0]), 1)
        self.store.observe(
            "fail3",
            "r",
            self.proxy,
            "global",
            "connectivity",
            Observation(Outcome.PROXY_FAILURE),
            now=1000 + 72 * 3600,
        )
        self.assertFalse(self.store.view()[0])
        self.store.observe(
            "revive", "r", self.proxy, "global", "connectivity", Observation(Outcome.SUCCESS), now=300000
        )
        self.assertEqual(len(self.store.view()[0]), 1)

    def test_parallel_connections_never_lease_same_proxy(self):
        for n in range(20):
            self.store.add(parse_uri(VLESS.replace("example.com", f"host{n}.test")))
        barrier, result = threading.Barrier(2), []

        def lease(owner):
            with Store(self.store.path) as connection:
                barrier.wait()
                result.append({p.identity for p in connection.lease("global", "connectivity", owner, 10, 60)})

        threads = [threading.Thread(target=lease, args=(str(n),)) for n in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertEqual([len(r) for r in result], [10, 10])
        self.assertFalse(result[0] & result[1])

    def test_restore_does_not_change_source_and_rejects_overwrite(self):
        from openray.storage import file_sha256, restore_backup

        self.store.add(self.proxy)
        with self.assertRaises(ValueError):
            self.store.backup(self.store.path)
        backup = self.root / "backup.sqlite3"
        self.store.backup(backup)
        before = file_sha256(backup)
        destination = self.root / "restored.sqlite3"
        restore_backup(backup, destination)
        self.assertEqual(file_sha256(backup), before)
        with Store(destination) as restored:
            self.assertEqual(restored.status(), self.store.status())
        with self.assertRaises(ValueError):
            restore_backup(backup, destination)

    def test_truncated_history_rolls_back_migration(self):
        (self.root / ".state").mkdir()
        (self.root / "output").mkdir()
        (self.root / "output/all_valid_proxies.txt").write_text(VLESS)
        (self.root / ".state/tested.txt.bin").write_bytes(struct.pack(">Q", 10) + b"h" * 20 + b"truncated")
        with self.assertRaises(ValueError):
            migrate(self.store, self.root)
        self.assertEqual(self.store.status()["proxy"], 0)
        self.assertEqual(self.store.status()["legacy_tested"], 0)

    def test_bundle_collision_nonfinite_and_policy_version(self):
        self.store.observe(
            "new-policy",
            "r",
            self.proxy,
            "global",
            "cursor",
            Observation(Outcome.SUCCESS),
            version=2,
            now=100,
        )
        self.store.observe(
            "old-policy",
            "r",
            self.proxy,
            "global",
            "cursor",
            Observation(Outcome.BLOCKED),
            version=1,
            now=110,
        )
        row = self.store.db.execute("SELECT * FROM health WHERE target='cursor'").fetchone()
        self.assertEqual((row["version"], row["outcome"]), (2, "success"))
        with self.assertRaises(ValueError):
            self.store.observe(
                "new-policy", "other", self.proxy, "mci", "connectivity", Observation(Outcome.SUCCESS)
            )
        payload = {
            "schema": 1,
            "id": "bad",
            "context": "mci",
            "observations": [{"uri": VLESS, "event_id": "bad", "time": float("nan"), "outcome": "success"}],
        }
        with self.assertRaises(ValueError):
            self.store.import_bundle(payload)

    def test_retention_preserves_counter_and_exactly_once_identity(self):
        from openray.maintenance import maintain

        # Regional bundle events keep a tombstone, so an old bundle can never count twice.
        self.store.observe(
            "expired", "r", self.proxy, "mci", "connectivity", Observation(Outcome.SUCCESS), now=100
        )
        with self.store.transaction() as db:
            db.execute("INSERT INTO legacy_tested VALUES(?,?)", (b"x" * 20, time.time()))
        report = maintain(self.store, 90)
        self.assertTrue(report["dry_run"])
        self.assertEqual((report["legacy_hashes_to_drop"], self.store.status()["observation"]), (1, 1))
        maintain(self.store, 90, True)
        self.assertEqual(self.store.status()["observation"], 0)
        self.assertEqual(self.store.status()["event_identity"], 1)
        self.assertEqual(self.store.status()["legacy_tested"], 0)
        self.assertFalse(
            self.store.observe(
                "expired", "r", self.proxy, "mci", "connectivity", Observation(Outcome.SUCCESS), now=100
            )
        )
        self.assertEqual(self.store.view()[1][self.proxy.identity]["mci"], 1)
        self.assertTrue(list((self.root / "backups").glob("maintenance-*.sqlite3")))

    def test_global_observations_expire_without_tombstones(self):
        from openray.maintenance import maintain

        now = time.time()
        for event, age in (("old", 4 * 86400), ("recent", 3600)):
            self.store.observe(
                event, "r", self.proxy, "global", "connectivity", Observation(Outcome.SUCCESS), now=now - age
            )
        self.assertEqual(maintain(self.store, 90, True)["global_observations_to_drop"], 1)
        events = {r[0] for r in self.store.db.execute("SELECT event_id FROM observation")}
        self.assertEqual((events, self.store.status()["event_identity"]), ({"recent"}, 0))
        # Counters and health survive; only the per-check history expires.
        self.assertEqual(self.store.view()[1][self.proxy.identity]["global"], 2)

    def test_unlisted_candidates_and_remark_aliases_are_purged(self):
        from openray.maintenance import maintain

        stale, listed = (parse_uri(VLESS.replace("example.com", f"{n}.test")) for n in ("stale", "listed"))
        member = parse_uri(VLESS.replace("example.com", "member.test"))
        for proxy in (stale, listed):
            self.store.add(proxy)
        self.store.add(member, accepted=True)
        self.store.add(parse_uri(listed.uri + "#renamed"))
        self.store.observe(
            "s", "r", stale, "global", "connectivity", Observation(Outcome.TIMEOUT), now=time.time()
        )
        with self.store.transaction() as db:
            db.execute(
                "UPDATE proxy SET seen=? WHERE id IN (?,?)",
                (time.time() - 4 * 86400, stale.identity, member.identity),
            )
        report = maintain(self.store, 90, True)
        self.assertEqual((report["unlisted_candidates_to_purge"], report["remark_aliases_to_drop"]), (1, 1))
        remaining = {r[0] for r in self.store.db.execute("SELECT id FROM proxy")}
        # Accepted proxies are never purged by listing; demotion handles them first.
        self.assertEqual(remaining, {listed.identity, member.identity})
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM observation").fetchone()[0], 0)
        aliases = [
            r[0] for r in self.store.db.execute("SELECT uri FROM alias WHERE proxy_id=?", (listed.identity,))
        ]
        self.assertEqual(aliases, [listed.uri])
        self.assertEqual(self.store.db.execute("PRAGMA foreign_keys").fetchone()[0], 1)

    def test_schema_upgrade_starts_the_unlisted_grace(self):
        self.store.add(self.proxy)
        with self.store.transaction() as db:
            db.execute("ALTER TABLE proxy DROP COLUMN seen")
            db.execute("PRAGMA user_version=4")
        self.store.close()
        before = time.time()
        self.store = Store(self.root / "state.sqlite3")
        seen = self.store.db.execute("SELECT seen FROM proxy").fetchone()[0]
        self.assertGreaterEqual(seen, before)
        self.assertEqual(self.store.db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)

    def test_out_of_order_observations_preserve_health_counters_and_lease(self):
        self.store.observe(
            "latest",
            "new",
            self.proxy,
            "mci",
            "connectivity",
            Observation(Outcome.SUCCESS),
            now=200,
            cooldown=0,
        )
        self.store.lease("mci", "connectivity", "active", 1, 1000, now=201)
        self.store.observe(
            "older-fail",
            "old",
            self.proxy,
            "mci",
            "connectivity",
            Observation(Outcome.PROXY_FAILURE),
            now=100,
        )
        self.store.observe(
            "older-success", "old", self.proxy, "mci", "connectivity", Observation(Outcome.SUCCESS), now=150
        )
        row = self.store.db.execute("SELECT * FROM health").fetchone()
        self.assertEqual((row["outcome"], row["last_success"], row["failures"]), ("success", 200, 0))
        self.assertEqual(row["lease_owner"], "active")
        self.assertEqual(self.store.view()[1][self.proxy.identity]["mci"], 2)
        self.assertEqual(self.store.view()[1][self.proxy.identity]["iran"], 2)
        self.store.lease("mci", "connectivity", "policy", 1, 1000, version=2, now=202)
        self.assertFalse(self.store.lease("mci", "connectivity", "obsolete", 1, 1, version=1, now=203))
        self.assertEqual(self.store.db.execute("SELECT version FROM health").fetchone()[0], 2)


class IdentityMigrationTests(unittest.TestCase):
    """A schema 5 checkpoint holds identity v2 ids; opening it must fold them into v3 losslessly."""

    RAW = VLESS + "?type=tcp"
    SAME = VLESS + "?headerType=none&telegram=advert"  # the same connection as RAW
    OTHER = VLESS + "?type=ws&path=%2Fx"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "state.sqlite3"

    def tearDown(self):
        self.tmp.cleanup()

    def legacy_database(self, *, dangling=False):
        db = sqlite3.connect(self.path)
        db.executescript(SCHEMA)
        db.execute("DELETE FROM meta")
        db.executemany(
            "INSERT INTO proxy VALUES(?,2,?,?,?,?,?)",
            [
                ("old-raw", self.RAW, "vless", 10, 1, 50),
                ("old-same", self.SAME, "vless", 5, 0, 70),
                ("old-other", self.OTHER, "vless", 20, 0, 60),
                ("old-bad", "vless://not-a-connection", "vless", 30, 0, 80),
            ],
        )
        db.executemany(
            "INSERT INTO alias VALUES(?,?,?)",
            [(self.RAW, "old-raw", "a"), (self.SAME, "old-same", "b"), (self.OTHER, "old-other", "c")],
        )
        db.executemany(
            "INSERT INTO score VALUES(?,?,?)",
            [
                ("old-raw", "global", 3),
                ("old-same", "global", 7),
                ("old-same", "iran", 1),
                ("old-other", "global", 2),
            ],
        )
        # health columns: proxy, context, target, version, last_success, first_failure, failures, next_due,
        # lease_owner, lease_until, outcome, observed_at
        db.executemany(
            "INSERT INTO health VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                ("old-raw", "global", "connectivity", 1, 100, None, 0, 0, None, None, "success", 100),
                ("old-same", "global", "connectivity", 2, 50, None, 0, 9, None, None, "success", 90),
                ("old-raw", "global", "aistudio", 1, None, 80, 2, 0, None, None, "blocked", 80),
            ],
        )
        db.executemany(
            "INSERT INTO observation VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (f"e{n}", "run", pid, "global", "connectivity", 1, "success", 1.0, 1.0, "", None, "xray")
                for n, pid in enumerate(("old-raw", "old-same", "old-other"))
            ],
        )
        db.execute("INSERT INTO event_identity VALUES('e0','run','old-raw','global','connectivity',1)")
        if dangling:
            db.execute("INSERT INTO alias VALUES('vless://dangling','missing-proxy','x')")
        db.execute("PRAGMA user_version=5")
        db.commit()
        db.close()

    def test_equivalent_proxies_fold_with_their_history(self):
        self.legacy_database()
        merged = parse_uri(self.RAW).identity
        self.assertEqual(merged, parse_uri(self.SAME).identity)
        with Store(self.path) as store:
            self.assertEqual(store.rekeyed, {"rekeyed": 4, "folded": 1, "unparsed": 1})
            proxies = {r["id"]: dict(r) for r in store.db.execute("SELECT * FROM proxy")}
            self.assertEqual(set(proxies), {merged, parse_uri(self.OTHER).identity, "old-bad"})
            # The accepted member represents the group, with the earliest creation and latest sighting.
            self.assertEqual(
                (proxies[merged]["uri"], proxies[merged]["accepted"], proxies[merged]["created"]),
                (self.RAW, 1, 5),
            )
            self.assertEqual(proxies[merged]["seen"], 70)
            self.assertEqual({p["identity_version"] for p in proxies.values()}, {3})
            self.assertEqual(store.view()[0][0].uri, self.RAW)
            aliases = dict(store.db.execute("SELECT uri,proxy_id FROM alias").fetchall())
            self.assertEqual(
                aliases, {self.RAW: merged, self.SAME: merged, self.OTHER: parse_uri(self.OTHER).identity}
            )
            scores = store.view()[1]
            self.assertEqual(scores[merged], {"global": 7, "iran": 1})  # max, never a sum
            self.assertEqual(scores[parse_uri(self.OTHER).identity], {"global": 2})
            health = {
                r["target"]: dict(r)
                for r in store.db.execute("SELECT * FROM health WHERE proxy_id=?", (merged,))
            }
            # The newest target version wins even though the other member was observed later.
            self.assertEqual(
                (health["connectivity"]["version"], health["connectivity"]["last_success"]), (2, 50)
            )
            self.assertEqual(health["aistudio"]["outcome"], "blocked")
            self.assertEqual(store.db.execute("SELECT count(*) FROM observation").fetchone()[0], 3)
            self.assertEqual(
                {r[0] for r in store.db.execute("SELECT proxy_id FROM observation")},
                {merged, parse_uri(self.OTHER).identity},
            )
            self.assertEqual(store.db.execute("SELECT proxy_id FROM event_identity").fetchone()[0], merged)
            self.assertEqual(store.db.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(store.db.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(store.db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
            self.assertEqual(
                store.db.execute("SELECT value FROM meta WHERE key='identity_version'").fetchone()[0], "3"
            )

    def test_migration_runs_once_and_new_sightings_join_the_folded_row(self):
        self.legacy_database()
        Store(self.path).close()
        with Store(self.path) as store:
            self.assertIsNone(store.rekeyed)
            before = store.db.execute("SELECT count(*) FROM proxy").fetchone()[0]
            self.assertFalse(store.add(parse_uri(self.SAME + "&fp=")))  # same connection, already known
            self.assertEqual(store.db.execute("SELECT count(*) FROM proxy").fetchone()[0], before)

    def test_failed_migration_changes_nothing(self):
        self.legacy_database(dangling=True)
        with self.assertRaisesRegex(RuntimeError, "dangling"):
            Store(self.path)
        db = sqlite3.connect(self.path)
        self.assertEqual(db.execute("SELECT count(*) FROM proxy WHERE identity_version=2").fetchone()[0], 4)
        self.assertIsNone(db.execute("SELECT 1 FROM meta WHERE key='identity_version'").fetchone())
        self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 5)
        db.close()

    def test_older_code_cannot_open_a_migrated_database(self):
        self.legacy_database()
        Store(self.path).close()
        db = sqlite3.connect(self.path)
        db.execute(f"PRAGMA user_version={SCHEMA_VERSION + 1}")
        db.close()
        with self.assertRaisesRegex(ValueError, "newer"):
            Store(self.path)

    def test_fresh_database_needs_no_migration(self):
        with Store(self.path) as store:
            self.assertEqual(store.rekeyed, {"rekeyed": 0, "folded": 0, "unparsed": 0})
