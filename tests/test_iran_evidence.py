import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from openray import iran_evidence as ev
from tools import iran_filter

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
MCI, TCI, RIGHTEL = "AS197207", "AS58224", "AS57218"


def ago(hours: float) -> str:
    return ev.stamp(NOW - timedelta(hours=hours))


def run(*argv) -> int:
    with contextlib.redirect_stdout(io.StringIO()):
        return iran_filter.main([str(a) for a in argv])


class LedgerTests(unittest.TestCase):
    def test_a_connect_is_kept_from_any_probe_and_clears_an_earlier_miss(self):
        ledger = {"1.1.1.1:443": {"asn": MCI, "reached": ago(30), "missed": ago(5)}}
        merged, counts = ev.merge(ledger, {"1.1.1.1:443": {RIGHTEL: [False, True]}}, set(), NOW)
        self.assertEqual(merged["1.1.1.1:443"], {"asn": RIGHTEL, "reached": ago(0)})
        self.assertEqual(counts, {"reached": 1})
        self.assertIn("missed", ledger["1.1.1.1:443"], "the input is not modified")

    def test_a_miss_counts_only_from_a_trusted_probe_and_keeps_when_it_was_last_good(self):
        results = {"1.1.1.1:443": {MCI: [False]}, "2.2.2.2:443": {MCI: [False]}}
        ledger = {"1.1.1.1:443": {"asn": MCI, "reached": ago(3)}}
        merged, counts = ev.merge(ledger, results, {MCI}, NOW)
        self.assertEqual(merged["1.1.1.1:443"], {"asn": MCI, "reached": ago(3), "missed": ago(0)})
        self.assertEqual(merged["2.2.2.2:443"], {"missed": ago(0)})
        self.assertEqual(counts["missed by a trusted probe"], 2)

        merged, counts = ev.merge(ledger, results, set(), NOW)
        self.assertEqual(merged, ledger)
        self.assertEqual(counts["missed, not counted (probe not trusted)"], 2)

    def test_a_run_older_than_the_ledger_changes_nothing(self):
        ledger = {"1.1.1.1:443": {"asn": MCI, "reached": ago(1)}}
        results = {"1.1.1.1:443": {MCI: [False]}}
        self.assertEqual(ev.merge(ledger, results, {MCI}, NOW - timedelta(hours=2))[0], ledger)
        # The same run folded in twice is the same ledger.
        once, _ = ev.merge({}, {"1.1.1.1:443": {MCI: [True]}}, {MCI}, NOW)
        self.assertEqual(ev.merge(once, {"1.1.1.1:443": {MCI: [True]}}, {MCI}, NOW)[0], once)

    def test_recent_is_reached_within_the_window_and_not_missed_since(self):
        ledger = {
            "edge": {"asn": MCI, "reached": ago(24)},
            "over": {"asn": MCI, "reached": ago(24.01)},
            "missed": {"asn": MCI, "reached": ago(5), "missed": ago(2)},
            "revived": {"asn": MCI, "reached": ago(1), "missed": ago(2)},
            "never": {"missed": ago(1)},
            "garbled": {"reached": "yesterday"},
        }
        self.assertEqual(ev.recent(ledger, NOW), {"edge", "revived"})
        self.assertEqual(ev.recent(ledger, NOW, timedelta(hours=2)), {"revived"})

    def test_last_checked_orders_like_time_and_unknown_comes_first(self):
        ledger = {"a": {"reached": ago(5)}, "b": {"reached": ago(9), "missed": ago(2)}}
        order = sorted(["a", "b", "c"], key=lambda key: ev.last_checked(ledger, key))
        self.assertEqual(order, ["c", "a", "b"])

    def test_prune_forgets_what_nobody_has_answered_for_a_week(self):
        ledger = {"old": {"reached": ago(24 * 8)}, "new": {"reached": ago(24 * 6)}, "bad": {}}
        self.assertEqual(set(ev.prune(ledger, NOW)), {"new"})

    def test_dump_is_deterministic_and_loads_back(self):
        ledger = {"2.2.2.2:443": {"missed": ago(1)}, "1.1.1.1:443": {"reached": ago(2), "asn": MCI}}
        text = ev.dump(ledger)
        self.assertEqual(text, ev.dump(dict(reversed(ledger.items()))))
        self.assertTrue(text.split("\n")[1].startswith('"1.1.1.1:443":'))
        self.assertEqual(json.loads(text)["endpoints"], ledger)
        self.assertEqual(json.loads(ev.dump({})), {"version": 1, "endpoints": {}})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.json"
            path.write_text(text, encoding="utf-8")
            self.assertEqual(ev.load(path), ledger)
            self.assertEqual(ev.load(Path(directory) / "missing.json"), {})
            self.assertEqual(ev.load(None), {})

    def test_a_damaged_ledger_is_an_error_not_an_empty_one(self):
        entry = '{"1.1.1.1:443":{"reached":"2026-10-31T10:00:00Z"}}'
        broken = [
            "{",
            "[]",
            '{"version":2,"endpoints":{}}',
            '{"version":1}',
            '{"version":1,"endpoints":{"1.1.1.1:443":{"reached":"soon"}}}',
            '{"version":1,"endpoints":{"1.1.1.1:443":{}}}',
            '{"version":1,"endpoints":{"1.1.1.1:443":{"reached":"2026-10-31T10:00:00Z","note":"x"}}}',
            '{"version":1,"endpoints":[]}',
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.json"
            path.write_text('{"version":1,"endpoints":' + entry + "}", encoding="utf-8")
            self.assertEqual(set(ev.load(path)), {"1.1.1.1:443"})
            for text in broken:
                path.write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "unreadable evidence ledger", msg=text):
                    ev.load(path)


def line(address: str, name: str = "") -> str:
    return f"trojan://secret@{address}:443?type=ws&sni=t.example.com&fp=chrome#{name or address}"


class CarryForwardTests(unittest.TestCase):
    """assemble and probe with a ledger from earlier runs, on five endpoints that are all otherwise equal."""

    ADDRESSES = ("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5")

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = root = Path(self.directory.name)
        self.lines = [line(a) for a in self.ADDRESSES]
        source, self.work, self.results = root / "source.txt", root / "work", root / "results"
        source.write_text("\n".join(self.lines) + "\n", encoding="utf-8")
        self.assertEqual(run("prepare", "--source", source, "--work", self.work, "--shards", 1), 0)
        rows = [{"id": f"{i}.o", "outcome": "success", "ms": 100} for i in range(len(self.lines))]
        self.results.mkdir()
        (self.results / "results-0.jsonl").write_text(iran_filter.jsonl_text(rows), encoding="utf-8")

    def write(self, name: str, data) -> Path:
        path = self.root / name
        path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
        return path

    def ledger(self, entries: dict) -> Path:
        return self.write("ledger.json", ev.dump({f"{a}:443": entry for a, entry in entries.items()}))

    def probe(self, endpoints: dict, **fields) -> Path:
        controls = {"start": {MCI: True}, "end": {MCI: True}}
        report = {"prober": "globalping", "status": "ok", "at": ago(0.5), "controls": controls}
        report.update(fields)
        report["endpoints"] = {f"{a}:443": nodes for a, nodes in endpoints.items()}
        return self.write("probe.json", report)

    def assemble(self, probe: Path | None, ledger: Path | None, *extra, minimum: int = 1) -> int:
        self.listed, self.verified = self.root / "list.txt", self.root / "verified.txt"
        self.out_ledger, self.report = self.root / "out_ledger.json", self.root / "report.json"
        for path in (self.listed, self.verified, self.out_ledger):
            path.unlink(missing_ok=True)
        args = [
            "assemble", "--work", self.work, "--results", self.results, "--summary", self.root / "summary.md",
            "--output", self.listed, "--verified", self.verified, "--report", self.report,
            "--min-lines", 1, "--min-verified", minimum, "--now", ev.stamp(NOW),
            "--evidence-output", self.out_ledger,
        ]  # fmt: skip
        if probe:
            args += ["--probe", probe]
        if ledger:
            args += ["--evidence", ledger]
        return run(*args, *extra)

    def lines_of(self, path: Path) -> list[str]:
        return sorted(path.read_text(encoding="utf-8").split("\n")[:-1])

    def test_a_run_cut_short_adds_to_the_verified_list_instead_of_replacing_it(self):
        ledger = self.ledger(
            {
                "1.1.1.1": {"asn": MCI, "reached": ago(2)},  # still good
                "2.2.2.2": {"asn": MCI, "reached": ago(2)},  # missed again this run
                "3.3.3.3": {"asn": MCI, "reached": ago(30)},  # too old
            }
        )
        probe = self.probe({"4.4.4.4": {MCI: [True]}, "2.2.2.2": {MCI: [False]}})
        self.assertEqual(self.assemble(probe, ledger), 0)
        # Nothing is dropped from the list itself; only 1.1.1.1 (recent) and 4.4.4.4 (this run) are verified.
        self.assertEqual(self.lines_of(self.listed), sorted(self.lines))
        self.assertEqual(self.lines_of(self.verified), sorted([self.lines[0], self.lines[3]]))
        report = json.loads(self.report.read_text(encoding="utf-8"))
        self.assertEqual(report["verdicts"], {"carried": 1, "reachable": 1, "unknown": 1, "unprobed": 2})
        self.assertEqual(report["buckets"]["1"], 2, "recent evidence lifts a line like this run's does")
        self.assertEqual(report["verified_gate"], "refreshed, 2 lines")
        # 1.1.1.1 is kept as it was, 4.4.4.4 is new, and 2.2.2.2 keeps when it was last good beside the miss.
        saved = json.loads(self.out_ledger.read_text(encoding="utf-8"))["endpoints"]
        self.assertEqual(saved["1.1.1.1:443"], {"asn": MCI, "reached": ago(2)})
        self.assertEqual(saved["4.4.4.4:443"], {"asn": MCI, "reached": ago(0.5)})
        self.assertEqual(saved["2.2.2.2:443"], {"asn": MCI, "reached": ago(2), "missed": ago(0.5)})
        self.assertEqual(saved["3.3.3.3:443"], {"asn": MCI, "reached": ago(30)})

    def test_a_probe_that_was_not_trusted_does_not_evict_anything(self):
        ledger = self.ledger({"1.1.1.1": {"asn": MCI, "reached": ago(2)}})
        probe = self.probe({"1.1.1.1": {MCI: [False]}}, controls={"start": {MCI: True}, "end": {MCI: False}})
        self.assertEqual(self.assemble(probe, ledger), 0)
        self.assertEqual(self.lines_of(self.verified), [self.lines[0]])
        saved = json.loads(self.out_ledger.read_text(encoding="utf-8"))["endpoints"]
        self.assertEqual(saved, {"1.1.1.1:443": {"asn": MCI, "reached": ago(2)}})

    def test_two_trusted_probes_that_fail_still_drop_the_line_despite_old_evidence(self):
        ledger = self.ledger({"1.1.1.1": {"asn": MCI, "reached": ago(2)}})
        both = {"start": {MCI: True, TCI: True}, "end": {MCI: True, TCI: True}}
        probe = self.probe({"1.1.1.1": {MCI: [False], TCI: [False]}}, controls=both)
        # The only line with evidence is gone, so the verified file is left alone (exit 4); the list is written.
        self.assertEqual(self.assemble(probe, ledger), 4)
        self.assertEqual(self.lines_of(self.listed), sorted(self.lines[1:]))
        self.assertFalse(self.verified.exists())
        saved = json.loads(self.out_ledger.read_text(encoding="utf-8"))["endpoints"]
        self.assertEqual(saved["1.1.1.1:443"], {"asn": MCI, "reached": ago(2), "missed": ago(0.5)})

    def test_with_no_probe_at_all_recent_evidence_still_publishes(self):
        ledger = self.ledger(
            {"1.1.1.1": {"asn": MCI, "reached": ago(20)}, "2.2.2.2": {"asn": MCI, "reached": ago(23)}}
        )
        probe = self.write("probe.json", {"prober": "globalping", "status": "no-probes", "endpoints": {}})
        self.assertEqual(self.assemble(probe, ledger), 0)
        self.assertEqual(self.lines_of(self.verified), sorted(self.lines[:2]))
        # Nothing was learned, so the ledger comes back as it went in.
        self.assertEqual(self.out_ledger.read_text(encoding="utf-8"), ledger.read_text(encoding="utf-8"))
        self.assertEqual(self.assemble(None, ledger), 0)
        self.assertEqual(self.lines_of(self.verified), sorted(self.lines[:2]))

    def test_too_little_evidence_leaves_the_verified_list_alone_but_publishes_the_list(self):
        ledger = self.ledger({"1.1.1.1": {"asn": MCI, "reached": ago(2)}})
        self.assertEqual(self.assemble(self.probe({}), ledger, minimum=2), 4)
        self.assertEqual(self.lines_of(self.listed), sorted(self.lines))
        self.assertFalse(self.verified.exists())
        report = json.loads(self.report.read_text(encoding="utf-8"))
        self.assertEqual(report["gates"], "pass")
        self.assertEqual(report["verified_gate"], "left unchanged, 1 lines have evidence and 2 are needed")
        self.assertIn("Verified list: left unchanged", (self.root / "summary.md").read_text(encoding="utf-8"))

    def test_a_failed_gate_on_the_list_still_writes_nothing(self):
        ledger = self.ledger({"1.1.1.1": {"asn": MCI, "reached": ago(2)}})
        code = self.assemble(self.probe({}), ledger, "--min-share", 2)
        self.assertEqual(code, 3)
        self.assertFalse(self.listed.exists() or self.verified.exists())
        # The evidence is still worth keeping in the artifacts.
        self.assertTrue(self.out_ledger.exists())

    def test_a_probe_report_without_a_start_time_is_used_for_this_run_only(self):
        probe = self.probe({"4.4.4.4": {MCI: [True]}})
        report = json.loads(probe.read_text(encoding="utf-8"))
        del report["at"]
        self.write("probe.json", report)
        ledger = self.ledger({"1.1.1.1": {"asn": MCI, "reached": ago(2)}})
        self.assertEqual(self.assemble(probe, ledger), 0)
        self.assertEqual(self.lines_of(self.verified), sorted([self.lines[0], self.lines[3]]))
        saved = json.loads(self.out_ledger.read_text(encoding="utf-8"))["endpoints"]
        self.assertEqual(set(saved), {"1.1.1.1:443"}, "an undated answer is not added to the ledger")

    def test_check_host_answers_never_enter_the_ledger_or_the_verified_list(self):
        probe = self.probe({"4.4.4.4": {"ir1.node.check-host.net": [True]}}, prober="check-host")
        self.assertEqual(self.assemble(probe, None), 4)
        self.assertFalse(self.verified.exists())
        self.assertFalse(self.out_ledger.exists())

    def test_a_damaged_ledger_stops_the_run(self):
        broken = self.write("ledger.json", "{")
        with self.assertRaisesRegex(ValueError, "unreadable evidence ledger"):
            self.assemble(self.probe({}), broken)

    def test_probe_asks_about_the_endpoint_checked_longest_ago_first(self):
        ledger = self.ledger(
            {
                "1.1.1.1": {"asn": MCI, "reached": ago(1)},
                "2.2.2.2": {"missed": ago(6)},
                "3.3.3.3": {"asn": MCI, "reached": ago(9), "missed": ago(3)},
            }
        )
        asked = []

        async def globalping_run(endpoints, minutes):
            asked.extend(endpoints)
            return {"prober": "globalping", "status": "ok", "endpoints": {}}

        def shuffled(addresses):
            return sorted(addresses, key=lambda key: hashlib.sha256(key.encode()).hexdigest())

        every = [f"{a}:443" for a in self.ADDRESSES]
        out = self.root / "probe_out.json"
        args = ("probe", "--work", self.work, "--results", self.results, "--output", out)
        with patch.object(iran_filter.globalping, "run", globalping_run):
            # With no ledger the order is the old one: a fixed shuffle inside each tier.
            self.assertEqual(run(*args), 0)
            self.assertEqual(asked, shuffled(every))
            at = ev.parse_stamp(json.loads(out.read_text(encoding="utf-8"))["at"])
            self.assertLess(abs(datetime.now(UTC) - at), timedelta(minutes=5))

            # With one, what no probe has answered for comes first, then the oldest answer, then the newest.
            asked.clear()
            self.assertEqual(run(*args, "--evidence", ledger), 0)
            self.assertEqual(asked[:2], shuffled(["4.4.4.4:443", "5.5.5.5:443"]))
            self.assertEqual(asked[2:], ["2.2.2.2:443", "3.3.3.3:443", "1.1.1.1:443"])


if __name__ == "__main__":
    unittest.main()
