import asyncio
import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from openray import globalping

MCI, RIGHTEL, TCI = 197207, 57218, 58224
REACHES = {(MCI, "10.0.0.1:443"), (TCI, "10.0.0.3:443")}
REACHES |= {(asn, "8.8.8.8:443") for asn in (MCI, RIGHTEL, TCI)}
ENDPOINTS = ["10.0.0.1:443", "10.0.0.2:443", "10.0.0.3:443"]


def probe(asn: int, city: str = "Tehran", country: str = "IR") -> dict:
    return {"location": {"country": country, "asn": asn, "city": city}, "tags": [], "version": "0"}


class FakeApi:
    """Just enough of the Globalping API for the prober."""

    def __init__(self, probes=None, offline=(), limited_once=False, quiet=None, vanish=None, invalid=()):
        default = [probe(MCI, "Tabriz"), probe(RIGHTEL), probe(TCI), probe(202468), probe(3320, country="DE")]
        self.probes = default if probes is None else probes
        self.offline, self.limited_once = set(offline), limited_once
        # After the first measurement, quiet probes answer "no probe found" this many times, vanish probes
        # leave in the middle of this many measurements, and invalid targets are refused outright.
        self.quiet, self.vanish, self.invalid = dict(quiet or {}), dict(vanish or {}), set(invalid)
        self.created: dict[str, tuple[int, str]] = {}
        self.spent = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/v1/probes":
            return httpx.Response(200, json=self.probes)
        if path == "/v1/limits":
            create = {"type": "ip", "limit": 250, "remaining": 250, "reset": 0}
            return httpx.Response(200, json={"rateLimit": {"measurements": {"create": create}}})
        if request.method == "POST":
            return self.create(json.loads(request.content))
        ident = path.rsplit("/", 1)[1]
        asn, endpoint = self.created[ident]
        if self.vanish.get(asn) and int(ident[1:]) > 1:
            self.vanish[asn] -= 1
            gone = {"probe": {"asn": asn}, "result": {"status": "offline"}}
            return httpx.Response(200, json={"status": "finished", "results": [gone]})
        reached = (asn, endpoint) in REACHES
        stats = {"rcv": 3 if reached else 0, "loss": 0 if reached else 100}
        result = {"probe": {"asn": asn}, "result": {"status": "finished", "stats": stats}}
        return httpx.Response(200, json={"status": "finished", "results": [result]})

    def create(self, body: dict) -> httpx.Response:
        asn = body["locations"][0]["asn"]
        if self.limited_once:
            self.limited_once = False
            error = {"error": {"type": "too_many_requests"}}
            return httpx.Response(429, headers={"Retry-After": "2"}, json=error)
        if asn in self.offline or (self.quiet.get(asn) and self.spent >= 1):
            if asn not in self.offline:
                self.quiet[asn] -= 1
            return httpx.Response(422, json={"error": {"type": "no_probes_found"}})
        if body["target"] in self.invalid:
            return httpx.Response(400, json={"error": {"type": "validation_error"}})
        self.spent += 1
        ident = f"m{self.spent}"
        self.created[ident] = (asn, f"{body['target']}:{body['measurementOptions']['port']}")
        headers = {"x-ratelimit-remaining": str(250 - self.spent), "x-ratelimit-reset": "3600"}
        return httpx.Response(202, headers=headers, json={"id": ident, "probesCount": 1})


class Clock:
    """A clock that only moves when the prober pauses, so waiting costs no real time."""

    def __init__(self):
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    async def sleep(self, seconds: float) -> None:
        self.t += seconds


def run(api: FakeApi, endpoints=ENDPOINTS, minutes: float = 5) -> dict:
    clock = Clock()
    with patch("openray.globalping.pause", new=clock.sleep), patch("openray.globalping.now", new=clock):
        return asyncio.run(globalping.run(endpoints, minutes, httpx.MockTransport(api)))


class GlobalpingTests(unittest.TestCase):
    def test_each_endpoint_stops_at_the_first_probe_that_connects(self):
        api = FakeApi()
        report = run(api)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(set(report["nodes"]), {"AS197207", "AS57218", "AS58224"})
        self.assertEqual(
            report["endpoints"],
            {
                "10.0.0.1:443": {"AS197207": [True]},
                "10.0.0.2:443": {"AS197207": [False], "AS57218": [False], "AS58224": [False]},
                "10.0.0.3:443": {"AS197207": [False], "AS57218": [False], "AS58224": [True]},
            },
        )
        everyone = {"AS197207": True, "AS57218": True, "AS58224": True}
        self.assertEqual(report["controls"], {"start": everyone, "end": everyone})
        # Three opening controls, 1 + 3 + 3 for the endpoints and three closing controls.
        self.assertEqual(api.spent, 13)

    def test_a_refusal_waits_for_the_allowance_and_retries(self):
        report = run(FakeApi(limited_once=True))
        self.assertEqual(report["refused"], 1)
        self.assertEqual(len(report["endpoints"]), 3)
        self.assertEqual(report["controls"]["end"], {"AS197207": True, "AS57218": True, "AS58224": True})

    def test_an_offline_probe_is_left_out(self):
        report = run(FakeApi(offline={TCI}))
        self.assertEqual(report["offline"], 1)
        self.assertFalse(report["controls"]["start"]["AS58224"])
        asked = {node for nodes in report["endpoints"].values() for node in nodes}
        self.assertEqual(asked, {"AS197207", "AS57218"})

    def test_a_probe_that_goes_quiet_is_asked_again_and_resumes(self):
        # Volunteer probes drop off and come back; on 2026-10-28 two of them left within 3 minutes of a run.
        report = run(FakeApi(probes=[probe(RIGHTEL)], quiet={RIGHTEL: 2}))
        self.assertEqual(report["status"], "ok")
        self.assertEqual(set(report["endpoints"]), set(ENDPOINTS))
        self.assertEqual((report["offline"], report["recovered"]), (2, 1))
        self.assertEqual(report["refusals"], {"422 no_probes_found": 2})
        self.assertFalse(report["gave_up"] or report["stopped_early"])
        self.assertEqual(report["controls"]["end"], {"AS57218": True})

    def test_a_probe_that_leaves_in_the_middle_of_a_test_is_asked_again(self):
        report = run(FakeApi(probes=[probe(RIGHTEL)], vanish={RIGHTEL: 1}))
        self.assertEqual(set(report["endpoints"]), set(ENDPOINTS))
        self.assertEqual(report["refusals"], {"result offline": 1})
        self.assertEqual((report["offline"], report["recovered"], report["errors"]), (1, 1, 0))

    def test_a_probe_that_never_returns_ends_the_run_early(self):
        report = run(FakeApi(probes=[probe(RIGHTEL)], quiet={RIGHTEL: 10**6}), minutes=180)
        self.assertEqual(report["endpoints"], {})
        self.assertTrue(report["gave_up"] and report["stopped_early"])
        self.assertEqual(report["recovered"], 0)
        # Waits of 60, 120 and then 300 seconds until 15 minutes pass without an answer.
        self.assertLessEqual(report["elapsed_s"], globalping.GIVE_UP + max(globalping.OFFLINE_RETRY) + 60)

    def test_a_refused_target_does_not_take_the_probes_out(self):
        report = run(FakeApi(invalid={"10.0.0.2"}))
        self.assertEqual(set(report["endpoints"]), {"10.0.0.1:443", "10.0.0.3:443"})
        self.assertEqual(report["offline"], 0)
        self.assertEqual(report["refusals"], {"http 400": 3})
        self.assertEqual(report["controls"]["end"], {"AS197207": True, "AS57218": True, "AS58224": True})

    def test_a_single_probe_is_enough(self):
        # Hourly runs often find only one Iranian subscriber probe online; its connects still count.
        api = FakeApi(probes=[probe(RIGHTEL)])
        report = run(api)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(set(report["nodes"]), {"AS57218"})
        self.assertEqual(
            report["endpoints"],
            {endpoint: {"AS57218": [False]} for endpoint in ENDPOINTS},
        )
        self.assertEqual(report["controls"], {"start": {"AS57218": True}, "end": {"AS57218": True}})

    def test_no_probe_or_an_unreachable_api_gives_no_data(self):
        report = run(FakeApi(probes=[probe(3320, country="DE"), probe(202468)]))
        self.assertEqual((report["status"], report["endpoints"]), ("no-probes", {}))

        def broken(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        with patch("openray.globalping.pause", new=AsyncMock()):
            report = asyncio.run(globalping.run(ENDPOINTS, 5, httpx.MockTransport(broken)))
        self.assertEqual((report["status"], report["endpoints"]), ("api-unavailable", {}))


if __name__ == "__main__":
    unittest.main()
