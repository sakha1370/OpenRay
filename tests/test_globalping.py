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

    def __init__(self, probes=None, offline=(), limited_once=False):
        default = [probe(MCI, "Tabriz"), probe(RIGHTEL), probe(TCI), probe(202468), probe(3320, country="DE")]
        self.probes = default if probes is None else probes
        self.offline, self.limited_once = set(offline), limited_once
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
        asn, endpoint = self.created[path.rsplit("/", 1)[1]]
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
        if asn in self.offline:
            return httpx.Response(422, json={"error": {"type": "no_probes_found"}})
        self.spent += 1
        ident = f"m{self.spent}"
        self.created[ident] = (asn, f"{body['target']}:{body['measurementOptions']['port']}")
        headers = {"x-ratelimit-remaining": str(250 - self.spent), "x-ratelimit-reset": "3600"}
        return httpx.Response(202, headers=headers, json={"id": ident, "probesCount": 1})


def run(api: FakeApi, endpoints=ENDPOINTS, minutes: float = 5) -> dict:
    with patch("openray.globalping.pause", new=AsyncMock()):
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

    def test_too_few_probes_or_an_unreachable_api_gives_no_data(self):
        report = run(FakeApi(probes=[probe(MCI)]))
        self.assertEqual((report["status"], report["endpoints"]), ("too-few-probes", {}))

        def broken(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        with patch("openray.globalping.pause", new=AsyncMock()):
            report = asyncio.run(globalping.run(ENDPOINTS, 5, httpx.MockTransport(broken)))
        self.assertEqual((report["status"], report["endpoints"]), ("api-unavailable", {}))


if __name__ == "__main__":
    unittest.main()
