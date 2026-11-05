import asyncio
import hashlib
import json
import time

import pytest

from tgwitness_capture.beacon import CHAIN, GENESIS, PERIOD, confirm, records, round_time, validate
from tgwitness_capture.journal import Journal
from tgwitness_capture.official import GuardStopped, OfficialBrowser, OfficialOptions


def value(number=100, signature="ab" * 48):
    return {"round": number, "signature": signature,
            "randomness": hashlib.sha256(bytes.fromhex(signature)).hexdigest()}


def test_signed_copies_do_not_replace_independent_beacon_queries():
    saved = {"seq": 4, **value()}
    assert confirm([saved], request=lambda number: value(number))["status"] == "PASS"
    with pytest.raises(ValueError, match="independently queried"):
        confirm([saved], request=lambda number: value(number, "cd" * 48))
    def offline(number):
        raise OSError("unavailable")
    assert confirm([saved], request=offline)["status"] == "INCOMPLETE"
    with pytest.raises(ValueError):
        validate({**value(), "randomness": "0" * 64})
    assert confirm([], request=offline)["status"] == "INCOMPLETE"


def test_other_chains_and_replayed_rounds_rejected():
    event = {"seq": 2, "kind": "official.drand", "payload": {**value(), "chain": CHAIN, "round_time": round_time(100)}}
    assert records([event])[0]["round"] == 100
    with pytest.raises(ValueError, match="increase"):
        records([event, event])
    with pytest.raises(ValueError, match="chain or time"):
        records([{**event, "payload": {**event["payload"], "chain": "other"}}])


def test_browser_records_fresh_beacon_through_owned_proxy_context(tmp_path):
    number = int((time.time() - GENESIS) / PERIOD) + 1
    current = value(number)
    requested, overlays = [], []
    class Reply:
        status = 200
        async def body(self):
            return json.dumps(current).encode()
        async def json(self):
            return current
        async def dispose(self):
            pass
    class Request:
        async def get(self, url, **kwargs):
            requested.append((url, kwargs))
            return Reply()
    class Page:
        async def evaluate(self, expression, round):
            overlays.append(round)
    journal = Journal(tmp_path / "records")
    browser = OfficialBrowser(OfficialOptions(proxy_server="http://proxy:3128"), journal)
    browser.context = type("Context", (), {"request": Request()})()
    browser.page = Page()
    async def check():
        await browser.beacon()
        await browser.beacon()
        assert len(records(journal.events())) == 1 and overlays == [number]
        assert requested[0][0].endswith(CHAIN + "/public/latest")
        assert requested[0][1]["max_redirects"] == 0
        current.update(value(1))
        with pytest.raises(GuardStopped, match="BeaconNotFresh"):
            await browser.beacon()
    try:
        asyncio.run(check())
    finally:
        journal.close()
