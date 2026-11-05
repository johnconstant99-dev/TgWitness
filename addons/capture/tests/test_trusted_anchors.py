import hashlib
import time

import pytest

from tgwitness_capture.format import canonical
from tgwitness_capture.journal import Journal
from tgwitness_capture.network_witness import observe as provider_observe
from tgwitness_capture.trusted_anchor import CHAIN, GENESIS, PERIOD, confirm, observe, egress_probe


def sample():
    signature = "ab" * 48
    return {"round": int((time.time() - GENESIS) // PERIOD) + 1, "signature": signature,
            "randomness": hashlib.sha256(bytes.fromhex(signature)).hexdigest()}


def test_drand_two_relays_and_no_false_time_bound():
    calls = []
    value = sample()
    def fetch(host, path, connector):
        calls.append((host, path, connector))
        return value
    connector = {"id": "selected"}
    result = observe(connector, fetch)
    assert len(calls) == 2 and all(call[2] is connector for call in calls)
    event = {"kind": "trusted.beacon.drand", "payload": result}
    report = confirm([event], online=True, fetch=lambda url: value)
    assert report["relay_checked"] and not report["bls_verified"] and not report["upper_time_bound"]
    assert result["chain"] == CHAIN


def test_drand_mismatch_stale_and_bad_digest_fail():
    value = sample()
    with pytest.raises(ValueError, match="disagree"):
        observe({}, lambda host, path, connector: value if "latest" in path else {**value, "round": value["round"] - 1})
    with pytest.raises(ValueError, match="stale"):
        observe({}, lambda *args: {**value, "round": 1})
    with pytest.raises(ValueError, match="digest"):
        observe({}, lambda *args: {**value, "randomness": "0" * 64})


def test_cloudflare_queries_are_read_only_scoped_and_token_is_not_exported(tmp_path):
    journal = Journal(tmp_path / "witness")
    token = "synthetic-provider-read-token"
    config = {"account": "a" * 32, "connector_id": "00000000-0000-0000-0000-000000000001",
              "gateway_location": "00000000-0000-0000-0000-000000000002", "source_ip": "192.0.2.5"}
    calls = []
    def request(path, supplied, body=None):
        assert supplied == token
        calls.append((path, body))
        if path == "/graphql":
            assert "mutation" not in body["query"] and body["variables"]["source"] == "192.0.2.5"
            return {"data": {"viewer": {"accounts": [{"cf1GatewayDnsRawGroups": []}]}}}
        return {"success": True, "result": {"status": "healthy"}}
    try:
        event = provider_observe(journal, config, token, request)
        assert len(calls) == 3 and all("/token" not in path for path, _ in calls)
        assert event["payload"]["outcomes"]["dns"]["complete"] is False
        assert "no proof of continuous presence" in event["payload"]["scope"]
        assert token.encode() not in canonical(journal.events())
        assert all(token.encode() not in path.read_bytes() for path in journal.objects.iterdir())
    finally:
        journal.close()


def test_provider_denials_are_unavailable_not_healthy(tmp_path):
    journal = Journal(tmp_path)
    def unavailable(*args):
        raise PermissionError("Never include upstream error text or credentials")
    try:
        result = provider_observe(journal, {"account": "a" * 32, "connector_id": "00000000-0000-0000-0000-000000000001"},
                                  "synthetic", unavailable)
        assert all(value["status"] == "unavailable" for value in result["payload"]["outcomes"].values())
    finally:
        journal.close()


def test_egress_change_or_warp_loss_fails_closed():
    connector = {"protocol": "socks5", "mode": "warp_proxy"}
    probe = lambda *args: b"ip=192.0.2.55\nwarp=on\n"
    assert egress_probe(connector, fetch=probe)["ip"] == "192.0.2.55"
    with pytest.raises(ValueError, match="changed"):
        egress_probe(connector, "192.0.2.56", fetch=probe)
    with pytest.raises(ValueError, match="not confirmed"):
        egress_probe(connector, fetch=lambda *args: b"ip=192.0.2.55\nwarp=off\n")
    assert egress_probe({"protocol": "mtproxy", "mode": "proxy"})["status"] == "unavailable"
