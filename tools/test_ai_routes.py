import asyncio
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import ai, analysis, netclient
from tgwitness.network import NetworkConfig, NoRoute


class Store:
    root = "synthetic-ai-route-test"

    def __init__(self, config):
        self.values = {"ai": config}

    def get_setting(self, key, default=None):
        return self.values.get(key, default)

    def set_setting(self, key, value):
        self.values[key] = value


def state(route, endpoint="http://127.0.0.1:11434", provider="ollama"):
    with patch.dict("os.environ", {"TGWITNESS_AI_LOCAL_ENDPOINT": endpoint}):
        config = ai.ProviderSettings(enabled=True, model="synthetic", endpoint=endpoint, provider=provider)
    sample = SimpleNamespace(route=route, store=Store(config.model_dump(exclude={"api_key", "clear_key"})),
                             vault=SimpleNamespace(read=lambda key: {}))
    sample.collector = SimpleNamespace(outside_route=lambda: sample.route)
    return sample


@pytest.mark.parametrize("endpoint", ["http://127.0.0.1:11434", "http://localhost:11434", "http://[::1]:11434",
                                     "https://127.0.0.2:11434", "https://[::ffff:127.0.0.1]:11434",
                                     "https://localhost.:11434", "https://host.localhost.:11434"])
@pytest.mark.parametrize("kind", ["socks5", "http"])
def test_loopback_proxy_rejected_before_transmission_or_budget(endpoint, kind):
    sample = state(NetworkConfig(kind=kind, host="proxy.example", port=1080), endpoint)
    with patch.object(netclient, "request", AsyncMock()) as send:
        with pytest.raises(ValueError, match="server-local AI endpoint requires"):
            asyncio.run(ai.Provider().complete(sample, [{"role": "user", "content": "SYNTHETIC_CONTEXT"}]))
        send.assert_not_awaited()
    assert "ai_usage" not in sample.store.values
    visible = ai.public(sample)
    assert visible["processing"] == "blocked" and visible["route_error"]


def test_local_proxy_and_private_opt_in_do_not_change_loopback_ownership():
    sample = state(NetworkConfig(kind="socks5", host="127.0.0.1", local_proxy=True), provider="compatible")
    with patch.dict("os.environ", {"TGWITNESS_ALLOW_PRIVATE_DESTINATIONS": "1"}), \
            patch.object(netclient, "request", AsyncMock()) as send:
        with pytest.raises(ValueError, match="server-local"):
            asyncio.run(ai.Provider().complete(sample, []))
        send.assert_not_awaited()


class Writer:
    def __init__(self):
        self.sent = bytearray()

    def write(self, data):
        self.sent.extend(data)

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


def response():
    body = json.dumps({"message": {"content": '{"claims":[]}'}, "done": True}).encode()
    reader = asyncio.StreamReader()
    reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    reader.feed_eof()
    return reader, Writer()


def test_direct_ollama_uses_local_connection():
    async def run():
        sample = state(NetworkConfig(kind="direct"))
        reader, writer = response()
        with patch.object(netclient, "connect_public", AsyncMock(return_value=(reader, writer))) as direct, \
                patch.object(netclient, "connect_proxy", AsyncMock()) as proxy:
            output, receipt = await ai.Provider().complete(sample, [{"role": "user", "content": "SYNTHETIC_CONTEXT"}])
        direct.assert_awaited_once_with("127.0.0.1", 11434, None, True)
        proxy.assert_not_awaited()
        assert output == {"claims": []} and b"SYNTHETIC_CONTEXT" in writer.sent
        assert receipt["processing"] == "server-local" and receipt["route"] == "direct"
    asyncio.run(run())


@pytest.mark.parametrize("kind", ["socks5", "http"])
def test_configured_https_ollama_retains_proxy_without_direct_retry(kind):
    async def run():
        endpoint = "https://ai.example"
        sample = state(NetworkConfig(kind=kind, host="proxy.example", port=1080), endpoint)
        reader, writer = response()
        with patch.dict("os.environ", {"TGWITNESS_AI_LOCAL_ENDPOINT": endpoint}), \
                patch.object(netclient, "proxy_address", AsyncMock(return_value="192.0.2.1")), \
                patch.object(netclient, "connect_proxy", AsyncMock(return_value=(reader, writer))) as proxy, \
                patch.object(netclient, "connect_public", AsyncMock()) as direct:
            _, receipt = await ai.Provider().complete(sample, [{"role": "user", "content": "SYNTHETIC_CONTEXT"}])
        direct.assert_not_awaited()
        assert proxy.await_count == 1 and proxy.await_args.args[2:4] == ("ai.example", 443)
        assert proxy.await_args.args[4] is not None
        assert b"SYNTHETIC_CONTEXT" in writer.sent
        assert receipt["processing"] == "configured-endpoint" and receipt["route"] == kind
    asyncio.run(run())


@pytest.mark.parametrize("route", [NoRoute("synthetic disabled route"), NetworkConfig(kind="mtproxy_auto")])
def test_blocked_external_routes_never_fall_back(route):
    sample = state(route, "https://ai.example/v1", "compatible")
    with patch.object(netclient, "connect_public", AsyncMock()) as direct, \
            patch.object(netclient, "connect_proxy", AsyncMock()) as proxy:
        with pytest.raises(netclient.RouteError):
            asyncio.run(ai.Provider().complete(sample, []))
        direct.assert_not_awaited()
        proxy.assert_not_awaited()


def test_preview_binds_proxy_identity_and_omits_credentials():
    sample = state(NetworkConfig(kind="socks5", host="proxy.example", username="SYNTHETIC_USER",
                                 password="SYNTHETIC_PASSWORD"), "https://ai.example/v1", "compatible")
    service = analysis.Analysis()
    body = SimpleNamespace(question="synthetic?", workspace="default")
    preview = service.remember(SimpleNamespace(owner="synthetic"), body, {"sources": [], "coverage": {"events": []}},
                               ai.settings(sample), sample.route)
    assert preview["provider"]["route"] == "socks5"
    assert preview["provider"]["route_host"] == "proxy.example"
    assert "SYNTHETIC_" not in json.dumps(preview) and "fingerprint" not in json.dumps(preview)
    expected = service.plans[preview["plan_id"]]["route_fingerprint"]
    sample.route = sample.route.model_copy(update={"password": "CHANGED_SYNTHETIC_PASSWORD"})
    with patch.object(netclient, "request", AsyncMock()) as send:
        with pytest.raises(ValueError, match="settings changed"):
            asyncio.run(service.provider.complete(sample, [], expected_route=expected))
        send.assert_not_awaited()


def test_route_change_while_queued_requires_new_preview():
    async def run():
        sample = state(NetworkConfig(kind="direct"), "https://ai.example/v1", "compatible")
        provider = ai.Provider()
        provider.slots = asyncio.Semaphore(0)
        with patch.object(netclient, "request", AsyncMock()) as send:
            task = asyncio.create_task(provider.complete(sample, []))
            await asyncio.sleep(0)
            assert provider.busy
            sample.route = NetworkConfig(kind="socks5", host="proxy.example")
            provider.slots.release()
            with pytest.raises(ValueError, match="settings changed"):
                await asyncio.wait_for(task, 2)
            send.assert_not_awaited()
        assert not provider.busy and "ai_usage" not in sample.store.values
    asyncio.run(run())


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
