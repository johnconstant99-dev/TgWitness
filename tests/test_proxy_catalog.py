import json

import pytest
from fastapi.testclient import TestClient

from tgwitness import collector as collector_module
from tgwitness.app import create_app
from tgwitness.network import parse_mtproxy_link
from test_collector import FakeClient, CHAT, saved_session


SECRET = "a7" * 16


@pytest.mark.parametrize("prefix", ["tg://proxy", "https://t.me/proxy", "https://telegram.me/proxy"])
def test_proxy_link_parse_without_connection(prefix):
    route = parse_mtproxy_link(prefix + "?server=proxy.example.org&port=443&secret=dd" + SECRET)
    assert (route.kind, route.host, route.port, route.secret) == ("mtproxy", "proxy.example.org", 443, "dd" + SECRET)
    assert not route.public()["fallback_to_direct"]


@pytest.mark.parametrize("link", [
    "https://example.org/proxy?server=host&port=443&secret=" + SECRET,
    "https://t.me@attacker.example/proxy?server=host&port=443&secret=" + SECRET,
    "tg://proxy?server=host&port=443&secret=" + SECRET + "&secret=" + SECRET,
    "tg://proxy?server=host&port=0&secret=" + SECRET,
    "tg://proxy?server=host&port=443&secret=ee" + SECRET + "6578616d706c652e6f7267",
    "tg://proxy?server=host/path&port=443&secret=" + SECRET,
    "tg://proxy?server=host&port=443&secret=" + SECRET + "#hidden",
])
def test_proxy_links_reject_ambiguous_or_unsupported_input_without_echoing_secrets(link):
    with pytest.raises(ValueError) as error:
        parse_mtproxy_link(link)
    assert SECRET not in str(error.value)


def test_catalog_authentication_manual_import_isolation_and_secret_exclusion(tmp_path, monkeypatch):
    catalog = tmp_path / "proxies.json"
    monkeypatch.setenv("TGWITNESS_PROXY_CATALOG", str(catalog))

    async def resolved(config):
        return "198.51.100.7"
    monkeypatch.setattr(collector_module, "proxy_address", resolved)
    app = create_app(tmp_path / "data", client_factory=FakeClient)
    with TestClient(app) as client:
        assert client.get("/api/network/catalog").status_code == 401
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        assert client.get("/api/network/catalog").status_code == 503
        catalog.write_text(json.dumps({"format": "tgwitness-proxy-catalog-v1", "proxies": [
            {"id": "project-a", "label": "Project A", "link": "tg://proxy?server=proxy.example.org&port=443&secret=" + SECRET}]}))
        listing = client.get("/api/network/catalog")
        assert listing.json()["proxies"][0]["host"] == "proxy.example.org" and SECRET not in listing.text
        imported = client.post("/api/network/parse-link", json={"link": "https://t.me/proxy?server=own.example.org&port=8443&secret=" + SECRET})
        assert imported.json()["secret"] == SECRET
        assert app.state.collector.network_config().kind == "mtproxy_auto"
        assert client.post("/api/network/catalog/absent", json={}).status_code == 404
        assert client.post("/api/network/catalog/project-a", json={}).status_code == 200
        assert app.state.collector.network_config().secret == SECRET
        child = client.post("/api/profiles", json={"label": "Separate"}).json()["id"]
        assert client.get("/profiles/" + child + "/api/status").json()["collector"]["network"]["kind"] == "mtproxy_auto"
        assert SECRET not in json.dumps(app.state.store.all_events()) + client.get("/api/status").text
        assert SECRET.encode() not in (tmp_path / "data/network.enc").read_bytes()
        token = client.post("/api/witness/tokens", json={"label": "Reader"}).json()["token"]
        assert client.get("/api/network/catalog", headers={"Authorization": "Bearer " + token}).status_code == 401
        client.post("/api/auth/configure", json={"api_id": 123, "api_hash": "a" * 32, "session": saved_session()})
        client.get("/api/dialogs")
        client.post("/api/targets", json={"chat_id": CHAT, "enabled": True})
        client.post("/api/collector/start", json={})
        assert client.post("/api/network/catalog/project-a", json={}).status_code == 400
        client.post("/api/collector/stop", json={})

        catalog.write_text("invalid-json-with-private-data")
        failed = client.get("/api/network/catalog")
        assert failed.status_code == 503 and "private-data" not in failed.text
        assert client.post("/api/network", json=imported.json()).status_code == 200
        monkeypatch.delenv("TGWITNESS_PROXY_CATALOG")
        fallback = client.get("/api/network/catalog").json()
        assert fallback["mode"] == "bundled" and fallback["proxies"]
