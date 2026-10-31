import asyncio
import json

from fastapi.testclient import TestClient

from tgwitness import proxy_catalog as catalogs
from tgwitness import proxy_sources
from tgwitness.app import create_app
from tgwitness.network import NetworkConfig
from test_collector import FakeClient
from test_public_proxy_lists import link, seed

TOKEN = "ghp_" + "A" * 36


def test_links_are_found_in_markdown_html_and_json_files():
    text = ("Fresh: [one](" + link("8.8.8.8").replace("&", "&amp;") + ") and https://t.me/proxy?server=1.1.1.1"
            "&port=443&secret=" + "b8" * 16 + ".\n" + json.dumps([{"query": {"server": "9.9.9.9", "port": 443,
                                                                         "secret": "c9" * 16}}]))
    rows, skipped = catalogs.parse_feed(catalogs.links_in(text))
    assert {row["route"].host for row in rows} == {"8.8.8.8", "1.1.1.1"} and not skipped
    rows, _ = catalogs.parse_feed(catalogs.links_in(text.split("\n")[1]))
    assert [row["route"].host for row in rows] == ["9.9.9.9"]


def test_own_lists_and_switched_off_bundled_lists_survive_restarts(tmp_path, monkeypatch):
    catalog = seed(tmp_path, monkeypatch)
    item, compatible, _ = catalog.add_list("team.txt", "# ours\n" + link("4.4.4.4") + "\n" + link("4.4.4.4"))
    assert compatible == 1 and item.kind == "list"
    hosts = {p["host"] for p in catalogs.PublicCatalog(tmp_path).public()["proxies"]}
    assert hosts == {"8.8.8.8", "1.1.1.1", "4.4.4.4"}
    settings = catalog.settings()
    settings.disabled = ["solispirit"]
    proxy_sources.save(tmp_path, settings)
    assert {p["host"] for p in catalog.public()["proxies"]} == {"1.1.1.1", "4.4.4.4"}
    settings.custom = []
    proxy_sources.save(tmp_path, settings)
    catalog.forget({item.id})
    restarted = catalogs.PublicCatalog(tmp_path)
    assert {p["host"] for p in restarted.public()["proxies"]} == {"1.1.1.1"} and restarted.snapshot()[1] == "cache"


def test_github_token_reaches_only_github_and_the_search_collects_lists(tmp_path, monkeypatch):
    catalog = seed(tmp_path, monkeypatch)

    class Vault:
        data = {}
        def read(self, name):
            return self.data.get(name, {})
        def save(self, name, value):
            self.data[name] = value
    catalog.vault = Vault()
    catalog.set_github_token(TOKEN)
    settings = catalog.settings()
    settings.custom = [proxy_sources.CustomSource(url="https://lists.example.org/mtproto.txt")]
    settings.github.enabled = True
    proxy_sources.save(tmp_path, settings)
    seen = []

    async def request(method, url, network, headers=None, **kwargs):
        seen.append((url, (headers or {}).get("Authorization")))
        if url.startswith("https://api.github.com/search/code"):
            return 200, {}, json.dumps({"items": [{"url": "https://api.github.com/repos/a/b/contents/README.md",
                                                   "repository": {"full_name": "a/b"}, "path": "README.md"},
                                                  {"url": "https://evil.example/contents", "path": "x"}]}).encode()
        if url.startswith("https://api.github.com/repos/"):
            return 200, {}, ("Proxies: " + link("5.5.5.5")).encode()
        return 200, {}, link("6.6.6.6").encode()
    monkeypatch.setattr(catalogs.netclient, "request", request)
    monkeypatch.setattr(proxy_sources.netclient, "request", request)
    result = asyncio.run(catalog.refresh(NetworkConfig(kind="direct")))
    assert proxy_sources.GITHUB_SEARCH_ID in result["refresh"]["updated"]
    assert {"5.5.5.5", "6.6.6.6"} <= {p["host"] for p in result["proxies"]}
    tokens = dict(seen)
    assert tokens["https://lists.example.org/mtproto.txt"] is None
    hosts = proxy_sources.GITHUB_HOSTS
    assert all((value == "Bearer " + TOKEN) == (url.split("/")[2] in hosts) for url, value in seen)
    assert not any("evil.example" in url for url, _ in seen)
    assert catalog.github_status["files"] == 1 and catalog.github_status["error"] is None
    assert proxy_sources.token_problem("ghp_short") and not proxy_sources.token_problem(TOKEN)


def test_countries_are_looked_up_once_and_shown_in_the_table(tmp_path, monkeypatch):
    catalog = seed(tmp_path, monkeypatch)
    asked = []

    async def request(method, url, network, **kwargs):
        asked.append(url)
        return 200, {}, json.dumps({"ip": url.rsplit("/", 1)[-1], "country": "DE"}).encode()
    monkeypatch.setattr(proxy_sources.netclient, "request", request)
    hosts = [p["host"] for p in catalog.public()["proxies"]]
    assert asyncio.run(catalog.countries.locate(hosts, NetworkConfig(kind="direct"))) == 2
    assert asyncio.run(catalog.countries.locate(hosts, NetworkConfig(kind="direct"))) == 0 and len(asked) == 2
    pool = catalogs.ProxyPool(catalogs.PublicCatalog(tmp_path))
    pool.succeeded(pool.table()[0]["id"], 42)
    rows = pool.table({"owner": "Main"})
    assert {r["country"] for r in rows} == {"DE"} and sorted(r["status"] for r in rows) == ["ok", "untested"]
    assert next(r for r in rows if r["status"] == "ok")["latency_ms"] == 42


def test_proxy_panel_api_keeps_the_token_secret_and_needs_the_administrator(tmp_path, monkeypatch):
    seed(tmp_path, monkeypatch)
    app = create_app(tmp_path / "data", client_factory=FakeClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        view = client.get("/api/network/proxies").json()
        assert view["summary"]["listed"] == 2 and view["settings"]["github_token"] is False
        assert client.post("/api/network/github-token", json={"token": "ghp_bad"}).status_code == 422
        stored = client.post("/api/network/github-token", json={"token": TOKEN})
        assert stored.status_code == 200 and stored.json()["settings"]["github_token"] is True
        assert TOKEN not in stored.text and TOKEN.encode() not in (tmp_path / "data" / "github.enc").read_bytes()
        added = client.post("/api/network/sources/list", json={"label": "pasted", "text": link("7.7.7.7")})
        assert added.status_code == 200 and added.json()["added"]["compatible"] == 1
        settings = added.json()["settings"]
        assert client.post("/api/network/sources", json={**{k: settings[k] for k in ("disabled", "github", "countries")},
                                                         "custom": [], "disabled": ["solispirit"]}).status_code == 200
        hosts = {r["host"] for r in client.get("/api/network/proxies").json()["rows"]}
        assert hosts == {"1.1.1.1"}
        assert client.post("/api/network/sources", json={"disabled": ["nope"]}).status_code == 422
        assert client.post("/api/network/sources/list", json={"text": "nothing here"}).status_code == 422
        grant = client.post("/api/access/grants", json={"label": "Analyst", "workspaces": {"default": None},
                                                        "permissions": ["view", "account"]}).json()
        session = TestClient(app).post("/api/access/login", json={"token": grant["token"]}).json()["session"]
        other = {"Authorization": "Bearer " + session}
        assert client.get("/api/network/proxies", headers=other).status_code == 200
        assert client.post("/api/network/github-token", json={"token": ""}, headers=other).status_code == 403
        assert client.post("/api/network/sources", json={}, headers=other).status_code == 403
        assert client.post("/api/network/sources/list", json={"text": link()}, headers=other).status_code == 403


def test_custom_proxy_can_be_selected_from_another_workspace(tmp_path, monkeypatch):
    seed(tmp_path, monkeypatch)
    app = create_app(tmp_path / "data", client_factory=FakeClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        child = client.post("/api/profiles", json={"label": "Second"}).json()["id"]
        added = client.post("/api/network/sources/list", json={"label": "Own", "text": link("7.7.7.7")})
        assert added.status_code == 200, added.text
        prefix = "/profiles/" + child + "/api/network"
        listed = client.get(prefix + "/catalog").json()["proxies"]
        own = next(p for p in listed if p["host"] == "7.7.7.7")
        chosen = client.post(prefix + "/catalog/" + own["id"], json={})
        assert chosen.status_code == 200, chosen.text
        assert app.state.profiles.entries[child]["app"].state.collector.network_config().host == "7.7.7.7"


def test_github_token_is_never_sent_over_plain_http():
    assert proxy_sources.github_headers("http://api.github.com/repos/test/file", TOKEN) is None
