"""Inspect real MTProto initialization metadata without connecting to Telegram."""
import asyncio
import argparse
import base64
import json
from pathlib import Path
import socket
import sys
import tempfile
from unittest.mock import patch

from telethon import TelegramClient
from telethon.crypto import AuthKey
from telethon.sessions import StringSession

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import api_pool, client_identity, client_profiles, i18n  # noqa: E402
from tgwitness.account_import import import_accounts, json_account  # noqa: E402
from tgwitness.collector import Collector  # noqa: E402
from tgwitness.security import Vault  # noqa: E402
from tgwitness.store import Store  # noqa: E402
from tools.browser_fixtures import FakeClient, saved_session, sqlite_fixture  # noqa: E402

PROFILE = {"device_model": "Synthetic laptop", "system_version": "Windows 11", "app_version": "6.0.0 x64",
           "lang_code": "en", "system_lang_code": "en-US", "lang_pack": "tdesktop"}
METADATA = {"app_id": 123, "app_hash": "a" * 32, "device": PROFILE["device_model"],
            "sdk": PROFILE["system_version"], **{k: v for k, v in PROFILE.items()
                                                if k not in ("device_model", "system_version")},
            "twoFA": "unused-synthetic-password", "proxy": ["unused.invalid", "unused-synthetic-password"],
            "device_token": "unused-synthetic-token", "program": "Synthetic importer"}


def uploaded(name, content):
    return {"name": name, "content": base64.b64encode(content).decode()}


def check_imports():
    assert client_identity.language_defaults("ru", "de-DE,de;q=0.9") == {"lang_code": "ru", "system_lang_code": "de-DE"}
    assert client_identity.language_defaults("es", "en-US;q=0.1,fr-CA;q=0.9") == {"lang_code": "es", "system_lang_code": "fr-CA"}
    assert client_identity.language_defaults("en", "*;q=1,de-DE;q=0,ru;q=nan") == {"lang_code": "en", "system_lang_code": "en"}
    for kind in ("telethon", "pyrogram"):
        result = import_accounts([uploaded("account.session", sqlite_fixture(kind)),
                                  uploaded("account.json", json.dumps(METADATA).encode())])
        assert result["client_profile"] == PROFILE
        assert result["api_id"] == 123 and result["has_authorization"]
        assert StringSession(result["session"]).auth_key.key == b"x" * 256
        assert "unused-synthetic" not in json.dumps(result)
    assert json_account(json.dumps(PROFILE).encode())["client_profile"] == PROFILE
    android = json_account(json.dumps({"device": "Synthetic Android", "sdk": "SDK 33", "app_version": "11.7.4 (56982)"}).encode())
    assert android["client_profile"] == {"device_model": "Synthetic Android", "system_version": "SDK 33", "app_version": "11.7.4 (56982)"}
    # Companion metadata is a connection profile, not client configuration or 2FA.
    assert client_identity.from_account({**METADATA, "phone": "+15550001111", "tz_offset": "-36000",
                                         "system_lang_pack": "en-US"}) == {**PROFILE, "tz_offset": -36000}
    assert client_identity.from_account({"system_lang_pack": "fr-CA"}) == {"system_lang_code": "fr-CA"}
    for field in ("string_session", "session_string", "session_str"):
        result = json_account(json.dumps({field: saved_session(), "session": "foreign-format-blob"}).encode())
        assert result["session"] == saved_session()
    assert client_identity.from_account({"lang_pack": ""}) == {"lang_pack": ""}
    assert client_identity.from_account({"device_model": "Synthetic phone", "device": "Synthetic phone",
                                         "system_version": "SDK 34", "sdk": "SDK 34"}) == {
        "device_model": "Synthetic phone", "system_version": "SDK 34"}
    for bad in ({"device": "x\nsecret"}, {"sdk": 11}, {"device": "a", "device_model": "b"},
                {"app_version": "x" * 129}, {"lang_code": "en/invalid"}, {"lang_pack": []},
                {"system_lang_code": "en", "system_lang_pack": "fr"}, {"tz_offset": True}, {"tz_offset": 50401},
                {"session_str": saved_session(), "session": saved_session(b"z")},
                {"session_str": "invalid", "session": saved_session()}):
        try:
            json_account(json.dumps(bad).encode())
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid imported profile accepted")


async def check_retention(root):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    vault.save("network", {"kind": "direct"})
    collector = Collector(store, vault, FakeClient)
    try:
        await collector.configure(123, "a" * 32, saved_session(), 44, PROFILE,
                                  {"lang_code": "fr", "system_lang_code": "fr-FR"})
        assert vault.read("credentials")["client_profile"] == PROFILE
        assert PROFILE["device_model"].encode() not in (root / "credentials.enc").read_bytes()
        await collector.stop(shutdown=True)
        collector = Collector(store, vault, FakeClient)
        with patch.object(client_identity.platform, "release", return_value="Changed OS"):
            await collector.restore()
        assert collector.client.options["system_version"] == PROFILE["system_version"]
        assert collector.client.tgwitness_client_profile == PROFILE
        assert collector.client.session.save() == saved_session()
        previous = vault.read("credentials")
        for bad in ({"proxy": "unused.invalid"}, {"system_version": ""}, {"device_model": 123}):
            try:
                await collector.configure(123, "a" * 32, saved_session(), 44, bad)
            except ValueError:
                pass
            else:
                raise AssertionError("Invalid profile accepted before authorization")
            assert vault.read("credentials") == previous
        try:
            await collector.configure(123, "a" * 32, saved_session(), 99, {**PROFILE, "device_model": "Wrong account"})
        except ValueError:
            pass
        else:
            raise AssertionError("Wrong account accepted")
        assert vault.read("credentials") == previous

        # Old vaults gain a fixed profile on their first successful restore.
        await collector.stop(shutdown=True)
        legacy = {k: v for k, v in previous.items() if k != "client_profile"}
        vault.save("credentials", legacy)
        collector = Collector(store, vault, FakeClient)
        with patch.object(client_identity.platform, "release", return_value="First OS"):
            await collector.restore()
        assert vault.read("credentials")["client_profile"]["system_version"] == "First OS"
        await collector.stop(shutdown=True)
        collector = Collector(store, vault, FakeClient)
        with patch.object(client_identity.platform, "release", return_value="Second OS"):
            await collector.restore()
        assert collector.client.options["system_version"] == "First OS"

        # A restore in flight cannot write obsolete credentials over a newer session.
        vault.save("credentials", legacy)
        replacement = {**previous, "session": saved_session(b"z")}
        async def changed_during_rpc():
            vault.save("credentials", replacement)
            return True
        with patch.object(collector.client, "is_user_authorized", changed_during_rpc):
            await collector.restore()
        assert vault.read("credentials") == replacement
    finally:
        await collector.stop(shutdown=True)
        store.close()


async def check_routes():
    from tools.check_session_reservations import workspace, import_body, RecordingClient
    async with workspace() as (app, http):
        headers = {"Accept-Language": "de-DE,de;q=0.9", "X-TgWitness-System-Language": "fr-CA", "Cookie": i18n.COOKIE + "=es"}
        response = await http.post("/api/auth/phone/start", json={"api_id": 321, "api_hash": "a" * 32,
                                                                "phone": "+15550001111"}, headers=headers)
        assert response.status_code == 200, response.text
        assert app.state.collector.login_client.options["lang_code"] == "es"
        assert app.state.collector.login_client.options["system_lang_code"] == "fr-CA"
        await app.state.collector.cancel_login()
        body = import_body()
        body["files"].append(uploaded("synthetic.json", json.dumps(METADATA).encode()))
        response = await http.post("/api/profiles/import", json=body, headers=headers)
        assert response.status_code == 200, response.text
        child = app.state.profiles.entries[response.json()["profile"]["id"]]["app"]
        assert child.state.vault.read("credentials")["client_profile"] == PROFILE
        assert child.state.collector.client.options["device_model"] == PROFILE["device_model"]
        assert not app.state.vault.read("credentials")

        response = await http.post("/api/auth/import", json={"files": [
            uploaded("other.json", json.dumps({**METADATA, "app_id": 321, "session": saved_session(b"q"),
                                               "tz_offset": -36000}).encode())]})
        assert response.status_code == 200, response.text
        imported = response.json()
        credentials = {k: imported[k] for k in ("api_id", "api_hash", "session", "client_profile")}
        response = await http.post("/api/auth/configure", json=credentials, headers=headers)
        assert response.status_code == 200, response.text
        assert app.state.vault.read("credentials")["client_profile"] == {**PROFILE, "tz_offset": -36000}
        connections = RecordingClient.connections
        response = await http.post("/api/auth/configure", json={**credentials, "client_profile": {"proxy": "unused.invalid"}})
        assert response.status_code == 422 and RecordingClient.connections == connections
        for invalid in (True, 1.5, 50401):
            response = await http.post("/api/auth/configure", json={**credentials, "client_profile": {"tz_offset": invalid}})
            assert response.status_code == 422 and RecordingClient.connections == connections
        response = await http.post("/api/auth/phone/start", json={"phone": "+15550001111"}, headers=headers)
        assert response.status_code == 200, response.text
        assert app.state.collector.login_client.tgwitness_client_profile == {**PROFILE, "tz_offset": -36000}


def check_catalog():
    data = client_profiles.catalog()
    models = {item["model"] for item in data["models"]}
    systems = {item["version"] for item in data["systems"]}
    assert len(models) == len(data["models"]) == 116
    assert systems == {"Windows 10 x64", "Windows 11 x64"}
    assert data["app_version"] == "7.3.3 x64" and data["api_id"] == api_pool.DESKTOP_ID
    assert all(isinstance(item["weight"], int) and item["weight"] > 0 for item in [*data["models"], *data["systems"]])
    assert Path(client_profiles.__file__).with_suffix(".LICENSE").is_file()
    found = set()
    for index in range(500):
        seed = "synthetic-workspace-" + str(index)
        profile = client_identity.resolve(api_pool.DESKTOP_ID, seed=seed)
        assert profile == client_identity.resolve(api_pool.DESKTOP_ID, seed=seed)
        assert profile["device_model"] in models and profile["system_version"] in systems
        assert profile["app_version"] == data["app_version"] and profile["lang_pack"] == "tdesktop"
        found.add(profile["device_model"])
    assert len(found) > 80
    with patch.object(api_pool, "rejected", set()):
        assert api_pool.login_order()[0][0] == api_pool.DESKTOP_ID
        saved_pair = next(pair for pair in api_pool.POOL if pair[0] != api_pool.DESKTOP_ID)
        assert api_pool.login_order(saved_pair)[0] == saved_pair
        api_pool.reject(api_pool.DESKTOP_ID)
        assert all(pair[0] != api_pool.DESKTOP_ID for pair in api_pool.login_order())


def check_platforms():
    data = client_profiles.catalog()["platforms"]
    for api_id, name in ((4, "android"), (6, "android"), (21724, "android_x"),
                         (10840, "ios"), (2834, "macos"), (2496, "web_a")):
        expected = data["profiles"][name]
        pairs = {(d["model"], d["system_version"]) for d in data["devices"][expected["catalog"]]}
        for index in range(50):
            profile = client_identity.resolve(api_id, seed=str(index))
            assert profile == client_identity.resolve(api_id, seed=str(index))
            assert (profile["device_model"], profile["system_version"]) in pairs
            assert profile["app_version"] == expected["app_version"]
            assert profile["lang_pack"] == expected["lang_pack"]
        supplied = {"device_model": "Synthetic imported device", "system_version": "Imported OS",
                    "app_version": "1.0 (1)", "lang_code": "fr", "system_lang_code": "fr-CA", "lang_pack": ""}
        assert client_identity.resolve(api_id, supplied, "fixed") == supplied
    for supplied, name in (({"app_version": "2.2 K"}, "web_k"), ({"lang_pack": "macos"}, "web_k"),
                           ({"app_version": "0.7.0"}, "webogram")):
        profile = client_identity.resolve(2496, supplied, "fixed")
        expected = data["profiles"][name]
        assert profile["lang_pack"] == expected["lang_pack"]
        assert profile["system_version"] in {d["system_version"] for d in data["devices"]["web_k"]}
    assert api_pool.device_for(123456789, "fixed") == {}
    for api_id in (4, 6, 21724, 10840, 2834, 2496, 2040):
        profile = client_identity.resolve(api_id, seed="fixed")
        assert client_identity.consistency_warnings(api_id, profile, 230) == []
    profile = client_identity.resolve(4, seed="fixed")
    mismatched = {**profile, "device_model": "iPhone 17", "system_version": "27.0.1", "lang_pack": "ios"}
    assert len(client_identity.consistency_warnings(4, mismatched, 230)) == 3
    assert "schema layer" in client_identity.consistency_warnings(4, profile, 229)[0]
    assert client_identity.resolve(4, mismatched, "fixed") == mismatched


async def check_catalog_retention(root):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    vault.save("network", {"kind": "direct"})
    collector = Collector(store, vault, FakeClient)
    try:
        pair = next(pair for pair in api_pool.POOL if pair[0] == api_pool.DESKTOP_ID)
        await collector.configure(*pair, saved_session(), languages={"lang_code": "es", "system_lang_code": "fr-CA"})
        saved = vault.read("credentials")["client_profile"]
        assert saved["lang_code"] == "es" and saved["system_lang_code"] == "fr-CA"
        await collector.stop(shutdown=True)
        collector = Collector(store, vault, FakeClient)
        # Updating bundled defaults must leave an existing account's complete profile intact.
        with patch.object(client_profiles, "desktop", return_value={**saved, "app_version": "99.0.0 x64"}):
            await collector.restore()
        assert collector.client.tgwitness_client_profile == saved
        assert vault.read("credentials")["client_profile"] == saved
    finally:
        await collector.stop(shutdown=True)
        store.close()


async def check_imported_pair_retention(root):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    vault.save("network", {"kind": "direct"})
    profile = {"device_model": "Synthetic phone", "system_version": "SDK 34", "app_version": "12.8.3 (69222)",
               "lang_code": "en", "system_lang_code": "en-us", "lang_pack": "android", "tz_offset": -36000}
    collector = Collector(store, vault, FakeClient)
    try:
        with patch.object(api_pool, "login_order", side_effect=AssertionError("Imported pair must not use the pool")):
            await collector.configure(4, "a" * 32, saved_session(), 4, profile)
            saved = vault.read("credentials")
            assert saved["api_id"] == 4 and saved["api_hash"] == "a" * 32
            assert saved["client_profile"] == profile
            await collector.stop(shutdown=True)
            collector = Collector(store, vault, FakeClient)
            assert collector.client_identity(credentials=saved)["device_model"] == profile["device_model"]
            await collector.restore()
            assert collector.client.tgwitness_client_profile == profile
            assert vault.read("credentials") == saved
    finally:
        await collector.stop(shutdown=True)
        store.close()


async def main(http=False):
    imported = StringSession()
    imported.set_dc(2, "149.154.167.51", 443)
    imported.auth_key = AuthKey(b"x" * 256)
    checks = 0
    with tempfile.TemporaryDirectory(prefix="client-identity-") as temporary, \
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS prohibited")), \
            patch.object(socket, "create_connection", side_effect=AssertionError("Network prohibited")):
        root = Path(temporary)
        vault, store = Vault(root), Store(root)
        vault.save("network", {"kind": "direct"})
        collector = Collector(store, vault, TelegramClient)
        try:
            for api_id in (*sorted(api_pool.POOL_IDS), 123, 4, 6, 21724, 10840, 2834, 2496):
                for session in ("", imported.save()):
                    client = collector.make_client(api_id, "a" * 32, session)
                    try:
                        request = client._init_request
                        labels = (request.device_model, request.system_version, request.app_version)
                        assert all(isinstance(value, str) and value for value in labels)
                        assert not any("tgwitness" in value.lower() for value in labels)
                        assert request.system_version != "Python"
                        if api_id not in (api_pool.DESKTOP_ID, 4, 6, 21724, 10840, 2834, 2496):
                            assert request.app_version == TelegramClient.__version__
                        assert request.api_id == api_id
                        if session:
                            assert client.session.auth_key.key == imported.auth_key.key
                            assert client.session.dc_id == imported.dc_id
                        checks += 1
                    finally:
                        await client.disconnect()
            client = collector.make_client(123, "a" * 32, imported.save(), {**PROFILE, "tz_offset": "-36000"})
            try:
                assert {field: getattr(client._init_request, field) for field in PROFILE} == PROFILE
                assert client._init_request.params.value[0].key == "tz_offset"
                assert client._init_request.params.value[0].value.value == -36000
                assert client._init_request.api_id == 123
                assert client.session.auth_key.key == imported.auth_key.key
                assert client.session.dc_id == imported.dc_id
                checks += 1
            finally:
                await client.disconnect()
        finally:
            store.close()
        check_imports()
        check_catalog()
        check_platforms()
        await check_retention(root / "retention")
        await check_catalog_retention(root / "catalog-retention")
        await check_imported_pair_retention(root / "imported-pair")
        if http:
            await check_routes()
    print(f"Client identity passed: {checks} real initialization requests; imported profiles, encrypted retention, "
          "legacy migration, stale-restore protection, Desktop/Android/iOS/macOS/Web catalogs; no Telegram connections.")
    if http:
        print("Single and bulk HTTP import also passed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--http", action="store_true", help="Also exercise HTTP import routes; requires dev dependencies.")
    asyncio.run(main(parser.parse_args().http))
