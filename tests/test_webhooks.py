import asyncio
import hashlib
import hmac
import json

import pytest

from test_access import HARBOR, OTHER, panel as panel
from tgwitness import netclient, webhooks
from tgwitness.network import NetworkConfig, NoRoute


def add(app, **changes):
    return webhooks.create(app.state.store, app.state.vault, webhooks.HookSettings(
        name="SIEM", url="https://receiver.example/webhook", **changes))


def test_metadata_scope_signature_and_replay_inputs(panel, monkeypatch):
    app, _ = panel
    issued = add(app, events=["changes"], chats=[HARBOR])
    sent = []

    async def request(method, url, route, **kwargs):
        sent.append(kwargs)
        return 204, {}, b""
    monkeypatch.setattr(netclient, "request", request)
    store = app.state.store
    store.append("message.edited", {"text": "PRIVATE_TEXT", "access_hash": "SECRET"}, chat_id=HARBOR, message_id=1)
    store.append("message.edited", {"text": "FOREIGN_TEXT"}, chat_id=OTHER, message_id=1)
    asyncio.run(webhooks.pump(store, app.state.vault, NetworkConfig(kind="direct"), "default"))
    assert len(sent) == 1
    body = sent[0]["body"]
    assert b"PRIVATE_TEXT" not in body and b"SECRET" not in body and b"FOREIGN_TEXT" not in body
    payload = json.loads(body)
    assert payload["workspace"] == "default" and payload["source"]["chat_id"] == HARBOR and payload["event_id"]
    header = dict(part.split("=", 1) for part in sent[0]["headers"]["X-TgWitness-Signature"].split(","))
    expected = hmac.new(issued["secret"].encode(), header["t"].encode() + b"." + body, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(expected, header["v1"])
    assert webhooks.state(store)["history"][-1]["status"] == "delivered"
    assert "secret" not in webhooks.public(app.state.vault.read("webhooks")["entries"][0])


def test_bounded_retries_keep_event_id_and_network_route(panel, monkeypatch):
    app, _ = panel
    issued = add(app)
    store, vault = app.state.store, app.state.vault
    asyncio.run(webhooks.enqueue_test(store, vault, "default", issued["connection"]["id"]))
    ids = []
    route = NoRoute("Outside traffic is disabled.")

    async def blocked(method, url, network, **kwargs):
        assert network is route
        ids.append(json.loads(kwargs["body"])["event_id"])
        raise netclient.RouteError("Outside traffic is disabled.")
    monkeypatch.setattr(netclient, "request", blocked)
    for attempt in range(8):
        data = webhooks.state(store)
        data["pending"][0]["next_attempt"] = 0
        store.set_setting("webhook_delivery", data)
        asyncio.run(webhooks.pump(store, vault, route, "default"))
    assert len(ids) == 8 and len(set(ids)) == 1
    assert not webhooks.state(store)["pending"]
    assert webhooks.state(store)["history"][-1]["status"] == "exhausted"


def test_text_opt_in_and_export_do_not_change_journal(panel, monkeypatch):
    app, admin = panel
    issued = add(app, events=["changes", "export"], chats=[HARBOR], include_text=True)
    head = app.state.store.stats()["head"]
    asyncio.run(webhooks.export_completed(app.state.store, app.state.vault, "default"))
    assert app.state.store.stats()["head"] == head
    event = app.state.store.append("message.edited", {"text": "explicit excerpt"}, chat_id=HARBOR, message_id=1)
    hook = app.state.vault.read("webhooks")["entries"][0]
    assert webhooks.envelope(event, "default", hook)["text"] == "explicit excerpt"
    assert admin.get("/api/integrations/webhooks").status_code == 200
    assert issued["secret"] not in admin.get("/api/integrations/webhooks").text
    assert admin.delete("/api/integrations/webhooks/" + issued["connection"]["id"]).status_code == 200
    assert not webhooks.state(app.state.store)["pending"]


@pytest.mark.parametrize("url", ["http://receiver.example", "https://user:secret@receiver.example", "https://receiver.example/?token=secret"])
def test_unsafe_destination_formats_rejected(url):
    with pytest.raises(ValueError):
        webhooks.HookSettings(name="Denied", url=url)
