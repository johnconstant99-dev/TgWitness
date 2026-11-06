import asyncio
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import zipfile

import pytest
from telethon.tl import functions, types

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import distributed_export, handover, interactions, report, report_design, verify
from tgwitness.collector import Collector, describe_message
from tgwitness.security import Vault
from tgwitness.store import Store, canonical
from tools.test_independent_report_pdf import capture_documents
from tools.test_distributed_export import Client

CHAT, HIDDEN, OBSERVER, BOT = -1000000000123, -1000000000456, 77001, 77002
WHEN = datetime(2020, 10, 1, 12, tzinfo=timezone.utc)
SEND = "PRIVATE_SEND_473 send-contact@example.invalid"
BUTTON = "PRIVATE_BUTTON_473 button-contact@example.invalid"
ANSWER = "PRIVATE_CALLBACK_473 callback-contact@example.invalid"
PREVIEW = "Permitted source context preview-contact@example.invalid"
OPAQUE = b"PRIVATE_CALLBACK_BYTES_473"
HIDDEN_TITLE = "PRIVATE_NONSELECTED_CHAT_473"
UNUSED = "PRIVATE_UNUSED_OPEN_TEXT_473"


def message(mid, text=None, sender=OBSERVER):
    return types.Message(id=mid, peer_id=types.PeerChannel(123), date=WHEN,
                         from_id=types.PeerUser(sender), message=text or "Synthetic message " + str(mid))


@pytest.fixture
def action_workspace(tmp_path):
    store, vault = Store(tmp_path), Vault(tmp_path)
    store.bind(vault)
    store.set_setting("account", {"id": OBSERVER, "first_name": "Synthetic observer"})
    store.set_setting("read_only", False)
    store.set_target(CHAT, "Selected synthetic source", "supergroup", True)
    store.set_target(HIDDEN, HIDDEN_TITLE, "supergroup", True)
    sent = message(1, SEND)
    sent.out = True
    menu = message(2, "Synthetic menu", BOT)
    menu.reply_markup = types.ReplyInlineMarkup([types.KeyboardInlineButtonRow([
        types.KeyboardInlineButton(BUTTON, types.InlineButtonTypeCallback(OPAQUE))])])
    peer = types.Channel(id=123, title=PREVIEW, photo=types.ChatPhotoEmpty(), date=WHEN,
                         access_hash=1, megagroup=True, username="SyntheticChat")

    class Client:
        async def send_message(self, *args, **kwargs):
            return sent

        async def get_messages(self, *args, **kwargs):
            return menu

        async def get_entity(self, *args, **kwargs):
            return peer

        async def __call__(self, request):
            if isinstance(request, functions.messages.GetBotCallbackAnswerRequest):
                return types.messages.BotCallbackAnswer(cache_time=0, message=ANSWER,
                    url="https://example.invalid/PRIVATE_CALLBACK_URL_473")
            assert isinstance(request, functions.channels.JoinChannelRequest)
            return SimpleNamespace(chats=[peer])

    async def capture(value, kind, chat, **kwargs):
        return store.append(kind, describe_message(value), chat, value.id, value.sender_id)

    collector = SimpleNamespace(store=store, running=True, restore=AsyncMock(), selected=lambda chat: chat == CHAT,
        resolve_target=AsyncMock(return_value=peer), capture_message=capture, client=Client(), dialog_cache={})

    async def seed():
        await interactions.execute(collector, interactions.Action(request_id="synthetic-send-00473",
                                    action="send", chat_id=CHAT, text=SEND))
        saved = await capture(menu, "message.new", CHAT)
        await interactions.execute(collector, interactions.Action(request_id="synthetic-press-00473", action="press",
            chat_id=CHAT, message_id=2, keyboard_event=saved["seq"], row=0, column=0))
        preview = await interactions.preview(collector, interactions.Preview(link="@SyntheticChat"))
        await interactions.execute(collector, interactions.Action(request_id="synthetic-open-00473", action="open",
                                    preview_id=preview["preview_id"], text=UNUSED))
    asyncio.run(seed())
    try:
        yield store, vault
    finally:
        store.close()


def field_keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from field_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from field_keys(item)


def projected(store, options):
    survey = handover.Survey(options.chats)
    events = store.all_events()
    for event in events:
        survey.add(event)
    requests, previews = survey.interactions()
    minimiser = handover.Minimiser(options, OBSERVER, survey.people, requests, previews)
    return [row for event in events if (row := minimiser.present(event)) is not None]


@pytest.mark.parametrize("design", report_design.DESIGNS)
@pytest.mark.parametrize("timeline", [False, True])
def test_signed_handover_projects_actions_and_chat_titles(action_workspace, tmp_path, monkeypatch, design, timeline):
    store, vault = action_workspace
    before = store.all_events()
    documents = capture_documents(monkeypatch)
    options = handover.Options(purpose="Synthetic private sharing test", chats=[CHAT], subjects=[BOT],
                               text="none", attachments="none", mask_contacts=True)
    archive, _ = handover.export(store, vault, options, {**report.resolved(), "design": design, "timeline": timeline})
    assert verify.verify_handover(archive, verify.fingerprint(vault.public_key))["report_seal"]
    forbidden = ("PRIVATE_SEND_473", "PRIVATE_BUTTON_473", "PRIVATE_CALLBACK_473", "PRIVATE_CALLBACK_URL_473",
                 "send-contact@example.invalid", "button-contact@example.invalid", "callback-contact@example.invalid",
                 "preview-contact@example.invalid", HIDDEN_TITLE, str(HIDDEN), UNUSED)
    with zipfile.ZipFile(archive) as source:
        for name in source.namelist():
            if name.endswith((".json", ".jsonl", ".html", ".js")):
                text = source.read(name).decode("utf-8")
                assert not any(marker in text for marker in forbidden), (design, timeline, name)
        rows = [json.loads(line) for line in source.read("records.jsonl").splitlines()]
        pdf = tmp_path / "projected.pdf"
        pdf.write_bytes(source.read("report.pdf"))
    assert verify.verify_report(pdf, verify.fingerprint(vault.public_key))["pdf_signature"]
    reading = "\n".join(documents[-1].reading_lines)
    assert not any(marker in reading for marker in forbidden), (design, timeline)
    actions = [row for row in rows if row["kind"].startswith("interaction.")]
    assert len(actions) == 7
    preview = next(row for row in actions if row["kind"] == "interaction.preview")
    assert preview["payload"]["title"] == "Permitted source context [e-mail]"
    for row in actions:
        original = next(event for event in before if event["seq"] == row["seq"])
        assert (row["hash"], row["signature"]) == (original["hash"], original["signature"])
        assert row["actor_id"] in (None, OBSERVER)
        if row["payload"] != original["payload"]:
            assert row["minimised"]
    assert store.all_events() == before


@pytest.mark.parametrize("text,subjects,others,send,callback", [
    ("none", [], "pseudonymize", False, False),
    ("subjects", [], "pseudonymize", True, False),
    ("subjects", [BOT], "pseudonymize", True, True),
    ("all", [], "pseudonymize", True, True),
    ("all", [OBSERVER], "omit", True, False),
])
def test_interaction_content_follows_author_policy(action_workspace, text, subjects, others, send, callback):
    store, _ = action_workspace
    options = handover.Options(purpose="Synthetic author policy", chats=[CHAT], text=text,
                               subjects=subjects, others=others, mask_contacts=True)
    rows = projected(store, options)
    action_rows = [row for row in rows if row["kind"].startswith("interaction.")]
    payloads = [row["payload"] for row in action_rows]
    actions = canonical(payloads).decode()
    assert ("PRIVATE_SEND_473" in actions) is send
    assert ("PRIVATE_BUTTON_473" in actions) is callback
    assert ("PRIVATE_CALLBACK_473" in actions) is callback
    assert "@example.invalid" not in actions and UNUSED not in actions
    assert {"raw", "data_base64"}.isdisjoint(field_keys(action_rows))
    assert str(OBSERVER) in actions and str(CHAT) in actions


def test_allowed_action_text_and_contacts_are_retained(action_workspace):
    store, _ = action_workspace
    options = handover.Options(purpose="Synthetic unrestricted copy", chats=[CHAT], text="all", others="show")
    actions = canonical([row for row in projected(store, options) if row["kind"].startswith("interaction.")]).decode()
    for allowed in (SEND, BUTTON, ANSWER, PREVIEW):
        assert allowed in actions


def test_actions_outside_selected_period_do_not_restore_text(action_workspace):
    store, _ = action_workspace
    options = handover.Options(purpose="Synthetic historical selection", chats=[CHAT], text="all", others="show",
                               until=WHEN + timedelta(seconds=1))
    rows = projected(store, options)
    assert any(row["kind"] == "message.new" for row in rows)
    actions = canonical([row for row in rows if row["kind"].startswith("interaction.")]).decode()
    assert SEND not in actions and ANSWER not in actions and BUTTON not in actions


def test_unknown_interaction_fields_are_not_copied(action_workspace):
    store, _ = action_workspace
    request = store.append("interaction.requested", {"account_id": OBSERVER, "unknown": "PRIVATE_UNKNOWN_473",
        "request": {"action": "send", "chat_id": CHAT, "text": SEND, "unknown": {"text": "PRIVATE_UNKNOWN_473"}},
        "button": {"type": "callback", "text": BUTTON, "data_base64": "PRIVATE_UNKNOWN_473"}}, CHAT, actor_id=OBSERVER)
    store.append("interaction.result", {"request_event": request["seq"], "chat_id": CHAT,
        "status": "succeeded", "unknown": "PRIVATE_UNKNOWN_473",
        "answer": {"message": ANSWER, "cache_time": 1, "raw": {"text": "PRIVATE_UNKNOWN_473"}}}, CHAT)
    options = handover.Options(purpose="Synthetic future field policy", chats=[CHAT], text="all", mask_contacts=True)
    assert "PRIVATE_UNKNOWN_473" not in canonical(projected(store, options)).decode()


async def multi_scenario(root, recovered_ids, *, fail_verification=False, recheck_error=False, tamper=False):
    stores, entries, fetched = [], {}, {}
    peer = types.Channel(id=123, title="Synthetic shared channel", photo=types.ChatPhotoEmpty(), date=WHEN,
                         access_hash=1, megagroup=True)
    other_started = asyncio.Event()

    class Latest(list):
        total = 8

    class ExportClient(Client):
        def __init__(self, name):
            super().__init__([message(mid) for mid in ((8, 6) if name == "default" else (3, 1))])
            self.name = name

        async def get_messages(self, entity, limit=None, offset_date=None, ids=None):
            if ids is not None:
                if recheck_error:
                    raise TimeoutError("Synthetic Telegram timeout")
                return [message(mid) for mid in recovered_ids]
            return Latest([message(8)])

        async def iter_messages(self, entity, offset_id=0, min_id=0, **options):
            assert (self.name, min_id, offset_id) in (("default", 4, 9), ("extra", 0, 5))
            for row in self.messages:
                fetched[row.id] = self.name
                yield row
            if self.name == "default":
                await asyncio.wait_for(other_started.wait(), 5)
            else:
                other_started.set()

    try:
        for index, name in enumerate(("default", "extra"), 1):
            folder = root / name
            folder.mkdir()
            store, vault = Store(folder), Vault(folder)
            stores.append(store)
            store.bind(vault)
            store.set_setting("account", {"id": 100 + index})
            vault.save("credentials", {"session": "synthetic-session-presence"})
            collector = Collector(store, vault)
            collector.restore = AsyncMock()
            collector.dialog_cache = {CHAT: {"kind": "supergroup", "title": "Synthetic source", "entity": peer}}
            collector.client = ExportClient(name)
            collector.telegram_clock = AsyncMock(return_value={})
            collector.chat_profile = AsyncMock(return_value=({}, {"role": "member"}, []))
            collector.client_identity = lambda: {}
            collector.route_receipt = lambda: {}

            entries[name] = {"label": name, "app": SimpleNamespace(state=SimpleNamespace(
                collector=collector, store=store, vault=vault))}
        coordinator = distributed_export.DistributedExport(SimpleNamespace(entries=entries, app=entries["default"]["app"]))
        real_verify = distributed_export.verify_chat_export
        checked_limits = []

        if tamper:
            launch = coordinator.launch
            def alter_before_selection(run):
                finish = run.finish_selection
                async def changed(directory, options):
                    path = directory / "chunks" / "1.jsonl"
                    path.write_bytes(path.read_bytes().replace(b"Synthetic message", b"Changed message"))
                    return await finish(directory, options)
                run.finish_selection = changed
                return launch(run)
            coordinator.launch = alter_before_selection

        def check(path, pinned, max_gib=None):
            checked_limits.append(max_gib)
            state = coordinator.public()
            assert not state["ready"] and coordinator.result_path(state["id"]) is None
            outbox.assert_not_called()
            if fail_verification:
                raise ValueError("Synthetic final verification failure")
            return real_verify(path, pinned, max_gib)

        with patch.object(distributed_export, "CHUNK", 4), patch.object(distributed_export, "verify_chat_export", check), \
                patch.object(distributed_export.replica, "outbox") as outbox:
            started = await coordinator.start(CHAT, ["default", "extra"], "default")
            await asyncio.wait_for(coordinator.runs[started["id"]].task, 30)
            state = coordinator.public(started["id"])
            if state["phase"] == "failed":
                assert not state["ready"] and coordinator.result_path(state["id"]) is None
                assert (coordinator.directory(state["id"]) / "chunks").is_dir()
                outbox.assert_not_called()
                return {"state": state, "checked_limits": checked_limits}
            assert state["phase"] == "done" and state["ready"], state
            outbox.assert_called_once()
            assert checked_limits and checked_limits[0] > 0
            path = coordinator.result_path(state["id"])
            checked = verify.verify_chat_export(path, verify.fingerprint(entries["default"]["app"].state.vault.public_key))
            with zipfile.ZipFile(path) as archive:
                manifest = json.loads(archive.read("manifest.json"))
                data = json.loads(archive.read("chat.json"))
            assert fetched == {8: "default", 6: "default", 3: "extra", 1: "extra"}
            return {"state": state, "checked": checked, "manifest": manifest, "data": data}
    finally:
        for store in stores:
            store.close()


@pytest.mark.parametrize("recovered", [[], [2], [2, 4, 5, 7]])
def test_recovered_messages_are_signed_by_the_actual_fetcher(tmp_path, recovered):
    result = asyncio.run(multi_scenario(tmp_path, recovered))
    assert result["state"]["phase"] == "done", result
    manifest, data = result["manifest"], result["data"]
    assert [row["id"] for row in data["messages"]] == sorted([1, 3, 6, 8, *recovered], reverse=True)
    assert manifest["message_count"] == result["checked"]["message_count"] == 4 + len(recovered)
    assert {worker["account_id"]: worker["captured"] for worker in result["state"]["workers"]} == {101: 2, 102: 2}
    ranges = [(bounds, part["statement"]["account_id"]) for part in manifest["parts"]
              for bounds in part["statement"]["ranges"]]
    assert all(part["statement"]["format"] == "tgwitness-chat-part-v1" for part in manifest["parts"])
    for mid in [1, 3, 6, 8, *recovered]:
        owners = [account for bounds, account in ranges if bounds["low"] <= mid <= bounds["high"]]
        assert len(owners) == 1
        assert owners == ([101] if mid in recovered or mid >= 5 else [102])
    assert {row["id"] for row in data["messages"] if row.get("found_on_recheck")} == set(recovered)
    assert sum(item["messages"] for item in result["checked"]["parts"]) == 4 + len(recovered)
    if recovered:
        next(row for row in data["messages"] if row["id"] == recovered[0])["text"] = "Tampered recovered text"
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("chat.json", '{\n "messages": [\n' + ",\n".join(
                json.dumps(row, ensure_ascii=False) for row in data["messages"]) + "\n ]\n}\n")
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive, pytest.raises(ValueError, match="differ from what the account signed"):
            verify.verify_parts(archive, manifest)


def test_failed_final_verification_never_publishes_ready_archive(tmp_path):
    result = asyncio.run(multi_scenario(tmp_path, [2], fail_verification=True))
    assert result["state"]["phase"] == "failed" and result["checked_limits"]
    assert "Synthetic final verification failure" in result["state"]["error"]


@pytest.mark.parametrize("recovered", [[2, 2], [3], [9]])
def test_invalid_recheck_ids_fail_closed(tmp_path, recovered):
    result = asyncio.run(multi_scenario(tmp_path, recovered))
    assert result["state"]["phase"] == "done", result
    assert [row["id"] for row in result["data"]["messages"]] == [8, 6, 3, 1]
    assert not any(row.get("found_on_recheck") for row in result["data"]["messages"])
    recheck = result["manifest"]["recheck"]
    assert recheck["asked"] == 0 and recheck["unchecked"] == 4
    assert recheck["errors"] == {"default": "ValueError", "extra": "ValueError"}


def test_recheck_error_keeps_the_original_signed_ranges(tmp_path):
    result = asyncio.run(multi_scenario(tmp_path, [], recheck_error=True))
    assert result["state"]["phase"] == "done", result
    assert result["manifest"]["recheck"]["errors"] == {"default": "TimeoutError", "extra": "TimeoutError"}
    assert len(result["manifest"]["parts"]) == 2


def test_selection_rejects_changed_original_fetch(tmp_path):
    result = asyncio.run(multi_scenario(tmp_path, [2], tamper=True))
    assert result["state"]["phase"] == "failed"
    assert result["state"]["error"] == "Acquired chunk changed before selection."
    assert not result["checked_limits"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
