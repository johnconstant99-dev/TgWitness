import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace as NS

from telethon.errors import SessionPasswordNeededError
from telethon.sessions import StringSession
from telethon.crypto import AuthKey
from telethon.tl import types

from tgwitness.collector import Collector

CHAT = -1000000000123


def saved_session():
    session = StringSession()
    session.set_dc(2, "149.154.167.51", 443)
    session.auth_key = AuthKey(b"x" * 256)
    return session.save()


class FakeClient:
    instances = []
    def __init__(self, session, api_id, api_hash, **kwargs):
        self.options = kwargs
        self.account_id = 44 if api_id == 123 else api_id
        self.authorized = bool(session.auth_key)
        self.session = NS(save=saved_session)
        self.connected = False
        self.handlers = []
        self.instances.append(self)

    def add_event_handler(self, handler, spec):
        self.handlers.append(handler)

    async def connect(self):
        self.connected = True

    async def disconnect(self):
        self.connected = False

    async def switch_route(self, options):
        self.connected = False
        self.options.pop("connection", None)
        self.options.pop("proxy", None)
        self.options.update(options)

    def is_connected(self):
        return self.connected

    async def is_user_authorized(self):
        return self.authorized

    async def log_out(self):
        self.authorized = self.connected = False
        return True

    async def get_me(self):
        return NS(id=self.account_id, username="synthetic", bot=False)

    async def send_code_request(self, phone):
        return NS(phone_code_hash="private-code-hash")

    async def sign_in(self, phone=None, code=None, phone_code_hash=None, password=None):
        if code == "22222":
            raise SessionPasswordNeededError(None)
        self.authorized = True

    async def iter_dialogs(self, limit):
        yield NS(id=CHAT, name="Synthetic group", is_group=True, is_channel=True,
                 entity=NS(megagroup=True, id=123))
        yield NS(id=55, name="Private dialog excluded", is_group=False, is_channel=False)

    async def iter_messages(self, entity, limit):
        for i in range(min(limit, 3)):
            yield telegram_message(i + 1)

    async def download_media(self, message, file, progress_callback):
        await progress_callback(4, 4)
        file.write(b"data")
        return file


def telegram_message(id=9, text="Original", media=None):
    return types.Message(id=id, peer_id=types.PeerChannel(123),
                         date=datetime.now(timezone.utc), message=text,
                         from_id=types.PeerUser(44), media=media)


def media_message(id=9, size=4, document_id=500):
    document = types.Document(id=document_id, access_hash=777, file_reference=b"original-reference",
                              date=datetime(2026, 1, 1, tzinfo=timezone.utc), mime_type="text/plain",
                              size=size, dc_id=2, attributes=[types.DocumentAttributeFilename("sample.txt")])
    return telegram_message(id, media=types.MessageMediaDocument(document=document))


async def wait_media(store):
    async def completed():
        while sum(v for k, v in store.media_stats().items() if k in ("queued", "running")):
            await asyncio.sleep(.01)
    await asyncio.wait_for(completed(), 4)


def test_authorize_2fa_restore_and_no_codes_on_disk(journal, tmp_path):
    async def run():
        store, vault = journal
        collector = Collector(store, vault, FakeClient)
        assert await collector.configure(123, "a"*32) == {"step": "phone"}
        assert await collector.send_code("+15550001111") == {"step": "code"}
        assert await collector.confirm_code("22222") == {"step": "password"}
        assert await collector.confirm_password("not-persisted-password") == {"step": "authorized"}
        saved = vault.read("credentials")
        assert set(saved) == {"api_id", "api_hash", "session"}
        authorized = [e for e in store.all_events() if e["kind"] == "account.authorized"]
        assert authorized[-1]["payload"]["key_origin"] == "created" == store.get_setting("account")["key_origin"]
        collector2 = Collector(store, vault, FakeClient)
        await collector2.restore()
        assert collector2.client.is_connected()
        assert collector.pending_phone is None and collector.phone_hash is None
        await collector.stop()
        await collector2.stop()
    asyncio.run(run())
    for p in tmp_path.iterdir():
        if p.is_file():
            assert b"not-persisted-password" not in p.read_bytes()
            assert b"+15550001111" not in p.read_bytes()


def test_new_edit_delete_and_unscoped_attribution(journal):
    async def run():
        store, vault = journal
        collector = Collector(store, vault, FakeClient)
        store.set_target(CHAT, "Synthetic", "supergroup", True)
        collector.running = True
        await collector.on_new(NS(chat_id=CHAT, message=telegram_message()))
        await collector.on_edit(NS(chat_id=CHAT, message=telegram_message(text="Edited")))
        await collector.on_new(NS(chat_id=-100999, message=telegram_message(text="Not selected")))
        await collector.on_delete(NS(chat_id=CHAT, deleted_ids=[9], original_update={"_": "UpdateDeleteChannelMessages"}))
        await collector.on_delete(NS(chat_id=None, deleted_ids=[9], original_update={"_": "UpdateDeleteMessages"}))
        records = store.all_events()
        assert [e["kind"] for e in records] == ["message.new","message.edited","message.deleted","deletion.unscoped"]
        assert records[0]["actor_id"] == 44
        assert records[1]["actor_id"] is None and records[1]["payload"]["sender_id"] == 44
        assert records[2]["actor_id"] is None and records[2]["source_at"] is None
        assert records[3]["chat_id"] is None
        assert records[0]["payload"]["text"] == "Original"
    asyncio.run(run())


def test_reactions_and_membership_remain_partial(journal):
    async def run():
        store, vault = journal
        collector = Collector(store, vault, FakeClient)
        store.set_target(CHAT, "Synthetic", "supergroup", True)
        collector.running = True
        await collector.on_raw(types.UpdateMessageReactions(
            peer=types.PeerChannel(123), msg_id=9,
            reactions=types.MessageReactions(results=[types.ReactionCount(reaction=types.ReactionEmoji("👍"), count=2)])))
        await collector.on_raw(types.UpdateChannelParticipant(
            channel_id=123, date=datetime.now(timezone.utc), actor_id=44, user_id=55, qts=1))
        records = store.all_events()
        assert records[0]["payload"]["complete_actor_list"] is False
        assert records[0]["actor_id"] is None
        assert records[1]["actor_id"] == 44 and records[1]["payload"]["user_id"] == 55
    asyncio.run(run())


def test_live_service_messages_are_received_through_raw_handler(journal):
    from telethon import events
    async def run():
        store, vault = journal
        collector = Collector(store, vault, FakeClient)
        store.set_target(CHAT, "Synthetic", "supergroup", True)
        collector.running = True
        msg = types.MessageService(id=70, peer_id=types.PeerChannel(123),
                                   date=datetime.now(timezone.utc),
                                   from_id=types.PeerUser(44),
                                   action=types.MessageActionChatAddUser([55]))
        update = types.UpdateNewChannelMessage(message=msg, pts=1, pts_count=1)
        assert events.NewMessage.build(update) is None
        await collector.on_raw(update)
        assert len(store.events(kind="membership.service")) == 1
        record = store.events(kind="membership.service")[0]
        assert record["payload"]["action"]["users"] == [55]
        assert record["actor_id"] == 44
        await collector.on_raw(types.UpdateChannelTooLong(channel_id=123, pts=2))
        assert store.events(kind="coverage.gap")[0]["chat_id"] == CHAT
    asyncio.run(run())


def test_start_snapshot_pause_and_restart_intent(journal):
    async def run():
        store, vault = journal
        collector = Collector(store, vault, FakeClient)
        await collector.configure(123, "a"*32, saved_session())
        result = await collector.dialogs()
        # Private chats are a source type of their own since whole-account observation.
        assert [(d["chat_id"], d["kind"]) for d in result["dialogs"]] == [(CHAT, "supergroup"), (55, "private")]
        store.set_target(CHAT, "Synthetic", "supergroup", True)
        await collector.start()
        assert collector.running
        assert await collector.snapshot(CHAT, 2) == {"captured": 2, "requested": 2}
        assert len(store.events(kind="message.snapshot")) == 2
        await collector.stop(shutdown=True)
        assert store.get_setting("resume") is True
        await collector.start()
        await collector.stop()
        assert store.get_setting("resume") is False
    asyncio.run(run())


def test_media_saved_with_linked_hash_and_cancel_cleanup(journal, tmp_path):
    async def run():
        store, vault = journal
        collector = Collector(store, vault, FakeClient)
        await collector.configure(123, "a"*32, saved_session())
        store.set_target(CHAT, "Synthetic", "supergroup", True)
        await collector.start()
        store.set_setting("capture", {"download_media": True, "max_media_mb": 1})
        original = await collector.capture_message(media_message(), "message.new", CHAT)
        await wait_media(store)
        event = store.events(kind="media.saved")[0]
        assert event["payload"]["message_event"] == original["seq"]
        assert (tmp_path / "media" / event["payload"]["media_sha256"]).read_bytes() == b"data"
        await collector.capture_message(media_message(10, 2*1024**2), "message.new", CHAT)
        await wait_media(store)
        assert len(store.events(kind="media.failed")) == 1
        await collector.stop()
        assert not list((tmp_path/"media").glob("pending-*"))
    asyncio.run(run())


class PreviewClient(FakeClient):
    async def download_media(self, media, file, progress_callback):
        if isinstance(media, types.MessageMediaWebPage):  # as Telethon: the document before the photo
            media = media.webpage.document or media.webpage.photo
        data = b"video" * 2 if isinstance(media, types.Document) else b"jpeg"
        await progress_callback(len(data), len(data))
        file.write(data)
        return file


def test_link_preview_saves_the_file_its_size_and_type_were_checked_for(journal, tmp_path):
    async def run():
        store, vault = journal
        collector = Collector(store, vault, PreviewClient)
        await collector.configure(123, "a"*32, saved_session())
        store.set_target(CHAT, "Synthetic", "supergroup", True)
        await collector.start()
        when = datetime(2026, 1, 1, tzinfo=timezone.utc)
        photo = types.Photo(id=1, access_hash=2, file_reference=b"r", date=when, dc_id=2,
                            sizes=[types.PhotoSize(type="x", w=10, h=10, size=4)])
        video = media_message(size=10).media.document
        preview = types.MessageMediaWebPage(webpage=types.WebPage(
            id=1, url="https://example.org/v", display_url="example.org/v", hash=1, photo=photo, document=video))
        await collector.capture_message(telegram_message(media=preview), "message.new", CHAT)
        await wait_media(store)
        saved = store.events(kind="media.saved")
        assert not store.events(kind="media.failed") and len(saved) == 1
        assert (tmp_path / "media" / saved[0]["payload"]["media_sha256"]).read_bytes() == b"jpeg"
        await collector.stop()
    asyncio.run(run())


class ExportClient(FakeClient):
    flood_raised = False

    async def iter_messages(self, entity, limit=None, offset_id=0, min_id=0):
        pending = [i for i in (5, 4, 3, 2, 1) if (offset_id == 0 or i < offset_id) and i > min_id]
        for n, i in enumerate(pending):
            if not ExportClient.flood_raised and n == 2:
                ExportClient.flood_raised = True
                from telethon.errors import FloodWaitError
                raise FloodWaitError(request=None)
            yield telegram_message(i, text="Message " + str(i))


def test_full_chat_export_signs_resumes_floodwait_and_runs_alongside_observation(journal):
    from tgwitness.verify import verify_chat_export, fingerprint
    async def run():
        store, vault = journal
        ExportClient.flood_raised = False
        collector = Collector(store, vault, ExportClient)
        await collector.configure(123, "a"*32, saved_session())
        await collector.dialogs()
        store.set_target(CHAT, "Synthetic", "supergroup", True)
        started = await collector.start_export(CHAT)
        assert started["phase"] == "running"
        # Export and observation share the account's one client: starting and pausing
        # observation during the export neither blocks nor disconnects it.
        await collector.start()
        assert collector.running
        try:
            await collector.start_export(CHAT)
            raise AssertionError("a second export on the same account must be refused")
        except ValueError as exc:
            assert "already running" in str(exc)
        await collector.stop()
        assert collector.client.is_connected()
        await asyncio.wait_for(collector.export_task, 10)
        state = collector.poll_export(started["id"])
        assert state["phase"] == "done" and state["ready"] and state["captured"] == 5
        assert ExportClient.flood_raised  # the FloodWait branch was exercised
        path = collector.export_result_path(started["id"])
        result = verify_chat_export(path, fingerprint(vault.public_key))
        assert result["message_count"] == 5 and result["chat"]["id"] == CHAT
        kinds = [e["kind"] for e in store.all_events()]
        assert "chat_export.started" in kinds and "chat_export.completed" in kinds
        assert "telegram.backoff" in kinds
        await collector.stop(shutdown=True)
    asyncio.run(run())


def test_chat_export_cancel_records_interruption(journal):
    async def run():
        store, vault = journal
        collector = Collector(store, vault, FakeClient)
        await collector.configure(123, "a"*32, saved_session())
        await collector.dialogs()
        store.set_target(CHAT, "Synthetic", "supergroup", True)
        # Hold the export open with a client whose history never ends until cancelled.
        class Endless(FakeClient):
            async def iter_messages(self, entity, limit=None, offset_id=0, min_id=0):
                i = 0
                while True:
                    i += 1
                    yield telegram_message(10_000 - i)
                    await asyncio.sleep(0)
        collector.client_factory = Endless
        collector.client = None
        started = await collector.start_export(CHAT)
        await asyncio.sleep(0.05)
        assert await collector.cancel_export(started["id"]) == {"phase": "cancelled"}
        assert collector.poll_export(started["id"])["phase"] == "cancelled"
        assert collector.export_result_path(started["id"]) is None
        assert "chat_export.interrupted" in [e["kind"] for e in store.all_events()]
        await collector.stop(shutdown=True)
    asyncio.run(run())


def test_attachments_are_saved_by_default_and_pause_when_disk_is_low(journal, tmp_path, monkeypatch):
    import shutil
    from tgwitness import collector as collector_module
    real_usage = shutil.disk_usage
    free = {"bytes": 10 * 1024**2}
    monkeypatch.setattr(collector_module.shutil, "disk_usage",
                        lambda path: real_usage(path)._replace(free=free["bytes"]))
    monkeypatch.setattr(collector_module, "STORAGE_RECHECK_SECONDS", 0.01)

    async def run():
        store, vault = journal
        collector = Collector(store, vault, FakeClient)
        await collector.configure(123, "a"*32, saved_session())
        store.set_target(CHAT, "Synthetic", "supergroup", True)
        await collector.start()
        await collector.capture_message(media_message(), "message.new", CHAT)  # no capture setting saved
        assert not store.events(kind="media.skipped")
        await asyncio.sleep(0.1)
        assert len(store.events(kind="storage.low")) == 1 and collector.status()["storage_low"]
        assert store.media_stats().get("queued") == 1 and not store.events(kind="media.failed")
        free["bytes"] = 50 * 1024**3
        await wait_media(store)
        assert store.events(kind="storage.ok") and store.events(kind="media.saved")
        assert not collector.status()["storage_low"]
        await collector.stop(shutdown=True)
    asyncio.run(run())
