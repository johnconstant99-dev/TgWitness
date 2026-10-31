"""Synthetic clients and sample data for standalone browser checks; no live Telegram."""

import asyncio
import hashlib
import io
import secrets
import sqlite3
import struct
import zipfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS

from telethon.crypto import AES, AuthKey
from telethon.errors import InviteRequestSentError, SessionPasswordNeededError
from telethon.sessions import StringSession
from telethon.tl import functions, types

ALICE = 70001


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


def sqlite_fixture(kind="telethon", version=None, bot=0, test=0, address=None, port=None):
    source = StringSession(saved_session())
    with sqlite3.connect(":memory:") as db:
        if kind == "telethon":
            db.executescript("CREATE TABLE version(version INTEGER); CREATE TABLE sessions "
                             "(dc_id INTEGER,server_address TEXT,port INTEGER,auth_key BLOB);")
            db.execute("INSERT INTO version VALUES (?)", (version or 8,))
            db.execute("INSERT INTO sessions VALUES (?,?,?,?)", (source.dc_id, address or source.server_address,
                                                                 port or source.port, source.auth_key.key))
        else:
            db.executescript("CREATE TABLE version(number INTEGER); CREATE TABLE sessions "
                             "(dc_id INTEGER,auth_key BLOB,test_mode INTEGER,user_id INTEGER,is_bot INTEGER);")
            db.execute("INSERT INTO version VALUES (?)", (version or 3,))
            db.execute("INSERT INTO sessions VALUES (?,?,?,?,?)", (source.dc_id, source.auth_key.key, test, 44, bot))
        db.commit()
        return db.serialize()


def tdata_fixture(passcode="", account_count=1, user_id=44):
    """Synthetic Desktop encoding, using Telethon's separate AES-IGE implementation."""
    def array(data):
        return struct.pack(">I", len(data)) + data

    def encrypt(content, key):
        plain = struct.pack("<I", len(content) + 4) + content
        plain += b"\0" * (-len(plain) % 16)
        msg = hashlib.sha1(plain).digest()[:16]
        a = hashlib.sha1(msg + key[8:40]).digest()
        b = hashlib.sha1(key[40:56] + msg + key[56:72]).digest()
        c = hashlib.sha1(key[72:104] + msg).digest()
        d = hashlib.sha1(msg + key[104:136]).digest()
        return msg + AES.encrypt_ige(plain, a[:8] + b[8:20] + c[4:16], a[8:20] + b[:8] + c[16:20] + d[:8])

    def container(data):
        version = struct.pack("<I", 3004000)
        return b"TDF$" + version + data + hashlib.md5(data + struct.pack("<I", len(data)) + version + b"TDF$").digest()

    salt, local = b"s" * 32, b"l" * 256
    seed = hashlib.sha512(salt + passcode.encode() + salt).digest()
    key = hashlib.pbkdf2_hmac("sha512", seed, salt, 100000 if passcode else 1, 256)
    source = StringSession(saved_session())
    authorization = struct.pack(">qqii", -1, user_id, source.dc_id, 1) + struct.pack(">i", source.dc_id) + source.auth_key.key + struct.pack(">i", 0)
    keys = array(salt) + array(encrypt(local, key)) + array(encrypt(struct.pack(">iii", account_count, 0, 0), local))
    mtp = array(encrypt(struct.pack(">i", 75) + array(authorization), local))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("tdata/key_datas", container(keys))
        archive.writestr("tdata/D877F783D5D3EF8Cs", container(mtp))
    return output.getvalue()


class QRClient(FakeClient):
    async def qr_login(self):
        self.scan = asyncio.Event()
        self.loop = asyncio.get_running_loop()
        self.qr_outcome = "authorized"
        async def wait():
            await self.scan.wait()
            if self.qr_outcome == "password":
                raise SessionPasswordNeededError(None)
            if self.qr_outcome == "expired":
                raise TimeoutError()
            self.authorized = True
            return await self.get_me()
        return NS(url="tg://login?token=c3ludGhldGljLXFS", expires=datetime.now(timezone.utc)+timedelta(seconds=60), wait=wait)


NEWS = -1000000000456


_SCOPE_ALICE, SHOP_BOT, STRANGER, NEW_BOT = 777, 888, 999, 4242


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def channel(number, **flags):
    return types.Channel(id=number, title="Channel " + str(number), photo=types.ChatPhotoEmpty(), date=NOW, **flags)


ENTITIES = {
    CHAT: channel(123, megagroup=True), NEWS: channel(456, broadcast=True),
    _SCOPE_ALICE: types.User(id=_SCOPE_ALICE, first_name="Alice", contact=True),
    SHOP_BOT: types.User(id=SHOP_BOT, first_name="Shop", bot=True),
    STRANGER: types.User(id=STRANGER, first_name="Stranger"),
    NEW_BOT: types.User(id=NEW_BOT, first_name="Fresh bot", bot=True),
}


class ScopeClient(FakeClient):
    async def iter_dialogs(self, limit):
        yield NS(id=CHAT, name="Synthetic group", is_group=True, is_channel=True, entity=ENTITIES[CHAT], folder_id=None)
        yield NS(id=_SCOPE_ALICE, name="Alice", is_group=False, is_channel=False, entity=ENTITIES[_SCOPE_ALICE], folder_id=None)
        yield NS(id=SHOP_BOT, name="Shop", is_group=False, is_channel=False, entity=ENTITIES[SHOP_BOT], folder_id=None)
        yield NS(id=NEWS, name="News", is_group=False, is_channel=True, entity=ENTITIES[NEWS], folder_id=1)

    async def get_entity(self, peer):
        return ENTITIES[peer]

    async def __call__(self, request):
        title = types.TextWithEntities("Work", [])
        return types.messages.DialogFilters(filters=[
            types.DialogFilterDefault(),
            types.DialogFilter(id=2, title=title, pinned_peers=[], include_peers=[types.InputPeerUser(_SCOPE_ALICE, 1)],
                               exclude_peers=[], bots=True, exclude_archived=True)])

    async def get_messages(self, entity, limit=None, ids=None):
        return [] if ids is None else [None for _ in ids]

    async def iter_messages(self, entity, limit=None, offset_id=0, min_id=0, reverse=False):
        return
        yield


def message(chat_id, id=1, text="hi", out=False):
    peer = types.PeerUser(chat_id) if chat_id > 0 else types.PeerChannel(-chat_id - 1000000000000)
    return types.Message(id=id, peer_id=peer, date=NOW, message=text, out=out,
                         from_id=types.PeerUser(44 if out else (chat_id if chat_id > 0 else 55)))


def button(text, kind):
    return types.KeyboardInlineButton(text=text, type=kind)


def offer(message_id=10, text="Choose a payment method", url="https://pay.example/a"):
    item = message(SHOP_BOT, message_id, text)
    item.reply_markup = types.ReplyInlineMarkup(rows=[
        types.KeyboardInlineButtonRow(buttons=[button("Pay", types.InlineButtonTypeUrl(url)),
                                               button("I paid", types.InlineButtonTypeCallback(b"paid:7"))]),
        types.KeyboardInlineButtonRow(buttons=[button("Open shop", types.InlineButtonTypeWebView("https://shop.example/app")),
                                               button("Copy code", types.InlineButtonTypeCopy("PROMO-7"))])])
    return item


class InteractionClient(ScopeClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sent, self.callbacks, self.joined = [], [], []
        self.failure = None
        self.current = offer()
        self.pending_join = False

    async def get_entity(self, peer):
        if isinstance(peer, str):
            return ENTITIES[SHOP_BOT] if peer == "shop_bot" else ENTITIES[CHAT]
        return await super().get_entity(peer)

    async def send_message(self, entity, text, **kwargs):
        self.sent.append((entity.id, text, kwargs))
        if self.failure:
            raise self.failure
        item = message(entity.id, 100 + len(self.sent), text, out=True)
        if kwargs.get("reply_to"):
            item.reply_to = types.MessageReplyHeader(reply_to_msg_id=kwargs["reply_to"])
        return item

    async def get_messages(self, entity, limit=None, ids=None):
        if isinstance(ids, int):
            return self.current
        return await super().get_messages(entity, limit=limit, ids=ids)

    async def __call__(self, request):
        if isinstance(request, functions.messages.GetBotCallbackAnswerRequest):
            self.callbacks.append(request)
            if self.failure:
                raise self.failure
            return types.messages.BotCallbackAnswer(cache_time=0, message="Recorded answer", alert=True,
                                                     url="https://example.test/receipt")
        if isinstance(request, functions.messages.CheckChatInviteRequest):
            return types.ChatInvite(title="Preview group", photo=types.PhotoEmpty(1), participants_count=9, color=0)
        if isinstance(request, (functions.messages.ImportChatInviteRequest, functions.channels.JoinChannelRequest)):
            self.joined.append(request)
            if self.pending_join:
                raise InviteRequestSentError(request)
            return NS(chats=[ENTITIES[CHAT]])
        return await super().__call__(request)


class CapsuleClient(FakeClient):
    logout_calls = 0

    async def get_messages(self, entity, limit=None, offset_id=0, **kwargs):
        rows = [media_message(3), telegram_message(2, "Private synthetic text"), telegram_message(1)]
        return [m for m in rows if not offset_id or m.id < offset_id][:limit]

    async def log_out(self):
        type(self).logout_calls += 1
        return await super().log_out()


def config(recipient):
    return {"token": secrets.token_urlsafe(32), "recipient": recipient["recipient"], "seconds": 60,
            "context": {"collector_sha": "a" * 40, "repository": "user/fork", "run_id": "123", "run_attempt": "1"}}


def say(store, chat, message_id, sender, text, name, username=None, flags=None, photo=None, reply=None, raw=None):
    observed = {"id": sender, "display_name": name, "username": username}
    if flags:
        observed["flags"] = flags
    if photo:
        observed["photo_id"] = photo
    return store.append("message.new", {"text": text, "sender_id": sender, "sender_observation": observed,
                                        "sent_at": "2026-01-01T0" + str(message_id % 10) + ":00:00+00:00",
                                        "reply_to_message_id": reply, "raw": raw or {}},
                        chat, message_id, sender)
