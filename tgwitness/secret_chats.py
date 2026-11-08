import asyncio
import hashlib
import logging
import secrets
import shutil

from telethon import utils
from telethon.tl import types
from telethon.tl.tlobject import TLObject

from .monitoring import capture_settings

try:
    import telethon_secret_chat as library
    from telethon_secret_chat.schema import secret_tl as library_tl
except ImportError:
    library = library_tl = None

LOG = logging.getLogger("tgwitness.secret_chats")
SETTING = "secret_chats"
STATE = "secret_chats"
PENDING = "secret_chat_files"
HELD = "secret_chat_unwritten"
HIDDEN = {"key", "iv"}
QUIET = {"DecryptedMessageActionRequestKey", "DecryptedMessageActionAcceptKey", "DecryptedMessageActionCommitKey",
         "DecryptedMessageActionAbortKey", "DecryptedMessageActionNoop", "DecryptedMessageActionNotifyLayer",
         "DecryptedMessageActionResend"}
UNAVAILABLE = ("Pseudo-secret needs the optional package kiaro-telethon-secret-chat. "
               "Install TgWitness with the secret-chats extra and restart the panel.")


def available():
    return library is not None


def of(collector):
    existing = getattr(collector, "secret_chats", None)
    if existing is None:
        existing = SecretChats(collector)
        collector.secret_chats = existing
    return existing


def settings(store):
    saved = store.get_setting(SETTING, {}) or {}
    return {"enabled": bool(saved.get("enabled")), "accept_incoming": bool(saved.get("accept_incoming"))}


def plain(value):
    if isinstance(value, TLObject) or library is not None and isinstance(value, library_tl.SecretTLObject):
        value = value.to_dict()
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items() if k not in HIDDEN}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        return {"sha256": hashlib.sha256(value).hexdigest(), "bytes": len(value)}
    return value


def encode(value):
    if isinstance(value, dict):
        return {k: encode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [encode(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        return {"__bytes__": bytes(value).hex()}
    return value


def decode(value):
    if isinstance(value, dict):
        if set(value) == {"__bytes__"}:
            return bytes.fromhex(value["__bytes__"])
        return {k: decode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [decode(v) for v in value]
    return value


if library is not None:
    class VaultStorage(library.MemoryStorage):

        def __init__(self, vault):
            super().__init__()
            self.vault = vault
            saved = vault.read(STATE)
            if saved:
                state = decode(saved)
                if not all(isinstance(state.get(group), dict) for group in ("chats", "out", "in")):
                    raise ValueError("The saved secret-chat state is damaged.")
                self._state = state

        def _write(self):
            self.vault.save(STATE, encode(self._state))


class SecretChats:
    def __init__(self, collector):
        self.collector = collector
        self.manager = self.client = None
        self.lock = asyncio.Lock()
        self.seen = set()
        self.tasks = set()
        self.downloads = {}
        self.error = None

    @property
    def store(self):
        return self.collector.store

    def note(self, kind, payload):
        return self.store.append("secret_chat." + kind, payload)

    def hold(self, name, payload):
        held = self.collector.vault.read(HELD) or {}
        held[name] = payload
        self.collector.vault.save(HELD, held)

    def release(self, name):
        held = self.collector.vault.read(HELD) or {}
        if held.pop(name, None) is not None:
            self.collector.vault.save(HELD, held)

    def write_held(self):
        for name, payload in list((self.collector.vault.read(HELD) or {}).items()):
            if not self.recorded("message", payload.get("secret_chat_id"), payload.get("random_id")):
                try:
                    self.note("message", payload)
                except Exception:
                    LOG.exception("A held secret-chat message could not be written")
                    continue
            self.release(name)

    def peer(self, chat_id):
        try:
            return self.manager.status(chat_id).peer_user_id
        except Exception:
            return None

    async def attach(self, client):
        if not available() or not settings(self.store)["enabled"]:
            return False
        async with self.lock:
            if self.manager and self.client is client:
                return True
            await self._detach()
            manager = library.SecretChatManager(client, storage=VaultStorage(self.collector.vault))
            for name in ("ChatRequested", "ChatReady", "ChatClosedEvent", "MessageReceived", "ServiceActionReceived",
                         "DecryptFailed", "SendFailed"):
                manager.on(name, getattr(self, "on_" + name))
            self.manager, self.client = manager, client
            try:
                await manager.start()
            except BaseException:
                self.manager = self.client = None
                raise
            self.write_held()
            for item in list((self.collector.vault.read(PENDING) or {}).values()):
                self.save_later(item)
            return True

    async def detach(self):
        async with self.lock:
            await self._detach()

    async def _detach(self):
        manager, self.manager, self.client = self.manager, None, None
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        if manager is not None:
            try:
                await asyncio.wait_for(manager.stop(), 15)
            except Exception:
                LOG.exception("Secret chats did not stop cleanly")

    def require(self):
        if not available():
            raise ValueError(UNAVAILABLE)
        if not settings(self.store)["enabled"]:
            raise ValueError("Turn on pseudo-secret for this account first.")
        if self.manager is None:
            raise ValueError("Connect this account to Telegram first.")
        return self.manager

    def recorded(self, kind, chat_id, random_id=None):
        query = "SELECT 1 FROM events WHERE kind=? AND json_extract(payload,'$.secret_chat_id')=?"
        values = ["secret_chat." + kind, chat_id]
        if random_id is not None:
            query += " AND json_extract(payload,'$.random_id')=?"
            values.append(random_id)
        with self.store.lock:
            return self.store.db.execute(query + " LIMIT 1", values).fetchone() is not None

    def on_ChatRequested(self, event):
        accept = settings(self.store)["accept_incoming"]
        if not self.recorded("requested", event.chat_id):
            self.note("requested", {"secret_chat_id": event.chat_id, "peer_user_id": event.peer_user_id,
                                    "direction": "in", "accepted_automatically": accept})
        if accept:
            self.spawn(self.accept(event.chat_id, automatic=True))

    def on_ChatReady(self, event):
        payload = {"secret_chat_id": event.chat_id, "peer_user_id": event.peer_user_id,
                   "key_fingerprint": event.key_fingerprint}
        if event.key_hash:
            payload["key_visualization"] = library.key_visualization(event.key_hash).hex
        self.note("ready", payload)

    def on_ChatClosedEvent(self, event):
        self.note("closed", {"secret_chat_id": event.chat_id, "reason": event.reason,
                             "history_deleted_by_peer": bool(event.history_deleted),
                             "journal_copy": "kept; the journal is append-only"})

    def on_MessageReceived(self, event):
        key = (event.chat_id, event.random_id)
        recorded = key in self.seen or self.recorded("message", event.chat_id, event.random_id)
        payload = {"secret_chat_id": event.chat_id, "peer_user_id": self.peer(event.chat_id), "direction": "in",
                   "random_id": event.random_id, "seq_no": event.seq_no, "text": event.text, "ttl": event.ttl,
                   "reply_to_random_id": event.reply_to,
                   "entities": plain(event.entities) if event.entities else None,
                   "media": plain(event.media) if event.media is not None else None}
        item = None
        if event.media_reference is not None and not self.recorded("file", event.chat_id, event.random_id):
            item = {"secret_chat_id": event.chat_id, "random_id": event.random_id,
                    "reference": event.media_reference.to_dict(), "message": payload}
            pending = self.collector.vault.read(PENDING) or {}
            name = str(event.chat_id) + ":" + str(event.random_id)
            item = pending.get(name) or encode(item)
            pending[name] = item
            self.collector.vault.save(PENDING, pending)
        if not recorded:
            name = str(event.chat_id) + ":" + str(event.random_id)
            if item is None:
                try:
                    self.note("message", payload)
                except Exception:
                    self.hold(name, payload)
                    raise
            else:
                self.note("message", payload)
        if len(self.seen) >= 4096:
            self.seen.clear()
        self.seen.add(key)
        if item is not None:
            self.save_later(item)

    def on_ServiceActionReceived(self, event):
        if event.action_name in QUIET:
            return
        self.note("action", {"secret_chat_id": event.chat_id, "peer_user_id": self.peer(event.chat_id),
                             "action": event.action_name.removeprefix("DecryptedMessageAction"),
                             "details": plain(event.action), "applied_by_tgwitness": event.applied,
                             "meaning": "Reported by the other side. TgWitness keeps every earlier message."})

    def on_DecryptFailed(self, event):
        self.note("decrypt_failed", {"secret_chat_id": event.chat_id, "reason": event.reason})

    def on_SendFailed(self, event):
        self.note("send_failed", {"secret_chat_id": event.chat_id, "random_id": event.random_id, "cause": event.cause})

    def spawn(self, coroutine):
        task = asyncio.get_running_loop().create_task(coroutine)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    def save_later(self, item):
        name = str(item["secret_chat_id"]) + ":" + str(item["random_id"])
        existing = self.downloads.get(name)
        if existing is not None and not existing.done():
            return existing
        task = self.spawn(self.save_file(decode(item)))
        self.downloads[name] = task

        def finished(done):
            if self.downloads.get(name) is done:
                self.downloads.pop(name, None)

        task.add_done_callback(finished)
        return task

    def unaffordable(self, reference, media_root):
        size = getattr(reference, "size", None)
        if not isinstance(size, int):
            size = None
        limit = capture_settings(self.store)["max_media_mb"] * 1024**2
        if size is not None and size > limit:
            return "larger than the media size limit"
        free = shutil.disk_usage(media_root).free
        if free - (size or 0) < self.collector.param("media_min_free_mb") * 1024**2:
            return "not enough free disk space"
        return None

    async def save_file(self, item):
        name = str(item["secret_chat_id"]) + ":" + str(item["random_id"])
        media_root = self.store.root / "media"
        media_root.mkdir(exist_ok=True)
        temporary = media_root / (".secret-" + secrets.token_hex(8))
        try:
            if item.get("message") and not self.recorded("message", item["secret_chat_id"], item["random_id"]):
                self.note("message", item["message"])
            if self.recorded("file", item["secret_chat_id"], item["random_id"]):
                pending = self.collector.vault.read(PENDING) or {}
                if pending.pop(name, None) is not None:
                    self.collector.vault.save(PENDING, pending)
                return
            reference = library.MediaReference.from_dict(item["reference"])
            refused = self.unaffordable(reference, media_root)
            if refused:
                self.note("file_deferred", {"secret_chat_id": item["secret_chat_id"], "random_id": item["random_id"],
                                            "reason": refused,
                                            "meaning": "The encrypted file stays queued; nothing was downloaded."})
                return
            await self.manager.save_file(reference, temporary)
            digest, size = hashlib.sha256(), 0
            with temporary.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
                    size += len(block)
            target = media_root / digest.hexdigest()
            if target.exists():
                temporary.unlink()
            else:
                temporary.replace(target)
            self.note("file", {"secret_chat_id": item["secret_chat_id"], "random_id": item["random_id"],
                               "media_sha256": digest.hexdigest(), "size": size,
                               "meaning": "Decrypted by TgWitness and stored by its SHA-256; the message record describes it."})
        except asyncio.CancelledError:
            temporary.unlink(missing_ok=True)
            raise
        except Exception as exc:
            temporary.unlink(missing_ok=True)
            self.note("file_failed", {"secret_chat_id": item["secret_chat_id"], "random_id": item["random_id"],
                                      "error_type": type(exc).__name__})
            return
        pending = self.collector.vault.read(PENDING) or {}
        if pending.pop(name, None) is not None:
            self.collector.vault.save(PENDING, pending)

    async def acting(self, call, *args, **kwargs):
        from . import interactions
        interactions.permitted(self.collector)
        try:
            return await call(*args, **kwargs)
        except Exception as exc:
            interactions.note_restriction(self.store, exc)
            raise

    async def create(self, user):
        manager = self.require()
        client = self.collector.client
        try:
            entity = await client.get_input_entity(user)
        except ValueError:
            if not isinstance(user, int):
                raise ValueError("Telegram has no user with this username.") from None
            await self.collector.dialogs()
            try:
                entity = await client.get_input_entity(user)
            except ValueError:
                raise ValueError("This account does not know that user ID yet. Use the @username, "
                                 "or open a chat with the user first.") from None
        if not isinstance(utils.get_peer(entity), types.PeerUser):
            raise ValueError("This needs a Telegram user, not a group or channel.")
        chat = await self.acting(manager.create, entity)
        self.note("requested", {"secret_chat_id": chat.id, "peer_user_id": chat.peer_user_id, "direction": "out"})
        return self.snapshot(chat)

    async def accept(self, chat_id, automatic=False):
        manager = self.require()
        try:
            chat = await self.acting(manager.accept, chat_id)
        except Exception as exc:
            self.note("accept_failed", {"secret_chat_id": chat_id, "automatic": automatic,
                                        "reason": str(exc) if isinstance(exc, ValueError) else type(exc).__name__})
            if automatic:
                return None
            raise
        self.note("accepted", {"secret_chat_id": chat_id, "peer_user_id": chat.peer_user_id,
                               "automatic": automatic,
                               "meaning": "This chat now lives in TgWitness; other devices of the account do not get it."})
        return self.snapshot(chat)

    async def send(self, chat_id, text):
        manager = self.require()
        random_id = await self.acting(manager.send_message, chat_id, text)
        chat = manager.status(chat_id)
        self.note("message", {"secret_chat_id": chat_id, "peer_user_id": chat.peer_user_id, "direction": "out",
                              "random_id": random_id, "text": text, "ttl": chat.ttl})
        return random_id

    async def close(self, chat_id):
        manager = self.require()
        await self.acting(manager.close, chat_id, reason="ended from TgWitness")
        self.note("closed", {"secret_chat_id": chat_id, "reason": "ended from TgWitness", "history_deleted_by_peer": False,
                             "journal_copy": "kept; the journal is append-only"})

    @staticmethod
    def snapshot(chat):
        return {"id": chat.id, "state": getattr(chat.state, "name", str(chat.state)).lower(),
                "peer_user_id": chat.peer_user_id, "outbound": chat.is_outbound, "ttl": chat.ttl, "layer": chat.layer,
                "key_visualization": library.key_visualization(chat.key_hash).hex if chat.key_hash else None,
                "created_at": chat.created_at, "closed_reason": chat.closed_reason}

    def view(self):
        connected = self.manager is not None
        chats = [self.snapshot(chat) for chat in self.manager.list()] if connected else []
        records = self.store.events(kind="secret_chat.", limit=2000)
        return {"available": available(), "settings": settings(self.store), "connected": connected, "error": self.error,
                "chats": sorted(chats, key=lambda chat: chat["created_at"] or 0, reverse=True),
                "records": list(reversed(records)), "unavailable_reason": None if available() else UNAVAILABLE}
