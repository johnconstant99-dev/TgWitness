"""Preserve profile photos encountered in observed sources, independently of panel previews."""
import asyncio
import hashlib
import io
import re
import time
from collections import OrderedDict, deque

from telethon import utils
from telethon.errors import FloodWaitError

from .security import private_write
from .store import utcnow

MAX_BYTES = 2 * 1024 * 1024
MAX_PENDING = 128
MAX_HISTORY = 5000


class PhotoBuffer(io.BytesIO):
    def write(self, data):
        if self.tell() + len(data) > MAX_BYTES:
            raise ValueError("Profile photo exceeds the capture limit")
        return super().write(data)


def photo_metadata(data):
    from PIL import Image
    from .dossier import phash
    with Image.open(io.BytesIO(data)) as image:
        if image.width * image.height > 4_000_000:
            raise ValueError("Profile photo exceeds the pixel limit")
        image.verify()
        mime = Image.MIME.get(image.format)
    if mime not in ("image/jpeg", "image/png", "image/webp"):
        raise ValueError("Unsupported profile photo")
    return {"media_sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
            "mime_type": mime, "phash": phash(io.BytesIO(data))}


def history_events(store, chat_id=None):
    rows = store.bounded_read(
        "SELECT * FROM events WHERE kind IN ('actor.avatar_saved','actor.avatar_removed')" + (" AND chat_id=?" if chat_id is not None else "")
        + " ORDER BY seq DESC LIMIT ?", ([chat_id] if chat_id is not None else []) + [MAX_HISTORY], 3)
    return [store.decode(row) for row in reversed(rows)]


def history_index(store, chat_id=None, events=None):
    """Newest bounded set of journal-backed photos, scoped like the source that observed them."""
    result = {}
    for event in history_events(store, chat_id) if events is None else events:
        payload = event["payload"]
        peer, photo = payload.get("peer_id"), payload.get("photo_id")
        digest, perceptual = payload.get("media_sha256"), payload.get("phash")
        if (type(peer) is not int or type(photo) is not int or not isinstance(digest, str)
                or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)):
            continue
        if not isinstance(perceptual, str) or len(perceptual) != 16 or any(c not in "0123456789abcdef" for c in perceptual):
            perceptual = None
        key = (photo, digest)
        item = result.setdefault(peer, {}).setdefault(key, {
            "photo_id": photo, "sha256": digest, "phash": perceptual,
            "size": payload.get("size"), "mime_type": payload.get("mime_type"), "name": payload.get("name"),
            "first_at": event["observed_at"], "last_at": event["observed_at"], "records": [],
            "source": "signed actor.avatar_saved records"})
        item["last_at"] = event["observed_at"]
        item["records"].append(event["seq"])
    return {peer: list(photos.values()) for peer, photos in result.items()}


class AvatarHistory:
    def __init__(self, store, client_getter):
        self.store, self.client_getter = store, client_getter
        self.pending, self.seen, self.current, self.failed = deque(), OrderedDict(), OrderedDict(), {}
        self.worker = None
        self.loaded = False

    def observe(self, entity, *, chat_id):
        """Queue only an entity already recorded in a source; this hook never waits for Telegram."""
        photo_id = getattr(getattr(entity, "photo", None), "photo_id", None)
        if entity is None or not hasattr(entity, "photo") or type(chat_id) is not int or (photo_id is not None and type(photo_id) is not int):
            return False
        try:
            loop = asyncio.get_running_loop()
            peer_id = utils.get_peer_id(entity)
        except (RuntimeError, TypeError, ValueError):
            return False
        # A min User may omit an existing photo or contain stale fields. Telegram
        # requires apply_min_photo before that partial update replaces a full one.
        if peer_id > 0 and getattr(entity, "min", False) and not getattr(entity, "apply_min_photo", False):
            return False
        key = (chat_id, peer_id, photo_id)
        latest = next((item[0][2] for item in reversed(self.pending) if item[0][:2] == key[:2]),
                      self.current.get(key[:2], "unseen"))
        if latest == photo_id or time.time() < self.failed.get(key, 0):
            return False
        if len(self.pending) >= MAX_PENDING:
            return False
        self.pending.append((key, entity, utcnow()))
        if self.worker is None or self.worker.done():
            self.worker = loop.create_task(self.run())
        return True

    async def run(self):
        if not self.loaded:
            for event in history_events(self.store):
                p = event["payload"]
                key = (event["chat_id"], p.get("peer_id"), p.get("photo_id"))
                self.current[key[:2]] = key[2]
                if event["kind"] == "actor.avatar_saved":
                    self.seen[key] = p
            self.loaded = True
        while self.pending:
            key, entity, observed = self.pending[0]
            try:
                if key[2] is None:
                    if self.current.get(key[:2]) is not None:
                        self.store.append("actor.avatar_removed", {"peer_id": key[1], "photo_id": None,
                                          "previous_photo_id": self.current[key[:2]], "first_observed_at": observed},
                                          chat_id=key[0], actor_id=key[1])
                    self.current[key[:2]] = None
                elif self.current.get(key[:2]) != key[2]:
                    await self.capture(key, entity, observed)
            except asyncio.CancelledError:
                raise
            except FloodWaitError as exc:
                until = max(time.time() + exc.seconds, self.store.get_setting("rpc_backoff_until", 0))
                self.store.set_setting("rpc_backoff_until", until)
                self.failed[key] = until
            except Exception as exc:
                self.failed[key] = time.time() + 600
                self.store.append("actor.avatar_failed", {"peer_id": key[1], "photo_id": key[2],
                                  "error_type": type(exc).__name__}, chat_id=key[0], actor_id=key[1])
            finally:
                self.pending.popleft()
            if len(self.seen) > MAX_HISTORY:
                self.seen.popitem(last=False)
            if len(self.current) > MAX_HISTORY:
                self.current.popitem(last=False)
            if len(self.failed) > MAX_HISTORY:
                self.failed = {k: at for k, at in self.failed.items() if at > time.time()}
                if len(self.failed) > MAX_HISTORY:
                    self.failed.clear()

    async def capture(self, key, entity, observed):
        folder = self.store.root / "media"
        folder.mkdir(mode=0o700, exist_ok=True)
        previous = self.seen.get(key)
        if previous:
            metadata = {name: previous[name] for name in ("media_sha256", "size", "mime_type", "phash")}
            if not re.fullmatch(r"[a-f0-9]{64}", metadata["media_sha256"]):
                raise ValueError("Invalid saved avatar hash")
            source = folder / metadata["media_sha256"]
            if source.is_symlink() or source.stat().st_size > MAX_BYTES:
                raise ValueError("Saved avatar content changed")
            data = source.read_bytes()
        else:
            client = self.client_getter()
            if client is None or not client.is_connected() or time.time() < self.store.get_setting("rpc_backoff_until", 0):
                return
            with PhotoBuffer() as stream:
                await asyncio.wait_for(client.download_profile_photo(entity, file=stream, download_big=False), 20)
                data = stream.getvalue()
            if not data:
                self.failed[key] = time.time() + 600
                return
            metadata = await asyncio.to_thread(photo_metadata, data)
        destination = folder / metadata["media_sha256"]
        if destination.is_symlink() or (destination.exists() and (destination.stat().st_size > MAX_BYTES or
                hashlib.sha256(destination.read_bytes()).hexdigest() != metadata["media_sha256"])):
            raise ValueError("Saved avatar content changed")
        if not destination.exists():
            private_write(destination, data)
        extension = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}[metadata["mime_type"]]
        self.store.append("actor.avatar_saved", {"peer_id": key[1], "photo_id": key[2],
                          "first_observed_at": observed, "name": "avatar-" + str(key[1]) + "-" + str(key[2]) + extension, **metadata},
                          chat_id=key[0], actor_id=key[1])
        self.seen[key] = metadata
        self.current[key[:2]] = key[2]

    async def drain(self):
        if self.worker:
            await self.worker

    async def close(self):
        """Drop pending work before disconnect; the next observation can start a new worker."""
        if self.worker:
            self.worker.cancel()
            await asyncio.gather(self.worker, return_exceptions=True)
        self.worker = None
        self.pending.clear()
