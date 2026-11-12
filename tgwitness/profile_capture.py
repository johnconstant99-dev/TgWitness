import asyncio
import hashlib
import re
from datetime import datetime
from urllib.parse import urlsplit

from telethon import functions, types, utils

from .avatar_history import PhotoBuffer, photo_metadata
from .people import profile_from_entity, iso, stamp
from .security import private_write
from .telegram_client import FLOOD_ERRORS


def source_time(value):
    return iso(stamp(value.isoformat() if isinstance(value, datetime) else value))


def references(about, personal_channel=None):
    found = {}
    for match in re.finditer(r"https?://[^\s<>]+|(?<![\w@])@[A-Za-z][A-Za-z0-9_]{3,31}", about or ""):
        value = match.group().rstrip(".,;:!?)\"'")
        url = "https://t.me/" + value[1:] if value.startswith("@") else value
        parsed = urlsplit(url)
        name = parsed.path.strip("/").split("/")[0]
        telegram = parsed.hostname in {"t.me", "telegram.me", "www.t.me"} and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,31}", name)
        key = "telegram:" + name.lower() if telegram else url
        found.setdefault(key, {"key": key, "url": url, "relation": "bio_mention", "username": name if telegram else None})
    if personal_channel:
        found["channel:" + str(personal_channel)] = {"key": "channel:" + str(personal_channel),
            "relation": "personal_channel", "channel_id": personal_channel}
    return list(found.values())


def gift_details(saved):
    gift = saved.gift
    identity = getattr(saved, "saved_id", None) or getattr(saved, "msg_id", None)
    slug = getattr(gift, "slug", None)
    date = source_time(getattr(saved, "date", None))
    sender = getattr(saved, "from_id", None)
    sender = utils.get_peer_id(sender) if sender is not None else None
    key = "saved:" + str(identity) if identity is not None else "unique:" + slug if slug else \
        "gift:" + str(gift.id) + ":" + str(date) + ":" + str(sender)
    attributes = []
    for item in getattr(gift, "attributes", None) or []:
        value = {key: getattr(item, key, None) for key in ("name", "rarity_permille", "center_color", "edge_color", "pattern_color", "text_color")}
        value = {key: val for key, val in value.items() if val is not None}
        if value:
            attributes.append({"type": type(item).__name__.removeprefix("StarGiftAttribute"), **value})
    return {"key": key, "gift_id": str(gift.id), "slug": slug, "title": getattr(gift, "title", None),
        "number": getattr(gift, "num", None), "received_at": date, "sender_id": sender,
        "sender_hidden": bool(getattr(saved, "name_hidden", False)),
        "message": getattr(getattr(saved, "message", None), "text", None),
        "unique": isinstance(gift, types.StarGiftUnique), "pinned": bool(getattr(saved, "pinned_to_top", False)),
        "unsaved": bool(getattr(saved, "unsaved", False)), "refunded": bool(getattr(saved, "refunded", False)),
        "attributes": attributes}


class ProfileCapture:
    async def capture_profile(self, run, job, peer):
        result = await self.ask(run, lambda: self.collector.client(functions.users.GetFullUserRequest(utils.get_input_user(peer))))
        entity = next((user for user in result.users if user.id == job["user_id"]), None)
        if entity is None or getattr(entity, "min", False):
            raise ValueError("IncompleteProfile")
        full = result.full_user
        profile = {**profile_from_entity(entity), "first_name": entity.first_name, "last_name": entity.last_name,
            "about": getattr(full, "about", None), "personal_channel_id": getattr(full, "personal_channel_id", None),
            "common_chats": getattr(full, "common_chats_count", None), "gifts_count": getattr(full, "stargifts_count", None),
            "photo_id": str(getattr(getattr(entity, "photo", None), "photo_id", "")) or None}
        birthday = getattr(full, "birthday", None)
        profile["birthday"] = {key: getattr(birthday, key, None) for key in ("day", "month", "year")} if birthday else None
        intro = getattr(full, "business_intro", None)
        profile["business"] = {key: getattr(intro, key, None) for key in ("title", "description")} if intro else None
        bot = getattr(full, "bot_info", None)
        profile["bot_description"] = getattr(bot, "description", None)
        links = references(profile["about"], profile["personal_channel_id"])
        with self.store.transaction():
            self.emit(run, job, "actor.profile", {"profile": profile, "source": "full_profile_collection"})
            self.update_job(run, job, stage="avatars", cursor="", links=links, attempts=0, error=None)

    async def save_image(self, run, job, media, kind, details):
        from .monitoring import capture_settings
        import shutil
        capture = capture_settings(self.store)
        folder = self.store.root / "media"
        folder.mkdir(exist_ok=True)
        identity = details.get("photo_id") or details.get("key")
        previous = self.store.db.execute("SELECT payload FROM events WHERE kind=? AND actor_id=? "
            "AND (json_extract(payload,'$.photo_id')=? OR json_extract(payload,'$.key')=?) ORDER BY seq DESC LIMIT 1",
            (kind, job["user_id"], identity, identity)).fetchone()
        metadata = None
        if previous:
            import json
            cached = json.loads(previous[0])
            digest = cached.get("media_sha256", "")
            if re.fullmatch(r"[a-f0-9]{64}", digest):
                target = folder / digest
                if target.is_file() and not target.is_symlink() and target.stat().st_size <= 2 * 1024**2:
                    data = await asyncio.to_thread(target.read_bytes)
                    if hashlib.sha256(data).hexdigest() == digest:
                        metadata = {key: cached[key] for key in ("media_sha256", "size", "mime_type", "phash")}
        if metadata is None:
            if not capture["download_media"] or not capture["include_avatars"]:
                return {"image_status": "disabled_by_recording_settings"}
            if shutil.disk_usage(folder).free < (self.collector.param("media_min_free_mb") + 2) * 1024**2:
                return {"image_status": "insufficient_free_space"}
            with PhotoBuffer() as stream:
                await self.ask(run, lambda: self.collector.client.download_media(media, file=stream, thumb=-1), timeout=30)
                data = stream.getvalue()
            if not data:
                return {"image_status": "not_returned"}
            metadata = await asyncio.to_thread(photo_metadata, data)
            target = folder / metadata["media_sha256"]
            if target.is_symlink():
                raise ValueError("InvalidImageDestination")
            if target.exists() and hashlib.sha256(await asyncio.to_thread(target.read_bytes)).hexdigest() != metadata["media_sha256"]:
                raise ValueError("SavedImageContentChanged")
            if not target.exists():
                await asyncio.to_thread(private_write, target, data)
        extension = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}[metadata["mime_type"]]
        self.emit(run, job, kind, {**details, **metadata, "name": "profile-" + str(job["user_id"]) + "-" + metadata["media_sha256"][:12] + extension})
        return {"image_status": "saved", "media_sha256": metadata["media_sha256"], "mime_type": metadata["mime_type"]}

    async def capture_avatars(self, run, job, peer):
        if not run["options"]["avatars"]:
            self.update_job(run, job, stage="gifts", cursor="", attempts=0)
            return
        result = await self.ask(run, lambda: self.collector.client(functions.photos.GetUserPhotosRequest(
            user_id=utils.get_input_user(peer), offset=0, max_id=int(job["cursor"] or 0), limit=100)))
        photos = list(result.photos)
        previous = job["cursor"]
        if photos and str(photos[-1].id) == previous:
            raise ValueError("PhotoCursorDidNotAdvance")
        for photo in photos:
            if not isinstance(photo, types.Photo):
                continue
            uploaded = source_time(photo.date)
            details = {"peer_id": job["user_id"], "photo_id": photo.id, "uploaded_at": uploaded,
                "historical": True, "meaning": "A profile photo returned by Telegram; uploaded_at is its upload date, not its installation date."}
            image = await self.save_image(run, job, photo, "actor.avatar_saved", details)
            with self.store.transaction():
                if image["image_status"] != "saved":
                    self.emit(run, job, "actor.avatar_observed", {**details, **image})
                self.update_job(run, job, cursor=str(photo.id), avatars=job["avatars"] + 1, attempts=0)
        if not photos:
            self.emit(run, job, "actor.avatars_collected", {"count": job["avatars"], "complete": True})
            self.update_job(run, job, stage="gifts", cursor="", attempts=0)
        elif job["cursor"] == "" or not any(isinstance(photo, types.Photo) for photo in photos):
            raise ValueError("PhotoCursorDidNotAdvance")

    async def capture_gifts(self, run, job, peer):
        if not run["options"]["gifts"]:
            self.update_job(run, job, stage="links", cursor="", attempts=0)
            return
        previous = job["cursor"]
        result = await self.ask(run, lambda: self.collector.client(functions.payments.GetSavedStarGiftsRequest(
            peer=peer, offset=previous, limit=100)))
        for saved in result.gifts:
            details = gift_details(saved)
            picture = getattr(saved.gift, "sticker", None) or next((getattr(item, "document", None)
                for item in getattr(saved.gift, "attributes", None) or [] if getattr(item, "document", None)), None)
            if picture is not None:
                try:
                    details.update(await self.save_image(run, job, picture, "media.saved", {"key": details["key"], "source": "profile_gift"}))
                except (asyncio.CancelledError, *FLOOD_ERRORS):
                    raise
                except Exception as exc:
                    from .profiling import CollectionPaused
                    if isinstance(exc, CollectionPaused):
                        raise
                    details["image_status"] = type(exc).__name__
                    self.update_job(run, job, failures=job["failures"] + 1)
            self.emit(run, job, "actor.gift_observed", details)
        cursor = getattr(result, "next_offset", None) or ""
        if cursor and cursor == previous:
            raise ValueError("GiftCursorDidNotAdvance")
        with self.store.transaction():
            self.update_job(run, job, cursor=cursor, gifts=job["gifts"] + len(result.gifts), attempts=0)
            if not cursor:
                total = getattr(result, "count", None)
                complete = total is None or total == job["gifts"]
                self.emit(run, job, "actor.gifts_collected", {"count": job["gifts"], "reported_total": total, "complete": complete})
                if not complete:
                    self.emit(run, job, "actor.profile_unavailable", {"area": "gifts", "error_type": "GiftListIncomplete",
                        "meaning": "Telegram returned fewer or more gifts than its reported total; the list may have changed during collection."})
                    self.update_job(run, job, failures=job["failures"] + 1)
                self.update_job(run, job, stage="links", cursor="")

    async def capture_links(self, run, job, peer):
        if not run["options"]["links"]:
            self.finish_job(run, job)
            return
        position = int(job["cursor"] or 0)
        if position >= len(job["links"]):
            self.finish_job(run, job)
            return
        reference = job["links"][position]
        details = dict(reference)
        if reference.get("username") or reference.get("channel_id"):
            target = reference.get("username") or types.PeerChannel(reference["channel_id"])
            entity = await self.ask(run, lambda: self.collector.client.get_entity(target))
            details.update(peer_id=utils.get_peer_id(entity), title=utils.get_display_name(entity), username=getattr(entity, "username", None))
            if isinstance(entity, types.Channel):
                result = await self.ask(run, lambda: self.collector.client(functions.channels.GetFullChannelRequest(entity)))
                full = result.full_chat
                details.update(kind="group" if entity.megagroup else "channel", about=full.about,
                    participants=getattr(full, "participants_count", None), linked_chat_id=getattr(full, "linked_chat_id", None))
            elif isinstance(entity, types.User):
                details["kind"] = "user"
        with self.store.transaction():
            self.emit(run, job, "actor.profile_link", details)
            self.update_job(run, job, cursor=str(position + 1), attempts=0)
