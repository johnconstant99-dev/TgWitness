"""Telegram account-export reads, over the collector's existing connection only.

Takeout and split-range wrappers apply to reads and media DC downloads. Authorization
handles and input peers are kept in the vault, never in the portable export.
"""
import base64
import functools
import inspect
from datetime import datetime, timezone

from telethon import errors, utils
from telethon.extensions import BinaryReader
from telethon.tl import functions as f, types as t

from .scope import kind_of

SECRET_FIELDS = frozenset({"access_hash", "file_reference", "auth_key", "api_hash", "session", "string_session",
                           "token", "password", "secret", "hash", "takeout_id", "future_auth_token"})


def safe(value, depth=0):
    """Readable Telegram fields with operational authorization material removed."""
    if depth > 24:
        return "[depth limit]"
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, bytes):
        return {"bytes_omitted": len(value)}
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    if isinstance(value, dict):
        return {str(k): safe(v, depth + 1) for k, v in value.items() if k not in SECRET_FIELDS}
    if isinstance(value, (list, tuple)):
        return [safe(v, depth + 1) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return {"type": type(value).__name__}


def downloadable(media):
    if isinstance(media, (t.Photo, t.Document, t.MessageMediaPhoto, t.MessageMediaDocument)):
        return media
    webpage = getattr(media, "webpage", None)
    return (getattr(webpage, "document", None) or getattr(webpage, "photo", None)) if webpage else None


def attachments(media):
    if isinstance(media, t.MessageMediaPaidMedia):
        return [item for extended in media.extended_media
                if (item := downloadable(getattr(extended, "media", None))) is not None]
    item = downloadable(media)
    return [item] if item is not None else []


class WrappedClient:
    """Rebind Telethon helpers so downloads through _call also carry Takeout."""
    def __init__(self, client, takeout_id=None, message_range=None):
        self._export_client, self._export_takeout, self._export_range = client, takeout_id, message_range

    def wrap(self, request):
        if self._export_range is not None and isinstance(request, (f.messages.GetDialogsRequest,
                f.messages.GetHistoryRequest, f.messages.GetMessagesRequest, f.messages.SearchRequest)):
            request = f.InvokeWithMessagesRangeRequest(t.MessageRange(**self._export_range), request)
        return f.InvokeWithTakeoutRequest(self._export_takeout, request) if self._export_takeout else request

    async def __call__(self, request, ordered=False):
        if isinstance(request, (list, tuple)):
            return await self._export_client([self.wrap(r) for r in request], ordered=ordered)
        await request.resolve(self._export_client, utils)
        return await self._export_client(self.wrap(request), ordered=ordered)

    async def _call(self, sender, request, ordered=False, flood_sleep_threshold=None):
        wrapped = [self.wrap(r) for r in request] if isinstance(request, (list, tuple)) else self.wrap(request)
        return await self._export_client._call(sender, wrapped, ordered, flood_sleep_threshold)

    def __getattr__(self, name):
        value = getattr(self._export_client, name)
        return functools.partial(value.__func__, self) if inspect.ismethod(value) else value


class Transport:
    def __init__(self, collector, vault, job_id, options):
        self.collector, self.vault, self.job_id, self.options = collector, vault, job_id, options
        self.secret_name = "account-export-" + job_id
        self.secret = vault.read(self.secret_name)
        self.peers = {}
        self.client = None
        self.metadata = {}
        self.emoji = {}

    def save(self):
        self.vault.save(self.secret_name, self.secret)

    async def open(self):
        await self.collector.restore()
        me = await self.collector.client.get_me()
        self.account_id = me.id
        takeout = self.secret.get("takeout_id")
        if self.options["transport"] == "takeout" and not takeout:
            kinds = self.options["chat_kinds"]
            files = bool(self.options["media_types"] or self.options["include_profile_photos"]
                         or self.options["include_stories"] or self.options["include_other_data"])
            result = await self.collector.client(f.account.InitTakeoutSessionRequest(
                contacts=self.options["include_contacts"], message_users=bool({"private", "bot"} & set(kinds)),
                message_chats="group" in kinds, message_megagroups=bool({"group", "supergroup"} & set(kinds)),
                message_channels="channel" in kinds, files=files,
                file_max_size=self.options["max_media_file_mib"] * 1024**2 if files else None))
            self.secret["takeout_id"] = takeout = result.id
            self.secret["generation"] = self.secret.get("generation", 0) + 1
            self.save()
            self.collector.store.append("account_export.transport", {"job_id": self.job_id,
                "generation": self.secret["generation"], "transport": "takeout", "authorization_in_journal": False})
        self.client = WrappedClient(self.collector.client, takeout)
        for key, encoded in self.secret.get("peers", {}).items():
            with BinaryReader(base64.b64decode(encoded, validate=True)) as reader:
                self.peers[int(key)] = reader.tgread_object()

    async def validate_inventory(self, inventory):
        if self.options["transport"] == "takeout" and any(t["category"] == "messages" for t in inventory["tasks"]):
            current = [dict(min_id=r.min_id, max_id=r.max_id) for r in await self.client(f.messages.GetSplitRangesRequest())]
            current = current or [None]
            if any(task.get("telegram_range") not in current for task in inventory["tasks"] if task["category"] == "messages"):
                raise ValueError("Telegram's Takeout ranges changed. Preserve this acquisition and start a new export.")

    def invalidate(self):
        self.secret.pop("takeout_id", None)
        self.save()

    def ranged(self, task):
        return WrappedClient(self.collector.client, self.secret.get("takeout_id"), task.get("telegram_range"))

    async def discover(self):
        ranges = [None] if self.options["chat_kinds"] else []
        gaps = []
        if self.options["transport"] == "takeout" and ranges:
            ranges = [dict(min_id=r.min_id, max_id=r.max_id) for r in await self.client(f.messages.GetSplitRangesRequest())]
            if not ranges:
                ranges = [None]
        elif self.options["transport"] == "regular":
            if {"group", "supergroup", "channel"} & set(self.options["chat_kinds"]):
                gaps.append("Regular API export cannot enumerate left channels and supergroups.")
            if self.options["include_contacts"]:
                gaps.append("Regular API contacts include Telegram users, not the complete saved phone contact list.")
        chats = {}
        for index, split in enumerate(ranges):
            client = WrappedClient(self.collector.client, self.secret.get("takeout_id"), split)
            # No panel dialog_limit and no folder filter: includes Saved Messages and archived dialogs.
            async for dialog in client.iter_dialogs(limit=None, folder=None, ignore_migrated=False):
                entity = dialog.entity
                cid = utils.get_peer_id(entity)
                self.peers[cid] = utils.get_input_peer(entity)
                row = chats.setdefault(cid, {"id": cid, "title": dialog.name, "kind": kind_of(entity) or "private",
                    "archived": getattr(dialog, "folder_id", None) == 1, "left": False, "ranges": []})
                if index not in row["ranges"]:
                    row["ranges"].append(index)
        if self.options["transport"] == "takeout" and {"group", "supergroup", "channel"} & set(self.options["chat_kinds"]):
            offset = 0
            while True:
                result = await self.client(f.channels.GetLeftChannelsRequest(offset))
                for entity in result.chats:
                    cid = utils.get_peer_id(entity)
                    self.peers[cid] = utils.get_input_peer(entity)
                    chats.setdefault(cid, {"id": cid, "title": getattr(entity, "title", str(cid)),
                        "kind": kind_of(entity) or "channel", "archived": False, "left": True,
                        "ranges": [len(ranges) - 1]})
                offset += len(result.chats)
                if not result.chats or isinstance(result, t.messages.Chats):
                    break
        tasks = []
        selected_ids = set(self.options["chat_ids"])
        for chat in chats.values():
            chat["selected"] = (chat["kind"] in self.options["chat_kinds"]
                                and (not selected_ids or chat["id"] in selected_ids)
                                and (self.options["include_archived"] or not chat["archived"]))
            if not chat["selected"]:
                continue
            for index in chat["ranges"]:
                task = {"id": "messages:" + str(chat["id"]) + ":" + str(index), "category": "messages",
                    "chat_id": chat["id"], "telegram_range": ranges[index], "own_only": self.options["own_messages_only"]}
                try:
                    try:
                        response = await self.history(task, 0, 1)
                    except errors.ChannelPrivateError:
                        task["own_only"] = True
                        gaps.append("Chat " + str(chat["id"]) + ": full history unavailable; exporting own messages only.")
                        response = await self.history(task, 0, 1)
                    messages = [m for m in response.messages if not isinstance(m, t.MessageEmpty)]
                except (errors.TakeoutInvalidError, errors.FloodWaitError, errors.ServerError):
                    raise
                except errors.RPCError as exc:
                    task["discovery_error"] = type(exc).__name__
                    messages = []
                newest = max((m.id for m in messages), default=0)
                task.update(newest_message_id=newest, cursor_start=newest + 1)
                tasks.append(task)
        missing = selected_ids - set(chats)
        gaps += ["Selected chat " + str(cid) + " was not returned in the visible inventory." for cid in sorted(missing)]
        for flag, category in (("include_profile", "profile"), ("include_contacts", "contacts"),
                ("include_session_metadata", "sessions"), ("include_profile_photos", "profile_photos"),
                ("include_stories", "stories"), ("include_other_data", "other_data")):
            if self.options[flag]:
                tasks.append({"id": category, "category": category, "chat_id": None, "cursor_start": 0})
        if self.options["include_contacts"]:
            tasks.append({"id": "top_peers", "category": "contacts", "source": "top_peers", "chat_id": None, "cursor_start": 0})
        if self.options["include_profile"] and "audio" in self.options["media_types"]:
            tasks.append({"id": "profile_music", "category": "profile", "source": "profile_music", "chat_id": None, "cursor_start": 0})
        selected = [chat for chat in chats.values() if chat["selected"]]
        self.discovery_counts = {"chats_discovered": len(chats), "chats_excluded": len(chats) - len(selected)}
        self.peers = {chat["id"]: self.peers[chat["id"]] for chat in selected}
        self.secret["peers"] = {str(k): base64.b64encode(bytes(v)).decode() for k, v in self.peers.items()}
        self.save()
        return selected, tasks, gaps

    async def history(self, task, cursor, limit=100):
        peer = self.peers[task["chat_id"]]
        if task["own_only"]:
            request = f.messages.SearchRequest(peer, "", t.InputMessagesFilterEmpty(), None, None,
                cursor, 0, limit, task.get("newest_message_id", 0) + 1 if cursor else 0, 0, 0,
                from_id=t.InputPeerSelf())
        else:
            request = f.messages.GetHistoryRequest(peer, cursor, None, 0, limit,
                task.get("newest_message_id", 0) + 1 if cursor else 0, 0, 0)
        return await self.ranged(task)(request)

    async def page(self, task, cursor):
        category = task["category"]
        if task.get("source") == "top_peers":
            # Rankings can reorder between requests or restarts: seal this small
            # metadata acquisition together instead of resuming at a stale rank.
            rows, offset = [], 0
            while True:
                result = await self.client(f.contacts.GetTopPeersRequest(offset, 100, 0,
                    correspondents=True, bots_inline=True, phone_calls=True))
                categories = getattr(result, "categories", [])
                rows.append(({"category": category, "type": "top_peers", "offset": offset, "data": safe(result)}, None))
                if not categories or all(offset + len(c.peers) >= c.count for c in categories):
                    break
                if not any(c.peers for c in categories):
                    raise ValueError("Telegram top-peer pagination made no progress.")
                offset += 100
            return rows, cursor, True
        if task.get("source") == "profile_music":
            # Freeze the positional list privately once; export only safe metadata.
            if "profile_music" not in self.secret:
                documents, offset = [], 0
                while True:
                    result = await self.client(f.users.GetSavedMusicRequest(t.InputUserSelf(), offset, 100, 0))
                    current = getattr(result, "documents", [])
                    documents.extend(current)
                    if len(current) < 100:
                        break
                    offset += len(current)
                self.secret["profile_music"] = [base64.b64encode(bytes(d)).decode() for d in documents]
                self.save()
            documents = []
            for encoded in self.secret["profile_music"][cursor:cursor + 10]:
                with BinaryReader(base64.b64decode(encoded, validate=True)) as reader:
                    documents.append(reader.tgread_object())
            return [({"category": category, "type": "profile_music", "id": d.id, "data": safe(d)}, d)
                    for d in documents], cursor + len(documents), len(documents) < 10
        if category == "messages":
            result = await self.history(task, cursor)
            entities = {utils.get_peer_id(e): e for e in [*result.users, *result.chats]}
            rows = sorted([m for m in result.messages if not isinstance(m, t.MessageEmpty)], key=lambda m: -m.id)
            next_cursor = min((m.id for m in rows), default=cursor)
            output = []
            for message in rows:
                record = safe(message)
                sender_id = getattr(message, "sender_id", None)
                if sender_id is None and getattr(message, "from_id", None):
                    sender_id = utils.get_peer_id(message.from_id)
                if sender_id is None and getattr(message, "out", False):
                    sender_id = self.account_id
                record.update(category=category, chat_id=task["chat_id"], id=message.id,
                              text=getattr(message, "message", ""), outgoing=bool(getattr(message, "out", False)),
                              from_id=sender_id, sender=safe(entities.get(sender_id)))
                output.append((record, attachments(getattr(message, "media", None))))
            return output, next_cursor, not rows
        if category == "profile":
            value = await self.client(f.users.GetFullUserRequest(t.InputUserSelf()))
            return [({"category": category, "data": safe(value)}, None)], cursor, True
        if category == "contacts":
            # This API returns one complete snapshot. Seal it together; positional
            # paging of a freshly fetched contact list after restart could skip people.
            value = await self.client(f.contacts.GetSavedRequest()) if self.options["transport"] == "takeout" else \
                await self.client(f.contacts.GetContactsRequest(0))
            rows = value if isinstance(value, list) else value.users
            return [({"category": category, "data": safe(row)}, None) for row in rows], cursor, True
        if category == "sessions":
            active = await self.client(f.account.GetAuthorizationsRequest())
            web = await self.client(f.account.GetWebAuthorizationsRequest())
            return [({"category": category, "type": kind, "data": safe(value)}, None)
                    for kind, values in (("telegram", active.authorizations), ("web", web.authorizations))
                    for value in values], cursor, True
        if category == "profile_photos":
            result = await self.client(f.photos.GetUserPhotosRequest(t.InputUserSelf(), 0, cursor, 100))
            rows = result.photos
            return [({"category": category, "id": p.id, "data": safe(p)}, p) for p in rows], \
                rows[-1].id if rows else cursor, not rows
        if category == "stories":
            result = await self.client(f.stories.GetStoriesArchiveRequest(t.InputPeerSelf(), cursor, 100))
            rows = result.stories
            return [({"category": category, "id": s.id, "data": safe(s)}, downloadable(getattr(s, "media", None)))
                    for s in rows], rows[-1].id if rows else cursor, not rows
        if category == "other_data":
            if self.options["transport"] != "takeout":
                raise ValueError("Additional personal data requires Takeout; regular API was selected.")
            return [({"category": category, "type": "additional_personal_data"}, t.InputTakeoutFileLocation())], cursor, True
        raise ValueError("Unknown export category")

    async def extra_media(self, row, task):
        if row["category"] != "messages" or "sticker" not in self.options["media_types"]:
            return []
        def ids(value):
            if isinstance(value, dict):
                if value.get("_") in ("MessageEntityCustomEmoji", "ReactionCustomEmoji"):
                    yield value["document_id"]
                for item in value.values():
                    yield from ids(item)
            elif isinstance(value, list):
                for item in value:
                    yield from ids(item)
        requested = sorted(set(ids(row.get("entities", []))) | set(ids(row.get("reactions", {}))))
        missing = [identity for identity in requested if identity not in self.emoji]
        for start in range(0, len(missing), 100):
            batch = missing[start:start + 100]
            try:
                found = await self.ranged(task)(f.messages.GetCustomEmojiDocumentsRequest(batch))
            except (errors.TakeoutInvalidError, errors.FloodWaitError, errors.ServerError):
                raise
            except errors.RPCError:
                found = []
            self.emoji.update({identity: None for identity in batch})
            self.emoji.update({doc.id: doc for doc in found if isinstance(doc, t.Document)})
        for identity in requested:
            if self.emoji.get(identity) is None:
                row.setdefault("attachments", []).append({"kind": "sticker", "media_id": identity,
                    "expected_bytes": None, "outcome": "failed", "reason": "custom_emoji_unavailable"})
        output = [self.emoji[identity] for identity in requested if self.emoji.get(identity) is not None]
        if len(self.emoji) > 1000:
            self.emoji.clear()
        return output

    async def download(self, media, stream, progress, task):
        client = self.ranged(task)
        if isinstance(media, t.InputTakeoutFileLocation):
            return await client.download_file(media, file=stream, progress_callback=progress)
        try:
            return await client.download_media(media, file=stream, progress_callback=progress)
        except (errors.FileReferenceExpiredError, errors.FilerefUpgradeNeededError):
            category, message_id = task["category"], task.get("message_id")
            if any(isinstance(a, t.DocumentAttributeCustomEmoji) for a in getattr(media, "attributes", [])):
                result = await client(f.messages.GetCustomEmojiDocumentsRequest([media.id]))
                refreshed = next((d for d in result if d.id == media.id), None)
            elif task.get("source") == "profile_music":
                refreshed, offset = None, 0
                while True:
                    result = await client(f.users.GetSavedMusicRequest(t.InputUserSelf(), offset, 100, 0))
                    documents = getattr(result, "documents", [])
                    refreshed = next((d for d in documents if d.id == media.id), None)
                    if refreshed is not None or len(documents) < 100:
                        break
                    offset += len(documents)
            elif category == "messages" and message_id:
                peer = self.peers[task["chat_id"]]
                request = f.channels.GetMessagesRequest(utils.get_input_channel(peer), [t.InputMessageID(message_id)]) \
                    if isinstance(peer, t.InputPeerChannel) else f.messages.GetMessagesRequest([t.InputMessageID(message_id)])
                result = await client(request)
                source = next((m for m in result.messages if m.id == message_id), None)
                refreshed = getattr(source, "media", None)
            elif category == "stories" and message_id:
                result = await client(f.stories.GetStoriesByIDRequest(t.InputPeerSelf(), [message_id]))
                source = next((s for s in result.stories if s.id == message_id), None)
                refreshed = getattr(source, "media", None)
            elif category == "profile_photos" and message_id:
                result = await client(f.photos.GetUserPhotosRequest(t.InputUserSelf(), 0, message_id + 1, 1))
                refreshed = next((p for p in result.photos if p.id == message_id), None)
            else:
                raise
            def identity(value):
                item = getattr(value, "document", None) or getattr(value, "photo", None) or value
                return type(item).__name__, getattr(item, "id", None), getattr(item, "size", None)
            if refreshed is None or identity(refreshed) != identity(media):
                raise ValueError("Attachment changed or became unavailable while refreshing its file reference.")
            stream.reset()
            return await client.download_media(refreshed, file=stream, progress_callback=progress)

    async def finish(self, success):
        if self.secret.get("takeout_id"):
            try:
                await self.client(f.account.FinishTakeoutSessionRequest(success=success))
            except errors.TakeoutInvalidError:
                pass  # An expired/already-finished server session has no remaining handle to retain.
            self.secret.pop("takeout_id", None)
            self.save()
