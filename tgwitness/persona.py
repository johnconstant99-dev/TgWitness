import base64
import binascii
import hashlib
import io
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator
from telethon.errors import RPCError
from telethon.tl import functions, types

from .interactions import permitted
from .opsec import visibility
from .telegram_client import FLOOD_ERRORS

SETTINGS = (
    ("last_seen", "InputPrivacyKeyStatusTimestamp", "Last seen and online", "profile",
     "Who sees when the account was last online."),
    ("profile_photo", "InputPrivacyKeyProfilePhoto", "Profile photos", "profile", "Who sees the profile photos."),
    ("about", "InputPrivacyKeyAbout", "Bio", "profile", "Who sees the bio text."),
    ("birthday", "InputPrivacyKeyBirthday", "Birthday", "profile", "Who sees the date of birth."),
    ("phone_number", "InputPrivacyKeyPhoneNumber", "Phone number", "profile", "Who sees the phone number."),
    ("gifts", "InputPrivacyKeyStarGiftsAutoSave", "Gifts on the profile", "profile",
     "Whose gifts are shown on the profile automatically."),
    ("saved_music", "InputPrivacyKeySavedMusic", "Music on the profile", "profile", "Who sees the music saved to the profile."),
    ("find_by_phone", "InputPrivacyKeyAddedByPhone", "Finding by phone number", "contact",
     "Who can find the account by its phone number."),
    ("forwards", "InputPrivacyKeyForwards", "Link in forwarded messages", "contact",
     "Whose forwards of the account's messages link back to it."),
    ("calls", "InputPrivacyKeyPhoneCall", "Calls", "contact", "Who can call the account."),
    ("peer_to_peer", "InputPrivacyKeyPhoneP2P", "Peer-to-peer calls", "contact",
     "Who gets a direct connection in calls, which can reveal the IP address."),
    ("voice_messages", "InputPrivacyKeyVoiceMessages", "Voice and video messages", "contact",
     "Who can send voice and round video messages. Restricting it needs Telegram Premium."),
    ("chat_invites", "InputPrivacyKeyChatInvite", "Adding to groups and channels", "contact",
     "Who can add the account to groups and channels."),
)
GLOBAL = (
    ("hide_read_marks", "Hide my read time",
     "Others do not see when the account read their private messages; it also stops seeing theirs."),
    ("archive_and_mute_new_noncontact_peers", "Archive and mute new chats from unknown people",
     "New chats from people outside the contacts go to the archive without notifications."),
    ("keep_archived_unmuted", "Keep unmuted archived chats archived",
     "An archived chat with notifications on stays archived when a new message arrives."),
    ("keep_archived_folders", "Keep archived chats from folders archived",
     "An archived chat from a folder stays archived when a new message arrives."),
    ("new_noncontact_peers_require_premium", "Only contacts and Premium users can write",
     "New private messages from others are blocked. Needs Telegram Premium."),
)
RULES = {"everybody": "InputPrivacyValueAllowAll", "contacts": "InputPrivacyValueAllowContacts",
         "nobody": "InputPrivacyValueDisallowAll"}
BASE = {"PrivacyValueAllowAll", "PrivacyValueAllowContacts", "PrivacyValueDisallowAll"}
SPECIAL = {"PrivacyValueAllowCloseFriends": "close_friends", "PrivacyValueAllowPremium": "premium",
           "PrivacyValueAllowBots": "bots_allowed", "PrivacyValueDisallowBots": "bots_denied",
           "PrivacyValueDisallowContacts": "contacts_denied"}
KEYS = {name: key for name, key, *_ in SETTINGS}
GLOBAL_KEYS = {name for name, *_ in GLOBAL}
USERNAME = r"@?[A-Za-z][A-Za-z0-9_]{3,31}"
MAX_AVATAR = 5 * 1024 * 1024
AVATAR_FORMATS = {"JPEG": "image/jpeg", "PNG": "image/png"}


class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    first_name: str | None = Field(default=None, min_length=1, max_length=64)
    last_name: str | None = Field(default=None, max_length=64)
    about: str | None = Field(default=None, max_length=140)
    username: str | None = Field(default=None, max_length=32)

    @field_validator("username")
    @classmethod
    def valid_username(cls, value):
        if value and not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{4,31}", value):
            raise ValueError("Use 5–32 letters, digits or underscores, starting with a letter.")
        return value

    @model_validator(mode="after")
    def something(self):
        if not self.model_fields_set:
            raise ValueError("Change at least one field.")
        if "first_name" in self.model_fields_set and self.first_name is None:
            raise ValueError("The first name cannot be empty.")
        return self


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    visible_to: Literal["everybody", "contacts", "nobody"]
    allow_users: list[int | str] | None = Field(default=None, max_length=100)
    deny_users: list[int | str] | None = Field(default=None, max_length=100)

    @field_validator("allow_users", "deny_users")
    @classmethod
    def people(cls, value):
        if value is None:
            return None
        cleaned = []
        for item in value:
            if isinstance(item, str):
                if not re.fullmatch(USERNAME, item.strip()):
                    raise ValueError("Add people by @username or choose them from the list.")
                item = item.strip().lstrip("@").lower()
            elif item < 1:
                raise ValueError("Add people by @username or choose them from the list.")
            if item not in cleaned:
                cleaned.append(item)
        return cleaned

    @model_validator(mode="after")
    def apart(self):
        if set(self.allow_users or ()) & set(self.deny_users or ()):
            raise ValueError("The same person cannot be both always allowed and never allowed.")
        return self


class Privacy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rules: dict[str, Literal["everybody", "contacts", "nobody"] | Rule] = Field(min_length=1, max_length=len(KEYS))

    @field_validator("rules")
    @classmethod
    def known(cls, value):
        unknown = set(value) - set(KEYS)
        if unknown:
            raise ValueError("Unknown privacy settings: " + ", ".join(sorted(unknown)))
        return {name: rule if isinstance(rule, Rule) else Rule(visible_to=rule) for name, rule in value.items()}


class Global(BaseModel):
    model_config = ConfigDict(extra="forbid")
    settings: dict[str, StrictBool] = Field(min_length=1, max_length=len(GLOBAL))

    @field_validator("settings")
    @classmethod
    def known(cls, value):
        unknown = set(value) - GLOBAL_KEYS
        if unknown:
            raise ValueError("Unknown account settings: " + ", ".join(sorted(unknown)))
        return value


class Avatar(BaseModel):
    model_config = ConfigDict(extra="forbid")
    image_base64: str = Field(min_length=8, max_length=(MAX_AVATAR * 4) // 3 + 8)


async def current(client):
    me = await client.get_me()
    full = (await client(functions.users.GetFullUserRequest(types.InputUserSelf()))).full_user
    return me, {"first_name": me.first_name or "", "last_name": me.last_name or "",
                "about": getattr(full, "about", None) or "", "username": me.username or ""}


def person(user_id, users):
    user = users.get(user_id)
    name = " ".join(part for part in (getattr(user, "first_name", None), getattr(user, "last_name", None)) if part)
    return {"id": user_id, "name": name or getattr(user, "username", None) or str(user_id),
            "username": getattr(user, "username", None)}


def described(result):
    users = {user.id: user for user in getattr(result, "users", None) or []}
    chats = {chat.id: chat for chat in getattr(result, "chats", None) or []}
    found = {"allow_users": [], "deny_users": [], "allow_chats": [], "deny_chats": [], "special": []}
    for rule in result.rules or []:
        name = type(rule).__name__
        if name in ("PrivacyValueAllowUsers", "PrivacyValueDisallowUsers"):
            found["allow_users" if "Allow" in name else "deny_users"] += [person(i, users) for i in rule.users]
        elif name in ("PrivacyValueAllowChatParticipants", "PrivacyValueDisallowChatParticipants"):
            found["allow_chats" if "Allow" in name else "deny_chats"] += [
                {"id": i, "title": getattr(chats.get(i), "title", None) or str(i)} for i in rule.chats]
        elif name in SPECIAL:
            found["special"].append(SPECIAL[name])
    return found


def flags(settings):
    return {name: bool(getattr(settings, name, False)) for name, *_ in GLOBAL}


async def read(collector):
    await collector.restore()
    client = collector.client
    me, profile = await current(client)
    photo = getattr(me, "photo", None)
    privacy = {}
    for name, key, label, group, about in SETTINGS:
        kind = getattr(types, key, None)
        entry = {"label": label, "group": group, "description": about, "visible_to": None, "exceptions": False,
                 "available": kind is not None}
        if kind is not None:
            try:
                result = await client(functions.account.GetPrivacyRequest(kind()))
                entry.update(visibility(result.rules), **described(result))
            except FLOOD_ERRORS:
                raise
            except RPCError:
                entry["available"] = False
        privacy[name] = entry
    try:
        account = flags(await client(functions.account.GetGlobalPrivacySettingsRequest()))
    except FLOOD_ERRORS:
        raise
    except RPCError:
        account = None
    premium = bool(getattr(me, "premium", False))
    return {"id": me.id, "profile": profile, "premium": premium,
            "has_photo": photo is not None and not isinstance(photo, types.UserProfilePhotoEmpty),
            "about_limit": 140 if premium else 70, "privacy": privacy,
            "global": account and {name: {"label": label, "description": about, "enabled": account[name]}
                                   for name, label, about in GLOBAL}}


async def update_profile(collector, body):
    permitted(collector)
    await collector.restore()
    client = collector.client
    me, before = await current(client)
    wanted = {key: getattr(body, key) for key in body.model_fields_set}
    wanted = {key: value if value is not None else "" for key, value in wanted.items()}
    if any(key in wanted and wanted[key] != before[key] for key in ("first_name", "last_name", "about")):
        await client(functions.account.UpdateProfileRequest(
            first_name=wanted.get("first_name", before["first_name"]), last_name=wanted.get("last_name", before["last_name"]),
            about=wanted.get("about", before["about"])))
    if "username" in wanted and wanted["username"] != before["username"]:
        if wanted["username"] and not await client(functions.account.CheckUsernameRequest(wanted["username"])):
            raise ValueError("This username is taken or not allowed.")
        await client(functions.account.UpdateUsernameRequest(wanted["username"]))
    after = {**before, **wanted}
    changed = sorted(key for key in wanted if wanted[key] != before[key])
    event = collector.store.append("account.profile_updated", {"before": before, "after": after, "changed": changed},
                                   actor_id=me.id)
    return {"before": before, "after": after, "changed": changed, "event": event["seq"]}


def carried(result, replace_allow, replace_deny):
    users = {user.id: user for user in getattr(result, "users", None) or []}
    kept, lost = [], 0
    for rule in result.rules or []:
        name = type(rule).__name__
        kind = getattr(types, "Input" + name, None)
        if (name in BASE or name == "PrivacyValueAllowUsers" and replace_allow
                or name == "PrivacyValueDisallowUsers" and replace_deny):
            continue
        if kind is None:
            lost += 1
        elif hasattr(rule, "users"):
            found = [types.InputUser(user_id, users[user_id].access_hash) for user_id in rule.users
                     if getattr(users.get(user_id), "access_hash", None) is not None]
            lost += len(rule.users) - len(found)
            if found:
                kept.append(kind(users=found))
        elif hasattr(rule, "chats"):
            kept.append(kind(chats=list(rule.chats)))
        else:
            kept.append(kind())
    return kept, lost


async def resolve(client, item, users):
    if isinstance(item, int) and getattr(users.get(item), "access_hash", None) is not None:
        return types.InputUser(item, users[item].access_hash)
    try:
        peer = await client.get_input_entity(item)
    except FLOOD_ERRORS:
        raise
    except (ValueError, TypeError, RPCError):
        peer = None
    if isinstance(peer, types.InputPeerUser):
        return types.InputUser(peer.user_id, peer.access_hash)
    raise LookupError("@" + item if isinstance(item, str) else str(item))


def state_of(result):
    found = described(result)
    return {**visibility(result.rules), "allow_users": [p["id"] for p in found["allow_users"]],
            "deny_users": [p["id"] for p in found["deny_users"]]}


async def update_privacy(collector, body):
    permitted(collector)
    await collector.restore()
    client = collector.client
    before, applied, failed, kept = {}, {}, {}, {}
    for name, rule in body.rules.items():
        kind = getattr(types, KEYS[name], None)
        if kind is None:
            failed[name] = "unsupported"
            continue
        try:
            existing = await client(functions.account.GetPrivacyRequest(kind()))
            before[name] = state_of(existing)
            rules, lost = carried(existing, rule.allow_users is not None, rule.deny_users is not None)
            if lost:
                failed[name] = "exceptions_unavailable"
                continue
            known = {user.id: user for user in getattr(existing, "users", None) or []}
            chosen = {}
            try:
                for field, value in (("allow_users", "InputPrivacyValueAllowUsers"),
                                     ("deny_users", "InputPrivacyValueDisallowUsers")):
                    people = getattr(rule, field)
                    if people:
                        found = [await resolve(client, item, known) for item in people]
                        chosen[field] = [user.user_id for user in found]
                        rules.append(getattr(types, value)(users=found))
                    elif people is not None:
                        chosen[field] = []
            except LookupError as exc:
                failed[name] = "unknown_user:" + exc.args[0]
                continue
            await client(functions.account.SetPrivacyRequest(kind(), rules + [getattr(types, RULES[rule.visible_to])()]))
            applied[name] = {"visible_to": rule.visible_to,
                             "allow_users": chosen.get("allow_users", before[name]["allow_users"]),
                             "deny_users": chosen.get("deny_users", before[name]["deny_users"])}
            kept[name] = len(rules) - sum(1 for field in ("allow_users", "deny_users") if chosen.get(field))
        except FLOOD_ERRORS:
            raise
        except RPCError as exc:
            failed[name] = type(exc).__name__
    event = collector.store.append("account.privacy_updated", {"before": before, "applied": applied,
                                                               "exceptions_kept": kept, "failed": failed})
    return {"before": before, "applied": applied, "exceptions_kept": kept, "failed": failed, "event": event["seq"]}


async def update_global(collector, body):
    permitted(collector)
    await collector.restore()
    client = collector.client
    settings = await client(functions.account.GetGlobalPrivacySettingsRequest())
    before = flags(settings)
    for name, value in body.settings.items():
        setattr(settings, name, value)
    await client(functions.account.SetGlobalPrivacySettingsRequest(settings=settings))
    after = flags(settings)
    changed = sorted(name for name in body.settings if before[name] != after[name])
    event = collector.store.append("account.global_privacy_updated", {"before": before, "after": after,
                                                                      "changed": changed})
    return {"before": before, "after": after, "changed": changed, "event": event["seq"]}


def image(encoded):
    try:
        data = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("The image is not valid base64.") from None
    if len(data) > MAX_AVATAR:
        raise ValueError("The image is larger than 5 MB.")
    from PIL import Image
    try:
        with Image.open(io.BytesIO(data)) as picture:
            kind = picture.format
            width, height = picture.size
            picture.verify()
    except Exception:
        raise ValueError("Use a JPEG or PNG image.") from None
    if kind not in AVATAR_FORMATS or not (1 <= width <= 10000 and 1 <= height <= 10000):
        raise ValueError("Use a JPEG or PNG image.")
    return data, AVATAR_FORMATS[kind]


async def photo(collector):
    await collector.restore()
    data = await collector.client.download_profile_photo("me", file=bytes)
    if not data:
        return None
    if len(data) > MAX_AVATAR * 2:
        raise ValueError("The profile photo is too large to show.")
    return data, "image/png" if data[:8] == b"\x89PNG\r\n\x1a\n" else "image/jpeg"


async def set_avatar(collector, body):
    permitted(collector)
    data, mime = image(body.image_base64)
    await collector.restore()
    uploaded = await collector.client.upload_file(io.BytesIO(data),
                                                  file_name="avatar." + ("png" if mime == "image/png" else "jpg"))
    await collector.client(functions.photos.UploadProfilePhotoRequest(file=uploaded))
    digest = hashlib.sha256(data).hexdigest()
    event = collector.store.append("account.avatar_updated", {"sha256": digest, "size": len(data), "mime_type": mime})
    return {"sha256": digest, "event": event["seq"]}


async def remove_avatar(collector):
    permitted(collector)
    await collector.restore()
    found = await collector.client(functions.photos.GetUserPhotosRequest(
        user_id=types.InputUserSelf(), offset=0, max_id=0, limit=1))
    if not found.photos:
        raise ValueError("The account has no profile photo.")
    photo = found.photos[0]
    await collector.client(functions.photos.DeletePhotosRequest(
        id=[types.InputPhoto(id=photo.id, access_hash=photo.access_hash, file_reference=photo.file_reference)]))
    event = collector.store.append("account.avatar_removed", {"photo_id": photo.id})
    return {"removed": photo.id, "event": event["seq"]}
