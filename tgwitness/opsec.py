from pydantic import BaseModel, ConfigDict, StrictBool
from telethon import utils
from telethon.errors import RPCError
from telethon.tl import functions, types

PRIVACY = (
    ("last_seen", "InputPrivacyKeyStatusTimestamp", "Last seen and online", "nobody"),
    ("phone_number", "InputPrivacyKeyPhoneNumber", "Phone number", "nobody"),
    ("find_by_phone", "InputPrivacyKeyAddedByPhone", "Finding the account by its phone number", "contacts"),
    ("profile_photo", "InputPrivacyKeyProfilePhoto", "Profile photos", "contacts"),
    ("about", "InputPrivacyKeyAbout", "Bio", "contacts"),
    ("birthday", "InputPrivacyKeyBirthday", "Birthday", "nobody"),
    ("forwards", "InputPrivacyKeyForwards", "Link to the account in forwarded messages", "nobody"),
    ("calls", "InputPrivacyKeyPhoneCall", "Calls", "nobody"),
    ("peer_to_peer", "InputPrivacyKeyPhoneP2P", "Peer-to-peer calls, which can reveal the IP address", "nobody"),
    ("chat_invites", "InputPrivacyKeyChatInvite", "Adding the account to groups", "contacts"),
)
ORDER = {"nobody": 0, "contacts": 1, "everybody": 2}
ALLOWING = {"PrivacyValueAllowUsers", "PrivacyValueAllowChatParticipants", "PrivacyValueAllowCloseFriends",
            "PrivacyValueAllowPremium", "PrivacyValueAllowBots"}
MEANING = ("Read-only check by this workspace. Privacy rules and the profile are as Telegram returned them to the "
           "account itself; other clients, contacts and earlier screenshots can still reveal more.")


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hide_online_after_actions: StrictBool


def visibility(rules):
    names = {type(rule).__name__ for rule in rules or []}
    base = ("everybody" if "PrivacyValueAllowAll" in names else
            "contacts" if "PrivacyValueAllowContacts" in names else "nobody")
    return {"visible_to": base, "exceptions": bool(names & ALLOWING)}


def masked(phone):
    return "+" + "*" * max(len(phone) - 2, 0) + phone[-2:] if phone else None


def findings(privacy, profile):
    found = []
    for name, _, label, recommended in PRIVACY:
        state = privacy.get(name)
        if state and ORDER[state["visible_to"]] > ORDER[recommended]:
            found.append({"level": "risk", "item": name, "label": label, "visible_to": state["visible_to"],
                          "recommended": recommended})
        elif state and state["exceptions"]:
            found.append({"level": "notice", "item": name, "label": label, "visible_to": state["visible_to"],
                          "recommended": recommended, "exceptions": True})
    if profile.get("username"):
        found.append({"level": "notice", "item": "username", "label": "Public username",
                      "detail": "Anyone can find and mention the account by @" + profile["username"]})
    if profile.get("has_bio"):
        found.append({"level": "notice", "item": "bio", "label": "Bio text", "detail": "Shown to those allowed to see it"})
    if profile.get("premium"):
        found.append({"level": "notice", "item": "premium", "label": "Premium badge",
                      "detail": "Bots receive the Premium flag with every message"})
    return found


async def check(collector):
    await collector.restore()
    client = collector.client
    privacy, unavailable = {}, []
    for name, key, _, _ in PRIVACY:
        kind = getattr(types, key, None)
        if kind is None:
            unavailable.append(name)
            continue
        try:
            privacy[name] = visibility((await client(functions.account.GetPrivacyRequest(kind()))).rules)
        except RPCError:
            unavailable.append(name)
    me = await client.get_me()
    full = (await client(functions.users.GetFullUserRequest(types.InputUserSelf()))).full_user
    photo = getattr(me, "photo", None)
    profile = {"id": me.id, "username": me.username, "display_name": utils.get_display_name(me),
               "has_photo": photo is not None and not isinstance(photo, types.UserProfilePhotoEmpty),
               "has_bio": bool(getattr(full, "about", None)), "has_birthday": getattr(full, "birthday", None) is not None,
               "premium": bool(getattr(me, "premium", False)), "phone": masked(me.phone)}
    language = (getattr(client, "tgwitness_client_profile", None) or {}).get("lang_code")
    bot_view = {key: value for key, value in {
        "id": me.id, "first_name": me.first_name, "last_name": me.last_name, "username": me.username,
        "language_code": language, "is_premium": profile["premium"]}.items() if value not in (None, "")}
    result = {"privacy": privacy, "unavailable": unavailable, "profile": profile, "bot_view": bot_view,
              "findings": findings(privacy, profile), "meaning": MEANING}
    event = collector.store.append("account.opsec_checked", result, actor_id=me.id)
    return {**result, "event": {"seq": event["seq"], "hash": event["hash"], "observed_at": event["observed_at"]}}


def latest(store):
    found = store.events(kind="account.opsec_checked", limit=1)
    return ({**found[0]["payload"], "event": {key: found[0][key] for key in ("seq", "hash", "observed_at")}}
            if found else None)


def settings(store):
    return {"hide_online_after_actions": bool(store.get_setting("hide_online_after_actions", False))}


def save_settings(store, body):
    with store.transaction():
        store.set_setting("hide_online_after_actions", body.hide_online_after_actions)
        store.append("opsec.settings_changed", {
            "hide_online_after_actions": body.hide_online_after_actions,
            "meaning": "After a panel action the account asks Telegram to show it offline. The quick change from "
                       "online to offline can itself be noticed; hiding last seen in privacy settings is stronger."})
    return settings(store)


async def hide_presence(collector, request_event):
    if not collector.store.get_setting("hide_online_after_actions", False):
        return
    try:
        await collector.client(functions.account.UpdateStatusRequest(offline=True))
        collector.store.append("account.presence_hidden", {"request_event": request_event})
    except Exception as exc:
        collector.store.append("account.presence_hide_failed", {"request_event": request_event,
                                                               "error_type": type(exc).__name__})
