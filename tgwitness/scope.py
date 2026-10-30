"""What observation covers: chosen chats, one Telegram folder, or everything the account sees.

In folder and account modes the collector decides per chat from its type, the folder rules
and the exclusion list; a chat that first appears while observing (a new group, private chat
or bot) is added as a source on the spot and recorded in the journal.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool
from telethon import utils
from telethon.tl import types

# Source kinds as stored in targets.kind, and the type switch that covers each.
TYPE_OF = {"channel": "channels", "supergroup": "groups", "group": "groups", "private": "private", "bot": "bots"}
RECHECK_DEFAULTS = {"recheck_minutes": 15, "recheck_other_minutes": 360}
EXCLUDE_LIMIT = 5000  # chats the scope keeps out at most
WIDE_WARNING = ("Folder and whole-account modes record private chats and messages of third parties. "
                "Use them only on a dedicated account, for a lawful purpose, and keep the data protected.")


class SourceTypes(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channels: StrictBool = True
    groups: StrictBool = True
    private: StrictBool = True
    bots: StrictBool = True


class NewChats(BaseModel):
    """What is saved at once when a chat or bot first appears in folder or whole-account mode."""
    model_config = ConfigDict(extra="forbid")
    profile: StrictBool = False                       # bot description and commands, group/channel description
    history: int = Field(default=0, ge=0, le=1000)    # latest visible messages, 0 = none


class Scope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["selected", "folder", "account"] = "selected"
    folder_id: int | None = Field(default=None, ge=0, le=4096)
    types: SourceTypes = Field(default_factory=SourceTypes)
    exclude: list[int] = Field(default_factory=list, max_length=EXCLUDE_LIMIT)
    own_actions: StrictBool = True
    new_chats: NewChats = Field(default_factory=NewChats)


class ScopeUpdate(Scope):
    # Required when switching to folder or whole-account mode; recorded in the signed journal.
    acknowledged: StrictBool = False


class Recheck(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recheck_minutes: int = Field(default=15, ge=0, le=1440)          # priority sources; 0 turns them off
    recheck_other_minutes: int = Field(default=360, ge=0, le=10080)  # every other source


def scope_settings(store):
    return Scope.model_validate(store.get_setting("scope", {})).model_dump()


def unexclude(store, chat_id):
    """The operator chose this chat again: folder and account modes stop keeping it out."""
    scope = scope_settings(store)
    if chat_id not in scope["exclude"]:
        return False
    store.set_setting("scope", {**scope, "exclude": [c for c in scope["exclude"] if c != chat_id]})
    return True


def recheck_settings(store):
    return {key: store.get_setting(key, default) for key, default in RECHECK_DEFAULTS.items()}


def kind_of(entity):
    """targets.kind for a Telegram entity, or None."""
    if isinstance(entity, types.User):
        return "bot" if entity.bot else "private"
    if isinstance(entity, (types.Channel, types.ChannelForbidden)):
        return "supergroup" if getattr(entity, "megagroup", False) or getattr(entity, "gigagroup", False) else "channel"
    if isinstance(entity, (types.Chat, types.ChatForbidden, types.ChatEmpty)):
        return "group"
    return None


def allowed(scope, kind):
    return bool(kind) and scope["types"][TYPE_OF[kind]]


def peer_ids(peers, own_id=None):
    found = set()
    for peer in peers or []:
        if isinstance(peer, types.InputPeerSelf):
            if own_id is not None:
                found.add(own_id)
            continue
        try:
            found.add(utils.get_peer_id(peer))
        except (TypeError, ValueError):
            continue
    return found


def folder_rule(folder, own_id=None):
    """A plain description of a Telegram folder (DialogFilter) that membership checks use."""
    if folder is None or isinstance(folder, types.DialogFilterDefault):
        return {"all": True}
    title = getattr(folder, "title", "")
    rule = {"all": False, "id": folder.id, "title": getattr(title, "text", title) or "",
            "include": sorted(peer_ids(getattr(folder, "include_peers", []), own_id)
                              | peer_ids(getattr(folder, "pinned_peers", []), own_id)),
            "exclude": sorted(peer_ids(getattr(folder, "exclude_peers", []), own_id))}
    for flag in ("contacts", "non_contacts", "groups", "broadcasts", "bots", "exclude_archived"):
        rule[flag] = bool(getattr(folder, flag, False))
    return rule


def in_folder(rule, chat_id, kind, entity=None, archived=False):
    """Folder membership by its explicit chats and categories.

    Muted and read state (exclude_muted, exclude_read) change constantly and are not applied:
    a chat stays observed when it is read or muted.
    """
    if rule.get("all"):
        return True
    if chat_id in rule["exclude"]:
        return False
    if chat_id in rule["include"]:
        return True
    if rule["exclude_archived"] and archived:
        return False
    if kind == "bot":
        return rule["bots"]
    if kind == "private":
        return rule["contacts"] if getattr(entity, "contact", False) else rule["non_contacts"]
    if kind in ("group", "supergroup"):
        return rule["groups"]
    if kind == "channel":
        return rule["broadcasts"]
    return False
