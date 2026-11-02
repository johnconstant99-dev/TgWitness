"""Case Board input contracts. JSON Schemas are generated from these models."""
from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

ID = Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
Hash = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Peer = Annotated[StrictInt, Field(ge=-(2**53 - 1), le=2**53 - 1)]
Labels = Annotated[list[Annotated[str, Field(min_length=1, max_length=80)]], Field(max_length=30)]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Target(Model):
    event_hash: Hash
    seq: Annotated[StrictInt, Field(ge=1)] | None = None
    chat_id: Peer | None = None
    message_id: Peer | None = None
    kind: str | None = Field(default=None, max_length=100)


class Card(Model):
    id: ID | None = None
    supersedes: Hash | None = None
    title: str = Field(default="", max_length=240)
    labels: Labels = Field(default_factory=list)
    note: str = Field(default="", max_length=20000)


class Bookmark(Card):
    target: Target


class HighlightRange(Model):
    field: Literal["text", "caption"] = "text"
    start: Annotated[StrictInt, Field(ge=0, le=10_000_000)]
    length: Annotated[StrictInt, Field(ge=1, le=20000)]
    quote: str = Field(min_length=1, max_length=20000)
    version: Hash | None = None


class Highlight(Bookmark):
    range: HighlightRange
    color: Literal["amber", "blue", "green", "rose"] = "amber"


class SliceQuery(Model):
    chat_id: Peer | None = None
    chat_ids: list[Peer] = Field(default_factory=list, max_length=1000)
    from_: str | None = Field(default=None, alias="from", max_length=64)
    to: str | None = Field(default=None, max_length=64)
    from_message_id: Annotated[StrictInt, Field(ge=1)] | None = None
    to_message_id: Annotated[StrictInt, Field(ge=1)] | None = None
    kinds: Literal["all"] | list[Annotated[str, Field(pattern=r"^(?:messages|membership|media|actions|coverage|[a-z][a-z0-9_]*(?:\.[a-z0-9_*]+)+)$", max_length=100)]] = "all"
    actors: list[Peer] = Field(default_factory=list, max_length=100)
    search: str = Field(default="", max_length=200)
    hide_system: bool = False
    # Unknown-chat deletions are separate context, never attributed to selected chats.
    include_unscoped: bool = False

    @field_validator("from_", "to")
    @classmethod
    def utc(cls, value):
        if value is None:
            return value
        when = datetime.fromisoformat(value)
        if when.tzinfo is None:
            raise ValueError("Use a timestamp with a timezone")
        return when.astimezone(timezone.utc).isoformat(timespec="milliseconds")

    @field_validator("kinds")
    @classmethod
    def expand_kinds(cls, value):
        if value == "all":
            return value
        from .store import JOURNAL_KIND_GROUPS
        return list(dict.fromkeys(match + "*" if match.endswith(".") else match for kind in value
                    for match in JOURNAL_KIND_GROUPS.get(kind, (kind,))))

    @model_validator(mode="after")
    def bounds(self):
        if (self.chat_id is None) == (not self.chat_ids):
            raise ValueError("Choose chat_id or a nonempty chat_ids list")
        if self.from_ and self.to and self.from_ > self.to:
            raise ValueError("Start must precede end")
        if self.from_message_id and self.to_message_id and self.from_message_id > self.to_message_id:
            raise ValueError("First message must precede last message")
        if (self.from_message_id or self.to_message_id) and len(self.chats()) != 1:
            raise ValueError("A message range belongs to one chat")
        if isinstance(self.kinds, list) and not 1 <= len(self.kinds) <= 40:
            raise ValueError("Choose 1–40 event kinds or all")
        self.chat_ids = sorted(set(self.chat_ids))
        self.actors = sorted(set(self.actors))
        return self

    def chats(self):
        return [self.chat_id] if self.chat_id is not None else self.chat_ids


class Slice(Card):
    query: SliceQuery


class Collection(Model):
    id: ID | None = None
    supersedes: Hash | None = None
    title: str = Field(min_length=1, max_length=240)
    description: str = Field(default="", max_length=20000)
    chat_ids: list[Peer] = Field(default_factory=list, max_length=1000)
    card_ids: list[ID] = Field(default_factory=list, max_length=10000)
    order: Annotated[StrictInt, Field(ge=0, le=10000)] = 0


class Comment(Model):
    id: ID | None = None
    supersedes: Hash | None = None
    parent_id: ID
    text: str = Field(min_length=1, max_length=20000)
    mentions: list[Annotated[str, Field(pattern=r"^(?:admin|[a-f0-9]{16})$")]] = Field(default_factory=list, max_length=50)


class Status(Model):
    id: ID | None = None
    card_id: ID
    state: Literal["open", "review", "confirmed", "dismissed"]
    reason: str = Field(default="", max_length=20000)


class Move(Model):
    id: ID | None = None
    card_id: ID
    collection_id: ID | None = None


class Remove(Model):
    id: ID | None = None
    card_id: ID


MODELS = {"bookmark": Bookmark, "highlight": Highlight, "slice": Slice, "collection": Collection,
          "comment": Comment, "status": Status, "move": Move, "remove": Remove}
