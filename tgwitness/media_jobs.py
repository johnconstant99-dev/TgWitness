from contextlib import suppress
from dataclasses import dataclass
import hashlib
import json
import os
import shutil
from pathlib import Path

from . import ephemeral, file_hashes
from .journal_index import attachment_key
from .monitoring import duration_allowed, effective_media_rule, media_action, media_kind

REUSE_MEANING = ("Telegram serves a file under a fixed identifier. These bytes were saved earlier for the same file "
                 "identifier and size and were hashed again before reuse instead of being downloaded again.")
ATTACHMENTS = ".attachments.jsonl"
HEX = frozenset("0123456789abcdef")
KNOWN_DIRECTORIES = 4
known_files = {}


LANES = {
    "ephemeral": {"max_priority": 0},
    "urgent": {"min_priority": 1, "max_priority": 1},
    "bulk": {"min_priority": 2},
}
TRANSITIONS = {
    "queued": frozenset({"running"}),
    "retry": frozenset({"running"}),
    "running": frozenset({"ready", "retry", "failed"}),
    "ready": frozenset({"fetching", "hashing", "skipped", "retry", "failed"}),
    "fetching": frozenset({"hashed_bytes", "retry", "failed"}),
    "hashed_bytes": frozenset({"stored", "retry", "failed"}),
    "stored": frozenset({"done", "retry", "failed"}),
    "hashing": frozenset({"hashed", "retry", "failed"}),
    "done": frozenset(),
    "hashed": frozenset(),
    "failed": frozenset(),
    "skipped": frozenset(),
}


@dataclass(frozen=True)
class MediaOutcome:
    state: str
    payload: dict
    delay: float = 0


@dataclass(frozen=True)
class MediaPlan:
    action: str
    size: int | None
    outcome: MediaOutcome | None = None


class MediaAttempt:
    def __init__(self, store, job):
        self.store, self.job = store, job
        self.phase = job["state"]
        self.advance("running")

    def advance(self, phase):
        if phase not in TRANSITIONS[self.phase]:
            raise ValueError("Invalid media transition: " + self.phase + " -> " + phase)
        self.phase = phase

    def finish(self, outcome):
        if outcome.state not in TRANSITIONS[self.phase]:
            raise ValueError("Invalid media transition: " + self.phase + " -> " + outcome.state)
        self.store.finish_media(self.job, outcome.state, outcome.payload, delay=outcome.delay)
        self.phase = outcome.state


def lane_limits(lane):
    return dict(LANES.get(lane, {}))


def validate_observation(job, original):
    policy = original["payload"].get("media_capture", {})
    if (hashlib.sha256(job["descriptor"]).hexdigest() != policy.get("descriptor_sha256")
            or job["max_bytes"] != policy.get("max_bytes")
            or job["account_id"] != policy.get("account_id")
            or ("priority" in policy and job["priority"] != policy["priority"])
            or ("estimated_bytes" in policy and job["estimated_bytes"] != policy["estimated_bytes"])
            or job["chat_id"] != original["chat_id"] or job["message_id"] != original["message_id"]):
        raise ValueError("queue_descriptor_differs_from_signed_observation")
    return policy


def plan_media(job, policy, capture, message):
    ephemeral_media = ephemeral.describe(message.media)
    size = getattr(message.file, "size", None) if message.file else None
    kind = policy.get("media_type") or media_kind(message)
    rule = effective_media_rule(capture, kind, ephemeral_media)
    limit = rule["max_mb"] * 1024**2
    action = policy.get("action", "download")
    outcome = None
    if action == "exclude":
        outcome = MediaOutcome("skipped", {
            "reason": "above the size limit of the attachment settings"
            if size is not None and size > job["max_bytes"] else "excluded by the observed media policy"})
    else:
        current_action = media_action(capture, rule, size)
        if (not rule["enabled"] or not duration_allowed(message, rule) or current_action == "exclude"
                or (action == "download" and size is not None and limit < size <= job["max_bytes"])):
            outcome = MediaOutcome("skipped", {
                "reason": "above the size limit of the attachment settings" if rule["enabled"]
                else "attachment type not collected by policy: " + kind,
                "meaning": "the attachment settings changed after this file was queued"})
        elif action == "download" and current_action != "download":
            outcome = MediaOutcome("skipped", {"reason": "media action changed after this attachment was queued"})
    return MediaPlan(action, size, outcome)


def attachment(media):
    info = file_hashes.representation(media)
    return info, attachment_key(info)


def intact(path, digest, size):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size != size:
        return False
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest() == digest


def stored_copy(store, media_root, media, size):
    info, key = attachment(media)
    known = store.stored_media(key) if type(size) is int else None
    if known and known["bytes"] == size and intact(Path(media_root) / known["sha256"], known["sha256"], size):
        return info, known
    return info, None


def exported_files(directory):
    name = str(directory)
    if name not in known_files:
        found, path = {}, Path(directory) / ATTACHMENTS
        if path.is_file() and not path.is_symlink():
            with path.open(encoding="utf-8") as stream:
                for line in stream:
                    try:
                        item = json.loads(line)
                        key, digest, size = item["identity"], item["sha256"], item["bytes"]
                    except (ValueError, KeyError, TypeError):
                        continue
                    if isinstance(key, str) and isinstance(digest, str) and len(digest) == 64 and set(digest) <= HEX \
                            and type(size) is int:
                        found[key] = (digest, size)
        while len(known_files) >= KNOWN_DIRECTORIES:
            known_files.pop(next(iter(known_files)), None)
        known_files[name] = found
    return known_files[name]


def forget_files(directory):
    known_files.pop(str(directory), None)


def remember_file(directory, media, digest, size):
    key = attachment(media)[1]
    found = exported_files(directory)
    if key and found.get(key) != (digest, size):
        found[key] = (digest, size)
        with suppress(OSError), (Path(directory) / ATTACHMENTS).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"identity": key, "sha256": digest, "bytes": size}) + "\n")


def reuse_into(store, directory, media, size):
    key = attachment(media)[1]
    if key is None or type(size) is not int:
        return None
    directory = Path(directory)
    local = exported_files(directory).get(key)
    if local and local[1] == size and intact(directory / local[0], local[0], size):
        return {"sha256": local[0], "source": "this_export"}
    known = store.stored_media(key)
    if not known or known["bytes"] != size or not intact(store.root / "media" / known["sha256"], known["sha256"], size):
        return None
    source, target = store.root / "media" / known["sha256"], directory / known["sha256"]
    if not target.exists():
        temporary = directory / ("reuse-" + known["sha256"])
        try:
            temporary.unlink(missing_ok=True)
            try:
                os.link(source, temporary)
            except OSError:
                shutil.copyfile(source, temporary)
            temporary.replace(target)
        except OSError:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
            return None
    elif not intact(target, known["sha256"], size):
        return None
    remember_file(directory, media, known["sha256"], size)
    return {"sha256": known["sha256"], "source": {"media_event": known["seq"]}}


def failure_outcome(exc, attempts, maximum_attempts, maximum_delay):
    retry = isinstance(exc, (OSError, TimeoutError, ConnectionError)) and attempts < maximum_attempts
    delay = min(maximum_delay, 2 ** min(attempts, 20) * 5) if retry else 0
    return MediaOutcome("retry" if retry else "failed", {
        "error_type": type(exc).__name__,
        "reason": str(exc) if isinstance(exc, ValueError) else "download failed",
        "retry_after_seconds": delay}, delay)
