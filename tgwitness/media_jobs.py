from dataclasses import dataclass
import hashlib

from . import ephemeral
from .monitoring import duration_allowed, effective_media_rule, media_action, media_kind


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


def failure_outcome(exc, attempts, maximum_attempts, maximum_delay):
    retry = isinstance(exc, (OSError, TimeoutError, ConnectionError)) and attempts < maximum_attempts
    delay = min(maximum_delay, 2 ** min(attempts, 20) * 5) if retry else 0
    return MediaOutcome("retry" if retry else "failed", {
        "error_type": type(exc).__name__,
        "reason": str(exc) if isinstance(exc, ValueError) else "download failed",
        "retry_after_seconds": delay}, delay)
