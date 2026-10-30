"""Operating parameters: limits and pace of collection, rechecks, attachments, people profiles,
notifications, exports and the Telegram connection.

Every value here is changed in the panel (Parameters) without editing code. Values are kept per
workspace; only those that differ from the default are saved, and every change is recorded in
the signed journal (parameters.changed). Reading never fails: a saved value that no longer fits
its range falls back to the default.
"""
import re
from dataclasses import dataclass

MAX_LINES = 30
MAX_LINE_CHARS = 400


class Invalid(ValueError):
    def __init__(self, key, message):
        super().__init__(message)
        self.key = key


@dataclass(frozen=True)
class Parameter:
    key: str
    group: str
    default: object       # int, bool, or a tuple of text lines
    low: int | None = None
    high: int | None = None
    unit: str = ""
    label: str = ""
    help: str = ""

    @property
    def kind(self):
        return "bool" if isinstance(self.default, bool) else "lines" if isinstance(self.default, tuple) else "int"

    def initial(self):
        return list(self.default) if self.kind == "lines" else self.default


GROUPS = (
    ("collection", "Collection", "Chat list, liveness records and the start of observation."),
    ("recheck", "Recheck", "How rechecks spread their requests. How often each chat is rechecked is set under "
                           "Sources → Recheck."),
    ("attachments", "Photos & files", "Download pace and disk reserve. Types and sizes are set under Sources → "
                                      "Attachments."),
    ("people", "People profiles", "What profiles look for in saved messages."),
    ("notifications", "Notifications", "Size and pace of notifications and of the panel's notification list."),
    ("exports", "Exports & history", "Size limits of history snapshots, signed archives and browser downloads."),
    ("connection", "Telegram connection", "Timeouts and retries. Request timeouts and retries apply the next "
                                          "time the account connects."),
)

PARAMETERS = (
    Parameter("dialog_limit", "collection", 1000, 100, 20000, "chats", "Chats read from the account's list",
              "Sources, folder and whole-account modes read this many dialogs. Chats beyond it are added when "
              "they become active."),
    Parameter("scope_refresh_minutes", "collection", 60, 5, 1440, "minutes", "Re-read the chat list every",
              "Folder and whole-account modes: picks up folder changes and chats that appeared while offline."),
    Parameter("heartbeat_seconds", "collection", 60, 10, 600, "seconds", "Liveness record every",
              "Reports treat silence longer than three of these intervals, and at least three minutes, as a gap."),
    Parameter("checkpoint_minutes", "collection", 5, 1, 1440, "minutes", "Signed checkpoint every",
              "Local signed checkpoints while observing; one is also saved at start and on an orderly stop."),
    Parameter("startup_buffer", "collection", 10000, 1000, 200000, "updates", "Updates held while observation starts",
              "Beyond this number, updates that arrive while observation is starting are dropped and a coverage "
              "gap is recorded."),
    Parameter("keyboard_window", "collection", 500, 10, 20000, "records", "Records searched for a bot's keyboard",
              "To recognise this account's reply-keyboard button presses, the latest keyboard the bot sent is "
              "looked up among this many recent records of the chat."),
    Parameter("recheck_first_delay_seconds", "recheck", 30, 0, 3600, "seconds", "First recheck after a start",
              "After observation starts or reconnects, priority chats are rechecked after this delay; catch-up "
              "goes first."),
    Parameter("recheck_tick_seconds", "recheck", 60, 10, 3600, "seconds", "Look for due rechecks every"),
    Parameter("recheck_max_chats", "recheck", 30, 1, 1000, "chats", "Chats per recheck pass",
              "The rest wait for the next pass. Lower values spread requests out and keep the account clear "
              "of FloodWait."),
    Parameter("recheck_pause_seconds", "recheck", 2, 0, 60, "seconds", "Pause between chats",
              "Priority chats wait half as long."),
    Parameter("recheck_new_limit", "recheck", 1000, 0, 100000, "messages", "Missed messages recovered per chat and pass"),
    Parameter("recheck_batch", "recheck", 200, 10, 2000, "messages", "Saved messages asked for again per window",
              "The newest saved messages and a rolling window of older ones are requested again to find edits "
              "and messages Telegram no longer returns."),
    Parameter("media_min_free_mb", "attachments", 1024, 0, 1048576, "MiB", "Pause downloads below this free disk space",
              "Queued files stay queued and resume when space is freed. 0 never pauses."),
    Parameter("media_timeout_seconds", "attachments", 120, 10, 86400, "seconds", "Base download timeout"),
    Parameter("media_min_speed_kbps", "attachments", 256, 8, 1048576, "KiB/s", "Slowest expected download speed",
              "Large files get extra time at this speed on top of the base timeout."),
    Parameter("media_attempts", "attachments", 5, 0, 100, "attempts", "Retries after network errors"),
    Parameter("media_retry_max_seconds", "attachments", 300, 5, 86400, "seconds", "Longest wait between retries"),
    Parameter("dossier_max_refs", "people", 25, 1, 1000, "records", "Records cited per fact",
              "Counts stay complete; only the list of cited records is cut."),
    Parameter("dossier_similar_bits", "people", 10, 0, 32, "bits of 64", "Similar avatars: differing bits at most",
              "Avatars whose perceptual hashes differ in at most this many bits are listed as similar."),
    Parameter("dossier_wallets", "people", True, label="Find crypto wallet addresses"),
    Parameter("dossier_phones", "people", True, label="Find phone numbers"),
    Parameter("dossier_usernames", "people", True, label="Find @usernames and mentions by name"),
    Parameter("dossier_links", "people", True, label="Find links, including links hidden behind text"),
    Parameter("dossier_patterns", "people", (), unit="lines", label="Your own patterns",
              help="One per line: a name, a colon and a regular expression, for example "
                   "Domain: \\b[a-z0-9-]+\\.(top|xyz|shop)\\b. Matches are listed under Mentions with the pattern's name."),
    Parameter("alerts_check_seconds", "notifications", 60, 10, 3600, "seconds", "Look for new events every",
              "Changes in observed chats are grouped into one notification per check."),
    Parameter("alerts_max_lines", "notifications", 25, 1, 500, "lines", "Lines per notification"),
    Parameter("alerts_excerpt_chars", "notifications", 120, 20, 2000, "characters", "Length of message excerpts"),
    Parameter("panel_notifications", "notifications", 60, 10, 500, "items", "Items in the panel's notification list"),
    Parameter("snapshot_max", "exports", 500, 1, 10000, "messages", "Largest history snapshot"),
    Parameter("export_max_gib", "exports", 4, 1, 256, "GiB", "Largest signed ZIP, uncompressed",
              "Applies to evidence archives and full chat exports."),
    Parameter("browser_buffer_mib", "exports", 128, 16, 4096, "MiB", "Downloads kept in browser memory up to",
              "Browsers that cannot write a download straight to a file keep it in memory up to this size."),
    Parameter("operation_timeout_seconds", "connection", 120, 30, 7200, "seconds", "Panel action timeout",
              "How long a panel action that talks to Telegram may take, such as loading chats or a history snapshot."),
    Parameter("telegram_timeout_seconds", "connection", 15, 5, 300, "seconds", "Request timeout"),
    Parameter("telegram_request_retries", "connection", 2, 0, 20, "times", "Request retries"),
    Parameter("telegram_connection_retries", "connection", 5, 0, 100, "times", "Connection retries"),
    Parameter("reconnect_max_seconds", "connection", 300, 10, 3600, "seconds", "Longest wait between reconnect attempts"),
)
BY_KEY = {p.key: p for p in PARAMETERS}


def patterns(lines):
    """[(name, compiled)] from "name: regular expression" lines."""
    found = []
    for line in lines:
        name, sep, expression = line.partition(":")
        name, expression = name.strip(), expression.strip()
        if not sep or not name or not expression or len(name) > 40:
            raise ValueError("Each line needs a name, a colon and a regular expression.")
        try:
            found.append((name, re.compile(expression)))
        except re.error:
            raise ValueError("A pattern is not a valid regular expression.") from None
    return found


def validate(parameter, value):
    if parameter.kind == "bool":
        if not isinstance(value, bool):
            raise Invalid(parameter.key, "Choose on or off.")
        return value
    if parameter.kind == "lines":
        if not isinstance(value, list) or not all(isinstance(line, str) for line in value):
            raise Invalid(parameter.key, "Enter one value per line.")
        lines = [line.strip() for line in value if line.strip()]
        if len(lines) > MAX_LINES or any(len(line) > MAX_LINE_CHARS for line in lines):
            raise Invalid(parameter.key, "At most 30 lines of 400 characters.")
        if parameter.key == "dossier_patterns":
            try:
                patterns(lines)
            except ValueError as exc:
                raise Invalid(parameter.key, str(exc)) from None
        return lines
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or not parameter.low <= value <= parameter.high:
        raise Invalid(parameter.key, "Enter a whole number within the allowed range.")
    return value


def saved_values(store):
    saved = store.get_setting("parameters", {})
    return saved if isinstance(saved, dict) else {}


def value(store, key):
    parameter, saved = BY_KEY[key], saved_values(store)
    if key in saved:
        try:
            return validate(parameter, saved[key])
        except Invalid:
            pass
    return parameter.initial()


def values(store):
    return {key: value(store, key) for key in BY_KEY}


def changes(store, wanted):
    """Validate the requested values (None restores a default).

    Returns the overrides to save and the changed values before and after.
    """
    current, saved = values(store), dict(saved_values(store))
    before, after = {}, {}
    for key, raw in wanted.items():
        parameter = BY_KEY.get(key)
        if parameter is None:
            raise Invalid(key, "Unknown parameter.")
        new = parameter.initial() if raw is None else validate(parameter, raw)
        if new != current[key]:
            before[key], after[key] = current[key], new
        if new == parameter.initial():
            saved.pop(key, None)
        else:
            saved[key] = new
    return {k: v for k, v in saved.items() if k in BY_KEY}, before, after


def described(store):
    current = values(store)
    return {"groups": [{"id": group, "title": title, "description": description, "items": [
        {"key": p.key, "kind": p.kind, "default": p.initial(), "low": p.low, "high": p.high, "unit": p.unit,
         "label": p.label, "help": p.help, "value": current[p.key]}
        for p in PARAMETERS if p.group == group]} for group, title, description in GROUPS]}


def texts():
    """English texts of the Parameters page that the translations must cover."""
    found = [text for group in GROUPS for text in group[1:]]
    for p in PARAMETERS:
        found += [p.label, p.help, p.unit]
    return list(dict.fromkeys(text for text in found if text))
