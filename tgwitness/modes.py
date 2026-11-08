from dataclasses import asdict, dataclass
from typing import Literal

from .health import age, now_utc

Mode = Literal["easy", "signed", "witnessed", "court", "github", "mossad"]
SETTING = "mode"
PENDING = "mode_pending"
EXISTING = "witnessed"
MEANING = ("Only what the panel shows and suggests changed. Recording, signing and saved settings "
           "are the same in every mode; a hidden section keeps working.")


@dataclass(frozen=True)
class ModeInfo:
    id: str
    emoji: str
    name: str
    audience: str
    outcome: str
    effort: str


@dataclass(frozen=True)
class Feature:
    id: str
    mode: str
    name: str
    layers: tuple = ()


@dataclass(frozen=True)
class Layer:
    id: str
    mode: str
    name: str
    place: str | None


MODES = (
    ModeInfo("easy", "🟢", "Easy", "Anyone who wants to watch a chat and keep a copy.",
             "Chats, the journal and a chat export as JSON with its files. Signing runs in the background.",
             "A few minutes: connect an account and choose a chat."),
    ModeInfo("signed", "🟡", "Signed", "Reports to a platform, a hosting provider or an abuse desk.",
             "The signed archive, journal verification, checkpoints and the handover extract.",
             "Nothing more to set up."),
    ModeInfo("witnessed", "🟠", "Witnessed", "Cases where someone may later claim the record was changed.",
             "Everything in Signed, plus an independent witness that posts signed copies of the journal head "
             "to a Telegram channel.",
             "About 30 minutes: a bot, a channel and a second machine for the witness."),
    ModeInfo("court", "🔴", "Case preparation", "Prepare material for review by a lawyer, the police or a court.",
             "Shows timestamp, encrypted backup and case-detail settings. Enable and verify each service separately; "
             "this view does not establish admissibility.",
             "About an hour: timestamps work at once; the copy needs S3 storage."),
    ModeInfo("github", "🟣", "GitHub-verified", "Records whose software anyone must be able to check.",
             "Everything in Case preparation, plus a check of the running code against a public GitHub commit "
             "and the GitHub Actions capture.",
             "A public repository or fork; no token."),
    ModeInfo("mossad", "⚫", "Mossad", "High-stakes cases against a well-funded adversary.",
             "Every section, a sealed 24/7 server, a hidden IP address and the checklist of all 18 protection layers.",
             "A day or more: a cloud server, Cloudflare and proxies."),
)
IDS = tuple(mode.id for mode in MODES)
RANK = {mode.id: rank for rank, mode in enumerate(MODES, 1)}
NAMES = {mode.id: mode.name for mode in MODES}

FEATURES = (
    Feature("signed_exports", "signed", "Signed archive, JSONL journal and journal check"),
    Feature("verification", "signed", "Signing identity, checkpoints and the run receipt"),
    Feature("handover", "signed", "Handover extract with data minimisation"),
    Feature("witness", "witnessed", "Independent witness and its Telegram bot", ("witness_token",)),
    Feature("timestamps_backup", "court", "Automatic timestamps and an encrypted off-site copy", ("tsa", "ots", "replica")),
    Feature("code_check", "github", "Code check against a GitHub commit", ("code_check",)),
    Feature("github_capture", "github", "GitHub Actions capture"),
    Feature("cloud", "mossad", "Sealed 24/7 server", ("sealed_server",)),
)

LAYERS = (
    Layer("journal", "easy", "Every record signed and chained into the journal", None),
    Layer("run_receipt", "easy", "Signed run receipt with the program's hashes", None),
    Layer("media", "easy", "Attachments saved with their SHA-256", "sources:capture"),
    Layer("checkpoints", "signed", "Signed checkpoints of the journal head", None),
    Layer("recheck", "signed", "Rechecks for missed edits and deletions", "sources:recheck"),
    Layer("alerts", "witnessed", "Alerts when collection has a problem", "extras:alerts"),
    Layer("witness_token", "witnessed", "Read-only access for an independent witness", "extras:bot"),
    Layer("witness_checking", "witnessed", "A witness checks the journal on schedule", "extras:bot"),
    Layer("tsa", "court", "RFC 3161 timestamps", "wizard:timestamps"),
    Layer("ots", "court", "OpenTimestamps proofs anchored in Bitcoin", "wizard:timestamps"),
    Layer("timestamp_verified", "court", "Latest timestamp verified", "wizard:timestamps"),
    Layer("replica", "court", "Encrypted off-site copy", "extras:evidence"),
    Layer("case_details", "court", "Reports name the case and the examiner", "exports:settings"),
    Layer("code_check", "github", "Running code matches a public GitHub commit", "extras:github"),
    Layer("hidden_ip", "mossad", "Telegram never sees this machine's IP address", "connection"),
    Layer("outside_proxy", "mossad", "Timestamps, copies and alerts leave through a proxy", "connection"),
    Layer("object_lock", "mossad", "Off-site copy locked against deletion", "extras:evidence"),
    Layer("sealed_server", "mossad", "Sealed 24/7 server with provider records", "extras:cloud"),
)

NOT_YET = ("Threshold signing by several keys (FROST)", "Checkpoint mirror on GitLab",
           "Anchoring on Nostr relays", "Co-signers who countersign checkpoints")

UNKNOWN = "Choose one of the protection modes."
LOWER = "Confirm the lower mode: its hidden sections keep working and nothing is deleted."


class Downgrade(ValueError):
    pass


def texts():
    found = [text for mode in MODES for text in (mode.name, mode.audience, mode.outcome, mode.effort)]
    found += [feature.name for feature in FEATURES] + [layer.name for layer in LAYERS] + list(NOT_YET)
    return list(dict.fromkeys(found + [UNKNOWN, LOWER]))


def current(store):
    saved = store.get_setting(SETTING, None)
    return saved if saved in IDS else None


def recent(value, seconds, now):
    elapsed = age(value, now)
    return elapsed is not None and elapsed <= seconds


def measure(facts, now=None):
    now = now or now_utc()
    witness = facts["witness"]
    polled = [t for t in witness if t.get("last_poll")]
    checking = any(t["overdue"] is False or t["overdue"] is None and recent(t["last_poll"]["at"], 86400, now)
                   for t in polled)
    evidence, stamps = facts["evidence"], facts["timestamps"]
    tsa = evidence["enabled"] and bool(evidence["tsa_urls"])
    ots = evidence["enabled"] and bool(evidence["ots_calendars"])
    verified = tsa and stamps.get("last_verified_at") and stamps["state"] not in ("off", "failed", "unknown")
    replica, last = facts["replica"], facts["replica_last"] or {}
    locked = (last.get("object_lock") or {}).get("verified") is True
    report, alerts, source = facts["report"], facts["alerts"], facts["source_check"]
    checked = source.get("last") or {}
    recheck = facts["recheck"]

    def state(on, pending=False):
        return "on" if on else "pending" if pending else "off"

    return {
        "journal": "on",
        "run_receipt": "on",
        "media": state(facts["media"]),
        "checkpoints": state(facts["checkpoint"]),
        "recheck": state(recheck["recheck_minutes"] > 0 or recheck["recheck_other_minutes"] > 0),
        "alerts": state(alerts["enabled"] and alerts["problems"] and alerts["destinations"] > 0),
        "witness_token": state(bool(witness)),
        "witness_checking": state(checking, bool(witness) and not polled),
        "tsa": state(tsa),
        "ots": state(ots),
        "timestamp_verified": state(verified, tsa),
        "replica": state(replica["enabled"]),
        "case_details": state(bool((report.get("case_id") or report.get("case_title")) and report.get("examiner"))),
        "code_check": state(bool(checked) and source.get("current") and checked.get("matches") is True),
        "hidden_ip": state(facts["route"]["exposure"] == "hide" and facts["network"] != "direct"
                           and not facts["direct_fallback"]),
        "outside_proxy": state(facts["outside_route"] in ("socks5", "http")),
        "object_lock": state(replica["enabled"] and locked, replica["enabled"] and replica["retention_days"] > 0),
        "sealed_server": state(facts["assurance"]),
    }


def hidden_between(old, new):
    low = RANK[old] if old else len(MODES)
    return [f.id for f in FEATURES if RANK[new] < RANK[f.mode] <= low]


def shown_between(old, new):
    if old is None:
        return []
    return [f.id for f in FEATURES if RANK[old] < RANK[f.mode] <= RANK[new]]


def state(store, facts, now=None):
    measured = measure(facts, now)
    layers = [{**asdict(layer), "state": measured[layer.id]} for layer in LAYERS]
    features = [{"id": f.id, "mode": f.mode, "name": f.name,
                 "active": any(measured[layer] == "on" for layer in f.layers)} for f in FEATURES]
    mode = current(store)
    return {"mode": mode, "default": EXISTING, "modes": [{**asdict(m), "rank": RANK[m.id]} for m in MODES],
            "features": features, "layers": layers, "active": sum(layer["state"] == "on" for layer in layers),
            "total": len(LAYERS), "not_yet": list(NOT_YET)}


def change(store, new, by, confirm_downgrade=False, reason="chosen", active=None):
    if new not in IDS:
        raise ValueError(UNKNOWN)
    old = current(store)
    if old == new:
        return False
    if old is not None and RANK[new] < RANK[old] and not confirm_downgrade:
        raise Downgrade(LOWER)
    with store.transaction():
        store.set_setting(SETTING, new)
        store.db.execute("DELETE FROM settings WHERE key=?", (PENDING,))
        store.append("workspace.mode_changed", {
            "from": old, "to": new, "reason": reason, "shown": shown_between(old, new),
            "hidden": hidden_between(old, new), "active_layers": active, "total_layers": len(LAYERS),
            "by": by, "meaning": MEANING})
    return True


def migrate(store):
    if store.get_setting(SETTING, None) is not None or store.get_setting(PENDING, False) or store.get_setting("demo", False):
        return None
    if not store.stats()["total"]:
        store.set_setting(PENDING, True)
        return None
    with store.transaction():
        store.set_setting(SETTING, EXISTING)
        store.append("workspace.mode_changed", {
            "from": None, "to": EXISTING, "reason": "existing installation", "shown": [],
            "hidden": hidden_between(None, EXISTING), "active_layers": None, "total_layers": len(LAYERS),
            "by": None, "meaning": MEANING})
    return EXISTING
