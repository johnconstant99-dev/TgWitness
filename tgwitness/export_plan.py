import asyncio
import math
import secrets
import time

from telethon import errors, functions, types, utils

from . import interactions, report
from .distributed_export import CHUNK, RECHECK_EDGE, RECHECK_PER_ACCOUNT
from .scope import kind_of, public_username

DEFAULT_RATES = {"regular": 90.0, "takeout": 290.0}
PREPARATION, PREPARATION_PER_ACCOUNT, SELECTION = 1.0, 5.0, 1.0
RECHECK_BATCH, FAST_BATCHES, FAST_BATCH_SECONDS, SLOW_BATCH_SECONDS = 100, 3, 0.6, 16.0
PACKAGING_BASE, PACKAGING_RATE, PDF_SECONDS = 2.0, 5000.0, 0.009
AUTO_ACCOUNTS = 10
PROBES = 3
REASONS = ("unavailable", "no_session", "signed_out", "rate_limited", "observing", "busy", "not_member")


class AccessDenied(Exception):
    pass


def measured_rates(exports, allowed):
    found = {}
    for job in exports.list_jobs():
        if any(not allowed(worker.get("profile_id"), job.get("chat_id")) for worker in job.get("workers", [])):
            continue
        performance = job.get("performance") or {}
        rate, readers = performance.get("messages_per_second"), sum(
            1 for worker in job.get("workers", []) if worker.get("state") == "done")
        if (job.get("phase") == "done" and type(rate) in (int, float) and math.isfinite(rate) and rate > 0
                and readers and (performance.get("new_messages") or 0) >= 1000):
            found.setdefault(job.get("transport", "regular"), []).append(rate / readers)
    return {kind: sorted(values)[len(values) // 2] for kind, values in found.items()}


def duration(visible, last_id, missing, accounts, rate, numbered, pdf_limit, chunked=True):
    chunks = max(1, -(-last_id // CHUNK)) if chunked else accounts
    read = -(-chunks // accounts) * (visible / chunks) / rate
    recheck = 0.0
    if numbered:
        numbers = min(missing, RECHECK_EDGE + RECHECK_PER_ACCOUNT * accounts)
        batches = -(-(-(-numbers // RECHECK_BATCH)) // accounts)
        recheck = min(batches, FAST_BATCHES) * FAST_BATCH_SECONDS + max(0, batches - FAST_BATCHES) * SLOW_BATCH_SECONDS
    packaging = PACKAGING_BASE + visible / PACKAGING_RATE + (visible * PDF_SECONDS if visible <= pdf_limit else 0)
    return round(PREPARATION + PREPARATION_PER_ACCOUNT * accounts + read + recheck + SELECTION + packaging)


def availability(entry, chat_id, private):
    app = entry.get("app")
    if app is None or entry.get("error_type"):
        return "unavailable", None
    c = app.state.collector
    if not app.state.vault.read("credentials").get("session"):
        return "no_session", None
    if c.store.get_setting("account_loss", None):
        return "signed_out", None
    until = c.store.get_setting("rpc_backoff_until", 0)
    if until > time.time():
        return "rate_limited", until
    if c.running or c.observation_starting:
        return "observing", None
    account_export = getattr(app.state, "account_export", None)
    if (c.export_claim or c.export_busy() or c.history.busy or c.connection_change_task is not None
            or account_export and account_export.busy()):
        return "busy", None
    if private and c.dialog_cache and chat_id not in c.dialog_cache:
        return "not_member", None
    return None, None


async def read_facts(c, target, allowed):
    if "invite" in target:
        try:
            invite = await c.client(functions.messages.CheckChatInviteRequest(target["invite"]))
        except (errors.InviteHashExpiredError, errors.InviteHashInvalidError, errors.InviteHashEmptyError):
            raise ValueError("This invite link is invalid or has expired.") from None
        if not isinstance(invite, types.ChatInviteAlready):
            return {"readable": False,
                    "reason": "This account is not a member of this private chat. Join it under Sources first; "
                              "joining is recorded in the journal."}
        entity = invite.chat
    else:
        try:
            entity = await c.client.get_entity(target["username"])
        except (ValueError, errors.UsernameInvalidError, errors.UsernameNotOccupiedError):
            raise ValueError("Telegram has no public chat or user with this username.") from None
    chat_id = utils.get_peer_id(entity)
    if not allowed(chat_id):
        raise AccessDenied("This access does not open the linked chat.")
    kind = kind_of(entity)
    if kind in ("private", "bot", None):
        return {"title": utils.get_display_name(entity), "kind": kind, "readable": False,
                "reason": "This link opens a person or a bot. To export a private chat, open it in Chats and use Export there."}
    latest = await c.client.get_messages(entity, limit=1)
    facts = await interactions.channel_facts(c, entity)
    facts.pop("about", None)
    last = latest[0].id if latest else 0
    visible = getattr(latest, "total", None)
    return {"chat_id": chat_id, "title": utils.get_display_name(entity), "kind": kind,
            "username": public_username(entity), "readable": True, "last_id": last,
            "visible": visible if type(visible) is int else None,
            "missing": max(0, last - visible) if type(visible) is int else None, **facts}


async def probe(entries, target, allowed):
    failures, denied, attempts = [], False, 0
    ordered = sorted(entries.items(), key=lambda item: not (item[1].get("app") and item[1]["app"].state.collector.running))
    for profile_id, entry in ordered:
        if attempts >= PROBES:
            break
        reason, _ = availability(entry, None, False)
        if reason not in (None, "observing"):
            continue
        c = entry["app"].state.collector
        owner = None
        if not c.running:
            owner = "plan:" + secrets.token_hex(16)
            if not c.reserve_export(owner):
                continue
        try:
            attempts += 1
            async with asyncio.timeout(45):
                await c.restore()
                return profile_id, await read_facts(c, target, lambda chat_id: allowed(profile_id, chat_id))
        except AccessDenied:
            denied = True
        except ValueError:
            raise
        except Exception as exc:
            failures.append(type(exc).__name__)
        finally:
            if owner:
                c.release_export(owner)
    if denied:
        raise AccessDenied("This access does not open the linked chat.")
    raise ValueError("No connected account could read this link" + (" (" + ", ".join(failures) + ")" if failures else "")
                     + ". Check the link and the accounts' connection.")


async def plan(registry, exports, link, allowed):
    target = interactions.parse_link(link)
    if target.get("start") is not None:
        raise ValueError("Use a chat link, not a bot start link.")
    entries = {pid: entry for pid, entry in registry.entries.items() if allowed(pid, None)}
    if not entries:
        raise ValueError("This access opens no account workspace.")
    reader, facts = await probe(entries, target, allowed)
    result = {"link": link.strip(), "reader": reader, **facts}
    if not facts["readable"]:
        return result
    chat_id, private = facts["chat_id"], "invite" in target or not facts.get("username")
    basic = facts["kind"] == "group"
    rows = []
    for profile_id, entry in entries.items():
        if not allowed(profile_id, chat_id):
            continue
        reason, until = availability(entry, chat_id, private)
        app = entry.get("app")
        account = app.state.collector.store.get_setting("account", None) if app else None
        check = app.state.collector.store.get_setting("connection_check", {}) if app else {}
        rows.append({"profile_id": profile_id, "label": entry.get("label", profile_id), "usable": reason is None,
                     "reason": reason, "until": until, "member": chat_id in app.state.collector.dialog_cache if app else None,
                     "username": (account or {}).get("username"), "account_id": (account or {}).get("id"),
                     "connected": bool((check or {}).get("telegram_connected"))})
    usable = sorted((row for row in rows if row["usable"]),
                    key=lambda row: (row["profile_id"] != reader, not row["member"], not row["connected"], row["label"]))
    measured = measured_rates(exports, allowed)
    rates = {**DEFAULT_RATES, **measured}
    takeout = facts["kind"] in ("channel", "supergroup") and bool(facts.get("username"))
    numbered = chat_id < -1000000000000
    visible = facts["visible"] if facts["visible"] is not None else facts["last_id"]
    largest = max(len(usable), AUTO_ACCOUNTS) if not basic else 1
    pdf_limit = report.resolved(entries[reader]["app"].state.collector.store)["part_size"]
    estimates = {transport: [duration(visible, facts["last_id"], facts["missing"] or 0, n, rate, numbered, pdf_limit,
                                      transport == "regular") for n in range(1, largest + 1)]
                 for transport, rate in rates.items() if transport == "regular" or takeout}
    fastest = min(range(1, min(len(usable), 1 if basic else AUTO_ACCOUNTS) + 1),
                  key=lambda n: estimates["regular"][n - 1], default=0)
    chosen = [row["profile_id"] for row in usable[:fastest]]
    for row in rows:
        row["chosen"] = row["profile_id"] in chosen
    rows.sort(key=lambda row: (not row["chosen"], not row["usable"], row["label"]))
    return {**result, "accounts": rows, "chosen": chosen, "single_account": basic, "takeout_available": takeout,
            "estimates": estimates, "rates": rates,
            "rate_sources": {kind: "measured" if kind in measured else "default" for kind in rates},
            "estimate_scope": "Planning only: visible messages divided by measured or default reading rates, "
                              "plus number recheck and packaging. Attachments and Telegram waits are not included."}
