"""Bounded, read-only resource assessment. Estimates are never guarantees."""
import asyncio
import shutil
import time

from telethon import errors, utils

from . import file_hashes
from .export_budget import history_sample
from .scope import kind_of

MAX_DIALOGS, MAX_CHATS, MESSAGES_PER_CHAT, TIMEOUT = 1000, 12, 25, 20
RESERVE = 256 * 1024**2


def assess(options, free_bytes):
    issues = []
    if free_bytes < RESERVE:
        issues.append({"code": "insufficient_free_disk", "severity": "error",
                       "message": "Less than 256 MiB is free for export working files and packaging."})
    if not options["chat_kinds"] and not any(options[k] for k in options if k.startswith("include_") and k != "include_archived"):
        issues.append({"code": "empty_selection", "severity": "error", "message": "No chats or account data are selected."})
    if options["transport"] == "regular" and options["include_other_data"]:
        issues.append({"code": "takeout_required", "severity": "warning",
                       "message": "Other available account data requires Takeout and will be missing with regular API."})
    if options["transport"] == "regular" and not options["chat_ids"]:
        issues.append({"code": "left_chats_unavailable", "severity": "warning",
                       "message": "Regular API cannot enumerate left channels and supergroups."})
    if options["transport"] == "takeout":
        issues.append({"code": "approval_not_checked", "severity": "information",
                       "message": "Telegram may require export approval. This preview does not start Takeout or determine its waiting period."})
    return {"settings_valid": True, "can_start": not any(i["severity"] == "error" for i in issues),
            "fit": "unknown", "free_disk_bytes": free_bytes, "working_reserve_bytes": RESERVE,
            "media_budget_bytes": options["max_total_gib"] * 1024**3,
            "issues": issues, "sample": {"performed": False},
            "total_output_bytes": None, "estimated_seconds": None,
            "explanation": "A bounded sample cannot guarantee final archive size or completion time. "
                           "Messages, hashes, reports, ZIP and temporary copies also need space."}


async def preview(exports, options, *, sample=True):
    from .account_export import AccountExportOptions, media_info
    from .account_export_transport import attachments
    options = AccountExportOptions.model_validate(options).model_dump()
    result = assess(options, shutil.disk_usage(exports.root).free)
    result["effective_options"] = options
    collector = exports.collector
    if not sample:
        return result
    reservation = "export-preflight-" + str(time.monotonic_ns())
    if not collector.reserve_export(reservation):
        result["issues"].append({"code": "account_busy", "severity": "warning",
                                 "message": "An export is already using this account; no sample was read."})
        return result
    observed = {"performed": False, "dialog_inventory_complete": False, "visible_selected_chats": 0,
                "sampled_chats": 0, "messages_examined": 0, "matching_messages": 0,
                "known_download_bytes": 0, "known_hash_source_bytes": 0,
                "hash_manifest_estimate_bytes": 0, "unknown_size_files": 0,
                "excluded_attachments": 0, "duplicate_references": 0,
                "message_file_payload_downloaded_bytes": 0,
                "account_metadata_and_avatars_estimated": False,
                "max_chats": MAX_CHATS, "max_messages_per_chat": MESSAGES_PER_CHAT,
                "estimate_assumption": "Hash JSON estimate uses 128 KiB ranges and 160 bytes per range; actual Telegram ranges may differ.",
                "chats": []}
    seen = set()

    async def read():
        await collector.restore()
        selected = []
        number = 0
        async for dialog in collector.client.iter_dialogs(limit=MAX_DIALOGS + 1, ignore_migrated=False):
            number += 1
            if number > MAX_DIALOGS:
                break
            cid, kind = utils.get_peer_id(dialog.entity), kind_of(dialog.entity) or "private"
            if (kind in options["chat_kinds"] and (not options["chat_ids"] or cid in options["chat_ids"])
                    and (options["include_archived"] or getattr(dialog, "folder_id", None) != 1)):
                selected.append(dialog)
        observed["dialog_inventory_complete"] = number <= MAX_DIALOGS
        observed["visible_selected_chats"] = len(selected)
        observed["selected_inventory_complete"] = not options["chat_ids"] or set(options["chat_ids"]) <= {
            utils.get_peer_id(dialog.entity) for dialog in selected}
        for dialog in selected[:MAX_CHATS]:
            requested = time.monotonic()
            messages = await collector.client.get_messages(dialog.entity, limit=MESSAGES_PER_CHAT)
            timing = history_sample(messages, time.monotonic() - requested)
            observed["chats"].append(timing)
            observed["sampled_chats"] += 1
            for message in messages:
                observed["messages_examined"] += 1
                timing["text_bytes"] += len((message.message or "").encode("utf-8"))
                row = {"category": "messages", "date": message.date.isoformat() if message.date else None,
                       "from_id": utils.get_peer_id(message.from_id) if message.from_id else None,
                       "text": message.message or "", "outgoing": bool(message.out)}
                if not exports.selected(row, options):
                    continue
                observed["matching_messages"] += 1
                for media in attachments(message.media):
                    info = media_info(media)
                    rule = options["media_rules"].get(info["kind"], {})
                    action = options["media_actions"].get(info["kind"], rule.get("action") or options["media_action"])
                    if info["kind"] not in options["media_types"] or not rule.get("enabled", True) or action == "exclude":
                        observed["excluded_attachments"] += 1
                        continue
                    if rule.get("max_seconds"):
                        item = getattr(media, "document", None) or media
                        duration = next((a.duration for a in getattr(item, "attributes", []) if hasattr(a, "duration")), None)
                        if duration is None or not 0 <= duration <= rule["max_seconds"]:
                            observed["excluded_attachments"] += 1
                            continue
                    rep = file_hashes.representation(media)
                    size = rep["bytes"] if rep else info["expected_bytes"]
                    limit = min(options["max_media_file_mib"], rule.get("max_mb", options["max_media_file_mib"])) * 1024**2
                    if action == "download" and size is not None and size > limit:
                        action = options["oversized_media"]
                    if size is None:
                        timing["unknown_size_files"] += 1
                    elif action == "download":
                        timing["download_bytes"] += size
                    elif action == "hashes_only":
                        timing["hash_ranges"] += (size + 131071) // 131072
                    identity = (rep["kind"], rep["id"], rep["variant"], rep["bytes"]) if rep else None
                    if identity and identity in seen:
                        observed["duplicate_references"] += 1
                        continue
                    if identity:
                        seen.add(identity)
                    if size is None:
                        observed["unknown_size_files"] += 1
                        continue
                    if action == "download":
                        observed["known_download_bytes"] += size
                    elif action == "hashes_only":
                        observed["known_hash_source_bytes"] += size
                        observed["hash_manifest_estimate_bytes"] += 512 + ((size + 131071) // 131072) * 160
                    else:
                        observed["excluded_attachments"] += 1
        observed["performed"] = True

    try:
        await asyncio.wait_for(read(), TIMEOUT)
    except (errors.RPCError, OSError, ConnectionError, TimeoutError, ValueError) as exc:
        result["issues"].append({"code": "sample_incomplete", "severity": "warning", "error_type": type(exc).__name__,
                                 "message": "The sample could not finish. Saved settings are valid; total size and duration remain unknown."})
    finally:
        collector.release_export(reservation)
    result["sample"] = observed
    required = observed["known_download_bytes"]
    if required > result["media_budget_bytes"]:
        result["fit"] = "sample_exceeds_media_budget"
        result["issues"].append({"code": "sample_exceeds_media_budget", "severity": "warning",
                                 "message": "Even sampled selected files exceed the media budget. Some files will be omitted."})
    elif required + RESERVE > result["free_disk_bytes"]:
        result["fit"] = "sample_exceeds_free_disk"
        result["issues"].append({"code": "sample_exceeds_free_disk", "severity": "warning",
                                 "message": "Even sampled files need more disk than is currently free."})
    return result


async def preview_capture(collector, chat_id, settings, remaining_seconds):
    """Preview the actual sealed collector policy; no downloads or setting writes."""
    from .monitoring import media_action, media_kind, duration_allowed, effective_media_rule
    from . import ephemeral
    free = shutil.disk_usage(collector.store.root).free
    reserve = collector.param("media_min_free_mb") * 1024**2
    result = {"settings_valid": True, "can_start": free >= reserve and remaining_seconds > 0,
              "fit": "unknown", "free_disk_bytes": free, "working_reserve_bytes": reserve,
              "remaining_seconds": remaining_seconds, "total_output_bytes": None, "estimated_seconds": None,
              "uncompressed_archive_limit_bytes": collector.param("export_max_gib") * 1024**3,
              "browser_decryption_limit_bytes": 256 * 1024**2,
              "effective_options": settings, "issues": [],
              "explanation": "This is a sample, not a total. Messages, reports and temporary archives also need space. "
                  "The deadline includes login and preparation. A time limit preserves partial captured history; "
                  "the uncompressed archive limit can prevent packaging. Large deliveries require the CLI decryptor."}
    if not result["can_start"]:
        result["issues"].append({"severity": "error", "code": "insufficient_disk_or_time",
                                 "message": "Insufficient free disk or no capture time remains."})
    sample = {"performed": False, "messages_examined": 0, "known_download_bytes": 0,
              "known_hash_source_bytes": 0, "hash_manifest_estimate_bytes": 0, "unknown_size_files": 0,
              "excluded_attachments": 0, "duplicate_references": 0, "message_file_payload_downloaded_bytes": 0,
              "account_metadata_and_avatars_estimated": False, "max_messages": MESSAGES_PER_CHAT, "chats": []}
    seen = set()
    try:
        async with asyncio.timeout(min(TIMEOUT, max(1, remaining_seconds))):
            entity = await collector.resolve_target(chat_id)
            requested = time.monotonic()
            rows = await collector.client.get_messages(entity, limit=MESSAGES_PER_CHAT)
        timing = history_sample(rows, time.monotonic() - requested)
        sample["chats"].append(timing)
        for message in rows:
            sample["messages_examined"] += 1
            timing["text_bytes"] += len((getattr(message, "message", None) or "").encode("utf-8"))
            if not getattr(message, "file", None):
                continue
            rule = effective_media_rule(settings, media_kind(message), ephemeral.describe(message.media))
            size = getattr(message.file, "size", None)
            action = media_action(settings, rule, size) if duration_allowed(message, rule) else "exclude"
            if action == "exclude":
                sample["excluded_attachments"] += 1
                continue
            if size is None:
                timing["unknown_size_files"] += 1
            elif action == "download":
                timing["download_bytes"] += size
            else:
                timing["hash_ranges"] += (size + 131071) // 131072
            rep = file_hashes.representation(message.media)
            identity = (rep["kind"], rep["id"], rep["variant"], rep["bytes"]) if rep else None
            if identity and identity in seen:
                sample["duplicate_references"] += 1
                if action == "hashes_only":
                    continue
            if identity:
                seen.add(identity)
            if size is None:
                sample["unknown_size_files"] += 1
            elif action == "download":
                sample["known_download_bytes"] += size
            else:
                sample["known_hash_source_bytes"] += size
                sample["hash_manifest_estimate_bytes"] += 512 + ((size + 131071) // 131072) * 160
        sample["performed"] = True
    except (errors.RPCError, OSError, TimeoutError, ValueError) as exc:
        result["issues"].append({"severity": "warning", "code": "sample_incomplete", "error_type": type(exc).__name__,
                                 "message": "The sample did not finish; total size and time remain unknown."})
    result["sample"] = sample
    required = sample["known_download_bytes"]
    if required + reserve > free:
        result["fit"] = "sample_exceeds_free_disk"
        result["issues"].append({"severity": "warning", "code": result["fit"],
                                 "message": "Even sampled downloads exceed free disk. Select hashes or fewer file types."})
    if required > result["browser_decryption_limit_bytes"]:
        result["issues"].append({"severity": "warning", "code": "browser_delivery_size_risk",
                                 "message": "Sampled downloads already exceed the browser decryptor's limit before ZIP compression."})
    return result
