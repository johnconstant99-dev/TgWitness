"""Close an interrupted acquisition using its already signed observations."""
import json

from .store import canonical, utcnow


def finalize(export, job, reason):
    from .account_acquisition import StagedTransport
    from .account_attachment_cache import read as saved_attachment, read_emoji
    from .account_export import durable_write, read_json, sha

    directory = export.directory(job["job_id"])
    export.recover(job)
    if export.inventory is None:
        inventory = {"format": "tgwitness-account-export-inventory-v1", "public_key": export.vault.public_key,
            **{k: job[k] for k in ("job_id", "account_id", "options_sha256")}, "observed_at": utcnow(),
            "chats": [], "tasks": [], "discovery_complete": False, "gaps": [reason],
            "discovery_counts": {"chats_discovered": 0, "chats_excluded": 0}}
        durable_write(directory / "inventory.json", canonical(export.signed(inventory)))
        export.recover(job)

    staged = StagedTransport(None, export, job)
    staged.recover()
    for task in export.inventory["tasks"]:
        while True:
            previous = export.progress.get(task["id"])
            if previous and previous["terminal"]:
                break
            cursor = previous["cursor_after"] if previous else task["cursor_start"]
            reference = staged.reference(task, cursor)
            if reference is None:
                export.seal(job, task, cursor, cursor, True, [], 0, utcnow(), "failed", reason)
                break
            envelope = read_json(staged.path(reference["seq"]))
            if sha(canonical(envelope)) != reference["page_sha256"]:
                raise ValueError("Saved history changed while finishing the partial export.")
            page = export.verify_signed(envelope)
            indexes, after, terminal, seen = staged.slice(page, task, cursor)
            rows = [json.loads(json.dumps(page["rows"][i])) for i in indexes]
            deferred = page.get("deferred_media", [])
            if len(deferred) != len(page["rows"]):
                raise ValueError("Saved history has no complete attachment inventory.")
            for row, index in zip(rows, indexes):
                row.setdefault("attachments", [])
                for pending in deferred[index]:
                    item, action = pending["metadata"], pending["action"]
                    if item.get("outcome") == "excluded":
                        result = item
                    else:
                        result = saved_attachment(export, item.get("representation"), "hashed" if action == "hashes_only" else "saved")
                        if result is None and action == "download" and job["options"].get("budget_exhausted") == "hashes_only":
                            result = saved_attachment(export, item.get("representation"), "hashed")
                        result = result or {**item, "outcome": "failed", "reason": reason}
                    row["attachments"].append(result)
                if "sticker" in job["options"]["media_types"]:
                    def emoji_ids(value):
                        if isinstance(value, dict):
                            if value.get("_") in ("MessageEntityCustomEmoji", "ReactionCustomEmoji"):
                                yield value["document_id"]
                            for item in value.values():
                                yield from emoji_ids(item)
                        elif isinstance(value, list):
                            for item in value:
                                yield from emoji_ids(item)
                    for identity in sorted(set(emoji_ids([row.get("entities"), row.get("reactions")]))):
                        options = job["options"]
                        rule = options.get("media_rules", {}).get("sticker", {})
                        action = options.get("media_actions", {}).get("sticker", rule.get("action") or options["media_action"])
                        excluded = action == "exclude" or not rule.get("enabled", True)
                        result = None if excluded else read_emoji(export, identity, "hashed" if action == "hashes_only" else "saved")
                        if result is None and not excluded and options.get("budget_exhausted") == "hashes_only":
                            result = read_emoji(export, identity, "hashed")
                        row["attachments"].append(result or {"kind": "sticker", "media_id": identity,
                            "outcome": "excluded" if excluded else "failed", "reason": "media_policy" if excluded else reason,
                            "expected_bytes": None})
            export.seal(job, task, cursor, after, terminal, rows,
                        seen, page["captured_from"], page["outcome"], page.get("error"))

    export.recover(job)
    export.current.update(phase="packaging", current_chat=None, wait_until=None, wait_reason=None)
    export.persist()
    export.package(job)
    export.current.update(phase="done" if export.complete() else "partial", ready=True, error=None,
                          finish_reason=reason)
    export.persist()
    export.store.append("account_export.completed", {"job_id": job["job_id"], "receipt_head_sha256": export.head,
        "counts": export.counts, "complete_within_scope": export.complete(), "finish_reason": reason})
