from .store import canonical


def identity(export, representation, outcome):
    from .account_export import linked, sha
    current = getattr(export, "current", None)
    if not current or not representation:
        return None
    directory = export.directory(current["id"]) / "attachment-results"
    if linked(directory):
        raise ValueError("Attachment results must not be filesystem links.")
    directory.mkdir(mode=0o700, exist_ok=True)
    return directory / (sha(canonical({"representation": representation, "outcome": outcome})) + ".json")


def save(export, attachment):
    from .account_export import durable_write, sha
    path = identity(export, attachment.get("representation"), attachment["outcome"])
    if path is None:
        return
    statement = {"format": "tgwitness-account-attachment-v1", "public_key": export.vault.public_key,
        "job_id": export.current["id"], "account_id": export.current["account_id"],
        "options_sha256": sha(canonical(export.current["options"])), "attachment": attachment}
    durable_write(path, canonical(export.signed(statement)))
    if attachment.get("kind") == "sticker" and type(attachment.get("media_id")) is int:
        alias = path.parent / f"emoji-{attachment['media_id']}-{attachment['outcome']}.json"
        if alias.is_symlink():
            raise ValueError("Attachment results must not be filesystem links.")
        durable_write(alias, canonical(export.signed(statement)))


def read_emoji(export, media_id, outcome):
    from .account_export import read_json
    if type(media_id) is not int or outcome not in ("saved", "hashed"):
        return None
    path = export.directory(export.current["id"]) / "attachment-results" / f"emoji-{media_id}-{outcome}.json"
    if not path.exists():
        return None
    statement = export.verify_signed(read_json(path))
    item = statement["attachment"]
    if item.get("media_id") != media_id or item.get("kind") != "sticker" or item.get("outcome") != outcome:
        raise ValueError("Saved custom emoji belongs to a different attachment.")
    return read(export, item.get("representation"), outcome)


def read(export, representation, outcome):
    from .account_export import file_sha, linked, read_json, sha
    from .verify import validate_server_hashes
    path = identity(export, representation, outcome)
    if path is None or not path.exists():
        return None
    statement = export.verify_signed(read_json(path))
    attachment = statement["attachment"]
    if (statement.get("format") != "tgwitness-account-attachment-v1"
            or statement.get("job_id") != export.current["id"] or statement.get("account_id") != export.current["account_id"]
            or statement.get("options_sha256") != sha(canonical(export.current["options"]))
            or attachment.get("representation") != representation or attachment.get("outcome") != outcome):
        raise ValueError("Saved attachment belongs to a different acquisition.")
    if outcome == "saved":
        digest = attachment.get("sha256", "")
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest) or attachment.get("file") != "media/" + digest:
            raise ValueError("Invalid saved attachment path.")
        source = export.directory(export.current["id"]) / attachment["file"]
        if linked(source) or source.stat().st_size != attachment["bytes"] or file_sha(source) != digest:
            raise ValueError("Saved attachment changed after it was signed.")
    else:
        validate_server_hashes(attachment["server_hashes"])
        if attachment["server_hashes"]["status"] != "complete":
            raise ValueError("Incomplete saved hash acquisition.")
    return attachment
