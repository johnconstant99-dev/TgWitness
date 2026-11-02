import hashlib
import os
import secrets
import shutil
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from .replica import filesystem_link

LIMIT = 20
MAX_CACHE_BYTES = 2 * 1024**3
KEY = "prepared_exports"
CLEANUP_KEY = "prepared_exports_cleanup"


def prepared(store, path, fmt, encrypted, *, owner=None, workspace=None, required_permissions=None, chat_ids=None):
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
        size = os.fstat(source.fileno()).st_size
    folder = store.root / "prepared-exports"
    if filesystem_link(folder):
        raise ValueError("Prepared exports directory must not be a filesystem link.")
    folder.mkdir(exist_ok=True, mode=0o700)
    ident = secrets.token_hex(16)
    cached = folder / ident
    entry = {"id": ident, "format": fmt, "encrypted": bool(encrypted), "bytes": size, "sha256": digest,
             "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if owner is not None and workspace is not None and required_permissions:
        entry.update(owner=owner, workspace=workspace, required_permissions=sorted(set(required_permissions)),
                     chat_ids=sorted(set(chat_ids)) if chat_ids is not None else None)
    with store.transaction():
        previous = store.get_setting(KEY, [])
        remove = {item for item in store.get_setting(CLEANUP_KEY, []) if valid_id(item)}
        oversized = size > MAX_CACHE_BYTES
        keep, used = [entry], 0 if oversized else size
        for old in previous:
            old_size = 0 if old.get("cache_warning") else old["bytes"]
            if len(keep) < LIMIT and used + old_size <= MAX_CACHE_BYTES:
                keep.append(old)
                used += old_size
            elif valid_id(old.get("id", "")):
                remove.add(old["id"])
        retry = []
        for old_id in remove:
            stale = folder / old_id
            if stale.parent.resolve() == folder.resolve() and not filesystem_link(stale):
                try:
                    stale.unlink(missing_ok=True)
                except OSError:
                    retry.append(old_id)
        if oversized:
            entry["cache_warning"] = "This export exceeds the saved-copy cache limit. Download it now; prepare it again later."
        elif not retry:
            try:
                if os.name == "nt":
                    shutil.copy2(path, cached)
                else:
                    try:
                        os.link(path, cached)
                    except OSError:
                        shutil.copy2(path, cached)
            except OSError:
                try:
                    cached.unlink(missing_ok=True)
                except OSError:
                    retry.append(ident)
                entry["cache_warning"] = "A saved copy is unavailable. Download this export now; prepare it again later to retry."
        else:
            entry["cache_warning"] = "Saved-copy cleanup is pending. Download this export now; prepare it again later to retry."
        store.set_setting(CLEANUP_KEY, retry)
        store.set_setting(KEY, keep)
    return entry


def permitted(entry, principal, profile_id):
    if principal.admin:
        return True
    permissions = entry.get("required_permissions")
    if entry.get("format") == "group" or entry.get("owner") != principal.owner \
            or entry.get("workspace") != profile_id or not principal.opens(profile_id) \
            or not isinstance(permissions, list) or not permissions \
            or not all(isinstance(p, str) and principal.may(p) for p in permissions):
        return False
    allowed = principal.chats(profile_id)
    chats = entry.get("chat_ids")
    return allowed is None or isinstance(chats, list) and set(chats) <= allowed


def metadata(store, ident):
    if not valid_id(ident):
        return None
    return next((e for e in store.get_setting(KEY, []) if e.get("id") == ident), None)


def listing(store, *, principal=None, profile_id=None):
    folder = store.root / "prepared-exports"
    return {"exports": [{**e, "available": bool(not e.get("cache_warning") and valid_id(e.get("id", "")) and not filesystem_link(folder)
                          and not filesystem_link(folder / e["id"]) and (folder / e["id"]).is_file())}
                        for e in store.get_setting(KEY, [])[:LIMIT]
                        if principal is None or permitted(e, principal, profile_id)], "limit": LIMIT}


def headers(entry):
    return {"X-TgWitness-Export-SHA256": entry["sha256"], "X-TgWitness-Export-Created": entry["created_at"],
            "X-TgWitness-Export-ID": entry["id"]}


def valid_id(ident):
    return isinstance(ident, str) and len(ident) == 32 and all(c in "0123456789abcdef" for c in ident)


def locate(store, ident, verify=True):
    if not valid_id(ident):
        raise ValueError("This prepared export is unavailable.")
    entry = metadata(store, ident)
    if entry and entry.get("cache_warning"):
        raise ValueError("This export was not retained for another download. Prepare it again.")
    path = store.root / "prepared-exports" / ident
    if not entry or filesystem_link(path.parent) or filesystem_link(path) or not path.is_file() or path.resolve().parent != Path(store.root / "prepared-exports").resolve():
        raise ValueError("This prepared export has expired. Prepare it again.")
    if verify:
        try:
            with path.open("rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != entry["sha256"]:
                    raise ValueError("The saved export changed. Prepare a new export.")
        except OSError:
            raise ValueError("The prepared export could not be read. Prepare it again.") from None
    return path, entry


def download_copy(store, ident):
    source, entry = locate(store, ident, False)
    directory = store.root / "temporary-exports"
    if filesystem_link(directory) or directory.resolve().parent != store.root.resolve():
        raise ValueError("Temporary export directory must belong to this workspace.")
    directory.mkdir(mode=0o700, exist_ok=True)
    path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="tgwitness-export-download-", suffix=".zip",
                                         dir=directory, delete=False) as target:
            path = Path(target.name)
            digest, size = hashlib.sha256(), 0
            with source.open("rb") as incoming:
                while chunk := incoming.read(1024 * 1024):
                    size += len(chunk)
                    if size > entry["bytes"]:
                        raise ValueError("The saved export changed. Prepare a new export.")
                    digest.update(chunk)
                    target.write(chunk)
        if size != entry["bytes"] or digest.hexdigest() != entry["sha256"]:
            raise ValueError("The saved export changed. Prepare a new export.")
        return path, entry
    except BaseException as exc:
        if path is not None:
            path.unlink(missing_ok=True)
        if isinstance(exc, OSError):
            raise ValueError("The prepared export could not be read. Prepare it again.") from None
        raise
