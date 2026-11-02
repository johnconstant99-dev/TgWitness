import asyncio
import hashlib
import json
import re
import tempfile
import zipfile
from pathlib import Path

from fastapi import Depends, HTTPException, Request

from . import export_history
from .downloads import TemporaryDownload
from .store import canonical, utcnow
from .verify import fingerprint


def safe(label):
    return re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip("-.")[:40] or "account"


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def bundle(directory, group, parts, vault):
    handle, name = tempfile.mkstemp(prefix="tgwitness-group-", suffix=".zip", dir=directory)
    path = Path(name)
    try:
        with open(handle, "wb") as raw, zipfile.ZipFile(raw, "w", zipfile.ZIP_STORED) as archive:
            accounts = []
            for workspace_id, label, part, public_key in parts:
                inner = "accounts/" + safe(label) + "-" + workspace_id[:8] + ".zip"
                archive.write(part, inner)
                accounts.append({"workspace_id": workspace_id, "label": label, "file": inner, "sha256": digest(part),
                                 "bytes": part.stat().st_size, "signing_key_fingerprint": fingerprint(public_key)})
            statement = {"format": "tgwitness-group-export-v1", "group": {"id": group["id"], "label": group["label"]},
                         "created_at": utcnow(), "accounts": accounts}
            archive.writestr("manifest.json", json.dumps(statement, ensure_ascii=False, indent=2))
            archive.writestr("manifest.signature.json", json.dumps(
                {"signature": vault.sign(canonical(statement)), "public_key": vault.public_key,
                 "signing_key_fingerprint": fingerprint(vault.public_key)}))
        return path, accounts
    except BaseException:
        path.unlink(missing_ok=True)
        raise


async def export(app, request, group_id, language=None):
    registry, store = app.state.profiles, app.state.store
    try:
        group = registry._group(group_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    members = registry.members(group_id)
    if not members:
        raise HTTPException(409, "This group has no accounts to export.")
    if any(registry.entries[p].get("app") is None for p in members):
        raise HTTPException(409, "Every account of the group must be available to export it.")
    parts = []
    try:
        for workspace_id in members:
            entry = registry.entries[workspace_id]
            member = entry["app"]
            path, _ = await member.state.build_export("zip", request, language=language)
            parts.append((workspace_id, entry["label"], path, member.state.vault.public_key))
        directory = store.root / "temporary-exports"
        directory.mkdir(mode=0o700, exist_ok=True)
        path, accounts = await asyncio.to_thread(bundle, directory, group, parts, app.state.vault)
    finally:
        for part in parts:
            part[2].unlink(missing_ok=True)
    try:
        receipt = await asyncio.to_thread(export_history.prepared, store, path, "group", False)
        store.append("profile_group.exported", {
            "group_id": group["id"], "group": group["label"], "file_sha256": receipt["sha256"],
            "accounts": [{"workspace_id": a["workspace_id"], "sha256": a["sha256"]} for a in accounts]})
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return TemporaryDownload(path, filename="tgwitness-group-" + safe(group["label"]) + ".zip",
                             media_type="application/zip", headers=export_history.headers(receipt))


def register(app, authenticate):
    @app.get("/api/profile-groups/{group_id}/export", dependencies=[Depends(authenticate)])
    async def group_export(group_id: str, request: Request, language: str | None = None):
        return await export(app, request, group_id, language)
