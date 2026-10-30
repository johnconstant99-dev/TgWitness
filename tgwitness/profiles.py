"""Isolated account collectors behind one authenticated panel."""
import asyncio
import re
import shutil
import uuid

from starlette.responses import JSONResponse


class Profiles:
    # No fixed cap: the operator adds as many workspaces as their machine and accounts allow.
    MAX_PROFILES = None

    def __init__(self, app, root, factory):
        self.app, self.root, self.factory = app, root, factory
        label = app.state.store.get_setting("profile_label", "Main account")
        self.entries = {"default": {"id": "default", "label": label, "app": app, "cm": None}}
        self.lock = asyncio.Lock()
        app.state.collector.account_guard = self.check_account

    def check_account(self, account_id, collector):
        for entry in self.entries.values():
            other = entry["app"]
            if other and other.state.collector is not collector:
                account = other.state.store.get_setting("account", {}) or {}
                if account.get("id") == account_id:
                    raise ValueError("This Telegram account already belongs to another profile. Use its existing workspace.")

    async def open(self):
        try:
            for entry in self.app.state.store.get_setting("profiles", []):
                await self.open_entry(entry)
        except BaseException:
            await self.close()
            raise

    async def open_entry(self, entry):
        if not re.fullmatch(r"[a-f0-9]{32}", entry["id"]):
            raise ValueError("Invalid stored profile ID")
        if entry.get("deleting"):
            # Erasure may have removed only part of the vault before a failure or
            # process stop. Never restart collection or create replacement keys.
            self.entries[entry["id"]] = {**entry, "app": None, "cm": None, "error_type": "DeletionPending"}
            return
        child = self.factory(self.root / "profiles" / entry["id"],
                             token_override=self.app.state.vault.token, allow_profiles=False,
                             account_guard=self.check_account)
        cm = child.router.lifespan_context(child)
        try:
            await cm.__aenter__()
        except Exception as exc:
            # One damaged journal must not prevent access to healthy account profiles.
            self.entries[entry["id"]] = {**entry, "app": None, "cm": None, "error_type": type(exc).__name__}
            self.app.state.store.append("profile.unavailable", {
                "profile_id": entry["id"], "error_type": type(exc).__name__})
            return
        self.entries[entry["id"]] = {**entry, "app": child, "cm": cm}

    async def create(self, label):
        async with self.lock:
            if self.MAX_PROFILES is not None and len(self.entries) >= self.MAX_PROFILES:
                raise ValueError("This installation allows up to " + str(self.MAX_PROFILES) + " account workspaces.")
            entry = {"id": uuid.uuid4().hex, "label": label}
            await self.open_entry(entry)
            with self.app.state.store.transaction():
                items = self.app.state.store.get_setting("profiles", [])
                self.app.state.store.set_setting("profiles", [*items, entry])
                self.app.state.store.append("profile.created", entry)
            return entry

    async def rename(self, profile_id, label):
        async with self.lock:
            entry = self.entries.get(profile_id)
            if not entry:
                raise ValueError("Unknown account profile.")
            entry["label"] = label
            with self.app.state.store.transaction():
                if profile_id == "default":
                    self.app.state.store.set_setting("profile_label", label)
                else:
                    items = self.app.state.store.get_setting("profiles", [])
                    for item in items:
                        if item["id"] == profile_id:
                            item["label"] = label
                    self.app.state.store.set_setting("profiles", items)
                self.app.state.store.append("profile.renamed", {"profile_id": profile_id})
            return {"id": profile_id, "label": label}

    async def delete(self, profile_id):
        async with self.lock:
            if profile_id == "default":
                raise ValueError("The main account workspace cannot be deleted.")
            entry = self.entries.get(profile_id)
            if not entry:
                raise ValueError("Unknown account profile.")
            directory = self.root / "profiles" / profile_id
            if not re.fullmatch(r"[a-f0-9]{32}", profile_id) or directory.resolve() != directory:
                raise ValueError("Refusing to delete a workspace through a filesystem link. Inspect its data directory.")
            # A multi-account export run by the main app keeps using this workspace's store,
            # client and key until it ends; closing them underneath it would break both.
            # No await separates this check from detaching the app below.
            multi = getattr(self.app.state, "multi_export", None)
            if multi and multi.uses(profile_id):
                raise ValueError("This account is part of a running multi-account export. "
                                 "Cancel the export or wait for it to finish, then delete the account.")
            # Persist intent before closing or removing anything, so interrupted
            # deletion remains visible and retryable after a process restart.
            if not entry.get("deleting"):
                with self.app.state.store.transaction():
                    items = self.app.state.store.get_setting("profiles", [])
                    for item in items:
                        if item["id"] == profile_id:
                            item["deleting"] = True
                    self.app.state.store.set_setting("profiles", items)
                    self.app.state.store.append("profile.deletion_started", {"profile_id": profile_id})
                entry["deleting"] = True
            cm = entry.get("cm")
            entry.update(app=None, error_type="DeletionPending")
            if cm is not None:
                # The child app lifespan stops its collector and closes its store.
                await cm.__aexit__(None, None, None)
            entry.update(app=None, cm=None, error_type="DeletionPending")
            try:
                if directory.exists():
                    shutil.rmtree(directory)
            except OSError as exc:
                self.app.state.store.append("profile.deletion_failed", {
                    "profile_id": profile_id, "error_type": type(exc).__name__})
                raise ValueError("Could not delete all workspace files. Close programs using them and retry "
                                 "deleting this account. Its observation remains stopped.") from None
            with self.app.state.store.transaction():
                items = [e for e in self.app.state.store.get_setting("profiles", []) if e["id"] != profile_id]
                self.app.state.store.set_setting("profiles", items)
                self.app.state.store.append("profile.deleted", {"profile_id": profile_id})
            self.entries.pop(profile_id, None)
            return {"id": profile_id, "deleted": True}

    def summary(self):
        result = []
        for profile in self.entries.values():
            app = profile["app"]
            result.append({
                "id": profile["id"], "label": profile["label"],
                "collector": app.state.collector.status() if app else None,
                "stats": app.state.store.stats() if app else None,
                "sources_enabled": len(app.state.store.targets(True)) if app else None,
                "sources_total": len(app.state.store.targets()) if app else None,
                "error_type": profile.get("error_type"),
            })
        return result

    async def close(self):
        for profile_id, entry in list(self.entries.items()):
            if profile_id == "default":
                continue
            cm = entry.get("cm")
            if cm is not None:
                try:
                    await cm.__aexit__(None, None, None)
                except Exception:
                    pass


class ProfileDispatch:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return
        path = scope["path"]
        root = scope.get("root_path", "")
        relative = path[len(root):] if path.startswith(root) else path
        profile_id = relative.lstrip("/").split("/", 1)[0]
        registry = getattr(self.app.state, "profiles", None)
        entry = registry.entries.get(profile_id) if registry else None
        if not entry or profile_id == "default":
            await JSONResponse({"detail": "Unknown account profile"}, status_code=404)(scope, receive, send)
            return
        if entry["app"] is None:
            detail = ("Workspace deletion is incomplete. Retry Delete from Accounts." if entry.get("deleting") else
                      "This profile could not start. Preserve its data directory for inspection.")
            await JSONResponse({"detail": detail},
                               status_code=503)(scope, receive, send)
            return
        child_scope = {**scope, "root_path": root + "/" + profile_id}
        await entry["app"](child_scope, receive, send)
