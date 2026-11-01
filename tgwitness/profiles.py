"""Isolated account collectors behind one authenticated panel."""
import asyncio
from contextlib import ExitStack
import re
import shutil
import uuid

from starlette.responses import JSONResponse

from . import health
from .account_import import session_key


# What a group shares, copied from its template workspace: setting keys in each workspace's store.
GROUP_SECTIONS = {
    "parameters": ("parameters",),
    "reports": ("report_options",),
    "capture": ("capture", "monitoring"),
    "recheck": ("recheck_minutes", "recheck_other_minutes"),
    "route": ("route_policy",),
}


class Profiles:

    MAX_PROFILES = None

    def __init__(self, app, root, factory):
        self.app, self.root, self.factory = app, root, factory
        label = app.state.store.get_setting("profile_label", "Main account")
        self.entries = {"default": {"id": "default", "label": label, "app": app, "cm": None}}
        self.opening = {}
        self.session_reservations = {}  # authorization keys reserved before a connection can start
        self.account_reservations = {}  # account IDs held through the durable ownership write
        self.lock = asyncio.Lock()
        app.state.collector.account_guard = self.check_account

    def holder(self, account_id=None, key=None, collector=None):
        """The workspace that already holds this Telegram account, by its ID once signed in or by the
        authorization key of its session, or None."""
        for entry in self.entries.values():
            other = entry["app"]
            if not other or other.state.collector is collector:
                continue
            account = other.state.store.get_setting("account", {}) or {}
            if account_id is not None and account.get("id") == account_id:
                return entry
            if key:
                try:
                    held = session_key(other.state.vault.read("credentials").get("session"))
                except Exception:
                    held = None
                if held == key:
                    return entry
        return None

    def check_account(self, account_id, collector, key=None):
        """Refuse an account another workspace holds. An imported session is checked by its key before it
        connects: the same key from a second address can make Telegram revoke it (AUTH_KEY_DUPLICATED)."""
        if self.holder(account_id, key, collector):
            raise ValueError("This Telegram account already belongs to another profile. Use its existing workspace.")
        if key:
            return self.reserve_session(key, collector)
        if account_id is not None:
            return self.reserve_account(account_id, collector)

    @staticmethod
    def _reserve(reservations, identity, owner):
        existing = reservations.get(identity)
        if existing is not None:
            if existing["owner"] is owner:
                return lambda: None  # an outer import already holds this lease
            raise ValueError("This Telegram account is being imported right now.")
        lease = {"owner": owner}
        reservations[identity] = lease

        def release():
            if reservations.get(identity) is lease:
                del reservations[identity]
        return release

    def reserve_session(self, key, owner):
        """Reserve a key synchronously before any await; return an identity-bound release callback."""
        if not key:
            raise ValueError("These files hold no login session. Add the .session or TData of the account.")
        if self.holder(key=key, collector=owner):
            raise ValueError("This Telegram account already belongs to another profile. Use its existing workspace.")
        return self._reserve(self.session_reservations, key, owner)

    def reserve_account(self, account_id, owner):
        if self.holder(account_id=account_id, collector=owner):
            raise ValueError("This Telegram account already belongs to another profile. Use its existing workspace.")
        return self._reserve(self.account_reservations, account_id, owner)

    def transfer_session(self, key, owner, collector, account_id=None):
        """Give a still-held import lease to its child without opening a reservation gap."""
        lease = self.session_reservations.get(key)
        if lease is None or lease["owner"] is not owner:
            raise ValueError("The account import no longer holds its session reservation.")
        account = self.account_reservations.get(account_id) if account_id is not None else None
        if account_id is not None and (account is None or account["owner"] is not owner):
            raise ValueError("The account import no longer holds its session reservation.")
        lease["owner"] = collector
        if account is not None:
            account["owner"] = collector

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


            self.entries[entry["id"]] = {**entry, "app": None, "cm": None, "error_type": "DeletionPending"}
            return
        child = self.factory(self.root / "profiles" / entry["id"],
                             token_override=self.app.state.vault.token, allow_profiles=False,
                             account_guard=self.check_account)
        cm = child.router.lifespan_context(child)
        self.opening[entry["id"]] = entry["label"]
        try:
            await cm.__aenter__()
        except Exception as exc:

            self.entries[entry["id"]] = {**entry, "app": None, "cm": None, "error_type": type(exc).__name__}
            self.app.state.store.append("profile.unavailable", {
                "profile_id": entry["id"], "error_type": type(exc).__name__})
            return
        finally:
            self.opening.pop(entry["id"], None)
        self.entries[entry["id"]] = {**entry, "app": child, "cm": cm}

    async def create(self, label, group=None):
        async with self.lock:
            if self.MAX_PROFILES is not None and len(self.entries) >= self.MAX_PROFILES:
                raise ValueError("This installation allows up to " + str(self.MAX_PROFILES) + " account workspaces.")
            if group is not None:
                self._group(group)
            entry = {"id": uuid.uuid4().hex, "label": label, **({"group": group} if group else {})}
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


            multi = getattr(self.app.state, "multi_export", None)
            if multi and multi.uses(profile_id):
                raise ValueError("This account is part of a running multi-account export. "
                                 "Cancel the export or wait for it to finish, then delete the account.")
            child = entry.get("app")
            if child and (child.state.collector.export_claim
                          or getattr(child.state, "operation_lock", None) and child.state.operation_lock.locked()
                          or getattr(child.state, "account_export", None) and child.state.account_export.busy()
                          or getattr(child.state, "disclosures", None) and child.state.disclosures.busy()):
                raise ValueError("Pause the account export and wait for current workspace operations and disclosure packaging before deleting this workspace.")


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
            if child:
                child.state.closing = True
            entry.update(app=None, error_type="DeletionPending")
            if cm is not None:

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

    # Groups: workspaces that share settings, copied from one of them on request ------------------

    def groups(self):
        return self.app.state.store.get_setting("profile_groups", [])

    def group_of(self, profile_id):
        if profile_id == "default":
            return self.app.state.store.get_setting("profile_group", None)
        return self.entries.get(profile_id, {}).get("group")

    def members(self, group_id):
        return [pid for pid in self.entries if self.group_of(pid) == group_id]

    def _group(self, group_id):
        group = next((g for g in self.groups() if g["id"] == group_id), None)
        if group is None:
            raise ValueError("Unknown account group.")
        return group

    async def save_group(self, group_id, label, template=None, sections=None):
        """Create (group_id None) or update a group; returns it."""
        async with self.lock:
            if not label.strip():
                raise ValueError("Enter a group label.")
            if sections is not None and set(sections) - set(GROUP_SECTIONS):
                raise ValueError("Unknown shared setting.")
            if template is not None and template not in self.entries:
                raise ValueError("Unknown account profile.")
            with self.app.state.store.transaction():
                groups = self.groups()
                if group_id is None:
                    group = {"id": uuid.uuid4().hex, "label": label, "template": template,
                             "sections": list(sections if sections is not None else ("parameters", "reports"))}
                    groups.append(group)
                    self.app.state.store.append("profile_group.created", {"group_id": group["id"]})
                else:
                    group = next((g for g in groups if g["id"] == group_id), None)
                    if group is None:
                        raise ValueError("Unknown account group.")
                    group.update(label=label, template=template)
                    if sections is not None:
                        group["sections"] = list(sections)
                    self.app.state.store.append("profile_group.changed", {"group_id": group_id})
                self.app.state.store.set_setting("profile_groups", groups)
            return group

    async def delete_group(self, group_id):
        async with self.lock:
            self._group(group_id)
            for profile_id in self.members(group_id):
                self._assign(profile_id, None)
            with self.app.state.store.transaction():
                self.app.state.store.set_setting("profile_groups", [g for g in self.groups() if g["id"] != group_id])
                self.app.state.store.append("profile_group.deleted", {"group_id": group_id})
            return {"id": group_id, "deleted": True}

    def _assign(self, profile_id, group_id):
        store = self.app.state.store
        if profile_id == "default":
            store.set_setting("profile_group", group_id)
            return
        items = store.get_setting("profiles", [])
        for item in items:
            if item["id"] == profile_id:
                item["group"] = group_id
        store.set_setting("profiles", items)
        self.entries[profile_id]["group"] = group_id

    async def assign(self, profile_id, group_id):
        async with self.lock:
            if profile_id not in self.entries:
                raise ValueError("Unknown account profile.")
            if group_id is not None:
                self._group(group_id)
            with self.app.state.store.transaction():
                self._assign(profile_id, group_id)
                self.app.state.store.append("profile_group.assigned", {"profile_id": profile_id, "group_id": group_id})
            return {"id": profile_id, "group": group_id}

    async def apply_group(self, group_id):
        """Copy the group's shared settings from its template to every other member; returns each result.

        Every member records what it received in its own journal. The IP mode goes through the
        member's collector, so a workspace that is observing keeps its route until it is paused."""
        from .network import RoutePolicy
        async with self.lock:
            group = self._group(group_id)
            template = self.entries.get(group.get("template") or "")
            if not template or template.get("app") is None:
                raise ValueError("Choose a running template workspace for this group.")
            source = template["app"].state.store
            settings = {key: source.get_setting(key, None)
                        for section in group.get("sections", []) for key in GROUP_SECTIONS[section]}
            results = []
            for profile_id in self.members(group_id):
                entry = self.entries[profile_id]
                if profile_id == template["id"]:
                    continue
                if entry.get("app") is None:
                    results.append({"id": profile_id, "label": entry["label"], "status": "unavailable"})
                    continue
                store, collector = entry["app"].state.store, entry["app"].state.collector
                applied, skipped = [], []
                for section in group.get("sections", []):
                    if section == "route":
                        if collector.running:
                            skipped.append(section)
                            continue
                        saved = settings["route_policy"]
                        try:
                            await collector.set_route_policy(RoutePolicy.model_validate(saved or {}), None, False)
                        except ValueError:
                            skipped.append(section)
                            continue
                        applied.append(section)
                        continue
                    with store.transaction():
                        for key in GROUP_SECTIONS[section]:
                            value = settings[key]
                            if value is None:
                                store.db.execute("DELETE FROM settings WHERE key=?", (key,))
                            else:
                                store.set_setting(key, value)
                    applied.append(section)
                store.append("group.settings_applied", {"group_id": group_id, "group": group["label"],
                                                        "from_workspace": template["label"], "sections": applied,
                                                        "settings": {key: settings[key] for section in applied
                                                                     for key in GROUP_SECTIONS[section]},
                                                        "skipped_while_observing": skipped})
                results.append({"id": profile_id, "label": entry["label"], "status": "applied" if applied else "skipped",
                                "applied": applied, "skipped": skipped})
            self.app.state.store.append("profile_group.applied", {"group_id": group_id, "members": len(results)})
            return {"group": group, "results": results}

    def summary(self):
        with ExitStack() as snapshots:
            result, pools = [], set()
            for profile in self.entries.values():
                app = profile["app"]
                pool = getattr(app.state.collector, "proxy_pool", None) if app else None
                if pool is not None and id(pool) not in pools:
                    snapshots.enter_context(pool.read_snapshot())
                    pools.add(id(pool))
                status = app.state.collector.status() if app else None
                sources = app.state.store.target_counts() if app else None
                result.append({
                    "id": profile["id"], "label": profile["label"], "group": self.group_of(profile["id"]),
                    "collector": status, "health": health.collector_of(app.state, status) if app else None,
                    "stats": app.state.store.stats() if app else None,
                    "sources_enabled": sources["enabled"] if sources else None,
                    "sources_total": sources["total"] if sources else None,
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
