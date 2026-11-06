import asyncio
import hashlib
import ipaddress
import json
import secrets
import time
from contextlib import AsyncExitStack, suppress
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from telethon.sessions import StringSession

from . import api_pool, netclient
from .network import NetworkConfig, RoutePolicy
from .portable_routes import PortableRoutes, target_platform, HASHES, wireguard_profile


class ConnectionDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["auto", "direct", "vpn", "proxy", "mtproxy", "warp"]
    scope: Literal["account", "group", "all"] = "account"
    account: str = Field(default="default", max_length=40)
    group: str | None = Field(default=None, max_length=40)
    keep_custom: bool = True
    proxy: NetworkConfig | None = None
    wireguard: str = Field(default="", max_length=16384)
    accept_setup: bool = False
    outside_enabled: bool = True
    allow_direct: bool = False
    proxy_url: str = Field(default="", max_length=2048)

    @model_validator(mode="after")
    def coherent(self):
        if self.proxy_url:
            from .network import parse_proxy_url
            if self.mode != "proxy" or self.proxy is not None:
                raise ValueError("Use one proxy address.")
            self.proxy = parse_proxy_url(self.proxy_url)
            self.proxy_url = ""
        if self.mode == "proxy" and (not self.proxy or self.proxy.kind not in ("socks5", "http", "mtproxy")):
            raise ValueError("Enter a SOCKS5, HTTP CONNECT or MTProxy route.")
        if self.mode != "proxy" and self.proxy is not None:
            raise ValueError("Proxy fields belong to the Proxy route.")
        if self.mode == "vpn" and not self.wireguard:
            raise ValueError("Paste a full-tunnel WireGuard profile.")
        if self.mode != "vpn" and self.wireguard:
            raise ValueError("WireGuard profiles belong to the VPN route.")
        if self.mode == "vpn" and self.scope != "account":
            raise ValueError("Import each account's own VPN profile separately; do not reuse one WireGuard key concurrently.")
        return self


class ApplyDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    plan: str = Field(min_length=32, max_length=64)


def revision(collector):
    data = [collector.network_config().model_dump(), collector.route_policy(), collector.vault.read("outside_proxy")]
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def busy_account(app):
    c = app.state.collector
    if c.export_busy() or c.export_claim or app.state.account_export.busy():
        raise ValueError("Pause the active export before changing its connection.")


async def probe(collector, route, mode, *, outside=True):
    started = time.monotonic()
    concrete, owner = route, None
    client = None
    try:
        if route.kind == "mtproxy_auto":
            owner = "connection-probe-" + secrets.token_hex(16)
            _, concrete = await collector.pool().acquire(owner, share=collector.share())
        if concrete.kind in ("socks5", "http", "mtproxy"):
            address = await netclient.proxy_address(concrete)
            concrete = concrete.model_copy(update={"host": address})
        api_id, api_hash = api_pool.login_order()[0]
        client = collector.client_factory(StringSession(), api_id, api_hash, receive_updates=False,
            connection_retries=0, request_retries=0, timeout=15, **concrete.client_options())
        await asyncio.wait_for(client.connect(), 20)
        latency = round((time.monotonic() - started) * 1000)
        result = {"telegram_connected": True, "latency_ms": latency, "checked_at": int(time.time()),
                  "exit_ip": None, "country": None, "warp": None}
        if not concrete.telegram_only and (outside or mode == "warp"):
            try:
                _, _, body = await asyncio.wait_for(netclient.request("GET", "https://www.cloudflare.com/cdn-cgi/trace",
                    concrete, timeout=15, limit=8192), 20)
                fields = dict(line.split("=", 1) for line in body.decode("ascii").splitlines() if "=" in line)
                result.update(exit_ip=str(ipaddress.ip_address(fields["ip"])),
                              country=fields.get("loc") if len(fields.get("loc", "")) == 2 else None,
                              warp=fields.get("warp") if fields.get("warp") in ("on", "plus", "off") else None)
            except (OSError, ValueError, TimeoutError, netclient.RouteError):
                result["exit_check_unavailable"] = True
            if mode == "warp" and result["warp"] not in ("on", "plus"):
                raise ValueError("WARP could not be confirmed through this route. Nothing was applied.")
        return result
    finally:
        try:
            if client:
                await asyncio.wait_for(client.disconnect(), 5)
        finally:
            if owner:
                collector.pool().release(owner)
                collector.pool().waiting.discard(owner)


class GuidedConnection:
    def __init__(self, app, profile_id):
        self.app, self.profile_id = app, profile_id
        self.portable = PortableRoutes(app.state.collector)
        self.task = self.maintenance = None
        self.plan, self.job = None, {"state": "idle"}
        self.retry_at, self.failures = 0, 0

    def entries(self):
        registry = getattr(self.app.state, "profiles", None)
        if registry:
            return registry.entries
        return {self.profile_id: {"id": self.profile_id, "label": "This account", "app": self.app}}

    def targets(self, body):
        entries = self.entries()
        if body.scope == "account":
            ids = [body.account]
        else:
            registry = getattr(self.app.state, "profiles", None)
            if not registry:
                raise ValueError("Open the main panel to apply a route to several accounts.")
            if body.scope == "group":
                if body.group not in {g["id"] for g in registry.groups()}:
                    raise ValueError("Choose an existing account group.")
                ids = registry.members(body.group)
            else:
                ids = list(entries)
        if not ids or any(i not in entries or entries[i].get("app") is None for i in ids):
            raise ValueError("One of the selected accounts is unavailable. Refresh the account list.")
        if len(ids) > 25:
            raise ValueError("Apply a connection to at most 25 accounts at a time using account groups.")
        return sorted(ids)

    def preview(self, body):
        rows = []
        for identifier in self.targets(body):
            entry = self.entries()[identifier]
            c = entry["app"].state.collector
            managed = entry["app"].state.connection.portable.selected()
            custom = c.network_config().kind != "mtproxy_auto"
            skip = body.scope != "account" and body.keep_custom and custom
            rows.append({"id": identifier, "label": entry["label"], "before": managed["mode"] if managed else c.network_config().kind,
                         "after": body.mode, "skipped": skip, "running": c.running})
        telegram_only = body.mode == "mtproxy" or body.proxy and body.proxy.telegram_only
        return {"rows": rows, "outside_enabled": body.outside_enabled and not telegram_only,
                "separate_instances": body.mode == "warp", "shared_proxy": body.mode == "proxy" and len(rows) > 1}

    def public(self):
        c = self.app.state.collector
        selected = self.portable.selected()
        registry = getattr(self.app.state, "profiles", None)
        process = self.portable.processes.get(selected["id"]) if selected else None
        check = c.store.get_setting("connection_check", None)
        if check:
            check = {**check, "current": check.get("revision") == revision(c)}
        return {"job": self.job, "current": {"mode": selected["mode"] if selected else c.network_config().kind,
                    "route": c.network_config().public(), "policy": c.policy_state(),
                    "managed": bool(selected), "process_running": process is not None and process.returncode is None,
                    "strategy": {k: v for k, v in c.store.get_setting("connection_strategy", {}).items() if k in ("mode", "allow_direct")},
                    "pool": c.pool().describe(c.route_owner)["pool"] if c.network_config().kind == "mtproxy_auto" else None,
                    "check": check},
                "supported": target_platform() in HASHES["wireproxy"],
                "accounts": [{"id": i, "label": e["label"]} for i, e in self.entries().items()],
                "groups": [{"id": g["id"], "label": g["label"]} for g in registry.groups()] if registry else []}

    def start_prepare(self, body):
        if self.job["state"] == "applying" or self.task and not self.task.done():
            raise ValueError("A connection operation is already running.")
        preview = self.preview(body)
        if not any(not row["skipped"] for row in preview["rows"]):
            raise ValueError("Every selected account keeps its own route. Change the selection or the keep-custom option.")
        self.job = {"state": "preparing", "stage": "Preparing connection", "rows": preview["rows"]}
        self.task = asyncio.create_task(self.prepare(body, preview))
        return self.job

    async def automatic_route(self, c, portable, body, progress):
        errors = []
        for mode in ("mtproxy", "warp", "direct"):
            if mode == "direct" and not body.allow_direct:
                continue
            managed = None
            try:
                progress("Checking " + mode)
                if mode == "warp":
                    managed = await portable.prepare("warp", "", body.accept_setup, progress)
                    route = NetworkConfig.model_validate(managed["network"])
                else:
                    route = NetworkConfig(kind="mtproxy_auto" if mode == "mtproxy" else "direct")
                result = await asyncio.wait_for(probe(c, route, mode, outside=body.outside_enabled), 45)
                if mode == "mtproxy" and body.outside_enabled and c.outside_proxy() is None:
                    # Timestamp/notification presets also need an external route.
                    errors.append("MTProxy works, but external services need WARP or a SOCKS5 proxy.")
                    continue
                return route, managed, result, mode
            except (OSError, ValueError, TimeoutError, netclient.RouteError) as exc:
                if managed and portable.selected() != managed:
                    await portable.stop(managed["id"])
                errors.append(str(exc) if isinstance(exc, ValueError) else type(exc).__name__)
        raise ValueError("No working connection. Try WARP or your own proxy. " + " · ".join(errors))

    async def discard(self):
        plan, self.plan = self.plan, None
        if plan:
            for item in plan["items"]:
                managed = item.get("managed")
                if managed and item["app"].state.connection.portable.selected() != managed:
                    await item["app"].state.connection.portable.stop(managed["id"])

    async def prepare(self, body, preview):
        items = []
        try:
            await self.discard()
            for row in preview["rows"]:
                if row["skipped"]:
                    continue
                app = self.entries()[row["id"]]["app"]
                busy_account(app)
                c, portable = app.state.collector, app.state.connection.portable
                item = {"id": row["id"], "app": app, "revision": revision(c), "managed": None}
                items.append(item)
                def progress(stage):
                    self.job.update(stage=stage, account=row["label"])
                progress("Preparing connection")
                auto_check = None
                actual_mode = body.mode
                if body.mode == "auto":
                    route, item["managed"], auto_check, actual_mode = await self.automatic_route(c, portable, body, progress)
                elif body.mode in ("warp", "vpn"):
                    if body.mode == "vpn":
                        key = wireguard_profile(body.wireguard)["interface"]["PrivateKey"]
                        for other_id, entry in self.entries().items():
                            other = entry.get("app")
                            selected = other.state.connection.portable.selected() if other else None
                            if (other_id != row["id"] and selected
                                    and wireguard_profile(selected["profile"])["interface"]["PrivateKey"] == key):
                                raise ValueError("Another account uses this WireGuard key. Give each account a separate VPN profile.")
                    item["managed"] = await portable.prepare(body.mode, body.wireguard, body.accept_setup, progress)
                    route = NetworkConfig.model_validate(item["managed"]["network"])
                elif body.mode == "proxy":
                    addresses = await netclient.resolve(body.proxy.host, body.proxy.port)
                    route = body.proxy.model_copy(update={"local_proxy": any(netclient.internal(a) for a in addresses)})
                else:
                    route = NetworkConfig(kind="direct" if body.mode == "direct" else "mtproxy_auto")
                item["route"] = route
                item["mode"] = actual_mode
                item["policy"] = RoutePolicy(exposure="tunnel" if route.kind == "direct" else "hide",
                                               outside_enabled=body.outside_enabled and (not route.telegram_only or c.outside_proxy() is not None))
                progress("Checking Telegram and the exit address")
                item["check"] = auto_check or await asyncio.wait_for(probe(c, route, body.mode, outside=body.outside_enabled), 45)
                row["check"] = item["check"]
            self.plan = {"token": secrets.token_hex(24), "expires": time.monotonic() + 600,
                         "body": body, "ids": self.targets(body), "items": items}
            self.job.update(state="ready", stage="Review and apply", plan=self.plan["token"], expires_in=600)
        except BaseException as exc:
            for item in items:
                portable, managed = item["app"].state.connection.portable, item.get("managed")
                if managed and portable.selected() != managed:
                    await portable.stop(managed["id"])
            self.job = {"state": "failed", "stage": "Connection was not changed",
                        "error": str(exc) if isinstance(exc, ValueError) else "Connection check failed: " + type(exc).__name__}
            if isinstance(exc, asyncio.CancelledError):
                raise

    def start_apply(self, token):
        if self.task and not self.task.done():
            raise ValueError("Wait for the connection check to finish.")
        if not self.plan or not secrets.compare_digest(token, self.plan["token"]):
            raise ValueError("This connection preview expired. Check the route again.")
        self.job = {"state": "applying", "stage": "Applying checked routes"}
        self.task = asyncio.create_task(self.apply_job(token))
        return self.job

    async def apply_job(self, token):
        try:
            await self.apply(token)
        except Exception as exc:
            self.job = {"state": "failed", "stage": "Application stopped",
                        "error": str(exc) if isinstance(exc, ValueError) else "Connection operation failed: " + type(exc).__name__}

    async def apply(self, token):
        plan = self.plan
        if not plan or not secrets.compare_digest(token, plan["token"]) or time.monotonic() > plan["expires"]:
            raise ValueError("This connection preview expired. Check the route again.")
        async with AsyncExitStack() as stack:
            registry = getattr(self.app.state, "profiles", None)
            if registry:
                await stack.enter_async_context(registry.lock)
            if self.targets(plan["body"]) != plan["ids"]:
                raise ValueError("The account selection changed. Check the route again.")
            for item in plan["items"]:
                await stack.enter_async_context(item["app"].state.operation_lock)
                busy_account(item["app"])
                if revision(item["app"].state.collector) != item["revision"]:
                    raise ValueError("A connection setting changed. Check the route again.")
            if self.plan is not plan or time.monotonic() > plan["expires"]:
                raise ValueError("This connection preview expired. Check the route again.")
            self.plan = None
            self.job = {"state": "applying", "stage": "Applying checked routes"}
            results = []
            try:
                for item in plan["items"]:
                    results.append(await self.apply_one(item, item.get("mode", plan["body"].mode)))
                    if results[-1]["applied"]:
                        item["app"].state.store.set_setting("connection_strategy", plan["body"].model_dump(exclude={"proxy", "proxy_url", "wireguard"}))
                        if plan["body"].allow_direct or plan["body"].mode == "direct":
                            item["app"].state.store.set_setting("ip_choice", "auto")
                if registry and plan["body"].scope == "group":
                    from .group_settings import record_route
                    record_route(registry, plan["body"].group, plan["body"].model_dump(),
                                 [r["id"] for r in results if r["applied"]])
                self.job = {"state": "applied", "rows": results, "stage": "Connection updated"}
            finally:
                for item in plan["items"]:
                    portable, managed = item["app"].state.connection.portable, item["managed"]
                    if managed and portable.selected() != managed:
                        await portable.stop(managed["id"])
            return self.job

    async def apply_one(self, item, mode):
        c, portable = item["app"].state.collector, item["app"].state.connection.portable
        old = {name: c.vault.read(name) for name in ("network", "outside_proxy", "portable_route")}
        policy, was_running = c.route_policy(), c.running
        try:
            check = await asyncio.wait_for(probe(c, item["route"], mode, outside=item["policy"].outside_enabled), 45)
            await c.stop()
            c.store.set_setting("route_policy", {"exposure": "tunnel", "outside_enabled": False})
            await c.set_network(item["route"])
            if not item["route"].telegram_only:
                c.vault.save("outside_proxy", {})
            c.vault.save("portable_route", item["managed"] or {})
            with c.store.transaction():
                c.store.set_setting("route_policy", item["policy"].model_dump())
                check["revision"] = revision(c)
                c.store.set_setting("connection_check", check)
                c.store.append("network.connection_applied", {"mode": mode, **item["route"].receipt(),
                    "policy": item["policy"].model_dump(), "check": check,
                    "meaning": "Transport checked; this does not authenticate message content."})
        except BaseException as exc:
            for name, value in old.items():
                c.vault.save(name, value)
            c.store.set_setting("route_policy", policy)
            c.store.append("network.connection_failed", {"error_type": type(exc).__name__, "previous_route_restored": True})
            # Resume only after restoring and checking the original route.
            if was_running and not c.running:
                with suppress(Exception):
                    await c.start()
            if isinstance(exc, asyncio.CancelledError):
                raise
            return {"id": item["id"], "applied": False, "running": c.running,
                    "error": "Connection was not applied. Previous settings were restored."}
        previous = old["portable_route"]
        if previous and (not item["managed"] or previous["id"] != item["managed"]["id"]):
            await portable.stop(previous["id"])
        error = None
        if was_running:
            try:
                await c.start()
            except Exception:
                error = "Route saved; observation could not resume. Review the account status and resume when ready."
        return {"id": item["id"], "applied": True, "running": c.running, "check": check, "error": error}

    async def check_current(self, always=True):
        c = self.app.state.collector
        await self.portable.restore()
        selected = self.portable.selected()
        previous = c.store.get_setting("connection_check", {}) or {}
        try:
            result = await asyncio.wait_for(probe(c, c.network_config(), selected["mode"] if selected else "proxy",
                outside=c.route_policy()["outside_enabled"]), 45)
        except Exception as exc:
            failed = {"telegram_connected": False, "checked_at": int(time.time()), "revision": revision(c),
                      "error_type": type(exc).__name__}
            with c.store.transaction():
                c.store.set_setting("connection_check", failed)
                if always or any(previous.get(key) != failed[key]
                                 for key in ("telegram_connected", "revision", "error_type")):
                    c.store.append("network.connection_checked", failed)
            raise
        result["revision"] = revision(c)
        changed = any(previous.get(key) != result.get(key)
                      for key in ("telegram_connected", "exit_ip", "country", "warp", "revision"))
        with c.store.transaction():
            c.store.set_setting("connection_check", result)
            if always or changed:
                c.store.append("network.connection_checked", result)
        return result

    async def control(self, action):
        c = self.app.state.collector
        busy_account(self.app)
        saved = self.portable.selected()
        if not saved:
            raise ValueError("This account does not use a managed tunnel.")
        if action == "stop":
            await c.stop()
            saved["paused"] = True
            c.vault.save("portable_route", saved)
            await self.portable.stop(saved["id"])
        else:
            saved.pop("paused", None)
            c.vault.save("portable_route", saved)
            await self.portable.restore()
        c.store.append("network.tunnel_control", {"action": action, "mode": saved["mode"]})
        return self.public()

    async def cancel(self):
        if self.job["state"] == "applying":
            raise ValueError("Wait for application to finish before changing the connection again.")
        if self.task and not self.task.done():
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        await self.discard()
        self.job = {"state": "idle", "stage": "Connection draft discarded"}
        return self.job

    async def maintain(self):
        health_at = 0
        while True:
            await asyncio.sleep(10)
            if self.plan and time.monotonic() > self.plan["expires"]:
                await self.discard()
                self.job = {"state": "expired", "stage": "Preview expired. Check the route again."}
            if time.monotonic() < self.retry_at:
                continue
            try:
                await self.portable.restore()
                self.failures = 0
            except Exception:
                self.failures += 1
                self.retry_at = time.monotonic() + min(300, 10 * 2 ** min(self.failures, 5))
            if time.monotonic() < health_at or self.task and not self.task.done() or self.plan:
                continue
            c = self.app.state.collector
            strategy = c.store.get_setting("connection_strategy", {})
            if not strategy:
                continue
            health_at = time.monotonic() + 60
            try:
                await self.check_current(always=False)
            except Exception:
                if strategy.get("mode") != "auto":
                    continue
                try:
                    busy_account(self.app)
                    body = ConnectionDraft(**{**strategy, "scope": "account", "account": self.profile_id,
                        "outside_enabled": c.route_policy()["outside_enabled"]})
                    self.task = asyncio.create_task(self.recover_automatic(body))
                except Exception:
                    health_at = time.monotonic() + 120

    async def recover_automatic(self, body):
        try:
            await self.prepare(body, self.preview(body))
            if self.plan:
                await self.apply(self.plan["token"])
        except Exception:
            self.job = {"state": "failed", "stage": "No connection", "error": "Automatic recovery failed. Check the connection in Settings."}

    async def close(self):
        for task in (self.task, self.maintenance):
            if task:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        await self.discard()
        await self.portable.close()
