from .. import __version__
from .. import alerts
from .. import assurance
from .. import interactions
from .. import modes
from .. import pdf_report
from .. import replica
from .. import tuning
from ..access import AccessControl
from ..account_export import AccountExport
from ..anchoring import anchor_loop
from ..app import create_app
from ..collector import Collector
from ..demo import seed_demo
from ..disclosure import Disclosures
from ..distributed_export import DistributedExport
from ..evidence import cleanup_exports
from ..evidence import retain_checkpoint
from ..monitoring import capture_settings
from ..operator_bot import OperatorBot
from ..profiles import Profiles
from ..provenance import run_receipt
from ..security import InstanceLock
from ..security import Vault
from ..storage import Storage
from ..store import Store
from ..workers import complete_in_thread
from contextlib import asynccontextmanager
from pathlib import Path
import asyncio
import secrets
import threading


class LifecycleOperations:
    @asynccontextmanager
    async def lifespan(self, app):
        app.state.closing = False
        if self.console:
            self.console.attach()
        instance = InstanceLock(self.root)
        store = None
        resume_task = None
        anchor_task = None
        replica_task = None
        storage_task = operator_bot_task = None
        alert_task = None
        host_task = address_task = None
        pool_task = None
        collector = None
        journal_ready = False
        profiles = None
        try:
            cleanup_exports(self.root)
            threading.Thread(
                target=pdf_report.available, name="pdf-preload", daemon=True
            ).start()
            vault = Vault(self.root)
            if self.token_override:
                vault.token = self.token_override

            def open_journal():
                nonlocal store
                store = Store(self.root)
                store.bind(vault)

            await complete_in_thread(open_journal)
            await complete_in_thread(store.verify, vault.public_key)
            if self.demo:
                if store.stats()["total"] and (not store.get_setting("demo", False)):
                    raise RuntimeError(
                        "Refusing to mix synthetic data into a real journal."
                    )
                seed_demo(store)
            elif store.get_setting("capture", None) is None:
                policy = capture_settings(store)
                if store.stats()["total"]:
                    for rule in policy["types"].values():
                        rule["enabled"] = True
                store.set_setting("capture", policy)
            await complete_in_thread(modes.migrate, store)
            collector = Collector(
                store,
                vault,
                **{"client_factory": self.client_factory}
                if self.client_factory
                else {},
            )
            collector.account_guard = self.account_guard
            collector.proxy_pool = self.shared_pool
            app.state.store, app.state.vault, app.state.collector = (
                store,
                vault,
                collector,
            )
            app.state.account_export = AccountExport(collector, store, vault)
            from ..guided_connection import GuidedConnection

            app.state.connection = GuidedConnection(app, self.profile_id)
            collector.portable_routes = app.state.connection.portable
            if not self.demo:
                try:
                    await app.state.connection.portable.restore()
                except Exception as exc:
                    store.append(
                        "network.tunnel_unavailable", {"error_type": type(exc).__name__}
                    )
                app.state.connection.maintenance = asyncio.create_task(
                    app.state.connection.maintain()
                )
            app.state.disclosures = Disclosures(app.state.account_export, vault)
            app.state.access = self.access or AccessControl(vault, store, self.console)
            if not self.access:

                def workspace_label(pid):
                    registry = getattr(app.state, "profiles", None)
                    if registry and pid in registry.entries:
                        return registry.entries[pid]["label"]
                    if registry and pid in registry.opening:
                        return registry.opening[pid]
                    if pid == "default":
                        return store.get_setting("profile_label", "Main account")
                    return next(
                        (
                            p["label"]
                            for p in store.get_setting("profiles", [])
                            if p["id"] == pid
                        ),
                        pid,
                    )

                app.state.access.labels = workspace_label
            store.listeners.append(app.state.access.journal_listener(self.profile_id))
            app.state.local_demo_token = secrets.token_urlsafe(32)
            app.state.run_receipt = run_receipt(store, vault)
            selected = assurance.mode()
            app.state.assurance = None
            if selected and (not self.demo):
                provider = await asyncio.to_thread(assurance.current_provider_record, selected)
                app.state.assurance = {"mode": selected, "provider": provider}
                app.state.run_receipt["host"] = await asyncio.to_thread(
                    assurance.snapshot, selected, provider, detail=True
                )
                quote = await asyncio.to_thread(
                    assurance.start_attestation, selected, app.state.run_receipt
                )
                if quote is not None:
                    app.state.run_receipt["tdx_start"] = quote
            collector.run_id = app.state.run_receipt["run_id"]
            previous = store.stats()["head"]
            process_event = store.append(
                "process.started",
                {
                    "version": __version__,
                    "previous_observation": previous,
                    "run": app.state.run_receipt,
                    "coverage": "No collection while process was offline.",
                },
            )
            app.state.run_event_seq = process_event["seq"]
            interactions.abandon(store, interactions.RESTART_STOP)
            retain_checkpoint(store, vault)
            journal_ready = True
            await complete_in_thread(store.fulltext.start)
            app.state.anchor_wakeup, app.state.anchor_status = (
                asyncio.Event(),
                {"busy": False},
            )
            app.state.replica_wakeup, app.state.replica_status = (
                asyncio.Event(),
                {"busy": False},
            )
            app.state.host_status = {}
            app.state.alert_wakeup = asyncio.Event()
            app.state.storage = Storage(store, vault, collector.outside_route)
            from ..capture_connections import CaptureConnections

            app.state.capture = CaptureConnections(store, vault)
            app.state.operator_bot = OperatorBot(app.state)
            if not store.get_setting("demo", False):
                storage_task = asyncio.create_task(app.state.storage.loop())
                operator_bot_task = asyncio.create_task(app.state.operator_bot.loop())
                alert_task = asyncio.create_task(
                    alerts.alert_loop(
                        store,
                        vault,
                        collector.outside_route,
                        app.state.alert_wakeup,
                        self.profile_id,
                    )
                )
                anchor_task = asyncio.create_task(
                    anchor_loop(
                        store,
                        collector.outside_route,
                        app.state.anchor_wakeup,
                        app.state.anchor_status,
                        collector.signed_in_devices,
                        lambda: (
                            vault.read("gateway").get("token") and vault.read("gateway")
                        ),
                    )
                )
                replica_task = asyncio.create_task(
                    replica.replica_loop(
                        store,
                        vault,
                        collector.outside_route,
                        app.state.replica_wakeup,
                        app.state.replica_status,
                    )
                )
                if app.state.assurance:
                    host_task = asyncio.create_task(
                        assurance.assurance_loop(
                            store,
                            app.state.assurance["mode"],
                            app.state.assurance["provider"],
                            status=app.state.host_status,
                        )
                    )
                    beacon = (assurance.deployment() or {}).get("beacon")
                    if beacon:
                        address_task = asyncio.create_task(
                            assurance.address_loop(vault, beacon)
                        )
                if self.proxy_pool is None:
                    self.shared_pool.intervals = lambda: {
                        "lists": tuning.value(store, "proxy_lists_minutes") * 60,
                        "probe": tuning.value(store, "proxy_probe_minutes") * 60,
                    }
                    self.shared_pool.outside = collector.outside_route
                    self.shared_pool.catalog.vault = vault
                    self.shared_pool.catalog.changed()
                    pool_task = asyncio.create_task(self.shared_pool.run())

            async def resume():
                try:
                    async with self.op_lock:
                        await collector.start()
                except Exception as exc:
                    collector.phase = (
                        "authorization_required"
                        if collector.authorization_required
                        else "resume_failed"
                    )
                    collector.last_error = type(exc).__name__
                    store.append(
                        "coverage.gap",
                        {"reason": "resume_failed", "error_type": type(exc).__name__},
                    )

            if store.get_setting("resume", False) and (
                not store.get_setting("demo", False)
            ):
                resume_task = asyncio.create_task(resume())
            if self.allow_profiles:

                def child_factory(path, **options):
                    return create_app(
                        path,
                        client_factory=self.client_factory,
                        proxy_pool=self.shared_pool,
                        access=app.state.access,
                        profile_id=Path(path).name,
                        **options,
                    )

                profiles = Profiles(app, self.root, child_factory)
                app.state.profiles = profiles
                app.state.access.group_of = profiles.group_of
                await profiles.open()
                app.state.multi_export = DistributedExport(profiles)
                from ..archive_api import startup as start_mcp

                await start_mcp(app)
            yield
        finally:
            app.state.closing = True
            try:
                if self.allow_profiles:
                    from ..archive_api import shutdown as stop_mcp

                    await stop_mcp(app)
                if getattr(app.state, "media_analysis", None):
                    await app.state.media_analysis.close()
                if getattr(app.state, "multi_export", None):
                    await app.state.multi_export.close()
                if profiles:
                    await app.state.connection.close()
                    await profiles.close()
                if getattr(app.state, "disclosures", None):
                    await app.state.disclosures.close()
                if getattr(app.state, "account_export", None):
                    await app.state.account_export.close()
                check_task = (
                    self.shared_pool.check_task if self.proxy_pool is None else None
                )
                for task in (
                    resume_task,
                    anchor_task,
                    replica_task,
                    alert_task,
                    host_task,
                    address_task,
                    pool_task,
                    check_task,
                    storage_task,
                    operator_bot_task,
                    getattr(getattr(app.state, "storage", None), "task", None),
                    *self.action_tasks,
                ):
                    if task:
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
                if collector:
                    await collector.stop(shutdown=True)
                if getattr(app.state, "connection", None):
                    await app.state.connection.close()
                if store and journal_ready:
                    store.append("process.stopped", {"reason": "graceful shutdown"})
                    retain_checkpoint(store, vault)
            finally:
                if store:
                    store.close()
                instance.close()
                if self.console:
                    self.console.detach()
