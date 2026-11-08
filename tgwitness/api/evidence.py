from .. import __version__
from .. import alerts
from .. import app as application
from .. import assurance
from .. import health
from .. import i18n
from .. import levels
from .. import modes
from .. import netclient
from .. import replica
from .. import report
from .. import source_check
from .. import tuning
from .. import witness_api
from ..anchor import request_archive
from ..anchoring import EvidenceMode
from ..anchoring import evidence_settings
from ..anchoring import request_anchor
from ..app import AlertUpdate
from ..app import GatewayLog
from ..app import ModeChange
from ..app import ReplicaUpdate
from ..app import SourceCheck
from ..evidence import checkpoint
from ..failures import describe
from ..monitoring import Capture
from ..monitoring import capture_settings
from ..scope import recheck_settings
from ..store import canonical
from ..store import utcnow
from ..verify import fingerprint
from ..workers import complete_in_thread
from .dependencies import current_context
from datetime import datetime
from datetime import timezone
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Request
from fastapi.responses import Response
from secrets import token_bytes as secrets_token
import asyncio
import base64
import io
import json
import time


async def get_evidence(*, ctx=Depends(current_context)):
    return ctx.evidence_state()


async def set_evidence(body: EvidenceMode, *, ctx=Depends(current_context)):
    ctx.require_live()
    ctx.require_external(body.enabled)
    store, vault = (ctx.app.state.store, ctx.app.state.vault)
    was = evidence_settings(store)["enabled"]
    with store.transaction():
        ctx.save_evidence(store, body)
    if body.enabled and (not was):
        request_anchor(store, vault, ctx.app.state.anchor_wakeup)
    return ctx.evidence_state()


async def set_gateway_log(body: GatewayLog, *, ctx=Depends(current_context)):
    ctx.require_live()
    store, vault = (ctx.app.state.store, ctx.app.state.vault)
    token = body.token or vault.read("gateway").get("token")
    if not token:
        raise HTTPException(422, "Paste the read-only Cloudflare token.")
    config = {
        "account": body.account,
        "location_id": body.location_id,
        "address": body.address or None,
        "token": token,
    }
    try:
        await application.gateway_rows(
            ctx.app.state.collector.outside_route(),
            config,
            time.time() - 3600,
            time.time() - 60,
        )
    except (netclient.RouteError, OSError, asyncio.TimeoutError):
        raise HTTPException(
            502,
            "Cloudflare could not be reached through this workspace's connection route.",
        )
    except (netclient.HTTPError, ValueError, KeyError, IndexError, TypeError):
        raise HTTPException(
            422,
            "Cloudflare did not accept this account, location or token. The token needs Account Analytics Read, and Zero Trust PII Read to keep one address only.",
        )
    vault.save("gateway", config)
    store.append(
        "evidence.gateway_set",
        {k: config[k] for k in ("account", "location_id", "address")},
    )
    return ctx.evidence_state()


async def remove_gateway_log(*, ctx=Depends(current_context)):
    ctx.require_live()
    store = ctx.app.state.store
    ctx.app.state.vault.save("gateway", {})
    with store.transaction():
        if evidence_settings(store)["gateway"]:
            ctx.save_evidence(
                store, EvidenceMode(**{**evidence_settings(store), "gateway": False})
            )
        store.append("evidence.gateway_removed", {})
    return ctx.evidence_state()


async def evidence_anchor(*, ctx=Depends(current_context)):
    ctx.require_live()
    if not evidence_settings(ctx.app.state.store)["enabled"]:
        raise HTTPException(409, "Turn on evidence mode first.")
    request_anchor(
        ctx.app.state.store, ctx.app.state.vault, ctx.app.state.anchor_wakeup
    )
    return ctx.evidence_state()


async def get_source_check(*, ctx=Depends(current_context)):
    return ctx.source_state()


async def get_mode(*, ctx=Depends(current_context)):
    return ctx.mode_state()


async def change_mode(
    request: Request, body: ModeChange, *, ctx=Depends(current_context)
):
    principal = request.state.principal
    try:
        modes.change(
            ctx.app.state.store,
            body.mode,
            {"access_id": principal.owner, "label": principal.label},
            confirm_downgrade=body.confirm_downgrade,
            reason=body.reason,
            active=ctx.mode_state()["active"],
        )
    except modes.Downgrade as exc:
        raise HTTPException(409, str(exc)) from None
    return ctx.mode_state()


async def run_source_check(body: SourceCheck, *, ctx=Depends(current_context)):
    ctx.require_live()
    try:
        result = await source_check.check(
            body.repository, body.ref.strip(), ctx.app.state.collector.outside_route()
        )
    except source_check.NotFound:
        raise HTTPException(
            422,
            "GitHub has no such public repository or version. Check the address and the tag, branch or commit.",
        )
    except source_check.Limited:
        raise HTTPException(
            503, "GitHub is limiting requests from this address. Try again in an hour."
        )
    except netclient.HTTPError:
        raise HTTPException(
            502,
            "GitHub could not be reached through this workspace's connection route.",
        )
    except ValueError:
        raise HTTPException(422, "Enter a GitHub repository as github.com/owner/name.")
    except (netclient.RouteError, OSError, asyncio.TimeoutError):
        raise HTTPException(
            502,
            "GitHub could not be reached through this workspace's connection route.",
        )
    store = ctx.app.state.store
    with store.transaction():
        store.set_setting("source_check", result)
        store.append(
            "source.checked",
            {
                **result,
                "meaning": "git blob ids of the running program files compared with the files of this commit on GitHub",
            },
        )
    return ctx.source_state()


async def get_replica(*, ctx=Depends(current_context)):
    return ctx.replica_state()


async def get_health(request: Request, *, ctx=Depends(current_context)):
    outside = ctx.outside_state()
    parts = {
        "collector": health.collector_of(ctx.app.state),
        "timestamps": ctx.timestamps_health(outside),
        "replica": ctx.replica_health(outside),
        "server": ctx.server_health(),
    }
    from ..operator_privacy import status_parts

    _, parts = status_parts(
        request.state.principal, {}, parts, ctx.visible_chats(request)
    )
    return {"checked_at": health.iso(health.now_utc()), **parts}


async def get_setup(*, ctx=Depends(current_context)):
    return ctx.setup_state()


async def apply_setup(body: levels.Setup, *, ctx=Depends(current_context)):
    ctx.require_live()
    store, vault = (ctx.app.state.store, ctx.app.state.vault)
    evidence_was = evidence_settings(store)
    try:
        planned = levels.plan(
            body, evidence_was, capture_settings(store), tuning.values(store)
        )
        saved, before, after = tuning.changes(store, planned["parameters"])
    except (ValueError, tuning.Invalid) as exc:
        raise HTTPException(422, str(exc)) from None
    changed = [name for name in ("evidence", "capture") if planned[name]] + (
        ["parameters"] if after else []
    )
    async with ctx.op_lock:
        with store.transaction():
            if planned["evidence"]:
                ctx.save_evidence(store, EvidenceMode(**planned["evidence"]))
            if planned["capture"]:
                ctx.save_capture(store, Capture(**planned["capture"]).model_dump())
            if after:
                ctx.save_parameters(store, saved, before, after)
            store.set_setting("setup", {**body.model_dump(), "at": utcnow()})
            store.append("setup.applied", {**body.model_dump(), "changed": changed})
    if (
        planned["evidence"]
        and planned["evidence"]["enabled"]
        and (not evidence_was["enabled"])
    ):
        request_anchor(store, vault, ctx.app.state.anchor_wakeup)
    if planned["capture"]:
        ctx.app.state.collector.media_wakeup.set()
    if after:
        ctx.app.state.alert_wakeup.set()
    return {**ctx.setup_state(), "changed": changed}


async def skip_setup(*, ctx=Depends(current_context)):
    ctx.require_live()
    ctx.app.state.store.set_setting("setup", {"skipped": True, "at": utcnow()})
    return ctx.setup_state()


async def set_replica(body: ReplicaUpdate, *, ctx=Depends(current_context)):
    ctx.require_live()
    ctx.require_external(body.enabled)
    manager = ctx.app.state.storage
    if manager.lock.locked() or (manager.task and (not manager.task.done())):
        raise HTTPException(409, "Wait for the current storage operation to finish.")
    async with manager.lock:
        return await ctx.save_replica(body)


async def get_alerts(*, ctx=Depends(current_context)):
    return ctx.alert_state()


async def set_alerts(
    request: Request, body: AlertUpdate, *, ctx=Depends(current_context)
):
    ctx.require_external(body.enabled)
    ctx.require_live()
    store, vault = (ctx.app.state.store, ctx.app.state.vault)
    saved = vault.read("alerts").get("urls", [])
    urls = (
        list(saved)
        if body.urls is None
        else [u.strip() for u in body.urls if u.strip()]
    )
    urls += [
        u
        for u in dict.fromkeys((u.strip() for u in body.add_urls))
        if u and u not in urls
    ]
    for url in urls:
        if len(url) > 2048 or not alerts.describe(url):
            raise HTTPException(
                422,
                "Apprise does not recognise one of the destination addresses. Check it against the Apprise wiki.",
            )
    if any((alerts.own_socket(u) for u in urls if u not in saved)) and (
        not (request.state.principal.admin or netclient.private_allowed())
    ):
        raise HTTPException(
            403,
            "Only the main administrator can add destinations that connect without HTTP (IRC, MQTT, XMPP, syslog and similar).",
        )
    problem = alerts.route_problem(urls, ctx.app.state.collector.outside_route())
    if body.enabled and problem:
        raise HTTPException(422, problem)
    if body.enabled and (not urls):
        raise HTTPException(
            422, "Add at least one destination before turning notifications on."
        )
    settings = body.model_dump(exclude={"urls", "add_urls"})
    vault.save("alerts", {"urls": urls})
    with store.transaction():
        store.set_setting("alerts", settings)
        store.append("alerts.changed", alerts.change_record(settings, urls))
    ctx.app.state.alert_wakeup.set()
    return ctx.alert_state()


async def test_alerts(*, ctx=Depends(current_context)):
    ctx.require_live()
    store, urls = (
        ctx.app.state.store,
        ctx.app.state.vault.read("alerts").get("urls", []),
    )
    if not urls:
        raise HTTPException(409, "Save at least one destination first.")
    words = i18n.words(alerts.alert_settings(store)["language"])
    result = await asyncio.to_thread(
        alerts.deliver,
        urls,
        alerts.tr(words, "TgWitness · {name}: test", name=alerts.workspace_name(store)),
        alerts.tr(words, "Notifications from this workspace reach this destination."),
        ctx.app.state.collector.outside_route(),
    )
    if result["error"]:
        raise HTTPException(502, result["error"])
    return result


async def replica_sync(*, ctx=Depends(current_context)):
    ctx.require_live()
    if not replica.replica_settings(ctx.app.state.store)["enabled"]:
        raise HTTPException(409, "Turn on the off-site copy first.")
    ctx.app.state.replica_wakeup.set()
    return ctx.replica_state()


async def replica_test(*, ctx=Depends(current_context)):
    ctx.require_live()
    store, vault = (ctx.app.state.store, ctx.app.state.vault)
    settings, secrets = (replica.replica_settings(store), vault.read("replica"))
    if not (settings["endpoint"] and settings["bucket"] and secrets.get("access_key")):
        raise HTTPException(409, "Save the endpoint, bucket and access keys first.")
    s3 = replica.client(settings, secrets, ctx.app.state.collector.outside_route())
    key, prefix, _ = replica.replica_context(
        settings, base64.b64decode(secrets["key"], validate=True), replica.fingerprint(vault.public_key)
    )
    name = prefix + "/connection-test.tgwr"
    try:
        headers = replica.lock_headers(settings, 1 if settings["retention_days"] else 0)
        started_at = datetime.now(timezone.utc)
        await replica.require_evidence_lock(s3, settings)
        await asyncio.wait_for(
            replica.upload(
                s3,
                key,
                name,
                lambda: io.BytesIO(b"TgWitness connection test"),
                headers,
                recipient_public_key=settings["recipient_public_key"],
            ),
            60,
        )
        lock = await asyncio.wait_for(
            replica.lock_report(
                s3,
                name,
                {**settings, "retention_days": min(settings["retention_days"], 1)},
                headers,
                started_at,
            ),
            60,
        )
    except Exception as exc:
        raise HTTPException(
            502,
            "Storage did not accept a test object: "
            + (str(exc)[:200] if isinstance(exc, ValueError) else describe(exc)),
        ) from None
    return {"ok": True, "object": name, "object_lock": lock}


async def replica_key(*, ctx=Depends(current_context)):
    if not ctx.app.state.vault.read("replica").get("key"):
        raise HTTPException(
            404, "Save the off-site copy settings first; the key is created then."
        )
    return Response(
        json.dumps(
            replica.key_file(ctx.app.state.store, ctx.app.state.vault), indent=2
        ),
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="tgwitness-replica-key.json"'
        },
    )


async def get_checkpoint(*, ctx=Depends(current_context)):
    return checkpoint(ctx.app.state.store, ctx.app.state.vault)


async def get_run_receipt(*, ctx=Depends(current_context)):
    statement = {
        "format": "tgwitness-run-receipt-v1",
        "run": ctx.app.state.run_receipt,
        "journal_event_seq": ctx.app.state.run_event_seq,
    }
    return {
        "statement": statement,
        "signature": ctx.app.state.vault.sign(canonical(statement)),
        "public_key": ctx.app.state.vault.public_key,
    }


async def assurance_statement(challenge: str = "", *, ctx=Depends(current_context)):
    if not ctx.app.state.assurance:
        raise HTTPException(404)
    if challenge and (
        len(challenge) != 32 or any((c not in "0123456789abcdef" for c in challenge))
    ):
        raise HTTPException(
            422, "challenge must be 32 lowercase hexadecimal characters"
        )
    if not challenge:
        cached = getattr(ctx.app.state, "assurance_cache", None)
        if cached is not None and time.monotonic() - cached[0] < 10:
            return cached[1]
    statement = await asyncio.to_thread(
        assurance.statement,
        ctx.app.state.vault,
        ctx.app.state.run_receipt,
        ctx.app.state.run_event_seq,
        ctx.app.state.assurance["mode"],
        ctx.app.state.assurance["provider"],
        challenge or None,
    )
    if not challenge:
        ctx.app.state.assurance_cache = (time.monotonic(), statement)
    return statement


async def anchor_request(*, ctx=Depends(current_context)):
    return Response(
        request_archive(checkpoint(ctx.app.state.store, ctx.app.state.vault)),
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="tgwitness-timestamp-request.zip"'
        },
    )


def evidence_status(store, vault):
    folder = store.root / "checkpoints" / "anchors"
    stamped = [
        int(proof.name.split(".", 1)[0][11:])
        for proof in (folder.iterdir() if folder.is_dir() else [])
        if proof.suffix in (".tsr", ".ots")
        and proof.name.startswith("checkpoint-")
        and proof.name.split(".", 1)[0][11:].isdigit()
    ]
    polled = [
        entry["last_poll"]["at"]
        for entry in witness_api.state(vault, store)["tokens"]
        if entry.get("last_poll") and entry["last_poll"].get("witness") and not entry.get("overdue")
    ]
    return {
        "timestamps": bool(evidence_settings(store)["enabled"]),
        "stamped_through": max(stamped, default=0),
        "witness_at": max(polled, default=None),
    }


async def verify(*, ctx=Depends(current_context)):
    try:
        checked = await asyncio.to_thread(
            ctx.app.state.store.verify, ctx.app.state.vault.public_key
        )
    except Exception:
        raise HTTPException(
            409,
            "Journal integrity verification failed. Preserve the directory for inspection.",
        ) from None
    return {**checked, "conditions": evidence_status(ctx.app.state.store, ctx.app.state.vault)}


class EvidenceOperations:
    def outside_state(self):
        route = self.app.state.collector.outside_route()
        return {
            "route": route.kind,
            "route_problem": str(route.error) if route.kind == "none" else None,
        }

    def timestamps_health(self, outside):
        store = self.app.state.store
        last, success = (
            store.get_setting("evidence_last", None),
            store.get_setting("evidence_success", None),
        )
        if (
            success is None
            and last
            and any((r.get("ok") for r in last.get("results", [])))
        ):
            success = {
                "at": last["at"],
                "verified_at": last["at"]
                if any(
                    (
                        r.get("ok") and r.get("kind") == "rfc3161"
                        for r in last["results"]
                    )
                )
                else None,
            }
        return health.timestamps(
            evidence_settings(store),
            last,
            success,
            store.get_setting("evidence_failure", None),
            self.app.state.anchor_status,
            outside["route_problem"],
            health.now_utc(),
        )

    def replica_health(self, outside):
        store = self.app.state.store
        last, success = (
            store.get_setting("replica_last", None),
            store.get_setting("replica_success", None),
        )
        if success is None and last and (not last.get("error")):
            success = {"at": last["at"], "journal_seq": last.get("journal_seq")}
        return health.replica(
            replica.replica_settings(store),
            last,
            success,
            self.app.state.replica_status,
            outside["route_problem"],
            (store.stats()["head"] or {}).get("seq", 0),
            health.now_utc(),
        )

    def server_health(self):
        return health.server(
            self.app.state.assurance,
            self.app.state.run_receipt.get("host"),
            self.app.state.host_status,
            health.now_utc(),
        )

    def gateway_state(self):
        saved = self.app.state.vault.read("gateway")
        suggested = None
        if self.app.state.assurance:
            described = (assurance.deployment() or {}).get("gateway") or {}
            if described.get("location_id"):
                suggested = {
                    "account": described.get("account"),
                    "location_id": described["location_id"],
                    "address": (self.app.state.assurance.get("provider") or {}).get(
                        "public_ipv4"
                    ),
                }
        return {
            "account": saved.get("account"),
            "location_id": saved.get("location_id"),
            "address": saved.get("address"),
            "has_token": bool(saved.get("token")),
            "suggested": suggested,
        }

    def evidence_state(self):
        store, outside = (self.app.state.store, self.outside_state())
        return {
            "settings": evidence_settings(store),
            "last": store.get_setting("evidence_last", None),
            "witnesses": store.get_setting("evidence_witnesses", None) or {},
            "gateway": self.gateway_state(),
            "busy": self.app.state.anchor_status["busy"],
            **outside,
            "health": self.timestamps_health(outside),
            "defaults": EvidenceMode().model_dump(exclude={"enabled"}),
        }

    def save_evidence(self, store, body):
        store.set_setting("evidence", body.model_dump())
        store.append(
            "evidence.changed",
            {
                **body.model_dump(),
                "fingerprint": fingerprint(self.app.state.vault.public_key),
            },
        )

    def source_state(self):
        last, receipt = (
            self.app.state.store.get_setting("source_check", None),
            self.app.state.run_receipt,
        )
        return {
            "last": last,
            "version": __version__,
            "source_tree_sha256": receipt["source_tree_sha256"],
            "source_policy": receipt.get("source_policy"),
            "files": len(receipt["source_files"]),
            **self.outside_state(),
            "current": bool(last)
            and last["source_tree_sha256"] == receipt["source_tree_sha256"],
        }

    def mode_facts(self):
        store, vault, collector = (
            self.app.state.store,
            self.app.state.vault,
            self.app.state.collector,
        )
        outside = self.outside_state()
        return {
            "media": capture_settings(store)["download_media"],
            "checkpoint": store.retained_checkpoint() is not None,
            "recheck": recheck_settings(store),
            "alerts": {
                **alerts.alert_settings(store),
                "destinations": len(vault.read("alerts").get("urls", [])),
            },
            "witness": witness_api.state(vault, store)["tokens"],
            "evidence": evidence_settings(store),
            "timestamps": self.timestamps_health(outside),
            "replica": replica.replica_settings(store),
            "replica_last": store.get_setting("replica_last", None),
            "report": report.saved(store).model_dump(),
            "source_check": self.source_state(),
            "route": collector.route_policy(),
            "network": collector.network_config().kind,
            "direct_fallback": collector.direct_fallback,
            "outside_route": outside["route"],
            "assurance": bool(self.app.state.assurance),
        }

    def mode_state(self):
        return modes.state(self.app.state.store, self.mode_facts())

    def replica_state(self):
        store, vault, outside = (
            self.app.state.store,
            self.app.state.vault,
            self.outside_state(),
        )
        settings, secrets = (replica.replica_settings(store), vault.read("replica"))
        return {
            "settings": settings,
            "has_credentials": bool(secrets.get("access_key")),
            "has_key": bool(secrets.get("key")),
            "last": store.get_setting("replica_last", None),
            "busy": self.app.state.replica_status["busy"],
            **outside,
            "health": self.replica_health(outside),
            "location": replica.replica_prefix(settings, replica.fingerprint(vault.public_key)),
        }

    def setup_state(self):
        store, outside = (self.app.state.store, self.outside_state())
        saved = store.get_setting("setup", None)
        place = (saved or {}).get("place") or (
            "server" if self.app.state.assurance else "computer"
        )
        assessment = levels.assess(
            evidence_settings(store),
            replica.replica_settings(store),
            alerts.alert_settings(store),
            self.app.state.vault.read("alerts").get("urls", []),
            self.app.state.assurance,
            self.source_state(),
            witness_api.state(self.app.state.vault, store)["tokens"],
            place,
            bool(self.app.state.vault.read("gateway").get("token")),
        )
        return {
            "saved": saved,
            "recommended": levels.RECOMMENDED,
            "assessment": assessment,
            "levels": levels.LEVELS,
            "sealed": bool(self.app.state.assurance),
            "limits": {
                "dialog_limit": levels.DIALOG_LIMIT,
                "reserve_mb": levels.LARGE_MEDIA_RESERVE_MB,
            },
            "current": {
                "size": levels.size_choice(tuning.value(store, "dialog_limit")),
                "files": levels.files_choice(capture_settings(store)),
                "place": place,
            },
            "health": {
                "timestamps": self.timestamps_health(outside)["state"],
                "replica": self.replica_health(outside)["state"],
            },
        }

    async def save_replica(self, body):
        store, vault = (self.app.state.store, self.app.state.vault)
        secrets = dict(vault.read("replica"))
        if body.access_key or body.secret_key:
            if not (body.access_key and body.secret_key):
                raise HTTPException(
                    422, "Enter both the access key ID and the secret access key."
                )
            secrets.update(access_key=body.access_key, secret_key=body.secret_key)
        settings = body.model_dump(exclude={"access_key", "secret_key"})
        if settings["enabled"] and (
            not (
                settings["endpoint"]
                and settings["bucket"]
                and secrets.get("access_key")
            )
        ):
            raise HTTPException(
                422,
                "Enter the endpoint, bucket and access keys before turning the copy on.",
            )
        if settings["enabled"] and settings["evidence"]:
            try:
                await replica.require_evidence_lock(
                    replica.client(
                        settings, secrets, self.app.state.collector.outside_route()
                    ),
                    settings,
                )
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from None
        manager = self.app.state.storage
        obsolete = []
        if manager.public()["settings"]["backend"] == "s3":
            try:
                obsolete = await complete_in_thread(
                    manager.obsolete_copies,
                    manager.destination(replica_config=settings),
                )
            except ValueError as exc:
                raise HTTPException(409, str(exc)) from None
        secrets.setdefault("key", base64.b64encode(secrets_token(32)).decode())
        manager.discard_copies(obsolete)
        vault.save("replica", secrets)
        with store.transaction():
            store.set_setting("replica", settings)
            store.append("replica.changed", {**settings, "encrypted": True})
        if settings["enabled"]:
            self.app.state.replica_wakeup.set()
        return self.replica_state()

    def alert_state(self):
        urls = self.app.state.vault.read("alerts").get("urls", [])
        return {
            "settings": alerts.alert_settings(self.app.state.store),
            "destinations": [alerts.describe(u) or "?" for u in urls],
            "last": self.app.state.store.get_setting("alerts_last", None),
            **self.outside_state(),
        }
