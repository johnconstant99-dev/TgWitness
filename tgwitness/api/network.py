from .. import netclient
from .. import proxy_catalog
from .. import proxy_sources
from ..app import GitHubToken
from ..app import ProxyLink
from ..app import ProxyListUpload
from ..app import RoutePolicyUpdate
from ..guided_connection import ApplyDraft
from ..guided_connection import ConnectionDraft
from ..network import NetworkConfig
from ..network import RoutePolicy
from ..network import parse_mtproxy_link
from ..proxy_catalog import feed_network
from ..workers import complete_in_thread
from .dependencies import current_context
from contextlib import suppress
from datetime import datetime
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Request
import asyncio


async def network(
    request: Request, body: NetworkConfig, *, ctx=Depends(current_context)
):
    return await ctx.operation(
        ctx.app.state.collector.set_network, await ctx.approved_route(request, body)
    )


async def connection_state(*, ctx=Depends(current_context)):
    return ctx.app.state.connection.public()


async def connection_preview(body: ConnectionDraft, *, ctx=Depends(current_context)):
    ctx.require_live()
    try:
        return ctx.app.state.connection.preview(body)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


async def connection_prepare(body: ConnectionDraft, *, ctx=Depends(current_context)):
    ctx.require_live()
    try:
        return ctx.app.state.connection.start_prepare(body)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None


async def connection_apply(body: ApplyDraft, *, ctx=Depends(current_context)):
    ctx.require_live()
    try:
        return ctx.app.state.connection.start_apply(body.plan)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None


async def connection_check(*, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.connection.check_current)


async def connection_cancel(*, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.connection.cancel)


async def connection_stop(*, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.connection.control, "stop")


async def connection_start(*, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.connection.control, "start")


async def network_policy(*, ctx=Depends(current_context)):
    return ctx.app.state.collector.policy_state()


async def network_policy_set(
    request: Request, body: RoutePolicyUpdate, *, ctx=Depends(current_context)
):
    return await ctx.operation(
        ctx.app.state.collector.set_route_policy,
        RoutePolicy(exposure=body.exposure, outside_enabled=body.outside_enabled),
        await ctx.approved_route(request, body.outside_proxy),
        body.remove_outside_proxy,
    )


async def network_catalog(*, ctx=Depends(current_context)):
    try:
        return {**ctx.public_proxies.public(), **ctx.download_route()}
    except ValueError as exc:
        raise HTTPException(503, str(exc)) from None


async def network_catalog_refresh(*, ctx=Depends(current_context)):
    result = await ctx.operation(
        ctx.public_proxies.refresh, ctx.app.state.collector.outside_route()
    )
    return {**result, **ctx.download_route()}


async def network_catalog_apply(proxy_id: str, *, ctx=Depends(current_context)):
    try:
        catalog = ctx.public_proxies.catalog()
    except ValueError as exc:
        raise HTTPException(503, str(exc)) from None
    if not any((row["id"] == proxy_id for row in catalog["proxies"])):
        raise HTTPException(404, "Unknown public proxy. Refresh the list.")

    async def apply():
        if ctx.app.state.collector.running:
            raise ValueError("Pause observation before changing the Telegram route.")
        route = await ctx.public_proxies.selected_route(proxy_id)
        return await ctx.app.state.collector.set_network(route)

    return await ctx.operation(apply)


async def network_proxies(request: Request, *, ctx=Depends(current_context)):
    try:
        return ctx.proxy_view(request.state.principal)
    except ValueError as exc:
        raise HTTPException(503, str(exc)) from None


async def network_proxies_check(request: Request, *, ctx=Depends(current_context)):
    ctx.require_live()
    if ctx.shared_pool.check_task is None:
        ctx.shared_pool.check_task = asyncio.create_task(
            ctx.shared_pool.check_all(ctx.app.state.collector.outside_route())
        )
    return ctx.proxy_view(request.state.principal)


async def network_sources(
    body: proxy_sources.SourceSettings, *, ctx=Depends(current_context)
):
    ctx.require_live()
    catalog = ctx.shared_pool.catalog
    async with catalog.lock:
        before = {item.id for item in catalog.settings().custom}
        known = {source["id"] for source in proxy_catalog.SOURCES}
        if set(body.disabled) - known:
            raise HTTPException(422, "Unknown bundled list.")
        if any((item.id and item.id not in before for item in body.custom)):
            raise HTTPException(422, "Unknown own list. Reload the page.")
        try:
            proxy_sources.save(catalog.root, body)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        catalog.changed()
        catalog.forget(before - {item.id for item in body.custom})
    ctx.app.state.store.append(
        "network.sources_changed",
        {
            "bundled_off": body.disabled,
            "own_lists": len(body.custom),
            "github_search": body.github.enabled,
            "prefer_countries": body.prefer,
            "avoid_countries": body.avoid,
            "only_preferred": body.only_preferred,
        },
    )
    return ctx.proxy_view()


async def network_sources_list(body: ProxyListUpload, *, ctx=Depends(current_context)):
    ctx.require_live()
    try:
        async with ctx.shared_pool.catalog.lock:
            item, compatible, skipped = await complete_in_thread(
                ctx.shared_pool.catalog.add_list, body.label, body.text
            )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    ctx.app.state.store.append(
        "network.sources_changed",
        {"own_list_added": item.label, "compatible": compatible},
    )
    return {
        **ctx.proxy_view(),
        "added": {"id": item.id, "compatible": compatible, "skipped": skipped},
    }


async def network_github_token(
    request: Request, body: GitHubToken, *, ctx=Depends(current_context)
):
    ctx.require_live()
    if not request.state.principal.admin:
        raise HTTPException(
            403, "Only the main administrator can store a GitHub token."
        )
    token = body.token.strip()
    if token and proxy_sources.token_problem(token):
        raise HTTPException(422, proxy_sources.token_problem(token))
    try:
        ctx.shared_pool.catalog.set_github_token(token)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    ctx.app.state.store.append("network.github_token", {"stored": bool(token)})
    return ctx.proxy_view()


async def network_parse_link(body: ProxyLink, *, ctx=Depends(current_context)):
    try:
        return parse_mtproxy_link(body.link).model_dump()
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


async def network_test(*, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.collector.test_network)


class NetworkOperations:
    async def approved_route(self, request, config):
        if config is None or config.kind not in ("socks5", "http", "mtproxy"):
            return config and config.model_copy(update={"local_proxy": False})
        try:
            addresses = await netclient.resolve(config.host, config.port)
        except OSError:
            addresses = None
        inside = True if addresses is None else any((netclient.internal(a) for a in addresses))
        if inside and (
            not (request.state.principal.admin or netclient.private_allowed())
        ):
            raise HTTPException(
                403,
                "This proxy is inside this machine or its network. Only the main administrator can set it.",
            )
        return config.model_copy(update={"local_proxy": inside})

    def download_route(self):
        if feed_network():
            return {"download_route": "proxy", "download_problem": None}
        route = self.app.state.collector.outside_route()
        return {
            "download_route": "proxy"
            if route.kind in ("socks5", "http")
            else route.kind,
            "download_problem": str(route.error) if route.kind == "none" else None,
        }

    def lists_updated_at(self, sources):
        stamps = []
        for source in sources:
            with suppress(TypeError, ValueError):
                if source.get("enabled") and source.get("fetched_at"):
                    stamps.append(
                        datetime.fromisoformat(source["fetched_at"]).timestamp()
                    )
        return max(stamps, default=None)

    def proxy_view(self, principal=None):
        catalog = self.shared_pool.catalog
        labels = {
            str(self.app.state.store.root): self.app.state.store.get_setting(
                "profile_label", "this workspace"
            )
        }
        profiles = getattr(self.app.state, "profiles", None)
        for entry in profiles.entries.values() if profiles else ():
            if entry.get("app") is not None and (
                principal is None or principal.opens(entry["id"])
            ):
                labels[str(entry["app"].state.store.root)] = entry["label"]
        rows, settings, intervals = (
            self.shared_pool.table(labels),
            catalog.settings(),
            self.shared_pool.intervals(),
        )
        sources = catalog.public()["sources"]
        latencies = sorted((r["latency_ms"] for r in rows if r["latency_ms"]))
        return {
            "rows": rows,
            "summary": {
                "listed": len(rows),
                "ok": sum((r["status"] == "ok" for r in rows)),
                "resting": sum((r["status"] == "resting" for r in rows)),
                "untested": sum((r["status"] == "untested" for r in rows)),
                "excluded": sum((r["excluded"] for r in rows)),
                "preferred": sum((r["preferred"] for r in rows)),
                "median_ms": latencies[len(latencies) // 2] if latencies else None,
                "countries": len({r["country"] for r in rows if r["country"]}),
                "checked_at": self.shared_pool.probed_at or None,
                "checking": self.shared_pool.check_task is not None,
            },
            "schedule": {
                "lists_minutes": round(intervals["lists"] / 60),
                "probe_minutes": round(intervals["probe"] / 60),
                "lists_at": self.lists_updated_at(sources),
            },
            "sources": sources,
            "settings": {
                **settings.model_dump(),
                "github_token": bool(catalog.github_token()),
                "github_status": catalog.github_status,
            },
            **self.download_route(),
        }
