"""Exercise every registered panel API route before any Telegram connection."""
import asyncio
from pathlib import Path
import re
import sys

from fastapi.routing import APIRoute
import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.access import GrantSettings
from tools.check_session_reservations import RecordingClient, workspace


# These endpoints deliberately accept no panel credential. Other credential
# families (archive readers and one-use download cookies) must still deny access.
PUBLIC = {("GET", "/api/demo-access"): 200, ("GET", "/api/assurance"): 404}


def test_all_api_routes_reject_anonymous_and_revoked_access(record_property):
    async def run():
        checked = []
        async with workspace() as (app, _):
            token, grant = app.state.access.issue(GrantSettings(
                label="Synthetic revoked-access audit", permissions=['view'], workspaces={"default": None}))
            session, _ = app.state.access.login(token, "127.0.0.1", "Synthetic audit")
            app.state.access.revoke(grant['id'])
            routes = [r for r in app.routes if isinstance(r, APIRoute) and r.path.startswith("/api/")]
            for index, route in enumerate(routes):
                path = re.sub(r"\{[^}]+\}", "1", route.path)
                for method in sorted(route.methods):
                    body = {"tool": "list_workspaces"} if route.path.startswith("/api/archive/") else {}
                    if route.path == "/api/access/login":
                        body = {"token": "synthetic-invalid-token-for-audit"}
                    for mode in ("anonymous", "revoked"):
                        # Separate addresses keep authentication rate limiting from
                        # masking a later route's own authorization result.
                        peer = f"198.18.{index // 250}.{index % 250 + 1}"
                        transport = httpx.ASGITransport(app=app, client=(peer, 12345))
                        headers = {"Authorization": "Bearer " + session} if mode == "revoked" else {}
                        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
                            response = await client.request(method, path, headers=headers,
                                                            json=body if method in ("POST", "PUT", "PATCH") else None)
                        expected = PUBLIC.get((method, route.path))
                        if expected is not None:
                            assert response.status_code == expected, (mode, method, route.path, response.text)
                            if route.path == "/api/demo-access":
                                assert response.json() == {"available": False}
                        else:
                            assert response.status_code in (401, 403), (mode, method, route.path, response.status_code, response.text)
                        checked.append((mode, method, route.path, response.status_code))
            assert RecordingClient.connections == 0
            record_property("routes_checked", len(routes))
            record_property("requests_checked", len(checked))
    asyncio.run(run())
