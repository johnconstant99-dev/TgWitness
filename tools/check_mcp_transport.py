"""Exercise official MCP stdio and HTTP clients against synthetic scoped records."""
import asyncio
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time

import httpx2
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
import requests
import uvicorn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.check_browser import RunningApp
from tgwitness.archive import TOOLS
from tgwitness.mcp_server import ArchiveAPI, BearerAccess, build_server


async def check(client):
    tools = await client.list_tools()
    assert {t.name for t in tools.tools} == set(TOOLS)
    result = await client.call_tool("search_messages", {"query": "synthetic"})
    assert not result.is_error
    data = result.structured_content or json.loads(result.content[0].text)
    assert data["items"] and all(row["source"]["chat_id"] == -1001 for row in data["items"])
    refused = await client.call_tool("get_message_versions", {"chat_id": -1002, "message_id": 1})
    assert refused.is_error


def main():
    with tempfile.TemporaryDirectory(prefix="mcp-check-") as scratch, RunningApp(Path(scratch)) as app:
        store = app.app.state.store
        for chat_id in (-1001, -1002):
            store.set_target(chat_id, "Synthetic chat", "supergroup", True)
            store.append("message.new", {"text": "synthetic content", "sender_id": 7}, chat_id=chat_id, message_id=1)
        admin = {"Authorization": "Bearer " + app.app.state.vault.token}
        issued = requests.post(app.url + "/api/integrations/mcp", headers=admin, timeout=10,
                               json={"name": "Protocol test", "workspaces": {"default": [-1001]},
                                     "expires_at": time.time() + 3600}).json()
        token = issued["token"]
        checked = requests.post(app.url + "/api/integrations/mcp/check", headers=admin, timeout=25,
                                json={"token": token, "transport": "stdio"})
        assert checked.status_code == 200 and checked.json()["messages_read"] == 0, checked.text

        async def stdio():
            params = StdioServerParameters(command=sys.executable,
                                           args=["-m", "tgwitness.mcp_server", "--api-url", app.url],
                                           env={**os.environ, "TGWITNESS_ARCHIVE_TOKEN": token}, cwd=str(ROOT))
            async with Client(params, read_timeout_seconds=15) as client:
                await check(client)
        asyncio.run(stdio())

        api = ArchiveAPI(app.url)
        protocol = build_server(api).streamable_http_app(stateless_http=True, json_response=True)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        url = f"http://127.0.0.1:{sock.getsockname()[1]}/mcp"
        server = uvicorn.Server(uvicorn.Config(BearerAccess(protocol, api), log_level="error", access_log=False))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while not server.started:
                if time.monotonic() > deadline:
                    raise TimeoutError("MCP test server did not start")
                time.sleep(.05)
            assert requests.post(url, json={}, timeout=10).status_code == 401

            async def http():
                async with httpx2.AsyncClient(headers={"Authorization": "Bearer " + token}, timeout=15, trust_env=False) as transport:
                    async with Client(streamable_http_client(url, http_client=transport), read_timeout_seconds=15) as client:
                        await check(client)
            asyncio.run(http())
            checked = requests.post(app.url + "/api/integrations/mcp/check", headers=admin, timeout=25,
                                    json={"token": token, "transport": "http", "url": url})
            assert checked.status_code == 200 and checked.json()["messages_read"] == 0, checked.text
            response = requests.delete(app.url + "/api/integrations/mcp/" + issued["connection"]["id"], headers=admin, timeout=10)
            assert response.status_code == 200
            assert requests.post(url, headers={"Authorization": "Bearer " + token}, json={}, timeout=10).status_code == 401
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            sock.close()
    print("MCP stdio and Streamable HTTP passed: seven read-only tools, chat isolation, authentication and revocation.")


if __name__ == "__main__":
    main()
