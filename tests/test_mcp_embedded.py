"""MCP is a real scoped transport, with one canonical stdio entry point."""
import json
import time

import pytest
from fastapi.testclient import TestClient

from test_access import HARBOR, OTHER, panel as panel
from tgwitness import archive, mcp_server, mcp_stdio

pytest.importorskip("mcp")

HEADERS = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"}


def issue(admin, tools=None):
    settings = {"name": "Synthetic MCP client", "workspaces": {"default": [HARBOR]},
                "expires_at": time.time() + 3600}
    if tools is not None:
        settings["tools"] = tools
    response = admin.post("/api/mcp/connections", json=settings)
    assert response.status_code == 200, response.text
    return response.json()


def rpc(client, token, method, params=None, **headers):
    return client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
                       headers={**HEADERS, "Authorization": "Bearer " + token, **headers})


def test_embedded_initialize_lists_only_actual_tools_and_reads_scoped_data(panel):
    app, admin = panel
    created = issue(admin)
    token = created["token"]
    client = TestClient(app)
    ready = admin.get("/api/mcp").json()
    assert ready["available"] and ready["endpoint"] == "/mcp"
    assert ready["sdk_version"] and ready["tools"] == list(archive.TOOLS)
    initialized = rpc(client, token, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                                  "clientInfo": {"name": "synthetic-test", "version": "1"}})
    assert initialized.status_code == 200, initialized.text
    assert initialized.json()["result"]["protocolVersion"] == "2025-06-18"
    listed = rpc(client, token, "tools/list")
    assert listed.status_code == 200, listed.text
    tools = listed.json()["result"]["tools"]
    assert sorted(t["name"] for t in tools) == sorted(archive.TOOLS)
    assert all(t["annotations"]["readOnlyHint"] and not t["annotations"]["destructiveHint"] for t in tools)
    result = rpc(client, token, "tools/call", {"name": "search_messages", "arguments": {"query": "Harbor"}})
    assert result.status_code == 200, result.text
    content = result.json()["result"]
    assert not content.get("isError")
    text = json.dumps(content)
    assert "Harbor text" in text and "Other text" not in text and "untrusted_content" in text
    forbidden = rpc(client, token, "tools/call", {"name": "get_message_versions",
                    "arguments": {"chat_id": OTHER, "message_id": 1}}).json()["result"]
    assert forbidden["isError"] and "Other text" not in json.dumps(forbidden)


def test_tools_rotation_and_usage_metadata_follow_one_connection(panel):
    app, admin = panel
    created = issue(admin, ["list_chats"])
    token, connection_id = created["token"], created["connection"]["id"]
    client = TestClient(app, client=("127.0.0.42", 50001))
    tools = rpc(client, token, "tools/list").json()["result"]["tools"]
    assert [tool["name"] for tool in tools] == ["list_chats"]
    forbidden = rpc(client, token, "tools/call", {"name": "search_messages", "arguments": {"query": "Harbor"}})
    assert forbidden.status_code == 403
    assert "Harbor text" not in forbidden.text
    listed = rpc(client, token, "tools/call", {"name": "list_chats"})
    assert not listed.json()["result"].get("isError")
    public = admin.get("/api/mcp").json()["connections"][0]
    assert public["last_tool"] == "list_chats" and public["last_address"] == "127.0.0.42"
    assert public["uses"] >= 3 and public["last_used_at"]
    assert token not in json.dumps(public) and "sha256" not in public
    rotated = admin.post("/api/mcp/connections/" + connection_id + "/rotate").json()
    assert rotated["token"] != token and rotated["connection"]["id"] == connection_id
    assert rpc(client, token, "tools/list").status_code == 401
    assert rpc(client, rotated["token"], "tools/list").status_code == 200
    admin.delete("/api/mcp/connections/" + connection_id)
    assert rpc(client, rotated["token"], "tools/list").status_code == 401


def test_token_sources_prefer_canonical_and_warn_without_disclosing_secrets(tmp_path, capsys):
    canonical, legacy = "tgw_mcp_canonical_synthetic", "tgw_mcp_legacy_synthetic"
    assert mcp_stdio.read_token(environ={"TGWITNESS_MCP_TOKEN": canonical, "TGWITNESS_ARCHIVE_TOKEN": legacy}) == canonical
    assert not capsys.readouterr().err
    assert mcp_stdio.read_token(environ={"TGWITNESS_ARCHIVE_TOKEN": legacy}) == legacy
    warning = capsys.readouterr().err
    assert "deprecated" in warning and legacy not in warning
    private = tmp_path / "private-token"
    private.write_text(canonical)
    assert mcp_stdio.read_token(private, {}) == canonical
    with pytest.raises(ValueError):
        mcp_stdio.read_token(environ={"TGWITNESS_MCP_TOKEN": "panel-admin-token"})


@pytest.mark.parametrize("url", ["http://remote.example/mcp", "https://user:password@example.test/mcp",
                                 "https://example.test/mcp?token=secret", "https://example.test/mcp#fragment"])
def test_stdio_refuses_unsafe_urls(url):
    with pytest.raises(ValueError):
        mcp_stdio.check_url(url)


def test_runtime_install_command_uses_the_running_python():
    import sys
    status = mcp_server.runtime_status()
    assert status["available"] and status["sdk_version"]
    assert sys.executable in status["install_command"]
    assert "constraints-mcp.txt" in status["install_command"]
