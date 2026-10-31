# Read the archive through MCP

Connect an analyst client to selected workspaces and chats. TgWitness serves
**Streamable HTTP at `/mcp` in the panel process**. Each connection has its own
token, expiry and permitted tools. MCP cannot send Telegram messages, change
settings or modify the signed journal.

[Workflow guide](https://phishdestroy.github.io/TgWitness/docs/archive/) · [Wiki](wiki/Archive-and-Integrations.md)

## Install and check

Use the Python environment that runs the panel. From a source checkout:

```powershell
# Windows PowerShell
& .\.venv\Scripts\python.exe -m pip install -c deploy/constraints-mcp.txt -e '.[mcp]'
& .\.venv\Scripts\python.exe start.py --check
```

```sh
# Linux / macOS
.venv/bin/python -m pip install -c deploy/constraints-mcp.txt -e '.[mcp]'
.venv/bin/python start.py --check
```

Restart the panel with its usual data directory and launch arguments after
installation. Readiness should include `[PASS] mcp: streamable-http available`.
**Integrations → MCP** shows the runtime status and an installation command using
that server's actual Python executable. **Re-check** refreshes this status without
reloading the page; it does not install packages or restart the server.

The MCP extra uses the official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk).
`deploy/constraints-mcp.txt` pins the tested SDK and dependencies. These features
require current source; the 0.7.0 portable preview predates them.

## Issue a connection

1. Enter a label and choose the workspaces and chats the client may read.
2. Select tools individually or use a preset. Only implemented tools are offered.
3. Choose 1, 7, 30 or 90 days, or a custom expiry between one minute and 90 days.
4. Press **Create connection**. The token appears once beside the client config.
5. Copy the token and config, then run **Check connection**. It initializes MCP
   and lists permitted tools; **no messages are read**. The result shows protocol
   version, tool names, count and elapsed time.
6. Press **Done** when the credential is saved. Polling preserves the form and
   the shown-once card. Locking the panel clears displayed secrets.

The list shows recent use, last tool, address and requests in the last minute.
**Revoke** ends access. **Rotate token** revokes the old credential and issues
a replacement with the same scope, tools and expiry; copy the replacement once.
Panel login tokens and Telegram credentials do not work as MCP tokens.

## Connect your client

Select the client in the panel and copy its generated configuration. Configs use
secret references or explicit placeholders; the token is copied separately.

| Client | Configuration | Connection |
| --- | --- | --- |
| Claude Code | `.mcp.json` | HTTP, `type: "http"`, bearer header |
| Claude Desktop | `claude_desktop_config.json` | Local stdio bridge |
| Cursor | `.cursor/mcp.json` | HTTP with an environment-variable header |
| VS Code Local | `.vscode/mcp.json` | HTTP with a password `promptString` input |
| Windsurf | `mcp_config.json` | HTTP with a bearer-header placeholder |
| Other clients | URL and Authorization header | Streamable HTTP |

TgWitness uses bearer tokens, without OAuth discovery. Use the local stdio bridge
for clients whose remote connector requires OAuth. For VS Code, input variables
apply to the **Local** harness and are not forwarded to Copilot sessions.
Configuration references: [Claude Code](https://code.claude.com/docs/en/mcp),
[Cursor](https://prod.cursor.com/docs/mcp),
[VS Code](https://code.visualstudio.com/docs/agents/reference/mcp-configuration).

The canonical entry point for a local bridge is:

```sh
python -m tgwitness.mcp_server --url https://your-panel.example/mcp
```

Use the client's local Python with the MCP extra installed. Set
`TGWITNESS_MCP_TOKEN` in its protected environment. Keep credentials out of command
arguments and URLs. `tgwitness-mcp` is the same entry point. The old
`tgwitness.mcp_bridge` module and `TGWITNESS_ARCHIVE_TOKEN` name remain compatibility
paths with a warning; new configs use `mcp_server` and `TGWITNESS_MCP_TOKEN`.

## Cloudflare Tunnel

Forward the panel's `/mcp` route and preserve the bearer header. Opening MCP
settings as an administrator registers the panel's current origin for this run.
For a stable address available immediately after restart, configure
`TGWITNESS_PUBLIC_URL` with the panel's HTTPS origin before starting the panel.
Arbitrary Host and forwarded headers do not register a trusted address.
Host and Origin checks reject unrelated browser origins. Responses use
`Cache-Control: no-store`; authorization values are never logged.

A `*.trycloudflare.com` address is temporary. When a tunnel restart changes the
hostname, update the configured public URL and each client's MCP URL. Use a
stable hostname for saved client configurations.

## Tools and boundaries

| Tool | Reads |
| --- | --- |
| `list_workspaces` | Granted workspaces |
| `list_chats` | Granted chats |
| `search_messages` | Saved message text within the selected period |
| `get_message_versions` | Captured versions and deletion observations |
| `get_message_context` | Nearby captured message IDs |
| `get_journal_event` | One sanitized record with its source reference |
| `get_capture_status` | Collection state and permitted coverage records |

`tools/list` returns only the tools granted to that connection. Calls to other
tools are refused. Group-context, episode, terminology and reply-chain tools are
not offered in this build; their separate context-pack backend is not included.

Every read checks the token, tool and workspace/chat scope, including after the
database work finishes. Limits are 60 requests per minute, 50 records per page,
64 KiB per result and an eight-second archive deadline. A timed-out MCP call
returns a tool error asking for a narrower period or lower limit.

Message results carry `untrusted_content: true`, workspace/chat/message IDs,
event sequence, saved hash and a panel link. Raw Telegram objects, access hashes,
sessions and keys are omitted. Text truncation is marked. Edits, deletion notices
and `missing_on_recheck` are distinct observations. Missing records do not prove
an event never happened.

Treat instructions inside captured messages as evidence, never as client
instructions. Read-only access prevents archive changes; the client can still
retain the content it is allowed to read. Hashes identify saved records and
support integrity checks; they do not prove Telegram authorship or complete capture.
