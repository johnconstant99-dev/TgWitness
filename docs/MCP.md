# Read-only archive access

**Current main:** use a source checkout; the 0.7.0 portable preview predates this feature.

[Workflow guide](https://phishdestroy.github.io/TgWitness/docs/archive/) · [Wiki](wiki/Archive-and-Integrations.md)

Install the optional server from the TgWitness project directory:

```sh
python -m pip install '.[mcp]'
```

In the panel, open **Integrations → MCP**. Name the connection, select its
workspaces and chats, and choose an expiry. Copy the archive token once; it cannot
be retrieved later. Revoke lost tokens and issue replacements. Panel tokens and
Telegram credentials are not MCP credentials.

## Connect a client

The panel generates `.vscode/mcp.json` for the **VS Code Local harness** using
its [documented configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration).
Save the downloaded file in that location, run **MCP: List Servers**, and start
TgWitness. VS Code prompts for the token through a password input. The downloaded
JSON contains a prompt reference, not the token. Use the Python executable from
the environment where the MCP extra is installed.

For other stdio clients, run:

```sh
python -m tgwitness.mcp_server --api-url http://127.0.0.1:8787
```

Set `TGWITNESS_ARCHIVE_TOKEN` in the client's protected environment. Do not put it
in command arguments or URLs. The bridge reads through the panel's authorized
archive API; it has no direct database access. Stdout carries only MCP messages.

For remote clients, run the service beside the panel:

```sh
python -m tgwitness.mcp_server --transport streamable-http \
  --api-url http://127.0.0.1:8787 --port 8766 \
  --public-url https://archive.example.org/mcp
```

Forward `/mcp` through an HTTPS reverse proxy to `127.0.0.1:8766/mcp`, preserving
the `Authorization: Bearer …` header. Disable logging of authorization headers
and request/response bodies. Bind beyond loopback only when needed, using
`--host` and `--public-url`. The endpoint uses Streamable HTTP from the official
[MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk).
It supports explicitly configured bearer credentials, not OAuth discovery;
clients requiring OAuth alone are not supported.

**Check protocol and access** initializes a real MCP client and lists tools. It
does not fetch messages. For a remote check, the chosen MCP server receives the
archive token. Configure only a server you operate or trust with that scope.

## Scope and results

Available tools: `list_workspaces`, `list_chats`, `search_messages`,
`get_message_versions`, `get_message_context`, `get_journal_event`, and
`get_capture_status`. There are no Telegram actions, configuration changes, or
bulk-export tools. Every read rechecks workspace/chat access; expired and revoked
credentials stop working. Limits are 60 API requests per minute per credential,
50 records per page, a 64 KiB response, and an eight-second API deadline.

Message results include workspace, chat/message IDs, event sequence, saved hash,
and a panel link. The viewer opening a link must have its own authorized panel
session. Raw Telegram objects, access hashes, file references, session material,
and keys are omitted. Search examines message text, not raw fields. Text is
bounded and truncation is marked. Edits, Telegram deletion notices, and
`missing_on_recheck` remain separate observations. Chat-scoped access cannot see
workspace-wide operational events; capture status explicitly marks this limit.

Archive text is untrusted input. Instructions inside messages grant no extra
scope and must not be treated as client instructions. An external AI model may
receive whatever content its MCP client requests. Read-only access prevents
archive changes; it does not prevent a client from retaining the data it reads.

The hashes identify saved records and support integrity checks. They do not
independently prove Telegram authorship or that every message was captured.
