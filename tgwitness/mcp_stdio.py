"""Stdio transport helpers for the canonical tgwitness.mcp_server entry point."""
import ipaddress
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit


def check_url(value):
    parsed = urlsplit(value)
    if not parsed.hostname or parsed.scheme not in ("http", "https") or any((
            parsed.username, parsed.password, parsed.query, parsed.fragment)):
        raise ValueError("Use an MCP URL without credentials, query parameters or fragments.")
    try:
        local = parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        local = False
    if parsed.scheme != "https" and not local:
        raise ValueError("Remote MCP connections require HTTPS.")
    return value.rstrip("/")


def read_token(token_file=None, environ=None):
    environ = os.environ if environ is None else environ
    token = environ.get("TGWITNESS_MCP_TOKEN", "").strip()
    if not token and token_file:
        token = Path(token_file).read_text(encoding="utf-8").strip()
    if not token and environ.get("TGWITNESS_ARCHIVE_TOKEN"):
        token = environ["TGWITNESS_ARCHIVE_TOKEN"].strip()
        print("TGWITNESS_ARCHIVE_TOKEN is deprecated; use TGWITNESS_MCP_TOKEN.", file=sys.stderr)
    if not token.startswith("tgw_mcp_") or len(token) > 128 or any(c.isspace() for c in token):
        raise ValueError("Set TGWITNESS_MCP_TOKEN to an MCP connection token issued in Integrations.")
    return token


async def relay(url, token):
    import anyio
    import httpx2
    from mcp.client.streamable_http import streamable_http_client
    from mcp.server.stdio import stdio_server

    async with httpx2.AsyncClient(headers={"Authorization": "Bearer " + token}, timeout=15,
                                  trust_env=False, follow_redirects=False) as http, \
            stdio_server() as (from_client, to_client), \
            streamable_http_client(url, http_client=http) as (from_panel, to_panel):
        async with anyio.create_task_group() as group:
            async def copy(source, destination):
                async for message in source:
                    if isinstance(message, Exception):
                        # Do not print request headers, URLs or credential-bearing exception text.
                        print("TgWitness MCP transport failed: " + type(message).__name__, file=sys.stderr)
                    else:
                        await destination.send(message)
                group.cancel_scope.cancel()
            group.start_soon(copy, from_client, to_panel)
            group.start_soon(copy, from_panel, to_client)
