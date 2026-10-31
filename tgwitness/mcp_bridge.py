"""Compatibility entry point; use tgwitness.mcp_server for all MCP transports."""
import sys

from .mcp_stdio import check_url, read_token  # noqa: F401


def main(argv=None):
    from .mcp_server import main as canonical_main
    print("tgwitness.mcp_bridge is deprecated; use tgwitness.mcp_server.", file=sys.stderr)
    canonical_main(argv)


if __name__ == "__main__":
    main()
