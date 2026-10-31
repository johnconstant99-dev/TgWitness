import argparse
import os
import sys
import threading
from pathlib import Path

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def should_open_browser(host, no_browser, environ=os.environ, interactive=None):
    """Only a person starting the panel on this computer gets a browser tab: never in Docker,
    services, scheduled tasks or scripts, and never for an address reachable from elsewhere."""
    if interactive is None:

        interactive = all(stream is not None and getattr(stream, "isatty", lambda: False)()
                          for stream in (sys.stdin, sys.stdout))
    return interactive and host in LOOPBACK and not no_browser and not environ.get("TGWITNESS_NO_BROWSER")


def open_when_ready(url, host, port, token_file=None, timeout=60):
    """Open the panel once it answers. For a real workspace, show the token in this console,
    as the Docker helper does; the token never goes into the address bar or browser history."""
    import socket
    import time
    import webbrowser
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                break
        except OSError:
            time.sleep(0.3)
    else:
        return False
    if token_file is not None and token_file.is_file():
        print("Panel token:", token_file.read_text(encoding="utf-8").strip(), flush=True)
    webbrowser.open(url)
    return True


def main():
    parser = argparse.ArgumentParser(description="TgWitness observation journal")
    parser.add_argument("--host", default=os.environ.get("TGWITNESS_HOST", "127.0.0.1"),
                        help="Listen address (default 127.0.0.1, env TGWITNESS_HOST). Expose remotely only behind HTTPS")
    parser.add_argument("--port", type=int, default=os.environ.get("TGWITNESS_PORT", "8787"),
                        help="Listen port (default 8787, env TGWITNESS_PORT)")
    parser.add_argument("--data-dir", type=Path, default=None,
                        help="Data directory (default data/live, or data/demo with --demo; env TGWITNESS_DATA)")
    parser.add_argument("--demo", action="store_true", help="Use a separate synthetic journal; Telegram login disabled")
    parser.add_argument("--check", action="store_true", help="Check local installation, storage, keys and port; do not start")
    parser.add_argument("--json", action="store_true", help="JSON output for --check")
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not open the panel in a browser (env TGWITNESS_NO_BROWSER)")
    args = parser.parse_args()
    root = (args.data_dir or Path(os.environ.get("TGWITNESS_DATA", "data/demo" if args.demo else "data/live"))).resolve()
    if args.check:
        from .doctor import inspect_environment, print_report
        report = inspect_environment(root, args.host, args.port)
        print_report(report, args.json)
        raise SystemExit(0 if report["ready"] else 1)
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")
    import uvicorn
    from .app import create_app
    from .logging_config import server_logging
    print("TgWitness")
    host = "127.0.0.1" if args.host == "0.0.0.0" else "[" + args.host + "]" if ":" in args.host else args.host
    url = "http://" + host + ":" + str(args.port)
    print("Panel: " + url)
    print("Data directory:", root)
    if args.demo:
        print("Local demo opens without copying a token. Real account authorization is disabled.")
        print("For remote demo access, read", root / "panel-token.txt", "after startup.")
    else:
        print("Panel token: read", root / "panel-token.txt", "after startup (or use TGWITNESS_TOKEN).")
    print("For remote access, place the panel behind HTTPS or use an SSH tunnel.", flush=True)
    if should_open_browser(args.host, args.no_browser):
        print("Opening the panel in your browser. Keep this window open while observing.", flush=True)
        threading.Thread(target=open_when_ready, daemon=True,
                         args=(url, args.host, args.port, None if args.demo else root / "panel-token.txt")).start()
    uvicorn.run(create_app(root, demo=args.demo), host=args.host, port=args.port, workers=1,
                access_log=False, log_level="info", log_config=server_logging(root))


if __name__ == "__main__":
    main()
