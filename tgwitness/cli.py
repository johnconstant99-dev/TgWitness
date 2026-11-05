"""Commands that run beside the panel. Results go to stdout; progress and errors go to stderr.

Exit codes: 0 success, 1 failure, 2 usage error, 3 the data directory is open in a running panel."""
import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

COMMANDS = ("index",)
EXIT_FAILURE, EXIT_USAGE, EXIT_BUSY = 1, 2, 3


def workspaces(root, selected=None):
    found = [("default", root)] if (root / "journal.sqlite3").is_file() else []
    profiles = root / "profiles"
    if profiles.is_dir():
        found += [(p.name, p) for p in sorted(profiles.iterdir()) if p.is_dir() and (p / "journal.sqlite3").is_file()]
    if selected not in (None, "all"):
        found = [item for item in found if item[0] == selected]
    return found


def stored_status(name, root):
    """Index state read without opening the journal for writing; safe while the panel runs."""
    result = {"workspace": name}
    journal = sqlite3.connect(root / "journal.sqlite3")
    try:
        journal.execute("PRAGMA query_only=ON")
        head = journal.execute("SELECT coalesce(max(seq),0) FROM events").fetchone()[0]
        row = journal.execute("SELECT value FROM settings WHERE key='fulltext'").fetchone()
    finally:
        journal.close()
    from .fulltext import MODES
    mode = (json.loads(row[0]) if row else {}).get("mode") or os.environ.get("TGWITNESS_FULLTEXT", "disk")
    result.update(mode=mode if mode in MODES else "disk", head_seq=head)
    path = root / "search" / "fulltext.sqlite3"
    if result["mode"] != "disk" or not path.is_file():
        result["state"] = result["mode"] if result["mode"] != "disk" else "not built"
        return result
    index = sqlite3.connect(path)
    try:
        index.execute("PRAGMA query_only=ON")
        state = {key: json.loads(value) for key, value in index.execute("SELECT key,value FROM fulltext_state")}
    finally:
        index.close()
    result.update(state="ready" if state.get("seq") == head else "building", indexed_seq=state.get("seq"),
                  indexed_hash=state.get("hash"), documents=state.get("documents"), analyzer=state.get("analyzer"))
    return result


def rebuild(name, root):
    from .fulltext import configured_mode
    from .security import InstanceLock
    from .store import Store
    lock = InstanceLock(root)
    try:
        store = Store(root)
        try:
            mode = configured_mode(store)
            if mode != "disk":
                return {"workspace": name, "mode": mode, "state": mode,
                        "note": "Nothing is stored on disk in this mode; the panel builds the index when it starts."
                        if mode == "memory" else "Full-text search is off for this workspace."}
            def progress(status):
                print("  " + name + ": " + str(status.get("indexed_seq")) + " / " + str(status.get("head_seq")),
                      file=sys.stderr, flush=True)
            status = store.fulltext.rebuild(background=False, progress=progress)
            return {"workspace": name, **status}
        finally:
            store.close()
    finally:
        lock.close()


def index(args):
    root = (args.data_dir or Path(os.environ.get("TGWITNESS_DATA", "data/live"))).resolve()
    found = workspaces(root, args.workspace)
    if not found:
        print("No workspace journal found in " + str(root), file=sys.stderr)
        return EXIT_FAILURE
    results = []
    for name, path in found:
        try:
            results.append(stored_status(name, path) if args.action == "status" else rebuild(name, path))
        except RuntimeError as exc:
            print(str(exc) + " Stop the panel, or use Journal → Search index → Rebuild.", file=sys.stderr)
            return EXIT_BUSY
        except (OSError, sqlite3.Error, ValueError) as exc:
            print(name + ": " + type(exc).__name__ + ": " + str(exc), file=sys.stderr)
            return EXIT_FAILURE
    if args.json:
        print(json.dumps({"workspaces": results}, ensure_ascii=False, indent=1))
    else:
        for item in results:
            line = item["workspace"] + ": " + item.get("state", "unknown") + " (" + item.get("mode", "?") + ")"
            if item.get("indexed_seq") is not None:
                line += ", indexed " + str(item["indexed_seq"]) + " of " + str(item["head_seq"]) + " journal records"
            print(line)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="tgwitness", description="TgWitness command-line tools")
    commands = parser.add_subparsers(dest="command", required=True)
    search_index = commands.add_parser("index", help="Full-text search index: status or full rebuild")
    search_index.add_argument("action", choices=("status", "rebuild"))
    search_index.add_argument("--data-dir", type=Path, default=None,
                              help="Data directory (default data/live, env TGWITNESS_DATA)")
    search_index.add_argument("--workspace", default="all", help="Workspace ID, default or all (default all)")
    search_index.add_argument("--json", action="store_true", help="Print one JSON document on stdout; progress stays on stderr")
    args = parser.parse_args(argv)
    return index(args)
