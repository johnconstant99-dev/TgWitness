"""Commands that run beside the panel. Results go to stdout; progress and errors go to stderr.

Exit codes: 0 success, 1 failure, 2 usage error or invalid request, 3 unavailable now (the data directory is
open in a running panel, or the panel asks to retry later), 4 access refused."""
import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

COMMANDS = ("index", "search", "context", "messages", "stats", "export")
EXIT_FAILURE, EXIT_USAGE, EXIT_BUSY, EXIT_REFUSED = 1, 2, 3, 4
HTTP_EXITS = {401: EXIT_REFUSED, 403: EXIT_REFUSED, 404: EXIT_USAGE, 422: EXIT_USAGE, 429: EXIT_BUSY, 503: EXIT_BUSY}
WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


class Failure(Exception):
    def __init__(self, message, code=EXIT_FAILURE):
        super().__init__(message)
        self.code = code


def default_root():
    """TGWITNESS_DATA, ./data/live, or the data directory of the installation running this Python."""
    if os.environ.get("TGWITNESS_DATA"):
        return Path(os.environ["TGWITNESS_DATA"])
    local = Path("data/live")
    if local.is_dir():
        return local
    for folder in list(Path(sys.prefix).resolve().parents)[:3]:
        config = folder / "panel.json"
        try:
            if config.is_file():
                return Path(json.loads(config.read_text(encoding="utf-8"))["data"])
        except (OSError, ValueError, KeyError, TypeError):
            pass
        if (folder / "data" / "live" / "journal.sqlite3").is_file():
            return folder / "data" / "live"
    return local


def workspaces(root, selected=None):
    found = [("default", root)] if (root / "journal.sqlite3").is_file() else []
    profiles = root / "profiles"
    if profiles.is_dir():
        found += [(p.name, p) for p in sorted(profiles.iterdir()) if p.is_dir() and (p / "journal.sqlite3").is_file()]
    if selected not in (None, "all"):
        found = [item for item in found if item[0] == selected]
    return found


def labels(root):
    """Workspace names read without opening the journal for writing."""
    result = {}
    try:
        journal = sqlite3.connect(root / "journal.sqlite3")
        try:
            journal.execute("PRAGMA query_only=ON")
            rows = dict(journal.execute("SELECT key,value FROM settings WHERE key IN ('profile_label','profiles')"))
        finally:
            journal.close()
        result["default"] = json.loads(rows["profile_label"]) if "profile_label" in rows else "Main account"
        for entry in json.loads(rows.get("profiles", "[]")):
            result[entry["id"]] = entry["label"]
    except (sqlite3.Error, ValueError, KeyError, TypeError):
        pass
    return result


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


def progress_line(name):
    def report(status):
        print("  " + name + ": " + str(status.get("indexed_seq")) + " / " + str(status.get("head_seq")),
              file=sys.stderr, flush=True)
    return report


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
            status = store.fulltext.rebuild(background=False, progress=progress_line(name))
            return {"workspace": name, **status}
        finally:
            store.close()
    finally:
        lock.close()


def index(args):
    root = (args.data_dir or default_root()).resolve()
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


class Local:
    """A stopped workspace read in this process with full local access.

    Signed records are never changed; opening a workspace may bring its derived indexes up to date, as the panel does."""

    def __init__(self, root, workspace, budget):
        from .access import Principal
        from .archive import ArchiveReader
        from .security import InstanceLock
        from .store import Store
        paths = dict(workspaces(root))
        if workspace not in paths:
            raise Failure("No workspace " + repr(workspace) + " with a journal in " + str(root) + ".")
        try:
            self.lock = InstanceLock(paths[workspace])
        except RuntimeError:
            raise Failure("The panel has this workspace open. Stop it, or read through the panel with --url and an "
                          "archive connection token (Integrations → MCP).", EXIT_BUSY) from None
        try:
            self.store = Store(paths[workspace])
        except BaseException:
            self.lock.close()
            raise
        names = labels(root)
        state = SimpleNamespace(store=self.store, collector=SimpleNamespace(running=False))
        entries = {name: {"label": names.get(name, name),
                          "app": SimpleNamespace(state=state) if name == workspace else None} for name in paths}
        self.reader = ArchiveReader(SimpleNamespace(entries=entries), Principal(True, "Local command line"), budget)

    def guarded(self, action):
        from pydantic import ValidationError
        from .access import Refused
        try:
            return action()
        except Refused as exc:
            raise Failure(str(exc), EXIT_REFUSED) from None
        except ValidationError as exc:
            raise Failure(validation_text(exc.errors()), EXIT_USAGE) from None
        except ValueError as exc:
            raise Failure(str(exc), EXIT_USAGE) from None
        except TimeoutError as exc:
            raise Failure(str(exc), EXIT_BUSY) from None

    def query(self, body):
        from .archive import ArchiveQuery
        if body.get("ranked"):
            self.catch_up()
        return self.guarded(lambda: self.reader.read(ArchiveQuery(**body)))

    def catch_up(self):
        fulltext = self.store.fulltext
        if fulltext.lag() > 0:
            print("Updating the search index from the journal...", file=sys.stderr, flush=True)
            fulltext.catch_up(progress_line(self.store.root.name))

    def export(self, body):
        from .archive import ArchiveQuery
        lines = self.guarded(lambda: self.reader.export(ArchiveQuery(**body)))
        while (line := self.guarded(lambda: next(lines, None))) is not None:
            yield line

    def close(self):
        self.store.close()
        self.lock.close()


def validation_text(errors):
    if isinstance(errors, list):
        return "; ".join(str(error.get("msg", error)) if isinstance(error, dict) else str(error) for error in errors)
    return str(errors)


class Remote:
    """The panel's scoped archive API, read with an archive connection token."""

    def __init__(self, url, token):
        import requests
        from . import __version__
        from .mcp_server import endpoint
        url = url.rstrip("/")
        try:
            self.url = endpoint(url[:-4] if url.endswith("/mcp") else url)
        except ValueError as exc:
            raise Failure(str(exc), EXIT_USAGE) from None
        self.requests = requests
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({"Authorization": "Bearer " + token, "User-Agent": "TgWitness-CLI/" + __version__})

    def post(self, path, body, stream=False):
        try:
            response = self.session.post(self.url + path, json=body, timeout=(5, 60), allow_redirects=False, stream=stream)
        except self.requests.RequestException as exc:
            raise Failure("Could not reach the panel at " + self.url + " (" + type(exc).__name__ + ").") from None
        if response.status_code != 200:
            try:
                detail = response.json().get("detail")
            except ValueError:
                detail = None
            text = validation_text(detail) if detail else response.reason or "no detail"
            raise Failure("The panel refused the request (HTTP " + str(response.status_code) + "): " + text,
                          HTTP_EXITS.get(response.status_code, EXIT_FAILURE))
        return response

    def query(self, body):
        from .archive import MAX_RESPONSE
        response = self.post("/api/archive/query", body)
        if len(response.content) > MAX_RESPONSE * 2:
            raise Failure("The panel response exceeded the size limit.")
        return response.json()

    def export(self, body):
        response = self.post("/api/archive/export", body, stream=True)
        try:
            for line in response.iter_lines():
                if line:
                    yield json.loads(line)
        except (self.requests.RequestException, ValueError) as exc:
            raise Failure("The export stream was interrupted (" + type(exc).__name__ + ").") from None
        finally:
            response.close()

    def close(self):
        self.session.close()


def token_from(args):
    token = os.environ.get("TGWITNESS_MCP_TOKEN", "").strip()
    if not token and args.token_file:
        try:
            token = Path(args.token_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise Failure("Cannot read the token file: " + type(exc).__name__, EXIT_USAGE) from None
    if token and (not token.startswith("tgw_mcp_") or len(token) > 128 or any(c.isspace() for c in token)):
        raise Failure("Use an archive connection token issued in Integrations → MCP.", EXIT_USAGE)
    return token


def open_archive(args):
    url = args.url or os.environ.get("TGWITNESS_URL", "")
    if args.data_dir is not None and args.url:
        raise Failure("Choose either --data-dir (local) or --url (through the panel).", EXIT_USAGE)
    token = "" if args.data_dir is not None else token_from(args)
    if args.data_dir is None and (url or token):
        if not token:
            raise Failure("Set TGWITNESS_MCP_TOKEN or --token-file to an archive connection token.", EXIT_REFUSED)
        return Remote(url or "http://127.0.0.1:" + os.environ.get("TGWITNESS_PORT", "8787"), token)
    return Local((args.data_dir or default_root()).resolve(), args.workspace, args.timeout)


def moment(value, label):
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise Failure(label + " must be a date (2026-10-01) or an ISO time with a timezone.", EXIT_USAGE) from None
    if len(value) == 10:
        parsed = parsed.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        raise Failure(label + " needs a timezone, for example 2026-10-01T09:00+00:00.", EXIT_USAGE)
    return parsed.isoformat()


def period(args):
    return {"since": moment(args.since, "--since"), "until": moment(args.until, "--until")}


def compact(text, size=300):
    from .verify import safe_text
    text = safe_text(" ".join((text or "").split()))
    return text if len(text) <= size else text[:size] + "…"


def when(value):
    return value[:19].replace("T", " ") + " UTC" if isinstance(value, str) else "time unknown"


def item_line(item):
    source, sender = item["source"], item.get("sender") or {}
    who = ("@" + sender["username"] if sender.get("username") else sender.get("name")
           or ("sender " + str(sender["id"]) if sender.get("id") else "sender unknown"))
    marks = [mark for flag, mark in ((item.get("deletion_notice"), "deletion notice"),
                                     (item.get("missing_on_recheck"), "missing on recheck"),
                                     (item["kind"] == "message.edited", "edited version"),
                                     (item.get("text_truncated"), "text truncated")) if flag]
    if item.get("media_sha256"):
        marks.append("media " + item["media_sha256"][:16])
    line = ("#" + str(source["event_seq"]) + "  " + when(item.get("observed_at")) + "  chat " + str(source["chat_id"])
            + " · message " + str(source["message_id"]) + " · " + compact(who))
    if marks:
        line += " [" + ", ".join(marks) + "]"
    return line + "\n    " + (compact(item.get("text")) or "(no text)")


def print_items(result, empty="No saved observations match."):
    items = result.get("items", [])
    for item in items:
        print(item_line(item))
    if not items:
        print(empty)
    if result.get("next_offset") is not None and result.get("ranked"):
        print("More results: add --offset " + str(result["next_offset"]))
    elif result.get("next_before") is not None:
        print("Older records: add --before " + str(result["next_before"]))


def print_stats(result):
    scope = "chat " + str(result["chat_id"]) if result.get("chat_id") is not None else "all chats in scope"
    if result.get("sender_id") is not None:
        scope += ", sender " + str(result["sender_id"])
    print(scope + ": " + str(result["messages"]) + " messages from " + str(result["senders"]) + " senders"
          + ("" if result["complete"] else " (partial: time limit reached)"))
    if result.get("first_message_at"):
        print("Message times: " + when(result["first_message_at"]) + " to " + when(result["last_message_at"]))

    def percent(part):
        return str(part["messages"]) + (" (" + format(part["share"] * 100, ".1f") + "%)" if part["share"] is not None else "")
    print("Edited " + percent(result["edited"]) + " · deleted " + percent(result["deleted"])
          + " · missing on recheck " + percent(result["missing_on_recheck"]))
    print("By hour (UTC): " + " ".join(format(hour, "02") + ":" + str(count) for hour, count in enumerate(result["by_hour_utc"])))
    print("By weekday (UTC): " + " ".join(day + " " + str(count) for day, count in zip(WEEKDAYS, result["by_weekday_utc"])))
    if result["peaks"]["days"]:
        print("Busiest days: " + ", ".join(p["date"] + " (" + str(p["messages"]) + ")" for p in result["peaks"]["days"]))
    if result["participants"]:
        print("Senders:")
        for person in result["participants"]:
            name = " ".join(filter(None, (person.get("name"), "@" + person["username"] if person.get("username") else None)))
            print("  " + str(person["sender_id"] if person["sender_id"] is not None else "unknown") + "  "
                  + (compact(name) or "(no name observed)") + " — " + str(person["messages"]) + " messages, "
                  + str(person["edited"]) + " edited, " + str(person["deleted"]) + " deleted")
    for key, label in (("domains", "Domains"), ("handles", "@handles")):
        if result[key]:
            print(label + ": " + ", ".join(compact(entry[key[:-1]]) + " (" + str(entry["messages"]) + ")"
                                           for entry in result[key]))
    coverage = result["coverage"]
    print("Gap records: " + str(coverage["gap_records"]["count"]))
    liveness = coverage.get("collector_liveness")
    if liveness:
        print("Time without confirmed collection: " + str(round(liveness["unconfirmed_seconds"] / 3600, 1)) + " h in "
              + str(liveness["intervals"]) + " intervals")
    elif coverage.get("note"):
        print(coverage["note"])


def search(archive, args):
    if args.offset and args.exact or args.before and not args.exact:
        raise Failure("Use --offset with ranked search and --before with --exact.", EXIT_USAGE)
    body = {"tool": "search_messages", "workspace": args.workspace, "query": args.query, "chat_id": args.chat,
            "limit": args.limit, **period(args)}
    if args.exact:
        body.update(before=args.before)
    else:
        body.update(ranked=True, offset=args.offset, match="any" if args.any else "all")
    return archive.query(body), print_items


def context(archive, args):
    return archive.query({"tool": "get_message_context", "workspace": args.workspace, "chat_id": args.chat_id,
                          "message_id": args.message_id, "limit": args.limit, "before": args.before}), print_items


def messages(archive, args):
    if args.workspaces:
        result = archive.query({"tool": "list_workspaces", "offset": args.offset, "limit": args.limit})
        return result, lambda r: [print(w["workspace"] + "\t" + compact(w["name"])) for w in r["items"]]
    if args.chat_id is None:
        result = archive.query({"tool": "list_chats", "workspace": args.workspace, "offset": args.offset,
                                "limit": args.limit})
        return result, lambda r: [print(str(c["chat_id"]) + "\t" + (compact(c["title"]) or "(no title saved)") + "\t"
                                        + (c["kind"] or "") + ("" if c["enabled"] else "\tnot collected")) for c in r["items"]]
    if args.message is not None:
        return archive.query({"tool": "get_message_versions", "workspace": args.workspace, "chat_id": args.chat_id,
                              "message_id": args.message, "limit": args.limit, "before": args.before}), print_items
    return archive.query({"tool": "search_messages", "workspace": args.workspace, "chat_id": args.chat_id, "query": "",
                          "limit": args.limit, "before": args.before, **period(args)}), print_items


def stats(archive, args):
    return archive.query({"tool": "get_activity_stats", "workspace": args.workspace, "chat_id": args.chat,
                          "sender_id": args.sender, "limit": args.top, **period(args)}), print_stats


def export(archive, args):
    body = {"tool": "export_messages", "workspace": args.workspace, "chat_id": args.chat, **period(args)}
    target = Path(args.output) if args.output else None
    if target is not None and target.exists():
        raise Failure("The output file exists. Choose a new name.", EXIT_USAGE)
    partial = target.with_name(target.name + ".partial") if target else None
    if partial is not None and partial.exists():
        raise Failure("An interrupted export left " + str(partial) + ". Remove it or choose another name.", EXIT_USAGE)
    stream = open(partial, "x", encoding="utf-8", newline="\n") if partial else sys.stdout
    summary = None
    try:
        for line in archive.export(body):
            if "export_complete" in line:
                summary = line["export_complete"]
                break
            stream.write(json.dumps(line, ensure_ascii=False, separators=(",", ":")) + "\n")
        if summary is None:
            raise Failure("The export ended before its completion record; the output is incomplete.")
    except BaseException:
        if partial:
            stream.close()
            partial.unlink(missing_ok=True)
        raise
    if partial:
        stream.close()
        partial.replace(target)
    else:
        stream.flush()
    summary = {**summary, "output": str(target) if target else "stdout", "format": "jsonl"}
    print("Exported " + str(summary["records"]) + " records" + (" to " + str(target) if target else "") + ".",
          file=sys.stderr)
    if target is not None and args.json:
        return summary, None
    return None, None


def archive_command(args):
    try:
        archive = open_archive(args)
    except Failure as exc:
        print(str(exc), file=sys.stderr)
        return exc.code
    try:
        result, show = {"search": search, "context": context, "messages": messages, "stats": stats,
                        "export": export}[args.command](archive, args)
        if result is not None:
            if args.json or show is None:
                print(json.dumps(result, ensure_ascii=False, indent=1))
            else:
                show(result)
        return 0
    except Failure as exc:
        print(str(exc), file=sys.stderr)
        return exc.code
    except (OSError, sqlite3.Error) as exc:
        print(type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        return EXIT_FAILURE
    finally:
        archive.close()


def utf8_output():
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure") and (stream.encoding or "").lower() not in ("utf-8", "utf8"):
            stream.reconfigure(encoding="utf-8")


def main(argv=None):
    utf8_output()
    parser = argparse.ArgumentParser(prog="tgwitness", description="TgWitness command-line tools. Read-only except "
                                     "`index rebuild`, which rewrites only the derived search index.")
    commands = parser.add_subparsers(dest="command", required=True)
    search_index = commands.add_parser("index", help="Full-text search index: status or full rebuild")
    search_index.add_argument("action", choices=("status", "rebuild"))
    search_index.add_argument("--data-dir", type=Path, default=None,
                              help="Data directory (default TGWITNESS_DATA, data/live or this installation's data)")
    search_index.add_argument("--workspace", default="all", help="Workspace ID, default or all (default all)")
    search_index.add_argument("--json", action="store_true", help="Print one JSON document on stdout; progress stays on stderr")

    common = argparse.ArgumentParser(add_help=False)
    source = common.add_argument_group("archive")
    source.add_argument("--workspace", default="default", help="Workspace ID (default: default)")
    source.add_argument("--data-dir", type=Path, default=None,
                        help="Read a stopped workspace directly (default TGWITNESS_DATA, data/live or this installation's data)")
    source.add_argument("--url", help="Read through a running panel, e.g. https://panel.example (env TGWITNESS_URL; "
                                      "default http://127.0.0.1:8787 when a token is set)")
    source.add_argument("--token-file", help="File holding an archive connection token (or env TGWITNESS_MCP_TOKEN)")
    source.add_argument("--json", action="store_true", help="Print one JSON document on stdout")
    source.add_argument("--timeout", type=float, default=30, help="Seconds for local statistics (default 30)")
    dates = argparse.ArgumentParser(add_help=False)
    dates.add_argument("--since", help="Start date or ISO time with timezone")
    dates.add_argument("--until", help="End date or ISO time with timezone")

    def bounded(low, high):
        def parse(value):
            number = int(value)
            if not low <= number <= high:
                raise argparse.ArgumentTypeError("choose " + str(low) + " to " + str(high))
            return number
        return parse

    found = commands.add_parser("search", parents=[common, dates], help="Search saved messages; best matches first")
    found.add_argument("query", help='Words, "exact phrase", domain, @username, chat:ID, from:ID')
    found.add_argument("--chat", type=int, help="Chat ID")
    found.add_argument("--any", action="store_true", help="Match any word instead of all")
    found.add_argument("--exact", action="store_true", help="Exact text, newest first, without the index")
    found.add_argument("--limit", type=bounded(1, 50), default=20)
    found.add_argument("--offset", type=bounded(0, 1000), default=0, help="Next page of ranked results")
    found.add_argument("--before", type=int, help="Next page of --exact results (journal sequence)")
    nearby = commands.add_parser("context", parents=[common], help="Saved messages within ten IDs of one message")
    nearby.add_argument("chat_id", type=int)
    nearby.add_argument("message_id", type=int)
    nearby.add_argument("--limit", type=bounded(1, 50), default=20)
    nearby.add_argument("--before", type=int, help="Next page (journal sequence)")
    listed = commands.add_parser("messages", parents=[common, dates],
                                 help="Saved messages of a chat, newest first; without a chat, the chats you can read")
    listed.add_argument("chat_id", type=int, nargs="?")
    listed.add_argument("--message", type=int, help="Every saved version and deletion record of one message")
    listed.add_argument("--workspaces", action="store_true", help="List the workspaces you can read")
    listed.add_argument("--limit", type=bounded(1, 50), default=20)
    listed.add_argument("--offset", type=bounded(0, 100000), default=0, help="Next page of chats or workspaces")
    listed.add_argument("--before", type=int, help="Next page of messages (journal sequence)")
    counted = commands.add_parser("stats", parents=[common, dates], help="Activity by hour and weekday, edits, "
                                  "deletions, senders, domains and @handles")
    counted.add_argument("--chat", type=int, help="Chat ID (default: every chat in scope)")
    counted.add_argument("--sender", type=int, help="Sender ID")
    counted.add_argument("--top", type=bounded(1, 50), default=10, help="Senders, domains and @handles to list")
    dumped = commands.add_parser("export", parents=[common, dates], help="Saved observations as JSON Lines in journal order")
    dumped.add_argument("--chat", type=int, help="Chat ID (default: every chat in scope)")
    dumped.add_argument("--output", help="Write to this new file instead of stdout")
    args = parser.parse_args(argv)
    if args.command == "index":
        return index(args)
    return archive_command(args)
