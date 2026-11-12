import ast
import json
import re
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "tgwitness"
STATIC = PACKAGE / "static"
LITERAL = re.compile(r'''(["'])((?:\\[\s\S]|(?!\1)[^\\\r\n])*)\1''')

PANEL_MODULES = ("app.py", "collector.py", "account_import.py", "session_import.py", "tdata.py", "sessions.py", "network.py",
                 "profiles.py", "distributed_export.py", "message_selection.py",
                 "alerts.py", "witness_api.py", "tuning.py", "interactions.py",
                 "access.py", "history.py", "history_cursor.py", "history_transport.py", "history_admin.py",
                 "archive.py", "archive_api.py", "ai.py", "analysis.py", "analysis_api.py",
                 "media_analysis.py", "media_analysis_api.py", "webhooks.py", "webhook_api.py", "proxy_catalog.py",
                 "proxy_sources.py", "account_export.py", "account_export_transport.py", "account_report.py", "disclosure.py",
                 "cloud_wizard.py", "levels.py", "capture_api.py", "capture_connections.py", "fulltext.py", "search_api.py", "gap_analysis.py")

DYNAMIC_SCRIPT_KEYS = (
    "Inline diff", "Side by side", "Raw", "Previously observed", "Newly observed version",
    "All", "Priority", "Paused", "Unconfirmed access", "Enable selected", "Pause selected",
    "Mark priority", "Add selected", "Add all matching", "SHA-256", "Message ID", "Sender ID",
    "Link to this record",
    "Messages", "Edits", "Deletions", "Reactions", "Membership", "Attachments", "Actions", "Collection",
    "All events", "All sources", "Any time", "1 hour", "24 hours", "7 days", "Custom", "Custom period",
    "From (UTC)", "Until (UTC)", "Apply dates", "Close", "Clear filters",
    "Newer records", "Older records", "Latest", "Previous record", "Next record", "Open in chat",
    "Recent activity", "Most deletions", "Most edits", "Name", "Sort", "Filters", "Type", "State",
    "Channels", "Groups", "Bots", "Private chats", "Auto-discovered", "Access unconfirmed", "Excluded",
    "Paused", "Priority", "Mark regular", "Mark priority", "No chats match these filters.",
    "Recheck", "Media", "People", "Notifications", "Exports", "Gaps", "Chat state", "Telegram", "MTProxy",
        "Metrics",
    "Photos", "Videos", "GIFs & animations", "Round video messages", "Voice messages", "Music & audio", "Stickers", "Files & documents",
    "Show affected sources", "Exclude from scope", "Ignore until visible", "Enable downloads", "Download the account loss report",
    "Clear waiting queue", "Skip download-disabled notices",
    "Install MCP support in this Python environment and restart TgWitness.",
    "MCP support is installed. Restart TgWitness to activate the endpoint.",
    "visible to this account during the recorded acquisition intervals",
    "Version on GitHub", "A few seconds", "Cloudflare tunnel and address", "Hetzner firewall and server",
    "Usually under a minute", "TgWitness installs itself on the server",
    "Usually several minutes; the panel waits up to 30", "The server answers with its signing key",
    "Hetzner server and firewall", "Cloudflare address and tunnel", "Done", "Up and running", "Server deleted",
    "Starting",
    "Open the panel address and sign in with the panel token.", "Connect a Telegram account in the server's panel.",
    "Choose the chats to observe.", "Save the deployment record",
    "Phala Cloud confidential virtual machine", "Usually a few minutes", "TgWitness installs itself in the confidential virtual machine",
    "Usually several minutes; the panel waits up to 40", "The server answers with its signing key and Intel's attestation",
    "Save the measured docker-compose file",
    "Newest first · exact text", "Best match · word forms", "Recognized images (OCR)", "Transcripts",
    "Messages and recognition", "Search index on disk", "Search index in memory only", "Search index off",
    "Rebuild index",
)


def js_literal(body):
    escapes = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "0": "\0"}
    def replace(match):
        value = match.group(1)
        if value.startswith("u{"):
            return chr(int(value[2:-1], 16))
        if value[0] in {"u", "x"} and len(value) > 1:
            return chr(int(value[1:], 16))
        if value in {"\n", "\r", "\r\n"}:
            return ""
        return escapes.get(value, value)
    value = re.sub(r"\\(u\{[a-fA-F0-9]+\}|u[a-fA-F0-9]{4}|x[a-fA-F0-9]{2}|\r\n|[\s\S])", replace, body)
    return value.encode("utf-16-le", "surrogatepass").decode("utf-16-le")


def calls(source):
    for match in re.finditer(r"(?<![\w.$])(?:[A-Za-z_$][\w$]*\.)?trn?\(", source):
        depth, i, quote = 1, match.end(), None
        while depth and i < len(source):
            ch = source[i]
            if quote:
                if ch == "\\":
                    i += 1
                elif ch == quote:
                    quote = None
            elif ch in "\"'`":
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        yield match.group().endswith("trn("), source[match.end():i - 1]


def text_arguments(body, count):
    depth, quote, start, i = 0, None, 0, 0
    while i < len(body):
        ch = body[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            yield body[start:i]
            count -= 1
            if not count:
                return
            start = i + 1
        i += 1
    if count:
        yield body[start:]


def script_keys(source):
    keys = []
    for plural, body in calls(source):
        for argument in text_arguments(body, 2 if plural else 1):
            for match in LITERAL.finditer(argument):
                if re.search(r"[=!]==?\s*$", argument[:match.start()]):
                    continue
                text = js_literal(match.group(2))
                if re.search(r"[A-Za-z]{2}", text):
                    keys.append(text)
    return list(dict.fromkeys(keys))


def all_script_keys(package=PACKAGE):
    keys = list(DYNAMIC_SCRIPT_KEYS)
    static = package / "static"
    paths = list(static.glob("*.js"))
    for folder in ("core", "components", "views"):
        paths.extend((static / folder).glob("*.js"))
    for path in sorted(paths):
        if path.name == "sealed.js":
            continue
        source = path.read_text(encoding="utf-8")
        keys += script_keys(source)
        if path.name in {"system-map.js", "system-map-scene.js"}:
            keys += [js_literal(match.group(2)) for match in LITERAL.finditer(source)
                     if re.match(r"^[A-Z][A-Za-z]", match.group(2))
                     and not re.search(r"[<>{}\n]", match.group(2))]
            keys += [js_literal(match.group(2)) for match in re.finditer(r"(?<![\w.$])t\((['\"])((?:\\[\s\S]|(?!\1)[^\\\r\n])*)\1\)", source)
                     if re.search(r"[A-Za-z]{2}", match.group(2))]
    observer = ast.parse((package / "network_observer.py").read_text(encoding="utf-8"))
    keys += [item.value for item in ast.walk(observer) if isinstance(item, ast.Constant)
             and isinstance(item.value, str) and re.match(r"^[A-Z][a-z]+ ", item.value)]

    return list(dict.fromkeys(keys))


def server_keys():
    keys = []
    for name in PANEL_MODULES:
        tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            texts = []
            if isinstance(node, ast.Call):
                func = getattr(node.func, "id", None) or getattr(node.func, "attr", "")
                if func in ("HTTPException", "ValueError", "RouteError", "Refused", "WizardError"):
                    texts = node.args
                elif name == "disclosure.py" and func == "append" and isinstance(node.func.value, ast.Name) \
                        and node.func.value.id == "warnings":
                    texts = node.args[:1]
                elif func in ("tr", "Invalid") and len(node.args) > 1:
                    texts = node.args[1:2]
            elif isinstance(node, ast.Return) and name == "alerts.py":
                texts = [node.value]
            elif isinstance(node, ast.Assign) and any(
                    isinstance(target, ast.Name) and (name, target.id) in {
                        ("disclosure.py", "WARNINGS"), ("account_export.py", "LIMITATIONS")}
                    for target in node.targets):
                texts = node.value.elts if isinstance(node.value, (ast.List, ast.Tuple)) else []
            for arg in texts:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and " " in arg.value:
                    keys.append(arg.value)

    if str(PACKAGE.parent) not in sys.path:
        sys.path.insert(0, str(PACKAGE.parent))
    from tgwitness.tuning import texts
    from tgwitness.account_report import text_keys as account_report_keys
    from tgwitness.modes import texts as mode_texts
    return list(dict.fromkeys(keys + texts() + account_report_keys() + mode_texts()))


if __name__ == "__main__":
    json.dump({"script": all_script_keys(), "server": server_keys()}, sys.stdout, ensure_ascii=False, indent=1)
