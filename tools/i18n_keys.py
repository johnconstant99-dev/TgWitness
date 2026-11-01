"""List the English interface strings that the translations in tgwitness/locales must cover.

Script keys are the strings passed to tr()/trn() in the panel scripts. Server keys are the fixed
messages the panel can show from the server and the notification texts. Keys of the static pages
are listed in the browser by pageKeys() and checked by tools/check_browser.py.
"""
import ast
import json
import re
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "tgwitness"
STATIC = PACKAGE / "static"
LITERAL = re.compile(r'''(["'])((?:\\[\s\S]|(?!\1)[^\\\r\n])*)\1''')

PANEL_MODULES = ("app.py", "collector.py", "account_import.py", "tdata.py", "sessions.py", "network.py",
                 "profiles.py", "multi_export.py", "alerts.py", "witness_api.py", "tuning.py", "interactions.py",
                 "access.py", "history.py", "archive.py", "archive_api.py", "ai.py", "analysis.py", "analysis_api.py",
                 "media_analysis.py", "media_analysis_api.py", "webhooks.py", "webhook_api.py", "proxy_catalog.py",
                 "proxy_sources.py", "account_export.py", "account_export_transport.py", "account_report.py", "disclosure.py")

# Labels passed through small renderer tables (tr(label)), rather than literal tr() calls.
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
    "Recheck", "Media", "People", "Notifications", "Exports", "Telegram", "MTProxy",
    "Photos", "Videos", "GIFs & animations", "Round video messages", "Voice messages", "Music & audio", "Stickers", "Files & documents",
    "Show affected sources", "Exclude from scope", "Ignore until visible", "Enable downloads",
    "Clear waiting queue", "Skip download-disabled notices",
    "Install MCP support in this Python environment and restart TgWitness.",
    "MCP support is installed. Restart TgWitness to activate the endpoint.",
    "visible to this account during the recorded acquisition intervals",
)


def js_literal(body):
    """Decode a quoted JS string's contents without evaluating source code."""
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
    """Yield the source text of every tr(...)/trn(...) call, including nested calls."""
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
        yield source[match.end():i - 1]


def script_keys(source):
    keys = []
    for body in calls(source):

        for match in LITERAL.finditer(body):
            if re.search(r"[=!]==?\s*$", body[:match.start()]):
                continue
            text = js_literal(match.group(2))
            if re.search(r"[A-Za-z]{2}", text):
                keys.append(text)
    return list(dict.fromkeys(keys))


def all_script_keys():
    keys = list(DYNAMIC_SCRIPT_KEYS)
    paths = list(STATIC.glob("*.js"))
    for folder in ("core", "components", "views"):
        paths.extend((STATIC / folder).glob("*.js"))
    for path in sorted(paths):
        keys += script_keys(path.read_text(encoding="utf-8"))

    return list(dict.fromkeys(keys))


def server_keys():
    keys = []
    for name in PANEL_MODULES:
        tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            texts = []
            if isinstance(node, ast.Call):
                func = getattr(node.func, "id", None) or getattr(node.func, "attr", "")
                if func in ("HTTPException", "ValueError", "RouteError", "Refused"):
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
    return list(dict.fromkeys(keys + texts() + account_report_keys()))


if __name__ == "__main__":
    json.dump({"script": all_script_keys(), "server": server_keys()}, sys.stdout, ensure_ascii=False, indent=1)
