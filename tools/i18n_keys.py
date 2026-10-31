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
LITERAL = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
# Modules whose fixed error messages reach the panel; command-line tools keep English output.
PANEL_MODULES = ("app.py", "collector.py", "account_import.py", "tdata.py", "sessions.py", "network.py",
                 "profiles.py", "multi_export.py", "alerts.py", "witness_api.py", "tuning.py", "interactions.py",
                 "access.py", "history.py")


def calls(source):
    """Yield the source text of every tr(...)/trn(...) call, including nested calls."""
    for match in re.finditer(r"(?<![\w.$])trn?\(", source):
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
        # Property names inside {name:value} objects are unquoted, so every quoted word here is text.
        for match in LITERAL.finditer(body):
            if re.search(r"[=!]==?\s*$", body[:match.start()]):
                continue  # compared value such as kind==="deleted", not displayed text
            text = json.loads('"' + match.group(1) + '"')
            if re.search(r"[A-Za-z]{2}", text):
                keys.append(text)
    return list(dict.fromkeys(keys))


def all_script_keys():
    keys = []
    for name in ("app.js", "i18n.js", "guide.js"):
        keys += script_keys((STATIC / name).read_text(encoding="utf-8"))
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
                elif func in ("tr", "Invalid") and len(node.args) > 1:
                    texts = node.args[1:2]
            elif isinstance(node, ast.Return) and name == "alerts.py":
                texts = [node.value]
            for arg in texts:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and " " in arg.value:
                    keys.append(arg.value)
    # Labels, units and help of the Parameters page come from the server's parameter list.
    if str(PACKAGE.parent) not in sys.path:
        sys.path.insert(0, str(PACKAGE.parent))
    from tgwitness.tuning import texts
    return list(dict.fromkeys(keys + texts()))


if __name__ == "__main__":
    json.dump({"script": all_script_keys(), "server": server_keys()}, sys.stdout, ensure_ascii=False, indent=1)
