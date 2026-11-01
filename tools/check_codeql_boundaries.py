"""Offline regressions for reviewed CodeQL boundaries; synthetic accounts and bytes only."""
import hashlib
import http.client
import importlib.util
import json
import socket
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import quote, urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def tool(name):
    spec = importlib.util.spec_from_file_location("tools." + name, ROOT / "tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def refused(call):
    try:
        call()
    except ValueError:
        return
    raise AssertionError("Expected rejection")


@contextmanager
def local_client(app):
    """Exercise the real HTTP boundary using only installed runtime dependencies."""
    import uvicorn

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 15
        while not server.started:
            if not thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError("Synthetic application did not start")
            time.sleep(.05)

        def get(path, headers=None, params=None):
            if params:
                path += "?" + urlencode(params)
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            try:
                connection.request("GET", path, headers=headers or {})
                response = connection.getresponse()
                return SimpleNamespace(status_code=response.status, content=response.read(), headers=response.headers)
            finally:
                connection.close()

        yield SimpleNamespace(get=get)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        if thread.is_alive():
            raise RuntimeError("Synthetic application did not stop")


def check_locales_and_case_metadata():
    from tgwitness import i18n
    from tgwitness.report import HIDDEN_CODEPOINTS, ReportOptions

    with patch.object(Path, "read_text", side_effect=AssertionError("Unsupported language reached filesystem")):
        for bad in ("../english_fallbacks", "../guide_locales/am", "C:/outside", "ru/../../x", "ru\\x", "ru\0", "RU", ""):
            refused(lambda: i18n.words(bad))
            refused(lambda: i18n.guide_words(bad))
    assert i18n.words("en") == {}
    assert i18n.words("ru") and i18n.guide_words("am")
    # Golden fingerprint of all 76 codepoints rejected by the previous policy.
    # Enumerating the whole Unicode domain detects both added and removed points.
    rejected_text = "".join(chr(code) for code in range(sys.maxunicode + 1) if code in HIDDEN_CODEPOINTS)
    assert len(rejected_text) == 76
    assert hashlib.sha256(rejected_text.encode()).hexdigest() == "e524743ebc6eb569eda579e15428d183bc8cbcbb32082bfd43bd4f66cfd30aa2"
    assert ReportOptions(notes="line one\r\nline two\tend").notes == "line one\nline two\tend"
    for value in ("visible\x01hidden", "direction\u202eoverride", "\u2066isolate", "line\nnext"):
        refused(lambda: ReportOptions(case_title=value))


def check_media_and_locale_http():
    from tgwitness.access import GrantSettings
    from tgwitness.app import create_app

    with tempfile.TemporaryDirectory(prefix="tgwitness-codeql-") as temporary:
        root = Path(temporary).resolve()
        app = create_app(root, demo=True)
        with local_client(app) as client:
            admin = {"Authorization": "Bearer " + app.state.vault.token}
            data = b"synthetic attachment, not an executable preview"
            digest = hashlib.sha256(data).hexdigest()
            media = root / "media"
            media.mkdir(exist_ok=True)
            (media / digest).write_bytes(data)
            app.state.store.append("media.saved", {"media_sha256": digest}, chat_id=101)
            assert client.get("/api/media/" + digest).status_code == 401
            result = client.get("/api/media/" + digest, headers=admin)
            assert result.status_code == 200 and result.content == data
            inline = client.get("/api/media/" + digest + "?inline=true", headers=admin)
            assert inline.status_code == 200 and inline.content == data
            assert "attachment" in inline.headers["content-disposition"]
            assert "sandbox" in inline.headers["content-security-policy"]
            for bad in (digest.upper(), digest[:-1], digest + "0", digest + "\n", "../panel-token.txt",
                        "..\\panel-token.txt", "a" * 63 + "\0", "a" * 63 + "\u0430"):
                assert client.get("/api/media/" + quote(bad, safe=""), headers=admin).status_code == 404
            link = media / hashlib.sha256(b"synthetic symbolic link").hexdigest()
            try:
                link.symlink_to(media / digest)
            except OSError as exc:
                if getattr(exc, "winerror", None) != 1314:
                    raise
                # Windows without CreateSymbolicLink privilege: exercise the
                # refusal branch against a readable file; Linux CI uses a real link.
                link.write_bytes(data)
                original = Path.is_symlink
                with patch.object(Path, "is_symlink", lambda path: path == link or original(path)):
                    assert client.get("/api/media/" + link.name, headers=admin).status_code == 404
            else:
                assert client.get("/api/media/" + link.name, headers=admin).status_code == 404
            for chat, expected in ((101, 200), (202, 404)):
                issued, _ = app.state.access.issue(GrantSettings(label="Synthetic scoped viewer", workspaces={"default": [chat]}))
                token, _ = app.state.access.login(issued, "testclient", "synthetic check")
                result = client.get("/api/media/" + digest, headers={"Authorization": "Bearer " + token})
                assert result.status_code == expected
            for bad in ("../../outside", "C:\\outside", "ru/../outside", "ru\0"):
                response = client.get("/locale.js", params={"lang": bad}, headers={"Cookie": "tgwitness-lang=" + quote(bad)})
                assert response.status_code == 200 and b'window.TGW_LANG="en"' in response.content


def check_reviewed_protocol_and_tools():
    from tgwitness.tdata import read_tdata_zip

    fixtures = tool("browser_fixtures")
    for passcode in ("", "synthetic Desktop passcode"):
        payload = fixtures.tdata_fixture(passcode)
        dc, key, user = read_tdata_zip(payload, passcode)
        assert (dc, key, user) == (2, b"x" * 256, 44)
        refused(lambda: read_tdata_zip(payload, "incorrect synthetic passcode"))
        corrupted = bytearray(payload)
        corrupted[len(corrupted) // 2] ^= 1
        refused(lambda: read_tdata_zip(corrupted, passcode))
    publication = tool("check_publication")
    synthetic = "ghp_" + "x" * 36
    findings = publication.secret_findings("prefix " + synthetic, "synthetic.py")
    assert findings and synthetic not in json.dumps(findings)
    assert all("value withheld" in item for item in findings)
    diagrams = tool("site_diagrams")
    rendered = diagrams.render('flowchart TD\nA["<script>alert(1)</script>"] --> B["safe"]', 0)
    assert "<script>" not in rendered and "&lt;script&gt;" in rendered
    assert diagrams.esc("--!>") == "--!&gt;"


def main():
    check_locales_and_case_metadata()
    check_media_and_locale_http()
    check_reviewed_protocol_and_tools()
    print("CodeQL boundary regressions passed: locale/media scopes, full Unicode policy, legacy TData and safe tool output")


if __name__ == "__main__":
    main()
