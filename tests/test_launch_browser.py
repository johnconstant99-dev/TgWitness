"""A local double-click start opens the panel; services, containers and scripts never do."""
import socket
import webbrowser

import pytest

from tgwitness.__main__ import open_when_ready, should_open_browser


@pytest.mark.parametrize("host, no_browser, environ, interactive, expected", [
    ("127.0.0.1", False, {}, True, True),
    ("localhost", False, {}, True, True),
    ("::1", False, {}, True, True),
    ("127.0.0.1", False, {}, False, False),
    ("0.0.0.0", False, {}, True, False),
    ("127.0.0.1", True, {}, True, False),
    ("127.0.0.1", False, {"TGWITNESS_NO_BROWSER": "1"}, True, False),
])
def test_browser_opens_only_for_a_local_interactive_start(host, no_browser, environ, interactive, expected):
    assert should_open_browser(host, no_browser, environ, interactive) is expected


def test_panel_opens_once_it_answers_and_the_token_stays_in_the_console(tmp_path, monkeypatch, capsys):
    opened = []
    monkeypatch.setattr(webbrowser, "open", opened.append)
    token = tmp_path / "panel-token.txt"
    token.write_text("synthetic-token\n", encoding="utf-8")
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        url = f"http://127.0.0.1:{port}"
        assert open_when_ready(url, "127.0.0.1", port, token, timeout=5)
    assert opened == [url]
    assert "Panel token: synthetic-token" in capsys.readouterr().out


def test_nothing_opens_when_the_panel_never_starts(monkeypatch):
    opened = []
    monkeypatch.setattr(webbrowser, "open", opened.append)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    assert not open_when_ready(f"http://127.0.0.1:{port}", "127.0.0.1", port, timeout=0.5)
    assert opened == []


def test_windowless_start_without_console_streams_never_opens_a_browser(monkeypatch):
    import sys
    monkeypatch.setattr(sys, "stdin", None)
    monkeypatch.setattr(sys, "stdout", None)
    assert should_open_browser("127.0.0.1", False, {}) is False
