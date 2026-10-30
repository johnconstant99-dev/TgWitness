import hashlib
import io
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tgwitness.download import download_export


@pytest.fixture
def export_server():
    state = {"body": b"synthetic export" * 160000, "status": 200, "length": None, "requests": []}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            state["requests"].append((self.path, self.headers.get("Authorization")))
            self.send_response(state["status"])
            self.send_header("Content-Length", str(state["length"] if state["length"] is not None else len(state["body"])))
            incomplete = state["length"] is not None and state["length"] > len(state["body"])
            if incomplete:
                self.send_header("Connection", "close")
            self.send_header("Location", "/redirect-must-not-be-followed")
            self.end_headers()
            try:
                self.wfile.write(state["body"])
            except (ConnectionError, OSError):
                pass
            self.close_connection = incomplete

        def log_message(self, *args):
            pass

    class Server(ThreadingHTTPServer):
        def handle_error(self, request, client_address):
            pass  # Clients abort keep-alive connections on purpose in these tests.

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port), state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def test_download_streams_profile_export_and_refuses_overwrite(export_server, tmp_path):
    origin, state = export_server
    target = tmp_path / "evidence.zip"
    profile = "a" * 32
    result = download_export(origin, "synthetic-token", target, profile=profile)
    assert target.read_bytes() == state["body"]
    assert result["sha256"] == hashlib.sha256(state["body"]).hexdigest()
    assert result["bytes"] == len(state["body"])
    assert state["requests"] == [(f"/profiles/{profile}/api/export/zip", "Bearer synthetic-token")]
    with pytest.raises(ValueError, match="exists"):
        download_export(origin, "synthetic-token", target)
    assert len(state["requests"]) == 1
    assert not list(tmp_path.glob("*.part"))


@pytest.mark.parametrize("failure", ["redirect", "short", "advertised_limit"])
def test_failed_transfer_never_publishes_output(export_server, tmp_path, failure):
    origin, state = export_server
    limit = 8 * 1024**2
    if failure == "redirect":
        state["status"] = 302
    elif failure == "short":
        state["length"] = len(state["body"]) + 1
    elif failure == "advertised_limit":
        limit = 10
    with pytest.raises((ValueError, OSError)):
        download_export(origin, "synthetic-token", tmp_path / "evidence.zip", max_bytes=limit)
    assert list(tmp_path.iterdir()) == []
    assert len(state["requests"]) == 1


def test_unknown_length_is_bounded_and_cleanup_on_limit(monkeypatch, tmp_path):
    from tgwitness import download

    class Response(io.BytesIO):
        status = 200

        def getheader(self, name):
            return None

        def read(self, size=-1):
            assert 0 < size <= 1024**2
            return super().read(size)

    class Connection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return Response(b"x" * (2 * 1024**2))

        def close(self):
            pass

    monkeypatch.setattr(download.http.client, "HTTPConnection", Connection)
    with pytest.raises(ValueError, match="limit"):
        download_export("http://127.0.0.1", "token", tmp_path / "evidence.zip", max_bytes=1024**2)
    assert not list(tmp_path.iterdir())


def test_exclusive_fallback_without_hard_links(export_server, tmp_path, monkeypatch):
    from tgwitness import download
    origin, state = export_server
    monkeypatch.setattr(download.os, "link", lambda *args: (_ for _ in ()).throw(OSError("unsupported")))
    target = tmp_path / "evidence.zip"
    download_export(origin, "token", target)
    assert target.read_bytes() == state["body"]
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize("url", ["http://example.com", "https://user:pass@example.com", "https://example.com/path", "https://example.com/?token=secret"])
def test_remote_plaintext_and_credential_urls_rejected(tmp_path, url):
    with pytest.raises(ValueError):
        download_export(url, "token", tmp_path / "out.zip")
    assert not list(tmp_path.iterdir())
