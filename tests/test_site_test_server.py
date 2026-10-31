from http.client import HTTPConnection
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from tools.site_test_server import SiteHandler, site_server


@pytest.fixture
def site(tmp_path):
    root = tmp_path / "site"
    root.mkdir()
    (root / "index.html").write_text("public home", encoding="utf-8")
    (root / "docs").mkdir()
    (root / "docs/index.html").write_text("public docs", encoding="utf-8")
    (root / "sample file.txt").write_text("public asset", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("private fixture", encoding="utf-8")
    with site_server(root) as url:
        yield root, url


def request(url, path, method="GET"):
    address = urlsplit(url)
    connection = HTTPConnection(address.hostname, address.port, timeout=5)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def test_public_prefix_paths_and_head(site):
    _, url = site
    for path, content in (("/TgWitness/", b"public home"),
                          ("/TgWitness/docs/?lang=en", b"public docs"),
                          ("/TgWitness/sample%20file.txt", b"public asset")):
        status, _, body = request(url, path)
        assert (status, body) == (200, content)
        status, headers, body = request(url, path, "HEAD")
        assert (status, body) == (200, b"")
        assert int(headers["Content-Length"]) == len(content)
    status, headers, _ = request(url, "/TgWitness?lang=en")
    assert status == 301
    assert headers["Location"] == "/TgWitness/?lang=en"


@pytest.mark.parametrize("path", [
    "/", "/outside.txt", "/TgWitness-other/index.html", "/TgWitness/../outside.txt",
    "/TgWitness/%2e%2e/outside.txt", "/TgWitness/docs/../../outside.txt",
    "/TgWitness/docs/%2f..%2f..%2foutside.txt", "/TgWitness/%5c..%5coutside.txt",
    "/TgWitness/C:/outside.txt", "/TgWitness/index.html:stream", "/TgWitness/index.html.",
    "/TgWitness/%00index.html", "/TgWitness/%ff", "/TgWitness/%2", "/TgWitness/NUL",
    "/TgWitness/CONOUT$", "/TgWitness/COM%C2%B9",
    "http://example.invalid/TgWitness/", "/TgWitness/%252e%252e/outside.txt",
])
def test_rejects_outside_prefix_and_path_aliases(site, path):
    _, url = site
    for method in ("GET", "HEAD"):
        status, _, body = request(url, path, method)
        assert status == 404
        assert b"private fixture" not in body


def test_rejects_symlink_escape(site):
    root, url = site
    try:
        (root / "outside.txt").symlink_to(root.parent / "outside.txt")
        (root / "escape").symlink_to(root.parent, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Symlinks unavailable: {error}")
    assert request(url, "/TgWitness/outside.txt")[0] == 404
    assert request(url, "/TgWitness/escape/outside.txt")[0] == 404
    (root / "docs/index.html").unlink()
    (root / "docs/index.html").symlink_to(root.parent / "outside.txt")
    assert request(url, "/TgWitness/docs/")[0] == 404


def test_server_is_read_only_and_does_not_list_directories(site):
    root, url = site
    (root / "unlisted").mkdir()
    assert request(url, "/TgWitness/unlisted/")[0] == 404
    for method in ("POST", "PUT", "DELETE"):
        assert request(url, "/TgWitness/new.txt", method)[0] == 501
    assert not (root / "new.txt").exists()


def test_root_and_prefix_validation(tmp_path):
    with pytest.raises(ValueError, match="prefix"):
        with site_server(tmp_path, "/../"):
            pytest.fail("Invalid prefix accepted")
    file = tmp_path / "file"
    file.touch()
    with pytest.raises(ValueError, match="directory"):
        with site_server(file):
            pytest.fail("File root accepted")
    with pytest.raises(FileNotFoundError):
        with site_server(Path(tmp_path / "missing")):
            pytest.fail("Missing root accepted")


def test_client_cancellation_is_quiet_but_other_copy_errors_propagate():
    class ClosedConnection:
        def __init__(self, error):
            self.error = error

        def write(self, data):
            raise self.error

    handler = object.__new__(SiteHandler)
    for error in (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
        handler.copyfile(BytesIO(b"asset"), ClosedConnection(error()))
    with pytest.raises(OSError, match="unexpected"):
        handler.copyfile(BytesIO(b"asset"), ClosedConnection(OSError("unexpected")))
