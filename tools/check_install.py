"""Smoke-test an installed package using stdlib HTTP; no live account."""
import argparse
import importlib.metadata
import http.client
import json
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("test-results"))
    args = parser.parse_args()
    package = args.package.resolve()
    sys.path.insert(0, str(package))
    import tgwitness
    from tgwitness import i18n
    import uvicorn
    from tgwitness.app import create_app
    from tgwitness.verify import verify_bundle
    from tgwitness.download import download_export
    assert Path(tgwitness.__file__).resolve().is_relative_to(package)
    from tgwitness.proxy_catalog import SEED, read_snapshot
    assert SEED.is_relative_to(package) and read_snapshot(SEED)["sources"]
    for name in ("proof.html", "proof.css", "proof.js"):
        assert (package / "tgwitness/static" / name).read_bytes(), "Missing installed proof resource: " + name
    args.output.mkdir(exist_ok=True, parents=True)
    data = Path(tempfile.mkdtemp(prefix="installed-", dir=args.output))
    app = create_app(data, demo=True)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    origin = "http://127.0.0.1:" + str(sock.getsockname()[1])
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets":[sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 15
        while not server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("Installed application did not start")
            time.sleep(.05)
        def get(path, headers=None):
            connection = http.client.HTTPConnection("127.0.0.1", sock.getsockname()[1], timeout=10)
            try:
                connection.request("GET", path, headers=headers or {})
                response = connection.getresponse()
                return response.status, response.read()
            finally:
                connection.close()

        for path in ("/", "/app.js", "/theme.js", "/style.css", "/mark.svg", "/guide.html", "/guide.css", "/guide.js", "/dedicated-account.html"):
            code, body = get(path)
            print("Checking", path, "HTTP", code, "bytes", len(body), flush=True)
            assert code == 200 and body
        assert get("/api/status")[0] == 401
        code, body = get("/locale.js", {"Accept-Language": "es"})
        assert code == 200
        dictionary = json.loads(body.decode("utf-8").split("window.TGW_DICT=", 1)[1].rstrip().rstrip(";"))
        assert dictionary == i18n.words("es")
        # The installed package ships the fallback catalog: untranslated entries stay English, never missing.
        translated = json.loads((i18n.LOCALES / "es.json").read_text(encoding="utf-8"))
        fallbacks = json.loads(i18n.ENGLISH_FALLBACKS.read_text(encoding="utf-8"))
        assert fallbacks and all(dictionary[text] == translated.get(text, text) for text in fallbacks)
        headers = {"Authorization": "Bearer " + app.state.vault.token}
        code, body = get("/api/status", headers)
        assert code == 200
        status = json.loads(body)
        assert status["demo"] and status["stats"]["total"] >= 30
        code, body = get("/api/export/zip", headers)
        assert code == 200
        archive = data / "installed-evidence.zip"
        archive.write_bytes(body)
        result = verify_bundle(archive, status["fingerprint"])
        assert result["events"] == status["stats"]["total"]
        streamed = data / "streamed-evidence.zip"
        transfer = download_export(origin, app.state.vault.token, streamed)
        assert verify_bundle(streamed, status["fingerprint"])["events"] == result["events"]
        assert transfer["bytes"] == streamed.stat().st_size
        receipt = {"passed": True, "package_origin": str(Path(tgwitness.__file__).resolve()),
                   "version": tgwitness.__version__, "streamed_download_verified": True,
                   "verified_events": result["events"], "dependencies": {
                       name: importlib.metadata.version(name)
                       for name in ("fastapi", "uvicorn", "telethon", "cryptography", "pillow")}}
        (args.output / "install-receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        print(json.dumps(receipt, indent=2))
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()


if __name__ == "__main__":
    main()
