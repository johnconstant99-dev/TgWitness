import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from tgwitness_capture.format import canonical, decode, check_seal
from tgwitness_capture.journal import Journal
from tgwitness_capture.witness import witness_once


def test_live_challenge_receipt_and_rollback_rejection(tmp_path):
    observer = Journal(tmp_path / "observer")
    witness = Journal(tmp_path / "witness")
    observer.append("capture.started")
    rollback = False

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            assert self.headers["Authorization"] == "Bearer read-only-token"
            challenge = parse_qs(urlsplit(self.path).query)["challenge"][0]
            checkpoint = observer.checkpoint(challenge)
            if rollback:
                from tgwitness_capture.format import seal
                checkpoint["body"]["seq"] = 0
                checkpoint["body"]["head_hash"] = "0" * 64
                checkpoint["signature"] = seal(observer.key, "checkpoint", checkpoint["body"])
            body = canonical(checkpoint)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        path = witness_once(witness, url, "read-only-token", observer.fingerprint)
        receipt = decode(path.read_bytes())
        check_seal(witness.public_key, "receipt", receipt["body"], receipt["signature"])
        assert len(receipt["body"]["checkpoint"]["body"]["challenge"]) == 64
        rollback = True
        with pytest.raises(ValueError, match="rollback"):
            witness_once(witness, url, "read-only-token", observer.fingerprint)
        assert witness.events()[-1]["kind"] == "witness.conflict"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        observer.close()
        witness.close()
