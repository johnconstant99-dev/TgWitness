"""Local UI fixture. Synthetic client only; cannot open Telegram or use a real account."""
import argparse
import base64
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uvicorn

from tgwitness_capture.format import canonical
from tgwitness_capture.service import Config
from tgwitness_capture.trusted_service import create_app


class SyntheticScreen:
    def launch(self, choice, connector, profile):
        profile.mkdir(parents=True)
        return {"synthetic": True}

    def route(self, connector):
        return {"synthetic": True}

    def arm(self):
        pass

    def frame(self):
        return base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aL1sAAAAASUVORK5CYII=')

    def scroll(self, direction):
        pass

    def setup_input(self, value):
        pass

    def stop(self):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default=8794, type=int)
    parser.add_argument("--ffmpeg", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="tgw-trusted-ui-") as directory:
        root = Path(directory)
        exports = root / "inbox"
        exports.mkdir()
        original = exports / "result.json"
        original.write_bytes(canonical({"id": 123, "type": "public_supergroup", "name": "FICTIONAL CHAT — UI TEST",
                              "messages": [{"id": 1, "text": "First fictional message", "date": "2026-01-01", "date_unixtime": "1700000000"},
                                           {"id": 4, "text": "A reply outside this export", "reply_to_message_id": 2,
                                            "date": "2026-01-03", "date_unixtime": "1700200000"}]}))
        os.utime(original, (time.time() - 10, time.time() - 10))
        data = root / "recorder"
        data.mkdir()
        (data / "control-token.txt").write_text("synthetic-ui-only-not-a-real-account-token")
        config = Config(kind="trusted", ffmpeg_executable=args.ffmpeg,
                        video_input_args=["-re", "-f", "lavfi", "-i", "testsrc=size=1280x720:rate=10"],
                        trusted={"profile_root": str(root / "profiles"), "export_root": str(exports),
                                 "connectors": {"synthetic": {"label": "SYNTHETIC — no external connection", "mode": "proxy",
                                                 "protocol": "socks5", "host": "192.0.2.1", "port": 9}}})
        from tgwitness_capture import trusted_anchor
        def offline(*args):
            raise ValueError("Synthetic preview; no public beacon requested")
        trusted_anchor.observe = offline
        uvicorn.run(create_app(data, config, SyntheticScreen()), host="127.0.0.1", port=args.port,
                    access_log=False, log_level="warning")


if __name__ == "__main__":
    main()
