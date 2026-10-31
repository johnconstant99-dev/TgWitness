"""Linux Docker smoke check of the restricted image, without a Telegram login."""
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness.sealed_crypto import keypair


def main():
    if sys.platform != "linux":
        raise SystemExit("Run this smoke check on Linux with Docker.")
    name = "tgwitness-sealed-test-" + uuid.uuid4().hex[:12]
    subprocess.run(["docker", "build", "-f", "deploy/Dockerfile.sealed", "-t", name, "."], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix="tgwitness-sealed-container-") as temporary:
        root = Path(temporary)
        for part in ("config", "data", "out"):
            (root / part).mkdir(mode=0o700)
        token = secrets.token_urlsafe(32)
        (root / "config" / "session.json").write_text(json.dumps({"token":token,"recipient":keypair()["recipient"],
            "seconds":60,"context":{"collector_sha":"a"*40,"repository":"synthetic/test","run_id":"1"}}))
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        command = ["docker", "run", "-d", "--name", name, "--user", f"{os.getuid()}:{os.getgid()}",
            "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=256",
            "--memory=2g", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m", "-p", f"127.0.0.1:{port}:8787"]
        for part, target in (("config", "config"), ("data", "data"), ("out", "output")):
            command += ["--mount", f"type=bind,src={root / part},dst=/{target}" + (",readonly" if part == "config" else "")]
        try:
            subprocess.run([*command, name], check=True, capture_output=True)
            url, deadline = f"http://127.0.0.1:{port}", time.monotonic() + 40
            while True:
                try:
                    with urllib.request.urlopen(url, timeout=2) as response:
                        assert response.status == 200
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise AssertionError("Container did not become ready")
                    time.sleep(.3)
            try:
                urllib.request.urlopen(url + "/api/status", timeout=2)
                raise AssertionError("Unauthenticated status was accepted")
            except urllib.error.HTTPError as exc:
                assert exc.code == 401
            request = urllib.request.Request(url + "/api/cancel", data=b"{}",
                headers={"Authorization":"Bearer " + token,"Content-Type":"application/json"})
            with urllib.request.urlopen(request, timeout=10) as response:
                assert json.load(response)["phase"] == "cancelled"
            assert not (root / "out" / "evidence.zip").exists()
        finally:
            subprocess.run(["docker", "rm", "--force", name], capture_output=True)
            subprocess.run(["docker", "image", "rm", name], capture_output=True)
    print("Sealed Docker smoke passed: immutable image, restricted mounts, authentication, cancellation.")


if __name__ == "__main__":
    main()
