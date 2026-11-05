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
from tgwitness.provenance import source_files, source_tree_sha256


def main():
    if sys.platform != "linux":
        raise SystemExit("Run this smoke check on Linux with Docker.")
    if os.getuid() == 0:
        raise SystemExit("Run the sealed bind-mount check as an unprivileged test user.")
    name = "tgwitness-sealed-test-" + uuid.uuid4().hex[:12]
    subprocess.run(["docker", "build", "-f", "deploy/Dockerfile.sealed", "-t", name, "."], cwd=ROOT, check=True, timeout=900)
    with tempfile.TemporaryDirectory(prefix="tgwitness-sealed-container-") as temporary:
        root = Path(temporary)
        for part in ("config", "data", "out"):
            (root / part).mkdir(mode=0o700)
        token = secrets.token_urlsafe(32)
        (root / "config" / "session.json").write_text(json.dumps({"token":token,"recipient":keypair()["recipient"],
            "seconds":60,"context":{"collector_sha":"a"*40,"repository":"synthetic/test","run_id":"1"}}))
        (root / "config" / "session.json").chmod(0o600)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        command = ["docker", "run", "-d", "--name", name, "--user", f"{os.getuid()}:{os.getgid()}",
            "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=256",
            "--memory=2g", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m", "-p", f"127.0.0.1:{port}:8787"]
        for part, target in (("config", "config"), ("data", "data"), ("out", "output")):
            command += ["--mount", f"type=bind,src={root / part},dst=/{target}" + (",readonly" if part == "config" else "")]
        try:
            subprocess.run(["docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=64m,mode=1777",
                "--mount", f"type=bind,src={ROOT / 'tools'},dst=/checks,readonly", name,
                "python", "/checks/test_container_fetch_retry.py", "--installer",
                "/usr/share/tgwitness-build/containers/install-packages.sh"], check=True, timeout=120)
            subprocess.run(["docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=128m",
                "--mount", f"type=bind,src={ROOT / 'tools'},dst=/checks,readonly", name,
                "python", "/checks/check_container_runtime.py", "--output", "/tmp/checks"], check=True, timeout=180)
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
            measured = subprocess.run(["docker", "exec", name, "python", "-c",
                "import json, os, sqlite3; from pathlib import Path; "
                "from tgwitness.provenance import SOURCE_POLICY, source_files, source_tree_sha256; "
                "assert os.geteuid()!=0; "
                "db=sqlite3.connect('file:/data/journal.sqlite3?mode=ro',uri=True); "
                "receipt=json.loads(db.execute(\"SELECT payload FROM events WHERE kind='collector.started'\").fetchone()[0]); "
                "assert receipt['source_policy']==SOURCE_POLICY; "
                "assert receipt['source_files']==source_files(); "
                "assert receipt['source_tree_sha256']==source_tree_sha256(receipt['source_files']); "
                "assert all((Path('/data')/name).stat().st_mode & 0o077 == 0 "
                "for name in ('panel-token.txt','vault.key','signing.enc')); "
                "print(receipt['source_tree_sha256'])"], check=True, capture_output=True, text=True, timeout=20)
            assert measured.stdout.strip() == source_tree_sha256(source_files(ROOT / "tgwitness"))
            request = urllib.request.Request(url + "/api/status", headers={"Authorization": "Bearer " + token})
            with urllib.request.urlopen(request, timeout=10) as response:
                assert json.load(response)["phase"] == "login"
            request = urllib.request.Request(url + "/api/cancel", data=b"{}",
                headers={"Authorization":"Bearer " + token,"Content-Type":"application/json"})
            with urllib.request.urlopen(request, timeout=10) as response:
                assert json.load(response)["phase"] == "cancelled"
            assert not (root / "out" / "evidence.zip").exists()
            subprocess.run(["docker", "restart", "--time", "10", name], check=True, capture_output=True, timeout=30)
            deadline = time.monotonic() + 20
            while True:
                state = json.loads(subprocess.run(["docker", "inspect", "--format", "{{json .State}}", name],
                    check=True, capture_output=True, text=True, timeout=10).stdout)
                if not state["Running"]:
                    assert state["ExitCode"] != 0, "A sealed capture reused a nonempty session directory"
                    break
                if time.monotonic() > deadline:
                    raise AssertionError("A restarted sealed capture accepted used session directories")
                time.sleep(.2)
        finally:
            subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=30)
            subprocess.run(["docker", "image", "rm", name], capture_output=True, timeout=30)
    print("Sealed Docker passed: nonroot image, native signed PDFs, source measurements, private files, authentication, cancellation and refusal to reuse a session.")


if __name__ == "__main__":
    main()
