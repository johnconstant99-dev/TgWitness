"""Linux-only acceptance: official client startup, synthetic export, real video, network guard.

Never authenticates to Telegram. The selected gateway accepts TCP but forwards nothing.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness_capture.verify import verify_zip


def docker(*args, check=True):
    result = subprocess.run(["docker", *args], capture_output=True, timeout=120)
    if check and result.returncode:
        raise RuntimeError("Docker operation failed: " + result.stderr.decode(errors="replace")[-8000:])
    output = result.stdout + (result.stderr if args[0] == "logs" else b"")
    return output.decode(errors="replace").strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, default=Path("test-results/trusted-container"))
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("Run on a Linux Docker host")
    args.output.mkdir(parents=True, exist_ok=True)
    prefix = "tgw-trusted-ci-" + uuid.uuid4().hex[:12]
    network, gateway, client = prefix + "-net", prefix + "-gateway", prefix + "-client"
    try:
        docker("network", "create", network)
        sink = ("import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); "
                "s.bind(('0.0.0.0',1080)); s.listen();\nwhile True:\n c,_=s.accept(); c.close()")
        docker("run", "-d", "--name", gateway, "--network", network, "--user", "10001", "--cap-drop=ALL",
               "--entrypoint", "python", args.image, "-c", sink)
        address = json.loads(docker("inspect", gateway))[0]["NetworkSettings"]["Networks"][network]["IPAddress"]
        binary_hash = docker("run", "--rm", "--entrypoint", "python", args.image, "-c",
                             "import hashlib; print(hashlib.file_digest(open('/opt/Telegram/Telegram','rb'),'sha256').hexdigest())")
        config = {"kind": "trusted", "video_input_args": ["-f", "x11grab", "-framerate", "10", "-video_size", "1280x720", "-i", ":99"],
                  "trusted": {"desktop_sha256": binary_hash, "connectors": {
                      "ci-sink": {"label": "CI TCP sink; no Telegram access", "mode": "proxy", "protocol": "mtproxy", "host": address, "port": 1080}}}}
        with tempfile.TemporaryDirectory(prefix=prefix) as directory:
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps(config))
            docker("run", "-d", "--name", client, "--network", network, "--cap-drop=ALL",
                   "--cap-add=NET_ADMIN", "--cap-add=SETUID", "--cap-add=SETGID", "--cap-add=SETPCAP", "--cap-add=CHOWN",
                   "--security-opt=no-new-privileges:true", "--security-opt",
                   "seccomp=" + str(ROOT / "addons/capture/deploy/official-seccomp.json"), "--read-only", "--shm-size=512m",
                   "--tmpfs", "/session:rw,nosuid,nodev,mode=0700,size=256m",
                   "--tmpfs", "/exports:rw,nosuid,nodev,mode=0700,size=64m",
                   "--tmpfs", "/home/recorder:rw,nosuid,nodev,mode=0700,size=128m",
                   "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m", "--tmpfs", "/run:rw,nosuid,nodev,size=16m",
                   "--tmpfs", "/data:rw,nosuid,nodev,mode=0700,size=256m",
                   "-v", str(config_path) + ":/config.json:ro", "-e", "TRUSTED_CONNECTOR=ci-sink",
                   "-p", "127.0.0.1::8793", args.image)
            port = docker("port", client, "8793/tcp").rsplit(":", 1)[1]
            base = "http://127.0.0.1:" + port
            deadline = time.monotonic() + 45
            token = ""
            while time.monotonic() < deadline:
                token = docker("exec", "--user", "10001", client, "cat", "/data/control-token.txt", check=False)
                if len(token) >= 32:
                    break
                time.sleep(.5)
            assert len(token) >= 32, "Control service did not become ready"
            with requests.Session() as session:
                session.trust_env = False
                session.headers["Authorization"] = "Bearer " + token

                def call(path, body=None):
                    result = session.request("GET" if body is None else "POST", base + "/api/" + path,
                                             json=body, timeout=40)
                    assert result.status_code == 200, (path, result.status_code, result.text[:500])
                    return result

                state = call("status").json()
                assert state["phase"] == "configured" and not state["settings"]["enabled"]
                access_probe = """import os
path='/run/trusted-route.json'
assert os.stat(path).st_uid == 0
assert os.access(path,os.R_OK) and not os.access(path,os.W_OK)
try: os.chmod(path,0o600)
except PermissionError: pass
else: raise AssertionError('Recorder can change protected route permissions')
"""
                docker("exec", "--user", "10001", client, "python", "-c", access_probe)
                docker("exec", "--user", "10002", client, "python", "-c",
                       "import os; assert not os.access('/run/trusted-route.json',os.R_OK)")
                browser_probe = """import hashlib,json,subprocess
from pathlib import Path
binary=Path('/usr/bin/chromium').resolve(strict=True)
subprocess.run([str(binary),'--headless=new','--no-first-run','--disable-background-networking',
 '--disable-component-update','--disable-sync','--disable-extensions','--disable-dev-shm-usage',
 '--password-store=basic','--host-resolver-rules=MAP * ~NOTFOUND',
 '--proxy-server=http://%s:1080','--proxy-bypass-list=<-loopback>',
 '--user-data-dir=/session/web-sandbox','--screenshot=/session/web-sandbox.png','about:blank'],
 check=True,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
assert Path('/session/web-sandbox.png').read_bytes().startswith(b'\\x89PNG\\r\\n\\x1a\\n')
print(json.dumps({'binary_sha256':hashlib.file_digest(binary.open('rb'),'sha256').hexdigest(),
 'sandbox_enabled':True,'scope':'unauthenticated blank page; no Telegram request'}))
""" % address
                browser = json.loads(docker("exec", "--user", "10001", "-e", "HOME=/home/recorder",
                                            "-e", "DISPLAY=:99", client, "python", "-c", browser_probe))
                call("begin", {"case": "CI synthetic export; no account", "connector": "ci-sink", "client": "desktop", "method": "hybrid"})
                deadline = time.monotonic() + 20
                attempts = []
                while True:
                    result = session.post(base + "/api/start", json={}, timeout=15)
                    if result.status_code == 200:
                        break
                    attempts.append({"status": result.status_code, "detail": result.text[:500]})
                    current = call("status").json()
                    assert current["phase"] in {"setup", "paused"} and time.monotonic() < deadline, (attempts, current)
                    time.sleep(.5)
                frame = call("frame")
                assert frame.content.startswith(b"\x89PNG\r\n\x1a\n") and len(frame.content) > 1000
                (args.output / "official-client.png").write_bytes(frame.content)
                assert session.post(base + "/api/input", json={"action": "key", "key": "Return"}, timeout=5).status_code == 409
                probe = """import json,socket,struct
results={}
for name,host,port in [('gateway',%r,1080),('direct_ipv4','1.1.1.1',443),('direct_ipv6','2606:4700:4700::1111',443),('dns_tcp','1.1.1.1',53)]:
 try:
  connection=socket.create_connection((host,port),timeout=2); connection.close(); results[name]='connected'
 except OSError: results[name]='blocked'
dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
dns.settimeout(2)
# Docker can forward queries from 127.0.0.11 outside the guarded namespace.
# Its resolver must not receive queries even when the client uses loopback.
query=struct.pack('!HHHHHH',1234,0x0100,1,0,0,0)+b'\\x07example\\x03com\\x00'+struct.pack('!HH',1,1)
try:
 dns.sendto(query,('127.0.0.11',53)); dns.recv(2048); results['embedded_dns']='responded'
except OSError: results['embedded_dns']='blocked'
finally: dns.close()
print(json.dumps(results))
""" % address
                routes = json.loads(docker("exec", "--user", "10001", client, "python", "-c", probe))
                assert routes == {"gateway": "connected", "direct_ipv4": "blocked", "direct_ipv6": "blocked",
                                  "dns_tcp": "blocked", "embedded_dns": "blocked"}, routes
                original = {"id": 123, "type": "public_supergroup", "name": "CI SYNTHETIC EXPORT", "messages": [
                    {"id": 1, "text": "Synthetic first record"}, {"id": 4, "text": "Synthetic reply", "reply_to_message_id": 2}]}
                writer = "import os,time; from pathlib import Path; p=Path('/exports/result.json'); p.write_bytes(bytes.fromhex(%r)); os.utime(p,(time.time()-5,time.time()-5))" % json.dumps(original).encode().hex()
                docker("exec", "--user", "10001", client, "python", "-c", writer)
                report = call("import", {"name": "result.json"}).json()
                assert len(report["findings"]) == 2
                call("pause", {})
                finished = call("finish", {}).json()
                assert finished["phase"] == "completed"
                checkpoint = call("checkpoint").json()
                bundle = call("export", {})
                destination = args.output / "synthetic-evidence.zip"
                destination.write_bytes(bundle.content)
                verified = verify_zip(destination, state["fingerprint"], checkpoint, require_final_anchor=True)
                assert verified["valid"] and verified["trusted_reports_checked"] == 1
                events = call("events").json()
                assert any(event["kind"] == "video.segment" and event["artifacts"][0]["size"] > 1000 for event in events)
                assert docker("exec", "--user", "10001", client, "python", "-c",
                              "from pathlib import Path; print(len(list(Path('/session').glob('trusted-*'))))") == "0"
                result = {"official_binary_sha256": binary_hash, "browser": browser, "network": routes, "verification": verified,
                          "archive_sha256": hashlib.sha256(bundle.content).hexdigest(),
                          "scope": "official unauthenticated Desktop, generated export, real FFmpeg; no account or WARP qualification"}
                (args.output / "result.json").write_text(json.dumps(result, indent=2))
                print(json.dumps(result, indent=2))
    finally:
        logs = docker("logs", client, check=False)
        (args.output / "container.log").write_text(logs)
        startup = docker("exec", "--user", "10001", client, "python", "-c",
                         "from pathlib import Path; print('\\n'.join(p.read_text(errors='replace')[-16000:] for p in Path('/session').glob('trusted-*/log.txt')))",
                         check=False)
        (args.output / "official-client-startup.log").write_text(startup)
        docker("rm", "-f", client, gateway, check=False)
        docker("network", "rm", network, check=False)


if __name__ == "__main__":
    main()
