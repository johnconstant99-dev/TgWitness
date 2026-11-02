"""Acceptance helper: an empty, isolated installation on a disposable systemd host."""
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import socket
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def interactive_setup(launcher, mode, port):
    """A real controlling terminal with piped stdin, as in curl ... | bash."""
    child, terminal = pty.fork()
    if child == 0:
        args = [launcher, "setup", "--port", str(port)]
        os.execv("/bin/bash", ["bash", "-c", "printf '' | " + shlex.join(args)])
    output = bytearray()
    selected = False
    finished = False
    deadline = time.monotonic() + 240
    try:
        while time.monotonic() < deadline:
            if select.select([terminal], [], [], 0.2)[0]:
                try:
                    chunk = os.read(terminal, 65536)
                except OSError:
                    chunk = b""
                if chunk:
                    output.extend(chunk)
                if not selected and b"Choose [1-4]:" in output:
                    os.write(terminal, b"1\n" if mode == "local" else b"2\n")
                    selected = True
            exited, status = os.waitpid(child, os.WNOHANG)
            if exited:
                finished = True
                safe = "\n".join(line for line in output.decode(errors="replace").splitlines() if "Access key:" not in line)
                assert os.waitstatus_to_exitcode(status) == 0, safe
                assert selected and "Your panel is ready" in safe, safe
                return safe
        raise AssertionError("Interactive setup did not finish within four minutes")
    finally:
        os.close(terminal)
        if not finished:
            os.killpg(child, signal.SIGTERM)
            os.waitpid(child, 0)


def check_service(app, mode):
    assert app.is_relative_to(Path("/opt")) and app.parent.name.startswith("tgwitness-install-check-")
    service = "tgwitness-" + hashlib.sha256(str(app).encode()).hexdigest()[:12]
    unit = Path("/etc/systemd/system") / (service + ".service")
    assert not unit.exists(), "Acceptance must never reuse an existing service"
    launcher = str(app / "bin" / "tgwitness")
    with socket.socket() as available:
        available.bind(("127.0.0.1", 0))
        port = available.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"

    def run(*args):
        result = subprocess.run([launcher, *args], capture_output=True, text=True, timeout=240)
        if result.returncode:
            # First-run output includes a fresh access key: never publish it in CI.
            safe = "\n".join(line for line in result.stdout.splitlines() if "Access key:" not in line)
            raise AssertionError(safe + "\n" + result.stderr)
        return result.stdout

    def request(url, token=None):
        try:
            headers = {"Authorization": "Bearer " + token} if token else {}
            with urlopen(Request(url, headers=headers), timeout=15) as response:
                return response.status, response.read()
        except HTTPError as exc:
            return exc.code, b""

    try:
        output = interactive_setup(launcher, mode, port)
        assert "Your panel is ready" in output
        config = json.loads((app / "panel.json").read_text())
        data = Path(config["data"])
        for name in ('START-HERE.html', 'START-HERE.txt'):
            assert (app / name).is_file()
        assert 'https://github.com/phishdestroy/TgWitness' in run('guide', '--print')
        assert str(data) in run('paths')
        assert data == Path("/var/lib") / service
        assert subprocess.check_output(["systemctl", "is-enabled", service], text=True).strip() == "enabled"
        token = (data / "panel-token.txt").read_text().strip()
        assert request(origin + "/api/status")[0] == 401
        assert request(origin + "/api/status", token)[0] == 200
        assert token not in run("status")
        address = json.loads((data / "panel-address.json").read_text())["url"]
        if mode == "quick":
            assert address.startswith("https://") and address.endswith(".trycloudflare.com")
            assert request(address + "/api/status")[0] == 401
            assert request(address + "/api/status", token)[0] == 200
        (data / "acceptance-record").write_text("keep this record\n")
        rotation_output = run('token', 'rotate')
        rotated = (data / 'panel-token.txt').read_text().strip()
        assert rotated != token and 'Access key: ' + rotated in rotation_output
        assert request(origin + '/api/status', token)[0] == 401
        token = rotated
        assert request(origin + '/api/status', token)[0] == 200
        if mode == 'quick':
            before = json.loads(request(origin + '/api/status', token)[1])['run_id']
            run('tunnel', 'off')
            state = json.loads((data / 'panel-address.json').read_text())
            assert state['url'] == origin and state['tunnel_enabled'] is False
            assert json.loads(request(origin + '/api/status', token)[1])['run_id'] == before
            run('restart')
            assert json.loads((data / 'panel-address.json').read_text())['tunnel_enabled'] is False
            before = json.loads(request(origin + '/api/status', token)[1])['run_id']
            for action in ('on', 'restart'):
                previous = json.loads((data / 'panel-address.json').read_text())
                run('tunnel', action)
                current = json.loads((data / 'panel-address.json').read_text())
                assert current['tunnel_revision'] != previous['tunnel_revision']
                assert current['tunnel_enabled'] and current['url'].endswith('.trycloudflare.com')
                assert json.loads(request(origin + '/api/status', token)[1])['run_id'] == before
        run("restart")
        assert (data / "acceptance-record").read_text() == "keep this record\n"
        assert (data / "panel-token.txt").read_text().strip() == token
        if mode == "quick":
            current = json.loads((data / "panel-address.json").read_text())["url"]
            assert current in run("open")
            assert request(current + "/api/status", token)[0] == 200
        run("stop")
        deadline = time.monotonic() + 10
        while True:
            try:
                request(origin)
            except (URLError, OSError):
                break
            assert time.monotonic() < deadline, "Stop left a listening panel"
            time.sleep(0.2)
        run("start")
        assert request(origin + "/api/status", token)[0] == 200
        assert (data / "acceptance-record").read_text() == "keep this record\n"
        if mode == "local":
            # Run the actual pinned Caddy binary against the generated own-domain
            # configuration. Certificate issuance needs the operator's DNS/ports.
            python = next((app / "versions").glob("*/venv/bin/python"))
            snippet = ("import json; from pathlib import Path; from tgwitness.panelctl import fetch_tool, bridge_command; "
                       "root=Path(" + repr(str(app)) + "); "
                       "tool=fetch_tool(root,'caddy'); "
                       "config={'mode':'domain','domain':'panel.example.org','port':" + str(port) + ",'bridge':str(tool)}; "
                       "args=bridge_command(config,root/'domain-check'); "
                       "import subprocess; result=subprocess.check_output([str(tool),'adapt','--config',args[3],'--adapter','caddyfile']); "
                       "assert json.loads(result)['apps']['http']['servers']; print('Caddy configuration: passed')")
            subprocess.run([str(python), "-I", "-c", snippet], check=True, timeout=120)
        print(f"{mode}: installed panel, authentication, boot enablement, restart, retained data, stop/start: passed")
    finally:
        if unit.exists():
            assert unit.read_text().startswith("# TgWitness managed panel service v1\n")
            subprocess.run(["systemctl", "stop", service], check=True, timeout=60)
            subprocess.run(["systemctl", "clean", "--what=state", service], check=True, timeout=30)
            subprocess.run(["systemctl", "disable", service], check=True, timeout=30)
            unit.unlink()
            subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=30)
