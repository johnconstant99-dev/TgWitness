import os
import runpy
import sys
import http.client
import socket
import subprocess
import time
from pathlib import Path

import pytest

from tgwitness.security import InstanceLock


def test_old_python_gets_actionable_message_before_tomllib(monkeypatch):
    import builtins
    original = builtins.__import__

    def no_tomllib(name, *args, **kwargs):
        if name == "tomllib":
            raise AssertionError("Python version check must happen before tomllib import")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(sys, "version_info", (3, 10, 0))
    monkeypatch.setattr(builtins, "__import__", no_tomllib)
    with pytest.raises(SystemExit, match="Install Python 3.11 or newer"):
        runpy.run_path(str(Path(__file__).resolve().parents[1] / "start.py"), run_name="__main__")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions require a POSIX filesystem")
def test_new_data_directory_is_private_before_vault_creation(tmp_path):
    root = tmp_path / "new-data"
    lock = InstanceLock(root)
    try:
        assert root.stat().st_mode & 0o077 == 0
    finally:
        lock.close()


def test_windowless_launch_serves_panel_and_retains_diagnostics(tmp_path):
    with socket.socket() as address:
        address.bind(("127.0.0.1", 0))
        port = address.getsockname()[1]
    root = tmp_path / "windowless"
    if os.name == "nt":
        command = [str(Path(sys.executable).with_name("pythonw.exe")), "-m", "tgwitness"]
    else:
        command = [sys.executable, "-c",
                   "import sys; sys.stdout=sys.stderr=None; from tgwitness.__main__ import main; main()"]
    command += ["--demo", "--data-dir", str(root), "--port", str(port)]
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("TGWITNESS_")}
    process = subprocess.Popen(command, cwd=Path(__file__).resolve().parents[1], env=environment,
                               creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    try:


        deadline = time.monotonic() + 60
        while True:
            assert process.poll() is None, "Windowless server exited before serving the panel"
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            try:
                connection.request("GET", "/")
                response = connection.getresponse()
                assert response.status == 200
                assert b"TgWitness" in response.read()
                break
            except OSError:
                assert time.monotonic() < deadline, "Windowless server did not become ready"
                time.sleep(.05)
            finally:
                connection.close()
        log = (root / "logs/server.log").read_text(encoding="utf-8")
        assert "Application startup complete" in log
        assert (root / "panel-token.txt").read_text().strip() not in log
        assert 'GET / HTTP' not in log
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@pytest.mark.parametrize("stops_in_time", [True, False])
def test_launcher_ctrl_c_lets_server_finish_orderly_stop(monkeypatch, stops_in_time):
    launcher = runpy.run_path(str(Path(__file__).resolve().parents[1] / "start.py"))
    calls = []

    class Server:
        def __init__(self, command, cwd):
            self.waits = 0

        def wait(self, timeout=None):
            self.waits += 1
            calls.append(("wait", timeout))
            if self.waits == 1:
                raise KeyboardInterrupt
            if not stops_in_time:
                raise subprocess.TimeoutExpired("tgwitness", timeout)
            return 0

        def kill(self):
            calls.append(("kill", None))

    monkeypatch.setattr(launcher["subprocess"], "Popen", Server)
    assert launcher["serve"](["python", "-m", "tgwitness"]) == 0
    assert calls[:2] == [("wait", None), ("wait", 30)]
    assert (("kill", None) in calls) == (not stops_in_time)


def test_launcher_reports_failed_setup_step_without_traceback():
    launcher = runpy.run_path(str(Path(__file__).resolve().parents[1] / "start.py"))
    with pytest.raises(SystemExit, match="Synthetic failure"):
        launcher["step"]([sys.executable, "-c", "raise SystemExit(3)"], "Synthetic failure")
