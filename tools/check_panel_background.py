import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import panelctl as panel  # noqa: E402

FIXTURE = ROOT / "tools" / "fixtures" / "evidence-before-fulltext.zip"
ENV = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONIOENCODING="utf-8")


def installation(tmp, **values):
    root = Path(tmp).resolve()
    (root / ".tgwitness-installer").write_text("tgwitness-managed-install-v1\n")
    if values:
        config = {"schema": "tgwitness-panel-v1", "mode": "local", "domain": None, "port": 8787, "system": False,
                  "service": panel.service_name(root), "data": str(root / "data" / "live"), "manager": "process", **values}
        panel.atomic(root / "panel.json", json.dumps(config))
    return root


def serving(root):
    return "/opt/venv/bin/python " + " ".join(panel.serve_args(root))


def run_main(root, *args):
    stdout, stderr = io.StringIO(), io.StringIO()
    code = 0
    with patch.object(sys, "argv", ["panelctl", "--root", str(root), *args]), \
            contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            panel.main()
        except SystemExit as exc:
            code = exc.code
    return code, stdout.getvalue(), stderr.getvalue()


class FastEvent(threading.Event):
    def wait(self, timeout=None):
        return self.is_set()


class Stop(Exception):
    pass


class WithoutSystemd(unittest.TestCase):
    def test_systemd_is_not_assumed_in_a_container(self):
        with patch.object(panel.sys, "platform", "linux"), patch.object(panel.subprocess, "run") as run, \
                patch.object(panel.Path, "exists", return_value=False):
            self.assertFalse(panel.systemd_ready(True))
            run.assert_not_called()
        with patch.object(panel.sys, "platform", "linux"), patch.object(panel.Path, "exists", return_value=True), \
                patch.object(panel.subprocess, "run", return_value=Mock(returncode=1)):
            self.assertFalse(panel.systemd_ready(False))
        with patch.object(panel.sys, "platform", "linux"), patch.object(panel.Path, "exists", return_value=True), \
                patch.object(panel.subprocess, "run", side_effect=FileNotFoundError("systemctl")):
            self.assertFalse(panel.systemd_ready(True))

    def test_container_setup_offers_quick_link_and_writes_panel_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = installation(tmp)
            with patch.object(panel.sys, "platform", "linux"), patch.object(panel.os, "geteuid", create=True, return_value=0), \
                    patch.object(panel, "systemd_ready", return_value=False), \
                    patch.object(panel, "open_terminal", return_value=io.StringIO("2\n")), \
                    patch.object(panel, "check_port"), patch.object(panel, "fetch_tool", return_value="/tools/cloudflared"), \
                    patch.object(panel, "systemctl") as ctl, patch.object(panel, "refresh_unit") as unit, \
                    patch.object(panel, "start_background") as start, patch.object(panel, "show") as show, \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                panel.setup(root)
            ctl.assert_not_called()
            unit.assert_not_called()
            show.assert_called_once_with(root, credentials=True, wait=120)
            self.assertIn("trycloudflare.com", output.getvalue())
            self.assertIn("tgwitness start", output.getvalue())
            config = panel.read_config(root)
            self.assertEqual((config["manager"], config["mode"], config["system"]), ("process", "quick", False))
            self.assertEqual(config["data"], str(root / "data" / "live"))
            self.assertEqual(config["bridge"], "/tools/cloudflared")
            start.assert_called_once_with(root, json.loads((root / "panel.json").read_text()))

    def test_setup_keeps_systemd_where_it_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = installation(tmp)
            with patch.object(panel.sys, "platform", "linux"), patch.object(panel.os, "geteuid", create=True, return_value=0), \
                    patch.object(panel, "systemd_ready", return_value=True), patch.object(panel, "check_port"), \
                    patch.object(panel, "PRIVATE_LOCATIONS", ()), \
                    patch.object(panel, "systemctl") as ctl, patch.object(panel, "refresh_unit") as unit, \
                    patch.object(panel, "start_background") as start, patch.object(panel, "show"), \
                    contextlib.redirect_stdout(io.StringIO()):
                panel.setup(root, "local")
            start.assert_not_called()
            unit.assert_called_once()
            self.assertEqual(ctl.call_args.args[1:], ("enable", "--now", panel.service_name(root)))
            config = panel.read_config(root)
            self.assertEqual((config["manager"], config["system"]), ("systemd", True))

    def test_domain_without_root_is_refused_without_systemd(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = installation(tmp)
            with patch.object(panel.sys, "platform", "linux"), patch.object(panel.os, "geteuid", create=True, return_value=1000), \
                    patch.object(panel, "systemd_ready", return_value=False), patch.object(panel, "start_background") as start, \
                    self.assertRaisesRegex(ValueError, "80/443"):
                panel.setup(root, "domain", "panel.example.org")
            start.assert_not_called()
            self.assertFalse((root / "panel.json").exists())

    def test_background_start_detaches_and_records_its_pid(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = installation(tmp, port=8790)
            config = panel.read_config(root)
            logs = Path(config["data"]) / "logs"
            logs.mkdir(parents=True)
            with open(logs / "service.log", "wb") as old:
                old.truncate(5 * 1024**2 + 1)
            with patch.object(panel, "check_port") as port, patch.object(panel, "process_command", return_value=""), \
                    patch.object(panel.subprocess, "Popen", return_value=SimpleNamespace(pid=4321)) as popen:
                panel.start_background(root, config)
            port.assert_called_once_with(8790)
            args, options = popen.call_args
            self.assertEqual(args[0], [sys.executable, *panel.serve_args(root)])
            self.assertTrue(options["start_new_session"])
            self.assertEqual((options["stdin"], options["stderr"], options["umask"], options["cwd"]),
                             (subprocess.DEVNULL, subprocess.STDOUT, 0o077, root))
            self.assertEqual((root / "panel.pid").read_text(), "4321\n")
            self.assertTrue((logs / "service.log").is_file())
            self.assertEqual((logs / "service.log.1").stat().st_size, 5 * 1024**2 + 1)
            with patch.object(panel, "process_command", return_value=serving(root)), \
                    patch.object(panel.subprocess, "Popen") as again, patch.object(panel, "check_port") as port:
                panel.start_background(root, config)
            again.assert_not_called()
            port.assert_not_called()

    def test_pid_file_never_names_an_unrelated_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = installation(tmp)
            self.assertIsNone(panel.background_pid(root))
            (root / "panel.pid").write_text("4321\n")
            for command, expected in ((serving(root), 4321), ("", None), ("/usr/sbin/sshd -D", None),
                                      (serving(root.parent / "other"), None),
                                      (serving(root) + " extra", None)):
                with self.subTest(command=command), patch.object(panel, "process_command", return_value=command):
                    self.assertEqual(panel.background_pid(root), expected)
            (root / "panel.pid").write_text("not a pid")
            with patch.object(panel, "process_command", return_value=serving(root)):
                self.assertIsNone(panel.background_pid(root))

    def test_stop_waits_for_a_clean_exit_then_forces(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = installation(tmp)
            (root / "panel.pid").write_text("4321\n")
            with patch.object(panel, "process_command", side_effect=[serving(root), serving(root), ""]), \
                    patch.object(panel.os, "kill") as kill, patch.object(panel.os, "killpg", create=True) as group, \
                    patch.object(panel.time, "sleep"):
                panel.stop_background(root)
            kill.assert_called_once_with(4321, panel.signal.SIGTERM)
            group.assert_not_called()
            self.assertFalse((root / "panel.pid").exists())
            (root / "panel.pid").write_text("4321\n")
            with patch.object(panel, "process_command", return_value=serving(root)), \
                    patch.object(panel.os, "kill") as kill, patch.object(panel.os, "killpg", create=True) as group, \
                    patch.object(panel.signal, "SIGKILL", 9, create=True), patch.object(panel.time, "sleep"), \
                    patch.object(panel.time, "monotonic", side_effect=[0, 10, 50]):
                panel.stop_background(root)
            group.assert_called_once_with(4321, 9)
            self.assertFalse((root / "panel.pid").exists())
            (root / "panel.pid").write_text("4321\n")
            with patch.object(panel, "process_command", return_value=serving(root)), \
                    patch.object(panel.os, "kill", side_effect=ProcessLookupError):
                panel.stop_background(root)
            self.assertFalse((root / "panel.pid").exists())

    def test_status_and_doctor_without_panel_json_do_not_fail_with_errno(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = installation(tmp)
            for action in ("status", "start", "stop", "logs"):
                code, _, error = run_main(root, action)
                self.assertEqual(code, 1, action)
                self.assertIn("tgwitness setup", error)
                self.assertNotIn("Errno", error)
            with patch.object(panel.subprocess, "run", return_value=Mock(returncode=0)) as run:
                code, _, error = run_main(root, "doctor")
            self.assertEqual((code, error), (0, ""))
            self.assertEqual(run.call_args.args[0][-4:], ["--data-dir", str(root / "data" / "live"), "--port", "8787"])

    def test_status_reports_the_background_panel_without_systemctl(self):
        def no_systemctl(args, *rest, **options):
            raise AssertionError("systemctl was called: " + " ".join(args))

        with tempfile.TemporaryDirectory() as tmp:
            root = installation(tmp, port=8791)
            data = Path(panel.read_config(root)["data"])
            panel.atomic(data / "panel-address.json", json.dumps({"url": "http://127.0.0.1:8791", "id": "c" * 64}))
            panel.atomic(data / "panel-token.txt", "secret-key\n")
            (root / "panel.pid").write_text("4321\n")
            with patch.object(panel.subprocess, "run", side_effect=no_systemctl), \
                    patch.object(panel, "process_command", return_value=""):
                code, output, _ = run_main(root, "status")
            self.assertEqual(code, 0)
            self.assertIn("The panel is not running. Start it with: tgwitness start", output)
            with patch.object(panel.subprocess, "run", side_effect=no_systemctl), \
                    patch.object(panel, "process_command", return_value=serving(root)), \
                    patch.object(panel, "reachable", return_value=True) as reachable:
                code, output, _ = run_main(root, "status")
            self.assertEqual(code, 0)
            self.assertIn("Your panel is ready", output)
            self.assertIn("http://127.0.0.1:8791", output)
            self.assertNotIn("secret-key", output)
            reachable.assert_called_with("http://127.0.0.1:8791/_tgwitness/ready", "c" * 64)

    def test_start_stop_restart_and_logs_use_the_background_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = installation(tmp, mode="local")
            for action, stops, starts in (("start", 0, 1), ("stop", 1, 0), ("restart", 1, 1)):
                with patch.object(panel, "stop_background") as stop, patch.object(panel, "start_background") as start, \
                        patch.object(panel, "systemctl") as ctl, patch.object(panel, "refresh_unit") as unit, \
                        patch.object(panel, "show") as show:
                    code, output, _ = run_main(root, action)
                self.assertEqual(code, 0)
                self.assertEqual((stop.call_count, start.call_count), (stops, starts), action)
                ctl.assert_not_called()
                unit.assert_not_called()
                self.assertEqual(show.called, action != "stop")
                if action == "stop":
                    self.assertIn("Panel stopped", output)
            code, output, _ = run_main(root, "logs")
            self.assertIn("has not written a log yet", output)
            log = Path(panel.read_config(root)["data"]) / "logs" / "service.log"
            log.parent.mkdir(parents=True)
            log.write_text("".join(f"line {n}\n" for n in range(100)))
            code, output, _ = run_main(root, "logs")
            self.assertEqual(output.splitlines(), [f"line {n}" for n in range(20, 100)])

    def test_tunnel_change_in_background_mode_does_not_need_systemd(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = installation(tmp, mode="quick", bridge="/tools/cloudflared")
            with patch.object(panel, "process_command", return_value=""), \
                    patch.object(panel.subprocess, "run", side_effect=AssertionError("systemctl")):
                code, output, _ = run_main(root, "tunnel", "off")
            self.assertEqual(code, 0)
            self.assertIn("The panel is stopped", output)
            self.assertFalse(panel.tunnel_control(root)["enabled"])

    def test_background_supervisor_restarts_the_panel(self):
        for manager in ("process", "systemd"):
            with self.subTest(manager=manager), tempfile.TemporaryDirectory() as tmp:
                root = installation(tmp, manager=manager)
                crashed = Mock(returncode=3)
                crashed.poll.return_value = 3
                with patch.object(panel, "threading", SimpleNamespace(Event=FastEvent, Thread=threading.Thread)), \
                        patch.object(panel.signal, "signal"), patch.object(panel, "reachable", return_value=True), \
                        patch.object(panel.subprocess, "Popen", side_effect=[crashed, Stop()]) as popen, \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    if manager == "process":
                        with self.assertRaises(Stop):
                            panel.serve(root)
                        self.assertEqual(popen.call_args_list[0], popen.call_args_list[1])
                        self.assertIn("Restarting in 5 seconds", output.getvalue())
                    else:
                        with self.assertRaisesRegex(RuntimeError, "systemd will restart"):
                            panel.serve(root)
                        self.assertEqual(popen.call_count, 1)
                address = Path(panel.read_config(root)["data"]) / "panel-address.json"
                self.assertEqual(json.loads(address.read_text()), {})

    def test_help_lists_the_commands(self):
        for module in ("tgwitness", "tgwitness.panelctl"):
            with self.subTest(module=module):
                result = subprocess.run([sys.executable, "-m", module, "--help"], capture_output=True, text=True,
                                        env=ENV, cwd=ROOT, timeout=120)
                self.assertEqual(result.returncode, 0, result.stderr)
                for command in ("setup", "open", "status", "start, stop, restart", "logs", "doctor", "token rotate",
                                "tunnel on|off|restart|status", "verify ARCHIVE", "search"):
                    self.assertIn(command, result.stdout)
                self.assertNotIn("_serve", result.stdout)
                self.assertIn("usage: tgwitness", result.stdout)

    def test_verify_command_checks_an_archive(self):
        result = subprocess.run([sys.executable, "-m", "tgwitness", "verify", str(FIXTURE), "--json"],
                                capture_output=True, text=True, env=ENV, cwd=ROOT, timeout=300)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["verified"])
        with tempfile.TemporaryDirectory() as tmp:
            damaged = Path(tmp) / "damaged.zip"
            shutil.copyfile(FIXTURE, damaged)
            with open(damaged, "r+b") as archive:
                archive.truncate(damaged.stat().st_size // 2)
            result = subprocess.run([sys.executable, "-m", "tgwitness", "verify", str(damaged), "--json"],
                                    capture_output=True, text=True, env=ENV, cwd=ROOT, timeout=300)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)["verified"])
        result = subprocess.run([sys.executable, "-m", "tgwitness", "verify", "--help"], capture_output=True, text=True,
                                env=ENV, cwd=ROOT, timeout=120)
        self.assertIn("usage: tgwitness verify", result.stdout)


if __name__ == "__main__":
    unittest.main()
