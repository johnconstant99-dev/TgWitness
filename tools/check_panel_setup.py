"""Exercise first-run choices and failure boundaries without changing host services."""
import contextlib
import http.server
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import panelctl as panel  # noqa: E402


class SetupChecks(unittest.TestCase):
    def test_printed_guide_supports_legacy_windows_output(self):
        from tgwitness.operator_guide import write
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, windows=True)
            saved = (root / "START-HERE.txt").read_bytes()
            with io.BytesIO() as raw, io.TextIOWrapper(raw, encoding="cp1252") as output:
                with contextlib.redirect_stdout(output):
                    panel.guide(root, print_text=True)
                output.flush()
                printed = raw.getvalue().decode("cp1252")
            self.assertIn("Access > My limits", printed)
            self.assertIn("tgwitness.cmd' token rotate", printed)
            self.assertIn("https://github.com/phishdestroy/TgWitness", printed)
            self.assertEqual((root / "START-HERE.txt").read_bytes(), saved)

    def test_offline_guide_is_safe_repeatable_and_preserves_unrelated_files(self):
        from tgwitness.operator_guide import write
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "owner's & program"
            page = write(root, windows=True)
            first = page.read_bytes()
            self.assertIn(b"owner&#x27;s &amp; program", first)
            self.assertIn(b"Content-Security-Policy", first)
            self.assertIn(b"https://github.com/phishdestroy/TgWitness", first)
            self.assertIn("owner''s & program", (root / 'START-HERE.txt').read_text())
            write(root, windows=True)
            self.assertEqual(page.read_bytes(), first)
            (root / 'START-HERE.txt').write_text('My private notes')
            with self.assertRaisesRegex(ValueError, 'unrelated'):
                write(root)
            self.assertEqual((root / 'START-HERE.txt').read_text(), 'My private notes')

    def test_tunnel_control_requires_an_explicit_boolean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertTrue(panel.tunnel_control(root)['enabled'])
            for invalid in ('false', 0, None):
                panel.atomic(root / 'tunnel.json', json.dumps({'enabled': invalid, 'revision': 'a' * 32}))
                with self.assertRaises(ValueError):
                    panel.tunnel_control(root)
            panel.atomic(root / 'tunnel.json', json.dumps({'enabled': False, 'revision': 'b' * 32}))
            self.assertFalse(panel.tunnel_control(root)['enabled'])

    def test_domain_rejects_config_and_shell_injection(self):
        for bad in ("https://example.org", "example.org/", "example.org {\n file_server", "$(whoami).org",
                    "*.example.org", "127.0.0.1", "x.local", "a..org", "a.org:80", "a.org?token=x", "-a.org"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                panel.hostname(bad)
        self.assertEqual(panel.hostname("Panel.Example.ORG."), "panel.example.org")

    def test_occupied_port_is_preserved(self):
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            with self.assertRaisesRegex(ValueError, "Nothing was stopped"):
                panel.check_port(occupied.getsockname()[1])
            self.assertGreater(occupied.fileno(), -1)

    def test_no_terminal_does_not_publish_or_register_a_service(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(panel, "open_terminal", return_value=None), \
                patch.object(panel, "systemctl") as ctl, contextlib.redirect_stdout(io.StringIO()) as output:
            panel.setup(Path(tmp))
            ctl.assert_not_called()
            self.assertFalse((Path(tmp) / "panel.json").exists())
            self.assertIn("tgwitness setup", output.getvalue())

    def test_explicit_install_only_does_not_create_data(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(panel, "open_terminal", return_value=io.StringIO("4\n")), \
                patch.object(panel, "systemctl") as ctl, contextlib.redirect_stdout(io.StringIO()):
            panel.setup(Path(tmp))
            ctl.assert_not_called()
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_eof_cannot_accidentally_select_public_access(self):
        with self.assertRaisesRegex(ValueError, "cancelled"), contextlib.redirect_stdout(io.StringIO()):
            panel.choose(io.StringIO(""), "Choose:", {"1", "2"})

    def test_existing_installation_keeps_access_settings(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(panel, "show"), patch.object(panel, "fetch_tool") as fetch, \
                contextlib.redirect_stdout(io.StringIO()):
            root = Path(tmp)
            saved = '{"mode":"local","data":"keep"}\n'
            (root / "panel.json").write_text(saved)
            panel.setup(root, "quick")
            self.assertEqual((root / "panel.json").read_text(), saved)
            fetch.assert_not_called()

    def test_service_runs_without_root_and_keeps_private_state(self):
        config = {"system": True, "service": "tgwitness-example", "mode": "quick"}
        unit = panel.unit_text(Path("/opt/panel $USER %n"), config, "/opt/panel/python")
        for expected in ("DynamicUser=yes", "StateDirectoryMode=0700", "ProtectHome=yes", "ProtectSystem=strict",
                         "NoNewPrivileges=yes", "CapabilityBoundingSet=", "$$USER %%n", "KillMode=control-group"):
            self.assertIn(expected, unit)
        self.assertNotIn("AmbientCapabilities", unit)
        config["mode"] = "domain"
        self.assertIn("AmbientCapabilities=CAP_NET_BIND_SERVICE", panel.unit_text(Path("/opt/panel"), config, "/opt/python"))

    def test_public_code_permissions_do_not_touch_private_data(self):
        if os.name == "nt":
            self.skipTest("POSIX modes")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("versions", "tools", "data"):
                (root / name).mkdir(mode=0o700)
            secret = root / "data" / "session"
            secret.write_bytes(b"private")
            secret.chmod(0o600)
            panel.prepare_code(root)
            self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
            self.assertEqual((root / "data").stat().st_mode & 0o777, 0o700)

    def test_failed_public_readiness_is_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = {"schema": "tgwitness-panel-v1", "mode": "quick", "system": False,
                      "service": panel.service_name(root), "data": str(root / "data"), "port": 8787}
            panel.atomic(root / "panel.json", json.dumps(config))
            panel.atomic(root / "data" / "panel-address.json", json.dumps({"url": "https://not-ready.trycloudflare.com", "id": "a" * 64}))
            with patch.object(panel.subprocess, "run") as run, patch.object(panel, "reachable", return_value=False), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                run.return_value.returncode = 0
                panel.show(root)
            self.assertNotIn("Your panel is ready", output.getvalue())
            self.assertIn("not yet confirmed", output.getvalue())

    def test_wrong_site_with_http_200_is_not_the_installed_panel(self):
        class WrongSite(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"An unrelated website")

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), WrongSite)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            self.assertFalse(panel.reachable(f"http://127.0.0.1:{server.server_port}/_tgwitness/ready", "b" * 64))
        finally:
            server.shutdown()
            server.server_close()

    def test_tunnel_uses_only_loopback_and_ignores_ambient_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = panel.bridge_command({"mode": "quick", "port": 8787, "bridge": "/tools/cloudflared"}, Path(tmp))
            self.assertIn("http://127.0.0.1:8787", args)
            self.assertEqual(json.loads((Path(tmp) / "tunnel-config.yml").read_text()), {})
            self.assertNotIn("0.0.0.0", " ".join(args))
        for value in ("https://panel.trycloudflare.com.attacker.test", "https://panel.trycloudflare.com@attacker.test"):
            # Parsing is tightened to a full hostname boundary, never arbitrary URLs.
            self.assertIsNone(panel.QUICK_URL.search(value))


if __name__ == "__main__":
    unittest.main()
