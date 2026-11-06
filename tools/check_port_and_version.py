import os
from pathlib import Path
import re
import socket
import sys
import tomllib
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import tgwitness  # noqa: E402
from tgwitness import panelctl as panel  # noqa: E402

PROC_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:2253 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 55501 1 0000000000000000 100 0 0 10 0
   1: 0100007F:2253 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 55502 1 0000000000000000 20 4 30 10 -1
"""
NETSTAT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1100
  TCP    127.0.0.1:8787         127.0.0.1:50000        ESTABLISHED     2000
  TCP    127.0.0.1:18787        0.0.0.0:0              LISTENING       4000
  TCP    127.0.0.1:8787         0.0.0.0:0              ПРОСЛУШИВАНИЕ   3000
"""
IMAGE = r"TGWITNESS_IMAGE=\S+:([0-9][0-9A-Za-z.+-]*)"
VERSIONS = (
    ("README.md", r'alt="v([0-9.]+) · pre-release"'),
    ("docs/assets/presentation/identity-meta-version.svg", r"<title[^>]*>v([0-9.]+) · pre-release</title>"),
    ("docs/PROJECT-GUIDE.md", r'href="CHANGELOG.md">v([0-9.]+)</a>'),
    ("docs/*/README.md", r"badge/version-([0-9.]+)-"),
    ("deploy/env.example", IMAGE),
    ("docs/DEPLOYMENT.md", IMAGE),
    ("docs/*/DEPLOYMENT.md", IMAGE),
    ("docs/*/DEPLOYMENT.md", r"`pyproject.toml`[^`]*`v([0-9.]+)`"),
    ("tgwitness/static/guide.html", r'<span class="version">([0-9.]+)</span>'),
    ("tgwitness/static/index.html", r'id="github-ref"[^>]*placeholder="v([0-9.]+)"'),
)


class PortOwner(unittest.TestCase):
    def test_occupied_port_names_its_process_and_a_free_port(self):
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            port = occupied.getsockname()[1]
            with self.assertRaises(ValueError) as caught:
                panel.check_port(port, suggest=True)
            message = str(caught.exception)
            self.assertIn(f"Port {port} is already in use by process {os.getpid()}", message)
            self.assertIn("Nothing was stopped.", message)
            suggested = int(re.search(r"tgwitness setup --port (\d+)$", message).group(1))
            self.assertNotEqual(suggested, port)
            panel.check_port(suggested)
            with self.assertRaises(ValueError) as caught:
                panel.check_port(port, "127.0.0.1")
            self.assertNotIn("--port", str(caught.exception))
            self.assertGreater(occupied.fileno(), -1)

    @unittest.skipIf(os.name == "nt", "TIME_WAIT blocks a plain bind only on POSIX")
    def test_closed_connections_do_not_hold_the_port(self):
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", 0))
            server.listen()
            port = server.getsockname()[1]
            client = socket.create_connection(("127.0.0.1", port))
            accepted, _ = server.accept()
            accepted.close()
            client.close()
        panel.check_port(port)

    def test_unknown_owner_still_explains_the_port(self):
        with socket.socket() as occupied, patch.object(panel, "listening_pid", side_effect=OSError("denied")):
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            port = occupied.getsockname()[1]
            with self.assertRaisesRegex(ValueError, f"Port {port} is already in use or unavailable. Nothing was stopped."):
                panel.check_port(port)

    def test_linux_owner_from_proc(self):
        def read_text(path, *args, **kwargs):
            files = {"/proc/net/tcp": PROC_TCP, "/proc/777/comm": "python3\n"}
            if path.as_posix() not in files:
                raise FileNotFoundError(path)
            return files[path.as_posix()]

        def listdir(path):
            if path == "/proc/1/fd":
                raise PermissionError(path)
            return {"/proc": ["1", "self", "777", "900"], "/proc/777/fd": ["0", "1", "5"], "/proc/900/fd": ["0"]}[path]

        def readlink(path):
            return {"/proc/777/fd/5": "socket:[55501]"}.get(path, "/dev/null")

        with patch.object(panel.sys, "platform", "linux"), patch.object(panel.Path, "read_text", autospec=True, side_effect=read_text), \
                patch.object(panel.os, "listdir", side_effect=listdir) as listed, \
                patch.object(panel.os, "readlink", side_effect=readlink, create=True):
            self.assertEqual(panel.port_owner(8787), "process 777 (python3)")
            listed.reset_mock()
            self.assertIsNone(panel.port_owner(8788))
            listed.assert_not_called()

    def test_windows_owner_from_netstat_in_any_language(self):
        with patch.object(panel.sys, "platform", "win32"), \
                patch.object(panel.subprocess, "run", return_value=Mock(stdout=NETSTAT)) as run:
            self.assertEqual(panel.port_owner(8787), "process 3000")
            self.assertIsNone(panel.port_owner(8080))
        self.assertEqual(run.call_args.args[0], ["netstat", "-ano", "-p", "TCP"])
        self.assertEqual(run.call_args.kwargs["errors"], "replace")

    def test_macos_owner_from_lsof(self):
        with patch.object(panel.sys, "platform", "darwin"), patch.object(panel.subprocess, "run", return_value=Mock(stdout="512\n")):
            self.assertEqual(panel.port_owner(8787), "process 512")
        with patch.object(panel.sys, "platform", "darwin"), patch.object(panel.subprocess, "run", side_effect=FileNotFoundError("lsof")):
            self.assertIsNone(panel.port_owner(8787))


class OneVersion(unittest.TestCase):
    def test_every_published_version_matches_the_package(self):
        version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
        self.assertEqual(tgwitness.__version__, version)
        for pattern, expression in VERSIONS:
            files = sorted(ROOT.glob(pattern))
            found = [(path, value) for path in files
                     for value in re.findall(expression, path.read_text(encoding="utf-8"))]
            with self.subTest(pattern=pattern):
                self.assertTrue(found, "no version found in " + pattern)
                self.assertEqual([str(path.relative_to(ROOT)) for path, value in found if value != version], [])


if __name__ == "__main__":
    unittest.main()
