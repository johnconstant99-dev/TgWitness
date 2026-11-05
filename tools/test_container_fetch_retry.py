"""Run the complete package installer with network failures and corrupt downloads.

Run inside a built Wolfi container. Only apk transport and sleep are simulated;
shell control flow, cache enumeration, SHA-256 checks and cleanup are real.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

INSTALLER = Path(__file__).resolve().parents[1] / "deploy/containers/install-packages.sh"
PAYLOAD = b"synthetic authenticated package fixture\n"
APK = r'''
import json, os, pathlib, sys
state = pathlib.Path(os.environ["FIXTURE_STATE"])
args = sys.argv[1:]
with (state / "calls").open("a") as log:
    log.write(json.dumps(["apk", *args]) + "\n")
operation = args[0]
if operation == "--print-arch":
    print("x86_64")
elif operation == "verify":
    sys.exit(int(os.environ.get("BAD_SIGNATURE", "0")))
elif operation in ("update", "cache"):
    cache = pathlib.Path(args[args.index("--cache-dir") + 1])
    (state / "cache-path").write_text(str(cache.parent))
    counter = state / (operation + "-attempts")
    count = int(counter.read_text()) + 1 if counter.exists() else 1
    counter.write_text(str(count))
    if operation == "update":
        (cache / "APKINDEX.12345678.tar.gz").write_bytes(b"synthetic signed index")
    else:
        body = b"synthetic authenticated package fixture\n"
        if os.environ.get("CORRUPT") or count <= int(os.environ.get("CACHE_FAILURES", "0")):
            body = b"incomplete or modified download"
        (cache / "synthetic-1.0-r0.12345678.apk").write_bytes(body)
        if os.environ.get("EXTRA_PACKAGE"):
            (cache / "unreviewed-1.0-r0.12345678.apk").write_bytes(body)
    sys.exit(1 if count <= int(os.environ.get(operation.upper() + "_FAILURES", "0")) else 0)
elif operation == "add":
    assert "--no-network" in args
    assert args[-1] == "synthetic=1.0-r0"
    (state / "installed").write_text("only after verification")
else:
    raise AssertionError(args)
'''
SLEEP = r'''
import json, os, pathlib, sys
with (pathlib.Path(os.environ["FIXTURE_STATE"]) / "calls").open("a") as log:
    log.write(json.dumps(["sleep", *sys.argv[1:]]) + "\n")
'''


class FetchRetry(unittest.TestCase):
    def run_installer(self, **environment):
        with tempfile.TemporaryDirectory(prefix="container-fetch-fixture-") as temporary:
            root = Path(temporary)
            (root / "bin").mkdir()
            for name in ("dirname", "mktemp", "awk", "mkdir", "sort", "ls", "cmp", "ln", "sha256sum", "rm"):
                target = shutil.which(name)
                self.assertIsNotNone(target, name)
                (root / "bin" / name).symlink_to(target)
            (root / "install-packages.sh").write_bytes(INSTALLER.read_bytes())
            digest = hashlib.sha256(PAYLOAD).hexdigest()
            (root / "runtime-x86_64.lock").write_text(digest + "  synthetic-1.0-r0.apk\n")
            for name, body in (("apk", APK), ("sleep", SLEEP)):
                path = root / "bin" / name
                path.write_text("#!" + sys.executable + "\n" + body)
                path.chmod(0o700)
            result = subprocess.run([shutil.which("sh"), str(root / "install-packages.sh"), "runtime"],
                env={**os.environ, "PATH": str(root / "bin"),
                     "FIXTURE_STATE": str(root), **{key: str(value) for key, value in environment.items()}},
                capture_output=True, text=True, timeout=60)
            self.assertTrue((root / "calls").is_file(), result.stdout + result.stderr)
            calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
            self.assertFalse(Path((root / "cache-path").read_text()).exists(), "Temporary cache survived exit")
            return result, calls, (root / "installed").exists()

    def test_first_attempt_preserves_offline_install(self):
        result, calls, installed = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(installed)
        self.assertFalse(any(call[0] == "sleep" for call in calls))

    def test_partial_download_and_index_failures_recover_with_bounded_backoff(self):
        result, calls, installed = self.run_installer(UPDATE_FAILURES=1, CACHE_FAILURES=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(installed)
        self.assertEqual([call for call in calls if call[0] == "sleep"],
                         [["sleep", "2"], ["sleep", "2"], ["sleep", "4"]])
        self.assertEqual(sum(call[:2] == ["apk", "update"] for call in calls), 2)
        self.assertEqual(sum(call[:2] == ["apk", "cache"] for call in calls), 3)
        self.assertEqual(sum(call[:2] == ["apk", "verify"] for call in calls), 1)

    def test_exhausted_network_retries_never_install(self):
        for operation in ("UPDATE", "CACHE"):
            with self.subTest(operation=operation):
                result, calls, installed = self.run_installer(**{operation + "_FAILURES": 9})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(installed)
                self.assertEqual(sum(call[:2] == ["apk", operation.lower()] for call in calls), 3)
                self.assertEqual([call for call in calls if call[0] == "sleep"], [["sleep", "2"], ["sleep", "4"]])

    def test_signature_failure_is_not_retried_or_installed(self):
        result, calls, installed = self.run_installer(BAD_SIGNATURE=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(installed)
        self.assertFalse(any(call[0] == "sleep" or call[:2] == ["apk", "cache"] for call in calls))

    def test_modified_or_extra_packages_cannot_reach_installation(self):
        for flag in ("CORRUPT", "EXTRA_PACKAGE"):
            with self.subTest(flag=flag):
                result, calls, installed = self.run_installer(**{flag: 1})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(installed)
                self.assertFalse(any(call[0] == "sleep" for call in calls))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installer", type=Path, default=INSTALLER)
    args, extra = parser.parse_known_args()
    INSTALLER = args.installer
    if not Path("/etc/apk/repositories").is_file() or not shutil.which("sh"):
        parser.error("Run inside the built Linux container with its real repository configuration")
    unittest.main(argv=[sys.argv[0], *extra])
