"""Check installer artifacts"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", type=Path, default=ROOT / "dist" / "installer-site")
    parser.add_argument("--install", action="store_true", help="Install with real uv/Python/packages; map only the unpublished site's downloads locally")
    parser.add_argument("--service", choices=["local", "quick"], help="Linux root: also exercise an isolated systemd panel")
    parser.add_argument("--public", action="store_true", help="Use real HTTPS for the authenticated public installer snapshot")
    args = parser.parse_args()
    site = args.site.resolve()
    manifest = json.loads((site / "manifest.json").read_text())
    release = site / "releases" / manifest["release_id"]
    public_bytes = (release / "release-signing.pub").read_bytes()
    assert hashlib.sha256(public_bytes).hexdigest() == manifest["signing_key_sha256"]
    public_key = serialization.load_pem_public_key(public_bytes)
    if not manifest["test_only"]:
        assert public_bytes == (ROOT / "deploy/installer/release-signing.pub").read_bytes()
    else:
        assert urlsplit(manifest["base_url"]).hostname.endswith(".invalid"), "A test signing key cannot be published"
    if release.resolve().parent != (site / "releases").resolve():
        raise ValueError("Invalid release path")
    for name, entry in manifest["files"].items():
        if Path(name).name != name or "\\" in name:
            raise ValueError("Invalid artifact filename")
        data = (release / name).read_bytes()
        assert len(data) == entry["bytes"] and hashlib.sha256(data).hexdigest() == entry["sha256"], name
        assert entry["url"] == manifest["base_url"] + "/releases/" + manifest["release_id"] + "/" + name
        assert (release / (name + ".sha256")).read_text().strip() == entry["sha256"] + "  " + name
        if not name.endswith(".sig") and name != "release-signing.pub":
            public_key.verify((release / (name + ".sig")).read_bytes(), data, padding.PKCS1v15(), hashes.SHA256())
        if name in ("install.sh", "install.ps1", "install.cmd"):
            assert (site / name).read_bytes() == data
            assert b"@@" not in data, "Unresolved installer template"
    assert (release / "manifest.json").read_bytes() == (site / "manifest.json").read_bytes()
    for name in ("manifest.json", "SHA256SUMS.txt"):
        public_key.verify((site / (name + ".sig")).read_bytes(), (site / name).read_bytes(),
                          padding.PKCS1v15(), hashes.SHA256())
    assert (release / "manifest.json.sig").read_bytes() == (site / "manifest.json.sig").read_bytes()
    assert manifest["files"]["install.ps1"]["sha256"] in (site / "install.cmd").read_text()
    assert urlsplit(manifest["base_url"]).scheme == "https"
    print("Artifact sizes, immutable files, SHA-256, RSA release signatures and pinned CMD bootstrap: passed", flush=True)
    if not args.install and not args.service:
        return
    if sys.platform not in ("linux", "darwin"):
        raise SystemExit("--install runs on Linux/macOS; Windows is qualified separately with PowerShell.")
    bash, curl = shutil.which("bash"), shutil.which("curl")
    if not bash or not curl:
        raise SystemExit("The Unix installation check needs bash and curl.")
    if args.service and (sys.platform != "linux" or os.geteuid() != 0):
        raise SystemExit("Service acceptance runs as root on a disposable Linux systemd host.")
    with tempfile.TemporaryDirectory(prefix="tgwitness-install-check-", dir="/opt" if args.service else None) as temporary:
        scratch = Path(temporary)
        if args.service:
            scratch.chmod(0o755)
        app = scratch / "private app"
        shim = scratch / "commands"
        shim.mkdir()
        proxy = shim / "curl"
        proxy_script = shim / "curl.py"
        proxy_script.write_text(r'''
import os, pathlib, shutil, subprocess, sys
from urllib.parse import urlsplit, unquote
args = sys.argv[1:]
origin = os.environ['TGW_CHECK_ORIGIN'].rstrip('/') + '/'
url = args[-1]
if not url.startswith(origin):
    raise SystemExit(subprocess.call([os.environ['TGW_CHECK_CURL'], *args]))
relative = unquote(url[len(origin):])
root = pathlib.Path(os.environ['TGW_CHECK_SITE']).resolve()
source = (root / relative).resolve()
if not source.is_relative_to(root) or not source.is_file():
    raise SystemExit('Unrecognized installer artifact')
flag = '--output' if '--output' in args else '-o'
destination = pathlib.Path(args[args.index(flag) + 1])
shutil.copyfile(source, destination)
if os.environ.get('TGW_CHECK_TAMPER_SIGNATURE') == '1' and relative.endswith('.whl.sig'):
    raw = bytearray(destination.read_bytes())
    raw[0] ^= 1
    destination.write_bytes(raw)
with open(os.environ['TGW_CHECK_DOWNLOADS'], 'a') as stream:
    stream.write(relative + '\n')
''', encoding="utf-8")
        proxy.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " " + shlex.quote(str(proxy_script)) + ' "$@"\n')
        proxy.chmod(0o700)
        env = dict(os.environ, TGWITNESS_INSTALL_DIR=str(app), TGWITNESS_NO_LINK="1",
                   TGW_CHECK_ORIGIN=manifest["base_url"], TGW_CHECK_CURL=curl, TGW_CHECK_SITE=str(site),
                   TGW_CHECK_DOWNLOADS=str(scratch / "downloads"), PATH=str(shim) + os.pathsep + os.environ["PATH"])
        script = str(site / "install.sh")
        subprocess.run([bash, "-n", script], check=True)
        subprocess.run([bash, script, "--plan"], env=env, check=True)
        assert not app.exists(), "Planning changed the filesystem"
        rejected_app = scratch / "rejected signature"
        rejected = subprocess.run([bash, script, "--no-start"],
                                  env=dict(env, TGWITNESS_INSTALL_DIR=str(rejected_app), TGW_CHECK_TAMPER_SIGNATURE="1"),
                                  capture_output=True, text=True, timeout=300)
        assert rejected.returncode != 0 and "Release signature rejected" in rejected.stderr, "A corrupt signature was not rejected"
        assert not list((rejected_app / "versions").glob("*/.ready")), "A rejected package was activated"
        print("Altered release signature: refused before package installation", flush=True)
        install_env = dict(env, PATH=os.environ["PATH"], TGWITNESS_NO_SETUP="1") if args.public else env
        command = ([bash, "-o", "pipefail", "-c",
                    "curl -fsSL " + shlex.quote(manifest["base_url"] + "/install.sh") + " | bash"]
                   if args.public else [bash, script, "--no-start"])
        subprocess.run(command, env=install_env, check=True, timeout=900)
        receipts = list((app / "versions").glob("*/.ready"))
        expected_receipt = app / "versions" / manifest["release_id"] / ".ready"
        assert receipts == [expected_receipt], "Installed public source changed during acceptance"
        wheel_name = next(name for name in manifest["files"] if name.endswith(".whl"))
        assert expected_receipt.read_text().splitlines() == [manifest["release_id"], manifest["source_revision"],
                                                           manifest["files"][wheel_name]["sha256"],
                                                           manifest["files"]["constraints.txt"]["sha256"]]
        launcher = app / "bin" / "tgwitness"
        original = launcher.read_bytes()
        (app / "data").mkdir(exist_ok=True)
        sentinel = app / "data" / "keep-this-record"
        sentinel.write_text("unchanged\n")
        reads = (scratch / "downloads").read_bytes()
        subprocess.run(command, env=install_env, check=True, timeout=120)
        assert launcher.read_bytes() == original and sentinel.read_text() == "unchanged\n"
        assert (scratch / "downloads").read_bytes() == reads, "Repeated setup downloaded files again"
        assert not (app / "data" / "live").exists(), "Installer initialized live user data"
        print("Real Unix installation, offline import checks, idempotency and data preservation: passed", flush=True)
        if args.service:
            from check_installer_service import check_service
            check_service(app, args.service)


if __name__ == "__main__":
    main()
