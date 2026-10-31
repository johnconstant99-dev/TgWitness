"""Check installer artifacts; optionally perform a real isolated Unix installation."""
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

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", type=Path, default=ROOT / "dist" / "installer-site")
    parser.add_argument("--install", action="store_true", help="Install with real uv/Python/packages; map only the unpublished site's downloads locally")
    args = parser.parse_args()
    site = args.site.resolve()
    manifest = json.loads((site / "manifest.json").read_text())
    release = site / "releases" / manifest["release_id"]
    if release.resolve().parent != (site / "releases").resolve():
        raise ValueError("Invalid release path")
    for name, entry in manifest["files"].items():
        if Path(name).name != name or "\\" in name:
            raise ValueError("Invalid artifact filename")
        data = (release / name).read_bytes()
        assert len(data) == entry["bytes"] and hashlib.sha256(data).hexdigest() == entry["sha256"], name
        assert entry["url"] == manifest["base_url"] + "/releases/" + manifest["release_id"] + "/" + name
        assert (release / (name + ".sha256")).read_text().strip() == entry["sha256"] + "  " + name
        if name in ("install.sh", "install.ps1", "install.cmd"):
            assert (site / name).read_bytes() == data
            assert b"@@" not in data, "Unresolved installer template"
    assert (release / "manifest.json").read_bytes() == (site / "manifest.json").read_bytes()
    assert manifest["files"]["install.ps1"]["sha256"] in (site / "install.cmd").read_text()
    assert urlsplit(manifest["base_url"]).scheme == "https"
    print("Artifact sizes, immutable files, SHA-256 sidecars and pinned CMD bootstrap: passed", flush=True)
    if not args.install:
        return
    if sys.platform not in ("linux", "darwin"):
        raise SystemExit("--install runs on Linux/macOS; Windows is qualified separately with PowerShell.")
    bash, curl = shutil.which("bash"), shutil.which("curl")
    if not bash or not curl:
        raise SystemExit("The Unix installation check needs bash and curl.")
    with tempfile.TemporaryDirectory(prefix="tgwitness-install-check-") as temporary:
        scratch = Path(temporary)
        app = scratch / "private app"
        shim = scratch / "commands"
        shim.mkdir()
        # Only the not-yet-published static origin is mapped locally. Runtime and
        # dependency downloads still use their real HTTPS URLs and pinned hashes.
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
        subprocess.run([bash, script], env=env, check=True, timeout=900)
        launcher = app / "bin" / "tgwitness"
        original = launcher.read_bytes()
        (app / "data").mkdir(exist_ok=True)
        sentinel = app / "data" / "keep-this-record"
        sentinel.write_text("unchanged\n")
        reads = (scratch / "downloads").read_bytes()
        subprocess.run([bash, script], env=env, check=True, timeout=120)
        assert launcher.read_bytes() == original and sentinel.read_text() == "unchanged\n"
        assert (scratch / "downloads").read_bytes() == reads, "Repeated setup downloaded files again"
        assert not (app / "data" / "live").exists(), "Installer initialized live user data"
        print("Real Unix installation, offline import checks, idempotency and data preservation: passed", flush=True)


if __name__ == "__main__":
    main()
