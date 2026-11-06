"""Install the checked PowerShell package in isolation and exercise its actual panel."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def quoted(value):
    return "'" + str(value).replace("'", "''") + "'"


def panel(python, scratch):
    data = scratch / "empty workspace"
    with socket.socket() as available:
        available.bind(("127.0.0.1", 0))
        port = available.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    token = None
    for attempt in range(2):
        with (scratch / f"panel-{attempt}.log").open("w", encoding="utf-8") as log:
            process = subprocess.Popen([str(python), "-I", "-m", "tgwitness", "--host", "127.0.0.1",
                                        "--port", str(port), "--data-dir", str(data)],
                                       stdout=log, stderr=subprocess.STDOUT, cwd=scratch)
            try:
                deadline = time.monotonic() + 90
                while True:
                    if process.poll() is not None:
                        raise AssertionError("Installed panel exited before readiness; inspect the private test log")
                    try:
                        with urlopen(origin + "/", timeout=5) as response:
                            assert response.status == 200 and b"TgWitness" in response.read()
                        break
                    except (OSError, URLError):
                        if time.monotonic() >= deadline:
                            raise AssertionError("Installed panel did not become ready") from None
                        time.sleep(0.25)
                current = (data / "panel-token.txt").read_text().strip()
                if token is not None:
                    assert current == token, "Restart replaced the panel credential"
                token = current
                try:
                    urlopen(origin + "/api/status", timeout=10)
                    raise AssertionError("Unauthenticated status request was accepted")
                except HTTPError as exc:
                    assert exc.code == 401
                for path in ("/api/status", "/api/health"):
                    with urlopen(Request(origin + path, headers={"Authorization": "Bearer " + token}), timeout=15) as response:
                        assert response.status == 200 and isinstance(json.loads(response.read()), dict)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
    print("Installed Windows panel: HTTP, authentication and retained credentials after restart: passed", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", type=Path, default=ROOT / "dist/installer-site")
    parser.add_argument("--public", action="store_true", help="Download packages from the public HTTPS URLs")
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("This acceptance check requires Windows")
    site = args.site.resolve()
    subprocess.run([sys.executable, str(ROOT / "tools/check_installer.py"), "--site", str(site)], check=True)
    manifest = json.loads((site / "manifest.json").read_bytes())
    powershell = shutil.which("powershell.exe")
    if powershell is None:
        raise SystemExit("Windows PowerShell 5.1 is required")
    base = Path(os.environ["LOCALAPPDATA"]).resolve()
    with tempfile.TemporaryDirectory(prefix="tgwitness-installer-acceptance-", dir=base) as temporary:
        scratch = Path(temporary).resolve()
        assert scratch.parent == base and not scratch.is_symlink()
        app, script = scratch / "private app", site / "install.ps1"
        env = dict(os.environ, TGWITNESS_INSTALL_DIR=str(app), TGWITNESS_NO_SETUP="1")
        subprocess.run([powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-Plan"],
                       env=env, check=True, timeout=60)
        assert not app.exists(), "Planning changed the destination"
        wrapper = scratch / "install-checked.ps1"
        shim = "" if args.public else r'''
function Invoke-WebRequest {
    param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing, [int]$TimeoutSec)
    if ($Uri.StartsWith($env:TGW_CHECK_ORIGIN + '/', [StringComparison]::Ordinal)) {
        $Relative = [Uri]::UnescapeDataString($Uri.Substring($env:TGW_CHECK_ORIGIN.Length + 1))
        $Source = [IO.Path]::GetFullPath((Join-Path $env:TGW_CHECK_SITE $Relative))
        $Root = [IO.Path]::GetFullPath($env:TGW_CHECK_SITE).TrimEnd('\') + '\'
        if (-not $Source.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase) -or -not [IO.File]::Exists($Source)) {
            throw 'Unrecognized installer artifact'
        }
        [IO.File]::Copy($Source, $OutFile, $false)
    } else {
        Microsoft.PowerShell.Utility\Invoke-WebRequest @PSBoundParameters
    }
}
'''
        wrapper.write_text(shim + "\n& " + quoted(script) + " -NoStart\n", encoding="utf-8")
        env.update(TGW_CHECK_ORIGIN=manifest["base_url"], TGW_CHECK_SITE=str(site))
        command = [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass"]
        command += (["-Command", "irm " + quoted(manifest["base_url"] + "/install.ps1") + " | iex"]
                    if args.public else ["-File", str(wrapper)])
        subprocess.run(command, env=env, check=True, timeout=900)
        launcher = app / "bin/tgwitness.cmd"
        original = launcher.read_bytes()
        sentinel = app / "data/live/keep-this-record"
        sentinel.write_text("unchanged\n")
        receipts = list((app / "versions").glob("*/.install-complete.json"))
        assert len(receipts) == 1
        receipt = json.loads(receipts[0].read_text(encoding="utf-8-sig"))
        assert receipt["revision"] == manifest["source_revision"] and receipt["release"] == manifest["release_id"]
        subprocess.run(command, env=env, check=True, timeout=180)
        assert launcher.read_bytes() == original and sentinel.read_text() == "unchanged\n"
        assert list((app / "versions").glob("*/.install-complete.json")) == receipts
        python = receipts[0].parent / ".venv/Scripts/python.exe"
        wheel = next((site / "releases" / manifest["release_id"]).glob("*.whl"))
        package = receipts[0].parent / ".venv/Lib/site-packages"
        with zipfile.ZipFile(wheel) as archive:
            names = [name for name in archive.namelist() if name.startswith(("tgwitness/", "tgwitness_capture/"))]
            for name in names:
                assert hashlib.sha256((package / name).read_bytes()).digest() == hashlib.sha256(archive.read(name)).digest(), name
        print(f"Windows PowerShell installation, {len(names)} package files, exact source receipt and idempotency: passed", flush=True)
        panel(python, scratch)


if __name__ == "__main__":
    main()
