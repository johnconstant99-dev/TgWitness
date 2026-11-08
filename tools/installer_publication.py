"""Retain verified immutable downloads and check an installer publication over HTTPS."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import time
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://get.destroy.tools"
RELEASE = re.compile(r"[0-9a-f]{12}-[0-9a-f]{12}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,150}")
MAX_BYTES = 64 * 1024 * 1024


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, target):
        raise ValueError("Installer downloads must not redirect")


def fetch(path, limit=MAX_BYTES):
    request = Request(ORIGIN + "/" + path, headers={
        "User-Agent": "TgWitnessInstallerCheck/1", "Cache-Control": "no-cache"})
    with build_opener(NoRedirects).open(request, timeout=45) as response:
        if response.url != request.full_url:
            raise ValueError("Installer downloads must not redirect")
        data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Installer download exceeds size limit")
        return data


def validate_manifest(raw, release_id, public, *, allow_test=False):
    manifest = json.loads(raw)
    origin = "https://installer.invalid" if allow_test else ORIGIN
    if (not RELEASE.fullmatch(release_id) or manifest.get("release_id") != release_id
            or manifest.get("schema") != "tgwitness-installer-v1"
            or manifest.get("base_url") != origin or manifest.get("test_only") is not allow_test
            or manifest.get("signing_key_sha256") != hashlib.sha256(public).hexdigest()):
        raise ValueError("Untrusted installer manifest")
    files = manifest["files"]
    if not isinstance(files, dict) or not 10 <= len(files) <= 40:
        raise ValueError("Invalid installer inventory")
    wheels = [name for name in files if name.endswith(".whl")]
    dependency_file = "requirements.lock" if "requirements.lock" in files else "constraints.txt"
    expected = {"install.sh", "install.ps1", "install.cmd", dependency_file, "release-signing.pub", *wheels}
    expected.update(name + ".sig" for name in tuple(expected) if name != "release-signing.pub")
    if len(wheels) != 1 or set(files) != expected:
        raise ValueError("Unexpected installer inventory")
    for name, entry in files.items():
        if (not NAME.fullmatch(name) or not re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", ""))
                or type(entry.get("bytes")) is not int or not 0 < entry["bytes"] <= MAX_BYTES
                or entry.get("url") != f"{origin}/releases/{release_id}/{name}"):
            raise ValueError("Invalid installer artifact")
    return manifest


def verify_release(raw, release_id, read, public, *, allow_test=False):
    manifest = validate_manifest(raw, release_id, public, allow_test=allow_test)
    files = {name: read(name) for name in manifest["files"]}
    if files["release-signing.pub"] != public:
        raise ValueError("Release public key differs from the trusted key")
    key = serialization.load_pem_public_key(public)
    for name, data in files.items():
        entry = manifest["files"][name]
        if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("Artifact checksum mismatch: " + name)
        if not name.endswith(".sig") and name != "release-signing.pub":
            key.verify(files[name + ".sig"], data, padding.PKCS1v15(), hashes.SHA256())
    return files


def verify_local(site, public, revision=None, *, allow_test=False):
    site = Path(site).resolve(strict=True)
    if any(path.is_symlink() for path in site.rglob("*")):
        raise ValueError("Linked publication paths are not allowed")
    raw = (site / "manifest.json").read_bytes()
    key = serialization.load_pem_public_key(public)
    key.verify((site / "manifest.json.sig").read_bytes(), raw, padding.PKCS1v15(), hashes.SHA256())
    manifest = json.loads(raw)
    release_id = manifest.get("release_id", "")
    validate_manifest(raw, release_id, public, allow_test=allow_test)
    source = manifest.get("source_revision", "")
    if not re.fullmatch(r"[0-9a-f]{40}", source) or (revision is not None and source != revision):
        raise ValueError("Installer source revision differs from the requested revision")
    release = site / "releases" / release_id
    files = verify_release(raw, release_id, lambda name: (release / name).read_bytes(),
                           public, allow_test=allow_test)
    for name, data in files.items():
        expected = (hashlib.sha256(data).hexdigest() + "  " + name).encode()
        if (release / (name + ".sha256")).read_bytes().strip() != expected:
            raise ValueError("Installer checksum sidecar differs: " + name)
    for name in ("manifest.json", "manifest.json.sig", "release-signing.pub"):
        if (site / name).read_bytes() != (release / name).read_bytes():
            raise ValueError("Mutable and immutable installer files differ: " + name)
    scripts = ("install.sh", "install.ps1", "install.cmd")
    for name in scripts:
        if (site / name).read_bytes() != files[name] or (site / (name + ".sig")).read_bytes() != files[name + ".sig"]:
            raise ValueError("Mutable and immutable installer scripts differ: " + name)
        if b"@@" in files[name]:
            raise ValueError("Unresolved installer template: " + name)
    sums = (site / "SHA256SUMS.txt").read_bytes()
    key.verify((site / "SHA256SUMS.txt.sig").read_bytes(), sums, padding.PKCS1v15(), hashes.SHA256())
    expected = "".join(hashlib.sha256(files[name]).hexdigest() + "  " + name + "\n" for name in scripts).encode()
    if sums != expected:
        raise ValueError("Installer bootstrap checksum inventory differs")
    if hashlib.sha256(files["install.ps1"]).hexdigest().encode() not in files["install.cmd"]:
        raise ValueError("CMD bootstrap does not pin the PowerShell installer")
    return manifest


def release_ids(raw):
    catalog = json.loads(raw)
    values = catalog.get("releases")
    if (catalog.get("schema") != "tgwitness-installer-archive-v1" or not isinstance(values, list)
            or not 1 <= len(values) <= 512
            or any(not isinstance(value, str) or not RELEASE.fullmatch(value) for value in values)
            or len(set(values)) != len(values)):
        raise ValueError("Invalid immutable release catalog")
    return values


def index(site, public):
    releases = sorted((site / "releases").iterdir())
    ids = []
    for release in releases:
        if not release.is_dir() or release.is_symlink():
            raise ValueError("Invalid release directory")
        verify_release((release / "manifest.json").read_bytes(), release.name,
                       lambda name: (release / name).read_bytes(), public)
        ids.append(release.name)
    raw = (json.dumps({"schema": "tgwitness-installer-archive-v1", "releases": ids}, indent=2) + "\n").encode()
    release_ids(raw)
    (site / "releases.json").write_bytes(raw)


def retain(site, public):
    ids = release_ids(fetch("releases.json", 128 * 1024))
    for release_id in ids:
        release = site / "releases" / release_id
        prefix = "releases/" + release_id + "/"
        raw = fetch(prefix + "manifest.json", 128 * 1024)
        files = verify_release(raw, release_id, lambda name: fetch(prefix + name), public)
        files["manifest.json"] = raw
        try:
            signature = fetch(prefix + "manifest.json.sig", 4096)
        except HTTPError as exc:
            if exc.code != 404:
                raise
        else:
            serialization.load_pem_public_key(public).verify(signature, raw, padding.PKCS1v15(), hashes.SHA256())
            files["manifest.json.sig"] = signature
        for name in tuple(files):
            if name not in {"manifest.json", "manifest.json.sig"}:
                files[name + ".sha256"] = (hashlib.sha256(files[name]).hexdigest() + "  " + name + "\n").encode()
        for name, data in files.items():
            target = release / name
            if target.exists() and target.read_bytes() != data:
                raise ValueError("Immutable release collision: " + release_id)
        release.mkdir(parents=True, exist_ok=True)
        for name, data in files.items():
            (release / name).write_bytes(data)
    index(site, public)


def download_current(site, public, revision=None):
    if site.exists() and any(site.iterdir()):
        raise ValueError("Choose an empty directory for public installer checks")
    raw = fetch("manifest.json", 128 * 1024)
    manifest = json.loads(raw)
    release_id = manifest.get("release_id", "")
    validate_manifest(raw, release_id, public)
    source = manifest.get("source_revision", "")
    if not re.fullmatch(r"[0-9a-f]{40}", source) or (revision is not None and source != revision):
        raise ValueError("Published installer does not match the expected source revision")
    prefix = "releases/" + release_id + "/"
    if fetch(prefix + "manifest.json", 128 * 1024) != raw:
        raise ValueError("Current and immutable installer manifests differ")
    # Use the immutable signature so a concurrent publication cannot pair two builds.
    signature = fetch(prefix + "manifest.json.sig", 4096)
    key = serialization.load_pem_public_key(public)
    key.verify(signature, raw, padding.PKCS1v15(), hashes.SHA256())
    files = verify_release(raw, release_id, lambda name: fetch(prefix + name), public)
    release = site / "releases" / release_id
    release.mkdir(parents=True)
    for name, data in files.items():
        (release / name).write_bytes(data)
        sidecar = fetch(prefix + name + ".sha256", 1024)
        if sidecar.strip() != (hashlib.sha256(data).hexdigest() + "  " + name).encode():
            raise ValueError("Published checksum sidecar differs: " + name)
        (release / (name + ".sha256")).write_bytes(sidecar)
    for name, data in (("manifest.json", raw), ("manifest.json.sig", signature)):
        (site / name).write_bytes(data)
        (release / name).write_bytes(data)
    for name in ("install.sh", "install.ps1", "install.cmd"):
        current = fetch(name)
        if current != files[name]:
            raise ValueError("Public installer changed during the check; download a fresh snapshot")
        (site / name).write_bytes(current)
        (site / (name + ".sig")).write_bytes(files[name + ".sig"])
    (site / "release-signing.pub").write_bytes(public)
    sums, sums_signature = fetch("SHA256SUMS.txt", 4096), fetch("SHA256SUMS.txt.sig", 4096)
    key.verify(sums_signature, sums, padding.PKCS1v15(), hashes.SHA256())
    expected = "".join(hashlib.sha256(files[name]).hexdigest() + "  " + name + "\n"
                       for name in ("install.sh", "install.ps1", "install.cmd")).encode()
    if sums != expected:
        raise ValueError("Public installer checksums belong to another build")
    (site / "SHA256SUMS.txt").write_bytes(sums)
    (site / "SHA256SUMS.txt.sig").write_bytes(sums_signature)
    print("Public installer authenticated: " + source + " (" + release_id + ")", flush=True)
    return manifest


def verify_public(site, *, attempts=7, delay=5):
    paths = [p.relative_to(site).as_posix() for p in site.rglob("*")
             if p.is_file() and not p.name.startswith((".", "_"))]

    def check(path):
        try:
            return fetch("" if path == "index.html" else path) == (site / path).read_bytes()
        except HTTPError as exc:
            if exc.code not in (404, 502, 503, 504):
                raise
            return False

    pending = paths
    with ThreadPoolExecutor(max_workers=6) as pool:
        for attempt in range(attempts):
            pending = [path for path, matches in zip(pending, pool.map(check, pending)) if not matches]
            if not pending:
                break
            if attempt + 1 < attempts:
                print(f"Waiting for {len(pending)} public paths to match the deployment ({attempt + 1}/{attempts}).")
                time.sleep(delay)
    if pending:
        raise ValueError("Published bytes differ or are unavailable: " + ", ".join(pending[:10]))
    try:
        fetch("missing-installer-publication-check")
    except HTTPError as exc:
        if exc.code != 404:
            raise
    else:
        raise ValueError("Missing downloads must return 404")
    print(f"Public HTTPS bytes checked: {len(paths)}; missing downloads: 404")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("retain", "index", "verify-public", "verify-local", "download-current"))
    parser.add_argument("--site", type=Path, default=ROOT / "dist/installer-site")
    parser.add_argument("--revision", help="Require this source commit when downloading or verifying the installer")
    parser.add_argument("--allow-test-key", action="store_true", help="Verify only an ephemeral-key build for https://installer.invalid")
    args = parser.parse_args()
    if args.allow_test_key and args.action != "verify-local":
        raise ValueError("Ephemeral keys are accepted only by verify-local")
    if args.action == "download-current":
        download_current(args.site.resolve(), (ROOT / "deploy/installer/release-signing.pub").read_bytes(), args.revision)
        return
    site = args.site.resolve(strict=True)
    if not (site / "manifest.json").is_file() or not (site / "releases").is_dir():
        raise ValueError("Expected a built installer site")
    if any(path.is_symlink() for path in site.rglob("*")):
        raise ValueError("Linked publication paths are not allowed")
    public = (ROOT / "deploy/installer/release-signing.pub").read_bytes()
    if args.action == "verify-local":
        if args.allow_test_key:
            public = (site / "release-signing.pub").read_bytes()
        verify_local(site, public, args.revision, allow_test=args.allow_test_key)
    elif args.action == "verify-public":
        verify_public(site)
    elif args.action == "retain":
        retain(site, public)
    else:
        index(site, public)
    print("Installer publication " + args.action + ": passed")


if __name__ == "__main__":
    main()
