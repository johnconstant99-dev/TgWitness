"""Retain verified immutable downloads and check an installer publication over HTTPS."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
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


def validate_manifest(raw, release_id, public):
    manifest = json.loads(raw)
    if (not RELEASE.fullmatch(release_id) or manifest.get("release_id") != release_id
            or manifest.get("schema") != "tgwitness-installer-v1"
            or manifest.get("base_url") != ORIGIN or manifest.get("test_only") is not False
            or manifest.get("signing_key_sha256") != hashlib.sha256(public).hexdigest()):
        raise ValueError("Untrusted installer manifest")
    files = manifest["files"]
    if not isinstance(files, dict) or not 10 <= len(files) <= 40:
        raise ValueError("Invalid installer inventory")
    wheels = [name for name in files if name.endswith(".whl")]
    expected = {"install.sh", "install.ps1", "install.cmd", "constraints.txt", "release-signing.pub", *wheels}
    expected.update(name + ".sig" for name in tuple(expected) if name != "release-signing.pub")
    if len(wheels) != 1 or set(files) != expected:
        raise ValueError("Unexpected installer inventory")
    for name, entry in files.items():
        if (not NAME.fullmatch(name) or not re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", ""))
                or type(entry.get("bytes")) is not int or not 0 < entry["bytes"] <= MAX_BYTES
                or entry.get("url") != f"{ORIGIN}/releases/{release_id}/{name}"):
            raise ValueError("Invalid installer artifact")
    return manifest


def verify_release(raw, release_id, read, public):
    """Never execute retained code. Verify bytes against the repository's public key."""
    manifest = validate_manifest(raw, release_id, public)
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
    """A missing/unavailable archive fails closed; never silently discard old URLs."""
    ids = release_ids(fetch("releases.json", 128 * 1024))
    for release_id in ids:
        release = site / "releases" / release_id
        prefix = "releases/" + release_id + "/"
        raw = fetch(prefix + "manifest.json", 128 * 1024)
        files = verify_release(raw, release_id, lambda name: fetch(prefix + name), public)
        files["manifest.json"] = raw
        # Legacy releases predate signed manifests. Retain their exact bytes too.
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


def verify_public(site):
    paths = [p.relative_to(site).as_posix() for p in site.rglob("*")
             if p.is_file() and not p.name.startswith((".", "_"))]

    def check(path):
        # Workers canonicalizes /index.html to /; downloads must not redirect.
        if fetch("" if path == "index.html" else path) != (site / path).read_bytes():
            raise ValueError("Published bytes differ: " + path)

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(check, paths))
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
    parser.add_argument("action", choices=("retain", "index", "verify-public"))
    parser.add_argument("--site", type=Path, default=ROOT / "dist/installer-site")
    args = parser.parse_args()
    site = args.site.resolve(strict=True)
    if not (site / "manifest.json").is_file() or not (site / "releases").is_dir():
        raise ValueError("Expected a built installer site")
    if any(path.is_symlink() for path in site.rglob("*")):
        raise ValueError("Linked publication paths are not allowed")
    public = (ROOT / "deploy/installer/release-signing.pub").read_bytes()
    if args.action == "verify-public":
        verify_public(site)
    elif args.action == "retain":
        retain(site, public)
    else:
        index(site, public)
    print("Installer publication " + args.action + ": passed")


if __name__ == "__main__":
    main()
