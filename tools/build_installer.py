"""Build a static installer site from a checked wheel"""
import argparse
import base64
import csv
from email.parser import BytesParser
import hashlib
import html
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib
from urllib.parse import urlsplit
import zipfile

from setuptools import find_packages
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "deploy" / "installer"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.check_output([
        "git", "-c", "safe.directory=" + ROOT.as_posix(), "-c", "core.commitGraph=false", *args
    ], cwd=ROOT).decode().strip()


def render(name, values):
    text = (TEMPLATES / name).read_text(encoding="utf-8")
    for key, value in values.items():
        text = text.replace("@@" + key + "@@", value)
    remaining = re.findall(r"@@[A-Z_]+@@", text)
    if remaining:
        raise ValueError(f"Unresolved placeholders in {name}: {remaining}")
    return text


def put(path, data, *, immutable=False):
    for candidate in (path, *path.parents):
        try:
            linked = candidate.is_symlink() or bool(getattr(candidate.lstat(), "st_file_attributes", 0) & 0x400)
        except FileNotFoundError:
            linked = False
        if linked:
            raise ValueError("Refusing linked output: " + str(candidate))
    if immutable and path.exists():
        if path.read_bytes() != data:
            raise ValueError("Release path already contains different bytes: " + str(path))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".write-", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def verify_wheel(path, version):
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    expected = set()
    packages = find_packages(where=str(ROOT), include=["tgwitness*"])
    for package in packages:
        directory = ROOT.joinpath(*package.split("."))
        expected.update(item.relative_to(ROOT).as_posix() for item in directory.glob("*.py"))
        for pattern in config["tool"]["setuptools"].get("package-data", {}).get(package, []):
            expected.update(item.relative_to(ROOT).as_posix() for item in directory.glob(pattern) if item.is_file())
    with zipfile.ZipFile(path) as archive:
        entries = archive.namelist()
        package_entries = set(entries) & expected
        if package_entries != expected or len(set(entries)) != len(entries) or archive.testzip():
            raise ValueError("Incomplete or damaged application wheel")
        dist_info = "tgwitness-" + version + ".dist-info/"
        permitted_metadata = {dist_info + name for name in
                              ("METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD", "licenses/LICENSE", "licenses/NOTICE")}
        for name in entries:
            if name not in expected and name not in permitted_metadata:
                raise ValueError("Unexpected wheel entry: " + name)
            if name in expected:
                source = ROOT / name
                if not source.is_file() or archive.read(name) != source.read_bytes():
                    raise ValueError("Wheel differs from checked source: " + name)
        metadata = [name for name in entries if name.endswith(".dist-info/METADATA")]
        if len(metadata) != 1 or BytesParser().parsebytes(archive.read(metadata[0]))["Version"] != version:
            raise ValueError("Wheel version differs from pyproject.toml")
        record_name = dist_info + "RECORD"
        records = list(csv.reader(io.StringIO(archive.read(record_name).decode())))
        if len(records) != len(entries) or {row[0] for row in records} != set(entries):
            raise ValueError("Wheel RECORD does not cover its contents")
        for name, checksum, size in records:
            if name == record_name and checksum == size == "":
                continue
            content = archive.read(name)
            expected_hash = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode().rstrip("=")
            if checksum != expected_hash or size != str(len(content)):
                raise ValueError("Wheel RECORD mismatch: " + name)


def requirements_lock():
    text = (ROOT / "deploy" / "mcp.lock").read_text(encoding="utf-8").replace("\r\n", "\n")
    packages = hashes = 0
    for line in text.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        if line[0].isspace():
            if not packages or not re.fullmatch(r"--hash=sha256:[0-9a-f]{64}(?:\s*\\)?", entry):
                raise ValueError("deploy/mcp.lock contains an invalid dependency hash")
            hashes += 1
        else:
            pin = entry.removesuffix("\\").strip()
            if (packages and not hashes) or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9_.-]*==[A-Za-z0-9_.+!-]+(?:\s*;[^\\\r\n]+)?", pin):
                raise ValueError("deploy/mcp.lock must pin every dependency with SHA-256 hashes")
            packages += 1
            hashes = 0
    if not packages or not hashes:
        raise ValueError("deploy/mcp.lock must pin every dependency with SHA-256 hashes")
    return text.encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="https://get.destroy.tools")
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "installer-site")
    parser.add_argument("--signing-key", type=Path, help="Private RSA release key (outside the repository)")
    parser.add_argument("--test-signing-key", action="store_true", help="Generate an ephemeral key; only for an .invalid test origin")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    url = urlsplit(base)
    if (url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment
            or any(part in (".", "..") for part in url.path.split("/"))
            or not re.fullmatch(r"https://[a-zA-Z0-9.-]+(?::[0-9]+)?(?:/[a-zA-Z0-9._/-]+)?", base)):
        parser.error("base-url must be a plain HTTPS origin or path without credentials")
    if args.test_signing_key:
        if not url.hostname.endswith(".invalid") or args.signing_key:
            parser.error("Test signatures require an .invalid hostname and no release key")
        signing_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    else:
        if not args.signing_key:
            parser.error("A release signing key is required; unsigned installers are not published")
        if args.signing_key.resolve().is_relative_to(ROOT):
            parser.error("Keep the private signing key outside the checkout")
        signing_key = serialization.load_pem_private_key(args.signing_key.read_bytes(), password=None)
        if not isinstance(signing_key, rsa.RSAPrivateKey) or signing_key.key_size < 3072:
            parser.error("Use an RSA release key of at least 3072 bits")
    public_key = signing_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    if not args.test_signing_key and public_key != (TEMPLATES / "release-signing.pub").read_bytes():
        parser.error("The signing key does not match the reviewed public release key")
    numbers = signing_key.public_key().public_numbers()
    public_modulus = base64.b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")).decode()
    public_exponent = base64.b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")).decode()
    revision = git("rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Expected a committed source revision")
    if git("status", "--porcelain", "--", "tgwitness", "tgwitness_capture", "pyproject.toml", "README.md", "deploy/mcp.lock"):
        raise ValueError("Commit application and dependency changes before building a published installer")
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    if args.output.is_symlink():
        raise ValueError("Choose an ordinary output directory")
    output = args.output.resolve()
    if output == ROOT or output in ROOT.parents or output.is_symlink():
        raise ValueError("Choose a dedicated output directory")
    if output.exists() and any(output.iterdir()) and not (output / ".tgwitness-installer-site").is_file():
        raise ValueError("Output directory is not an installer-site build")
    output.mkdir(parents=True, exist_ok=True)
    put(output / ".tgwitness-installer-site", b"TgWitness installer site v1\n")
    (ROOT / "build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="installer-wheel-", dir=ROOT / "build") as scratch:
        env = dict(os.environ, SOURCE_DATE_EPOCH=git("show", "-s", "--format=%ct", "HEAD"))
        subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation",
                        "--disable-pip-version-check", "--wheel-dir", scratch, str(ROOT)], check=True, env=env)
        candidates = list(Path(scratch).glob("tgwitness-*-py3-none-any.whl"))
        if len(candidates) != 1:
            raise ValueError("Expected one platform-independent wheel")
        wheel = candidates[0]
        verify_wheel(wheel, version)
        wheel_bytes = wheel.read_bytes()
        wheel_hash = digest(wheel_bytes)
        release_id = revision[:12] + "-" + wheel_hash[:12]
        release = output / "releases" / release_id
        locked = requirements_lock()
        values = {"BASE_URL": base, "VERSION": version, "REVISION": revision, "RELEASE_ID": release_id,
                  "WHEEL_NAME": wheel.name, "WHEEL_SHA256": wheel_hash, "LOCK_SHA256": digest(locked),
                  "SIGNING_PUBLIC_KEY": public_key.decode().strip(), "SIGNING_MODULUS": public_modulus,
                  "SIGNING_EXPONENT": public_exponent, "SIGNING_KEY_SHA256": digest(public_key),
                  "WHEEL_SIGNATURE_SHA256": digest(signing_key.sign(wheel_bytes, padding.PKCS1v15(), hashes.SHA256())),
                  "LOCK_SIGNATURE_SHA256": digest(signing_key.sign(locked, padding.PKCS1v15(), hashes.SHA256()))}
        values["SITE_SCRIPT_SRI"] = "sha256-" + base64.b64encode(hashlib.sha256((TEMPLATES / "site.js").read_bytes()).digest()).decode()
        scripts = {}
        for name in ("install.sh", "install.ps1"):
            content = render(name + ".in", values)
            scripts[name] = content.replace("\n", "\r\n").encode() if name.endswith(".ps1") else content.encode()
        values["POWERSHELL_SHA256"] = digest(scripts["install.ps1"])
        scripts["install.cmd"] = render("install.cmd.in", values).replace("\n", "\r\n").encode()
        artifacts = {wheel.name: wheel_bytes, "requirements.lock": locked, **scripts, "release-signing.pub": public_key}
        for name, content in list(artifacts.items()):
            if name != "release-signing.pub":
                artifacts[name + ".sig"] = signing_key.sign(content, padding.PKCS1v15(), hashes.SHA256())
        for name, content in artifacts.items():
            put(release / name, content, immutable=True)
            put(release / (name + ".sha256"), (digest(content) + "  " + name + "\n").encode(), immutable=True)
        manifest = {"schema": "tgwitness-installer-v1", "version": version, "source_revision": revision,
                    "release_id": release_id, "channel": "preview", "base_url": base,
                    "source_url": "https://github.com/phishdestroy/TgWitness/tree/" + revision,
                    "python": "3.12 (managed)", "mcp": True, "uv_version": "0.13.6",
                    "verification": "Pinned SHA-256 and RSA-PKCS1v15-SHA256 release signatures. The bootstrap is delivered over HTTPS.",
                    "signing_key_sha256": digest(public_key), "test_only": args.test_signing_key,
                    "files": {name: {"sha256": digest(content), "bytes": len(content),
                                     "url": base + "/releases/" + release_id + "/" + name}
                              for name, content in artifacts.items()}}
        manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode()
        put(release / "manifest.json", manifest_bytes, immutable=True)
        put(output / "manifest.json", manifest_bytes)
        manifest_signature = signing_key.sign(manifest_bytes, padding.PKCS1v15(), hashes.SHA256())
        put(release / "manifest.json.sig", manifest_signature, immutable=True)
        put(output / "manifest.json.sig", manifest_signature)
        for name, content in scripts.items():
            put(output / name, content)
            put(output / (name + ".sig"), artifacts[name + ".sig"])
        put(output / "release-signing.pub", public_key)
        sums = "".join(digest(content) + "  " + name + "\n" for name, content in scripts.items())
        put(output / "SHA256SUMS.txt", sums.encode())
        put(output / "SHA256SUMS.txt.sig", signing_key.sign(sums.encode(), padding.PKCS1v15(), hashes.SHA256()))
        page_values = {key: html.escape(value, quote=True) for key, value in values.items()}
        put(output / "index.html", render("index.html", page_values).encode())
        for name in ("style.css", "site.js"):
            put(output / name, (TEMPLATES / name).read_bytes())
        put(output / "mark.svg", (ROOT / "tgwitness" / "static" / "mark.svg").read_bytes())
        put(output / "_headers", (
            "/*\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: no-referrer\n"
            "  Content-Security-Policy: default-src 'none'; script-src '" + values["SITE_SCRIPT_SRI"] + "'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'\n"
            "  Cache-Control: no-cache, no-transform\n"
            "/install.sh\n  Content-Type: text/plain; charset=utf-8\n"
            "/install.ps1\n  Content-Type: text/plain; charset=utf-8\n"
            "/install.cmd\n  Content-Type: text/plain; charset=utf-8\n"
            "/releases/*\n  Cache-Control: public, max-age=31536000, immutable, no-transform\n"
        ).encode())
    print(json.dumps({"output": str(output), "source_revision": revision, "release_id": release_id,
                      "wheel_sha256": wheel_hash, "base_url": base}, indent=2))


if __name__ == "__main__":
    main()
