"""Build a static installer site from a checked wheel; no credentials or running accounts."""
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
        package_entries = {name for name in entries if name.startswith("tgwitness/")}
        if package_entries != expected or len(set(entries)) != len(entries) or archive.testzip():
            raise ValueError("Incomplete or damaged application wheel")
        dist_info = "tgwitness-" + version + ".dist-info/"
        permitted_metadata = {dist_info + name for name in
                              ("METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD", "licenses/LICENSE", "licenses/NOTICE")}
        for name in entries:
            if name not in expected and name not in permitted_metadata:
                raise ValueError("Unexpected wheel entry: " + name)
            if name.startswith("tgwitness/") and not name.endswith("/"):
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


def constraints():
    lines = []
    for name in ("constraints.txt", "constraints-mcp.txt"):
        for line in (ROOT / "deploy" / name).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "-c ")):
                if "==" not in line or line.startswith("-") or "://" in line:
                    raise ValueError("Unexpected dependency constraint")
                if line not in lines:
                    lines.append(line)
    return ("# TgWitness panel + MCP: qualified dependency versions.\n" + "\n".join(lines) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="https://get.destroy.tools")
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "installer-site")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    url = urlsplit(base)
    if (url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment
            or any(part in (".", "..") for part in url.path.split("/"))
            or not re.fullmatch(r"https://[a-zA-Z0-9.-]+(?::[0-9]+)?(?:/[a-zA-Z0-9._/-]+)?", base)):
        parser.error("base-url must be a plain HTTPS origin or path without credentials")
    revision = git("rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Expected a committed source revision")
    if git("status", "--porcelain", "--", "tgwitness", "pyproject.toml", "README.md", "deploy/constraints.txt", "deploy/constraints-mcp.txt"):
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
        locked = constraints()
        values = {"BASE_URL": base, "VERSION": version, "REVISION": revision, "RELEASE_ID": release_id,
                  "WHEEL_NAME": wheel.name, "WHEEL_SHA256": wheel_hash, "CONSTRAINTS_SHA256": digest(locked)}
        scripts = {}
        for name in ("install.sh", "install.ps1"):
            content = render(name + ".in", values)
            scripts[name] = content.replace("\n", "\r\n").encode() if name.endswith(".ps1") else content.encode()
        values["POWERSHELL_SHA256"] = digest(scripts["install.ps1"])
        scripts["install.cmd"] = render("install.cmd.in", values).replace("\n", "\r\n").encode()
        artifacts = {wheel.name: wheel_bytes, "constraints.txt": locked, **scripts}
        for name, content in artifacts.items():
            put(release / name, content, immutable=True)
            put(release / (name + ".sha256"), (digest(content) + "  " + name + "\n").encode(), immutable=True)
        manifest = {"schema": "tgwitness-installer-v1", "version": version, "source_revision": revision,
                    "release_id": release_id, "channel": "preview", "base_url": base,
                    "source_url": "https://github.com/phishdestroy/TgWitness/tree/" + revision,
                    "python": "3.12 (managed)", "mcp": True, "uv_version": "0.13.6",
                    "verification": "SHA-256 hashes embedded in installers; HTTPS delivery. Not an issuer signature.",
                    "files": {name: {"sha256": digest(content), "bytes": len(content),
                                     "url": base + "/releases/" + release_id + "/" + name}
                              for name, content in artifacts.items()}}
        manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode()
        put(release / "manifest.json", manifest_bytes, immutable=True)
        put(output / "manifest.json", manifest_bytes)
        for name, content in scripts.items():
            put(output / name, content)
        sums = "".join(digest(content) + "  " + name + "\n" for name, content in scripts.items())
        put(output / "SHA256SUMS.txt", sums.encode())
        page_values = {key: html.escape(value, quote=True) for key, value in values.items()}
        put(output / "index.html", render("index.html", page_values).encode())
        for name in ("style.css", "site.js"):
            put(output / name, (TEMPLATES / name).read_bytes())
        put(output / "mark.svg", (ROOT / "tgwitness" / "static" / "mark.svg").read_bytes())
        put(output / "_headers", (
            "/*\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: no-referrer\n"
            "  Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'\n"
            "  Cache-Control: public, max-age=300\n"
            "/install.sh\n  Content-Type: text/plain; charset=utf-8\n"
            "/install.ps1\n  Content-Type: text/plain; charset=utf-8\n"
            "/install.cmd\n  Content-Type: text/plain; charset=utf-8\n"
            "/releases/*\n  Cache-Control: public, max-age=31536000, immutable\n"
        ).encode())
    print(json.dumps({"output": str(output), "source_revision": revision, "release_id": release_id,
                      "wheel_sha256": wheel_hash, "base_url": base}, indent=2))


if __name__ == "__main__":
    main()
