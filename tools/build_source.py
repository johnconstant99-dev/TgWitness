"""Package public source only; explicitly excludes accounts, sessions, data, and environments."""
import hashlib
import zipfile
import tomllib
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
FILES = [
    "deploy/installer/install.sh.in", "deploy/installer/install.ps1.in", "deploy/installer/install.cmd.in",
    "deploy/installer/index.html", "deploy/installer/style.css", "deploy/installer/site.js", "deploy/installer/wrangler.toml",
    "deploy/media-worker/Dockerfile", "deploy/media-worker/worker.py",
    "deploy/media-worker/requirements.in", "deploy/media-worker/requirements.lock",
    "integrations/webhook.schema.json", "integrations/n8n-tgwitness.json", "tools/check_webhook_example.cjs",
    "tools/check_writeonly_drafts.mjs", "deploy/constraints-mcp.txt",
    "deploy/Dockerfile.sealed", "scripts/sealed_runner.py",
    "README.md", "docs/QUICKSTART.md", "LICENSE", "NOTICE", ".github/SECURITY.md", ".github/SUPPORT.md", ".github/CONTRIBUTING.md", "docs/CHANGELOG.md", "pyproject.toml",
    "start.py", "start.sh", "Start.cmd",
    "deploy/Dockerfile", "compose.yaml", "deploy/compose/compose.image.yaml", "deploy/compose/compose.https.yaml", "deploy/compose/compose.witness.yaml", "deploy/compose/compose.proof.yaml", "deploy/compose/compose.proxies.yaml",
    ".gitignore", ".gitattributes", ".dockerignore", "deploy/env.example", "deploy/constraints.txt", "deploy/requirements.lock", "deploy/build.lock",
    "deploy/audit.lock", "deploy/browser.lock", "deploy/mcp.lock", "deploy/site.lock",
]
FILES.extend("website/demo/downloads/" + name for name in (
    "tgwitness-demo.zip", "tgwitness-demo.jsonl", "tgwitness-demo.csv", "tgwitness-demo.html",
    "tgwitness-demo-checkpoint.json", "tgwitness-demo-run-receipt.json", "tgwitness-demo-timestamp-request.zip",
    "tgwitness-demo-account-export.zip", "tgwitness-demo-minimized-disclosure.zip",
))
FILES.extend("website/demo/report/" + name for name in (
    "index.html", "report.html", "sharing-copy.zip", "example.json",
))
DIRECTORIES = {
    "tgwitness": {".md", ".py", ".html", ".css", ".js", ".svg", ".json"},
    "docs": {".md", ".png", ".webp", ".svg", ".txt", ".gif", ".mp4"}, "tools": {".py", ".md"},
    "deploy": {".md", ".ps1", ".service", ".example", ".docker"},
    "scripts": {".md", ".cmd", ".sh"},
    ".github": {".md", ".yml", ".yaml"},
    "website": {".md", ".html", ".css", ".js", ".py", ".json"},
}
LANGUAGES = ("ru", "uk", "es", "pt", "tr", "ar", "fa", "ur", "hi", "id", "vi", "zh",
             "fr", "de", "it", "uz", "ko", "zh-Hant", "ms", "pl", "ja", "th", "he", "bn")
GUIDE_LANGUAGES = ("fr", "de", "it", "uz", "ko", "zh-Hant", "ms", "pl", "ja", "th", "he", "am", "bn")
PACKAGE_JSON = {"english_fallbacks.json", "public_proxies.json", "sealed_policy.json", *("locales/" + language + ".json" for language in LANGUAGES),
                "guide_locales/keys.json", *("guide_locales/" + language + ".json" for language in GUIDE_LANGUAGES)}

SITE_JSON = {"i18n/" + language + ".json" for language in
             ("en", *LANGUAGES, "fr", "de", "it", "uz", "ko", "zh-Hant", "ms", "pl", "ja", "th", "he", "am", "bn")}

SITE_JSON.add("demo/fixtures.json")
PRESENTATION_MEDIA = {
    "assets/presentation/investigation-overview.mp4",
    "assets/presentation/investigation.mp4", "assets/presentation/investigation.gif",
    "assets/presentation/message-history.mp4", "assets/presentation/message-history.gif",
}
PRIVATE_DIRECTORIES = {"data", "proof-data", "proof-config", "proxy-config", "witness-data", "__pycache__", ".venv", "venv", "test-results", ".pytest_cache", ".ruff_cache"}


def is_public_file(path, directory):
    """JSON is an explicit resource allowlist, never a blanket source extension."""
    relative = path.relative_to(directory)
    if any(part in PRIVATE_DIRECTORIES or part.startswith("tgwitness-backup") for part in relative.parts[:-1]):
        return False
    if path.suffix in {".gif", ".mp4"}:
        return directory.name == "docs" and relative.as_posix() in PRESENTATION_MEDIA
    if path.suffix == ".txt":
        return directory.name == "docs" and relative.as_posix() in {
            "assets/presentation/OFL-Manrope.txt",
            "assets/presentation/OFL-SpaceGrotesk.txt",
        }
    if path.suffix == ".json":
        return relative.as_posix() in {"tgwitness": PACKAGE_JSON, "website": SITE_JSON}.get(directory.name, ())
    return True


def public_sources(root):
    root = root.resolve()
    sources = [root / name for name in FILES]
    for directory, extensions in DIRECTORIES.items():
        sources.extend(p for p in (root / directory).rglob("*")
                       if p.is_file() and p.suffix in extensions and is_public_file(p, root / directory))
    for source in sources:

        if source.resolve() != source or not source.is_file():
            raise ValueError("Public source must be an ordinary repository file: " + str(source.relative_to(root)))
    return sorted(set(sources), key=lambda p: p.relative_to(root).as_posix())


def main():
    sources = public_sources(ROOT)
    out = ROOT / "dist"
    out.mkdir(exist_ok=True)
    target = out / ("TgWitness-" + VERSION + "-source.zip")
    manifest = []
    # Stage on the destination filesystem: a failed build leaves the previous ZIP intact.
    with tempfile.TemporaryDirectory(prefix=".source-build-", dir=out) as temporary:
        staged = Path(temporary) / target.name
        with zipfile.ZipFile(staged, "w") as archive:
            for source in sources:
                name = source.relative_to(ROOT).as_posix()
                data = source.read_bytes()
                write_member(archive, "TgWitness/" + name, data)
                manifest.append(hashlib.sha256(data).hexdigest() + "  " + name)
            write_member(archive, "TgWitness/SOURCE_SHA256SUMS", ("\n".join(manifest) + "\n").encode("utf-8"))
        with staged.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        checksum = staged.with_suffix(".zip.sha256")
        checksum.write_bytes((digest + "  " + target.name + "\n").encode("utf-8"))
        # Each rename is atomic; a failure between them leaves a detectable checksum mismatch.
        staged.replace(target)
        checksum.replace(target.with_suffix(".zip.sha256"))
    print("Public source archive:", target)
    print("Files:", len(sources), "| SHA-256:", digest)


def write_member(archive, name, data):
    # Archive timestamps are neutral metadata, never a claim about collection/build time.
    member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    member.create_system = 3
    member.external_attr = 0o100644 << 16
    archive.writestr(member, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)


if __name__ == "__main__":
    main()
