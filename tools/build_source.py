"""Package public source only; explicitly excludes accounts, sessions, data, and environments."""
import hashlib
import zipfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
FILES = [
    "README.md", "docs/QUICKSTART.md", "LICENSE", "NOTICE", ".github/SECURITY.md", ".github/SUPPORT.md", ".github/CONTRIBUTING.md", "docs/CHANGELOG.md", "pyproject.toml",
    "start.py", "start.sh", "Start.cmd",
    "deploy/Dockerfile", "compose.yaml", "deploy/compose/compose.image.yaml", "deploy/compose/compose.https.yaml", "deploy/compose/compose.witness.yaml", "deploy/compose/compose.proof.yaml", "deploy/compose/compose.proxies.yaml",
    ".gitignore", ".gitattributes", ".dockerignore", "deploy/env.example", "deploy/constraints.txt", "deploy/requirements.lock", "deploy/build.lock",
]
# A bounded service manifest: never recurse through node_modules, .dev.vars,
# controller state, browser profiles or locally exported receipts.
FILES.extend("services/witness-controller/" + name for name in (
    ".gitignore", "README.md", "package.json", "package-lock.json", "wrangler.jsonc",
    "src/dashboard.mjs", "src/engine.mjs", "src/protocol.mjs", "src/worker.mjs",
    "test/actions.test.mjs", "test/engine.test.mjs", "test/helpers.mjs", "test/worker.test.mjs",
    "tools/demo.mjs", "tools/local-keys.mjs", "tools/synthetic.mjs", "tools/verify.mjs",
))
DIRECTORIES = {
    "tgwitness": {".md", ".py", ".html", ".css", ".js", ".svg", ".json"},
    "docs": {".md", ".png", ".webp", ".svg", ".txt", ".gif", ".mp4"}, "tests": {".py", ".md"}, "tools": {".py", ".md"},
    "deploy": {".md", ".ps1", ".service", ".example", ".docker"},
    "scripts": {".md", ".cmd", ".sh"},
    ".github": {".md", ".yml", ".yaml"},
    "website": {".md", ".html", ".css", ".js", ".py", ".json"},
}
LANGUAGES = ("ru", "uk", "es", "pt", "tr", "ar", "fa", "ur", "hi", "id", "vi", "zh",
             "fr", "de", "it", "uz", "ko", "zh-Hant", "ms", "pl", "ja", "th", "he", "bn")
GUIDE_LANGUAGES = ("fr", "de", "it", "uz", "ko", "zh-Hant", "ms", "pl", "ja", "th", "he", "am", "bn")
PACKAGE_JSON = {"english_fallbacks.json", "public_proxies.json", *("locales/" + language + ".json" for language in LANGUAGES),
                "guide_locales/keys.json", *("guide_locales/" + language + ".json" for language in GUIDE_LANGUAGES)}
# Site translations: without them every non-English page silently falls back to English.
SITE_JSON = {"i18n/" + language + ".json" for language in
             ("en", *LANGUAGES, "fr", "de", "it", "uz", "ko", "zh-Hant", "ms", "pl", "ja", "th", "he", "am", "bn")}
# Recorded answers of the fictional demo for the read-only online demo (tools/capture_demo.py).
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
        # An allowlisted filename must not point at a local secret through a link.
        if source.resolve() != source or not source.is_file():
            raise ValueError("Public source must be an ordinary repository file: " + str(source.relative_to(root)))
    return sorted(set(sources), key=lambda p: p.relative_to(root).as_posix())


def main():
    sources = public_sources(ROOT)
    out = ROOT / "dist"
    out.mkdir(exist_ok=True)
    target = out / ("TgWitness-" + VERSION + "-source.zip")
    manifest = []
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for source in sources:
            name = source.relative_to(ROOT).as_posix()
            data = source.read_bytes()
            archive.writestr("TgWitness/" + name, data)
            manifest.append(hashlib.sha256(data).hexdigest() + "  " + name)
        archive.writestr("TgWitness/SOURCE_SHA256SUMS", "\n".join(manifest) + "\n")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    target.with_suffix(".zip.sha256").write_text(digest + "  " + target.name + "\n")
    print("Public source archive:", target)
    print("Files:", len(sources), "| SHA-256:", digest)


if __name__ == "__main__":
    main()
