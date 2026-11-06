import hashlib
import zipfile
import tomllib
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
CONTAINER_INPUTS = (
    "deploy/containers/runtime.packages", "deploy/containers/media.packages", "deploy/containers/build.packages",
    "deploy/containers/resolve-packages.sh", "deploy/containers/install-packages.sh",
    *("deploy/containers/" + role + "-" + arch + ".lock"
      for role in ("runtime", "media", "build") for arch in ("x86_64", "aarch64")),
    "deploy/media-worker/build-tesseract.sh", "deploy/media-worker/fetch-sources.py", "deploy/media-worker/tesseract.nfpm.yaml",
    "deploy/media-worker/sources.lock.json",
)
FILES = [
    "tgwitness/client_profiles.LICENSE",
    "tgwitness/dstack_measurement.LICENSE",
    "tgwitness/fonts/OFL.txt",
    "tgwitness/fonts/NotoSerif-OFL.txt",
    "deploy/installer/install.sh.in", "deploy/installer/install.ps1.in", "deploy/installer/install.cmd.in",
    "deploy/installer/release-signing.pub",
    "deploy/installer/index.html", "deploy/installer/style.css", "deploy/installer/site.js", "deploy/installer/wrangler.toml",
    "deploy/media-worker/Dockerfile", "deploy/media-worker/worker.py",
    "deploy/media-worker/requirements.in", "deploy/media-worker/requirements.lock",
    "integrations/webhook.schema.json", "integrations/n8n-tgwitness.json", "tools/check_webhook_example.cjs", "tools/check_privacy_js.cjs",
    "tools/check_writeonly_drafts.mjs", "deploy/constraints-mcp.txt",
    "deploy/Dockerfile.sealed", "scripts/sealed_runner.py",
    "examples/export-hashes.json", "examples/sealed-hashes.json", "examples/sealed-account.json",
    "README.md", "docs/QUICKSTART.md", "LICENSE", "NOTICE", ".github/SECURITY.md", ".github/SUPPORT.md", ".github/CONTRIBUTING.md", "docs/CHANGELOG.md", "pyproject.toml",
    "start.py", "start.sh", "Start.cmd",
    "deploy/Dockerfile", "compose.yaml", "deploy/compose/compose.image.yaml", "deploy/compose/compose.https.yaml", "deploy/compose/compose.witness.yaml", "deploy/compose/compose.proof.yaml", "deploy/compose/compose.proxies.yaml", "deploy/compose/compose.capture-panel.yaml",
    ".gitignore", ".gitattributes", ".dockerignore", "deploy/env.example", "deploy/constraints.txt", "deploy/requirements.lock", "deploy/build.lock",
    "deploy/audit.lock", "deploy/browser.lock", "deploy/mcp.lock", "deploy/site.lock", "deploy/installer.lock",
    "tools/tsa/time-stamps.json", "tools/fixtures/evidence-before-fulltext.zip",
    "tools/fixtures/narrative-events.json", "tools/fixtures/narrative-golden.json",
    "docs/examples/narrative.json",
    ".agents/skills/tgwitness-cli/SKILL.md",
    *CONTAINER_INPUTS,
]
FILES.extend("tgwitness/fonts/" + name for name in (
    "NotoSans-Regular.ttf", "NotoSans-Bold.ttf", "NotoSansMono-Regular.ttf",
    "NotoSerif-Regular.ttf", "NotoSerif-Bold.ttf",
    "NotoSansArabic-Regular.ttf", "NotoSansHebrew-Regular.ttf", "NotoSansDevanagari-Regular.ttf",
    "NotoSansBengali-Regular.ttf", "NotoSansThai-Regular.ttf", "NotoSansSymbols2-Regular.ttf",
    "NotoEmoji-Regular.ttf",
))
FILES.extend("website/demo/downloads/" + name for name in (
    "tgwitness-demo.zip", "tgwitness-demo.jsonl", "tgwitness-demo.csv", "tgwitness-demo.html",
    "tgwitness-demo-checkpoint.json", "tgwitness-demo-run-receipt.json", "tgwitness-demo-timestamp-request.zip",
    "tgwitness-demo-account-export.zip", "tgwitness-demo-minimized-disclosure.zip",
))
FILES.extend("website/demo/report/" + name for name in (
    "index.html", "report.html", "sharing-copy.zip", "example.json",
))
EXPORT_CLINIC_ASSETS = (
    "SHA256SUMS.txt", "comparison-data.json", "comparison-poster.jpg", "download-manifest.json",
    "original-metadata-audit.json", "publication-review.json", "recording-manifest.json",
    "review-file-manifest.json",
    *("assets/comparisons/" + conversation + "-" + version + ".jpg"
      for conversation in ("personal", "private-channel", "private-group", "private-supergroup",
                           "public-channel", "public-supergroup")
      for version in ("before", "modified")),
)
FILES.extend("website/export-clinic/media/" + name for name in EXPORT_CLINIC_ASSETS)
FILES.extend("tools/tdx/" + name for name in (
    "intel-v4.quote.hex", "intel-v4.collateral.json", "intel-v5-td15ex.quote.hex", "intel-v5-td15ex.collateral.json",
    "intel-outdated.collateral.json", "dstack-v4.json", "dstack-v4.collateral.json",
    "phala-dstack-0.5.12.json", "phala-dstack-0.5.12.collateral.json",
))
FILES.extend("addons/capture/" + name for name in (
    "README.md", "pyproject.toml", "requirements.lock", "lock_from_project.py", "compose.yaml", "compose.official.yaml",
    "config/browser.example.json", "config/ayugram.example.json", "config/official.example.json", "config/official-upstream.example.json",
    "deploy/Dockerfile", "deploy/Dockerfile.neko", "deploy/Dockerfile.gateway",
    "deploy/Dockerfile.official", "deploy/official-start.sh", "deploy/official-seccomp.json",
    "deploy/official-seccomp.README.md", "deploy/PLAYWRIGHT-LICENSE.txt",
    "deploy/chromium.conf", "deploy/chromium-policy.json", "deploy/neko-start.sh", "deploy/upstream-proxy.example.conf",
    "tests/conftest.py", "tests/test_capture.py", "tests/test_browser.py", "tests/test_video.py",
    "tests/test_panel.py", "tests/test_witness.py", "tests/test_deployment.py", "tests/test_integration.py",
    "tests/test_official.py", "tests/test_gateway.py", "tests/test_official_proof.py", "tests/test_beacon.py",
    "compose.trusted.yaml", "config/trusted.example.json", "deploy/Dockerfile.trusted",
    "deploy/trusted-entrypoint.py", "deploy/trusted-display.py",
    "tests/test_trusted.py", "tests/test_trusted_anchors.py",
))
DIRECTORIES = {
    "tgwitness_capture": {".py", ".html", ".css", ".js"},
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
PACKAGE_JSON = {"english_fallbacks.json", "public_proxies.json", "sealed_policy.json", "client_profiles.json", "jurisdictions.json", "verifier_languages.json", "analysis_words.json", *("locales/" + language + ".json" for language in LANGUAGES),
                *("schemas/board-" + name + ".json" for name in ("bookmark", "highlight", "slice", "collection", "comment", "status", "move", "remove")),
                "guide_locales/keys.json", *("guide_locales/" + language + ".json" for language in GUIDE_LANGUAGES)}
NARRATIVE_LANGUAGES = ("en", "de", "fr", "es", "it", "pt", "nl", "pl", "cs", "sk", "uk", "ru", "ro",
                       "bg", "hu", "el", "sv", "da", "fi", "no", "lt", "lv", "et", "tr", "ja")
PACKAGE_JSON.update({"narrative/review-policy.json",
                     *("narrative/texts/" + prefix + language + ".json"
                       for prefix in ("", "glossary.") for language in NARRATIVE_LANGUAGES),
                     *("narrative/jurisdictions/" + code + ".json" for code in
                       ("DE", "AT", "CH", "UK", "IE", "FR", "ES", "IT", "PL", "CZ", "UA", "NL", "BE", "US-federal"))})

SITE_JSON = {"i18n/" + language + ".json" for language in
             ("en", *LANGUAGES, "fr", "de", "it", "uz", "ko", "zh-Hant", "ms", "pl", "ja", "th", "he", "am", "bn")}

SITE_JSON.add("demo/fixtures.json")
PRESENTATION_MEDIA = {
    "assets/presentation/investigation-overview.mp4",
    "assets/presentation/investigation.mp4", "assets/presentation/investigation.gif",
    "assets/presentation/message-history.mp4", "assets/presentation/message-history.gif",
}
PRIVATE_DIRECTORIES = {"data", "proof-data", "proof-config", "proxy-config", "witness-data", "__pycache__", ".venv", "venv", "test-results", ".pytest_cache", ".ruff_cache", "build", "dist"}


def is_public_file(path, directory):
    relative = path.relative_to(directory)
    parts = tuple(part.casefold() for part in relative.parts)
    if any(part in PRIVATE_DIRECTORIES or part.startswith("tgwitness-backup") for part in parts[:-1]):
        return False
    if any(part == ".tmp" or part.startswith(".tmp-") for part in parts):
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
        staged.replace(target)
        checksum.replace(target.with_suffix(".zip.sha256"))
    print("Public source archive:", target)
    print("Files:", len(sources), "| SHA-256:", digest)


def write_member(archive, name, data):
    member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    member.create_system = 3
    member.external_attr = 0o100644 << 16
    archive.writestr(member, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)


if __name__ == "__main__":
    main()
