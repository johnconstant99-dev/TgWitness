"""Build an English GitHub Wiki bundle from reviewed Markdown pages.

No Git operations, publication, application imports or network access.
"""
import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import re
import tomllib
from urllib.parse import quote, unquote, urlsplit
import zipfile

if __package__:
    from .build_source import public_sources
else:
    from build_source import public_sources

ROOT = Path(__file__).resolve().parents[1]
PAGES = (
    "Home", "Archive-and-Integrations", "Getting-Started", "Accounts", "Access", "Collection", "Investigations",
    "Exports-and-Verification", "Proxies", "Independent-Witness", "Server-and-Docker",
    "Backup-and-Recovery", "Chat-Export", "Notifications", "Off-site-Copy",
    "Troubleshooting", "FAQ", "Glossary", "Operator-Incompatibility",
)
FILES = tuple(name + ".md" for name in (*PAGES, "_Sidebar", "_Footer"))
LINK = re.compile(r'(!?\[[^\]\n]*\]\()(<[^>\n]+>|[^)\s]+)((?:\s+"[^"\n]*")?\))')
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
HTML_IMAGE = re.compile(r"<(?:img|source)\b[^>]*>", re.IGNORECASE)
IMAGE_URL = re.compile(r'''(?<![\w-])(src|srcset)\s*=\s*(["'])(.*?)\2''', re.IGNORECASE)

IMAGES = {".svg", ".png", ".webp", ".gif"}


def render_links(content, source, root, public, repository, branch, assets):
    """Resolve local documentation links for GitHub's separate wiki repository."""
    repo_url = "https://github.com/" + repository
    wiki = root / "docs/wiki"

    def replace(match):
        href = urlsplit(match[2].strip("<>"))
        if href.scheme or href.netloc or not href.path:
            return match[0]
        target = (source.parent / unquote(href.path)).resolve()
        if not target.is_relative_to(root) or target not in public:
            raise ValueError("Wiki link is not a public source file in " + source.name + ": " + href.path)
        if target.parent == wiki and target.name in FILES:
            url = repo_url + "/wiki/" + quote(target.stem, safe="")
        else:
            name = quote(target.relative_to(root).as_posix(), safe="/")
            asset_root = root / "docs/assets"
            is_image = target.is_relative_to(asset_root) and target.suffix in IMAGES
            if match[1].startswith("!") or is_image:
                if not target.is_relative_to(asset_root) or target.suffix not in IMAGES:
                    raise ValueError("Wiki image must be a reviewed documentation asset: " + href.path)
                asset = "assets/" + target.relative_to(asset_root).as_posix()
                assets[asset] = target.read_bytes()

                url = repo_url + "/wiki/" + quote(asset, safe="/")
            else:
                url = repo_url + "/blob/" + branch + "/" + name
        if href.query:
            url += "?" + href.query
        if href.fragment:
            url += "#" + quote(unquote(href.fragment), safe="-_.~")
        return match[1] + url + match[3]

    def image_tag(match):
        def image_url(attribute):
            value = html.unescape(attribute[3])
            parsed = urlsplit(value)
            if parsed.scheme or parsed.netloc:
                return attribute[0]


            if attribute[1].lower() == "srcset" and ("," in value or any(c.isspace() for c in value)):
                raise ValueError("Wiki picture srcset must contain one image URL")
            link = LINK.fullmatch("![image](<" + value + ">)")
            if link is None:
                raise ValueError("Invalid wiki image URL")
            rewritten = replace(link)[len("![image]("):-1]
            return attribute[1] + "=" + attribute[2] + html.escape(rewritten, quote=True) + attribute[2]
        return IMAGE_URL.sub(image_url, match[0])

    lines, fence = [], None
    for line in content.splitlines(keepends=True):
        marker = FENCE.match(line)
        if marker and fence is None:
            fence = marker[1]
        elif marker and fence and marker[1][0] == fence[0] and len(marker[1]) >= len(fence) and not marker[2].strip():
            fence = None
        elif fence is None:
            line = LINK.sub(replace, line)
            line = HTML_IMAGE.sub(image_tag, line)
        lines.append(line)
    return "".join(lines)


def build_wiki(root=ROOT, *, repository="phishdestroy/TgWitness", branch="main"):
    root = Path(root).resolve()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository):
        raise ValueError("Repository must be OWNER/REPOSITORY")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", branch):
        raise ValueError("Branch must be a simple branch name")
    version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]*", version):
        raise ValueError("Invalid package version")
    public = set(public_sources(root))
    rendered, assets = {}, {}
    for name in FILES:
        source = root / "docs/wiki" / name
        if source not in public or source.resolve() != source:
            raise ValueError("Missing or linked wiki input: " + name)
        rendered[name] = render_links(source.read_text(encoding="utf-8"), source, root, public, repository, branch, assets)

    bundle = {name: content.encode("utf-8") for name, content in rendered.items()}
    bundle.update(assets)
    directories = {parent.as_posix() for name in bundle for parent in Path(name).parents if parent != Path(".")}

    output = root / "dist/wiki"
    archive_path = root / "dist" / ("TgWitness-" + version + "-wiki.zip")
    checksum_path = archive_path.with_suffix(".zip.sha256")
    manifest_path = root / "dist/wiki-manifest.json"

    if output.resolve() != output or (output.exists() and not output.is_dir()):
        raise ValueError("Wiki output must be an ordinary directory")
    if output.exists():
        for path in output.rglob("*"):
            name = path.relative_to(output).as_posix()
            allowed = name in directories if path.is_dir() else path.is_file() and name in bundle
            if path.resolve() != path or not allowed:
                raise ValueError("Unexpected or linked wiki output: " + name)
    for path in (archive_path, checksum_path, manifest_path):
        if path.resolve() != path or (path.exists() and not path.is_file()):
            raise ValueError("Wiki artifact must be an ordinary file: " + path.name)
    output.mkdir(parents=True, exist_ok=True)
    hashes = {}
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in bundle.items():
            destination = output / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            archive.writestr(name, data)
            hashes[name] = hashlib.sha256(data).hexdigest()
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    checksum_path.write_text(digest + "  " + archive_path.name + "\n", encoding="utf-8")
    manifest = {
        "format": "tgwitness-wiki-bundle-v1", "repository": repository,
        "source_branch": branch, "version": version, "language": "en",
        "pages": len(PAGES), "assets": len(assets), "files": hashes, "archive": archive_path.name, "sha256": digest,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY") or "phishdestroy/TgWitness")
    parser.add_argument("--branch", default="main")
    args = parser.parse_args()
    try:
        result = build_wiki(repository=args.repository, branch=args.branch)
    except (ValueError, OSError) as exc:
        parser.exit(1, "Wiki build failed: " + str(exc) + "\n")
    print(f"Built {result['pages']} English pages plus sidebar/footer in {ROOT / 'dist/wiki'}")
    print("Wiki archive:", ROOT / "dist" / result["archive"])
    print("SHA-256:", result["sha256"])


if __name__ == "__main__":
    main()
