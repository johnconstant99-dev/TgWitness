"""Check public source, local Markdown links and recognizable secret formats."""
import argparse
import ast
from collections import Counter
import importlib.util
import io
import json
from pathlib import Path
from pathlib import PurePosixPath
import re
import subprocess
import tomllib
import xml.etree.ElementTree as ET
import zipfile
from urllib.parse import unquote, urlsplit

if __package__:
    from .build_source import ROOT, public_sources
    from .i18n_keys import all_script_keys
else:
    spec = importlib.util.spec_from_file_location("build_source", Path(__file__).resolve().with_name("build_source.py"))
    if spec is None or spec.loader is None:
        raise ImportError("Could not load the public source builder")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    ROOT, public_sources = builder.ROOT, builder.public_sources
    spec = importlib.util.spec_from_file_location("i18n_keys", Path(__file__).resolve().with_name("i18n_keys.py"))
    if spec is None or spec.loader is None:
        raise ImportError("Could not load the interface key inventory")
    inventory = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inventory)
    all_script_keys = inventory.all_script_keys

BINARY = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp4", ".bin", ".tsq", ".tsr", ".ttf"}
DEEPL_UUID = r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}"
PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    "Telegram bot token": re.compile(r"\b[0-9]{6,12}:[A-Za-z0-9_-]{35}\b"),
    "Telethon session": re.compile(r"(?<![A-Za-z0-9_-])1[A-Za-z0-9_-]{340,}={0,2}(?![A-Za-z0-9_-])"),
    "AI provider API key": re.compile(
        r"\b(?:sk-(?:(?:proj|svcacct|ant|or-v1)-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{32,})"
        r"|gsk_[A-Za-z0-9_-]{32,}|AIza[A-Za-z0-9_-]{35})\b"),
    "DeepL API key": re.compile(
        rf"\b(?:{DEEPL_UUID}:fx|deepl[_-](?:auth|api)[_-]key\b[\"']?\s*[:=]?\s*[\"']?{DEEPL_UUID}(?::fx)?)\b",
        re.IGNORECASE),
}
LINK = re.compile(r"\[[^\]]*\]\(([^\s)]+)(?:\s+[^)]*)?\)")


def secret_findings(content, name):
    findings = []
    for label, pattern in PATTERNS.items():
        for match in pattern.finditer(content):
            line = content.count("\n", 0, match.start()) + 1
            findings.append(f"{name}:{line}: possible {label} (value withheld)")
    return findings


def data_findings(data, name):
    if Path(name).suffix.lower() != ".zip":
        try:
            return secret_findings(data.decode("utf-8"), name)
        except UnicodeError:
            return [f"{name}: invalid UTF-8 text"]
    findings = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) > 1000 or sum(item.file_size for item in members) > 20 * 1024**2:
                return [f"{name}: ZIP exceeds publication scan limits"]
            for item in members:
                path = PurePosixPath(item.filename)
                if path.is_absolute() or ".." in path.parts or "\\" in item.filename or ":" in item.filename:
                    findings.append(f"{name}: unsafe ZIP member path")
                    continue
                if item.is_dir() or path.suffix.lower() in BINARY:
                    continue
                if path.suffix.lower() == ".zip":
                    findings.append(f"{name}: nested ZIP needs separate review")
                    continue
                findings.extend(data_findings(archive.read(item), name + "/" + item.filename))
    except (zipfile.BadZipFile, RuntimeError):
        findings.append(f"{name}: ZIP could not be inspected")
    return findings


def check_sources(root):
    root = Path(root).resolve()
    sources = public_sources(root)
    selected = {p.relative_to(root).as_posix() for p in sources}
    findings, links = [], 0
    for source in sources:
        if source.suffix.lower() in BINARY:
            continue
        relative = source.relative_to(root).as_posix()
        data = source.read_bytes()
        findings.extend(data_findings(data, relative))
        if source.suffix != ".md":
            continue
        content = data.decode("utf-8")
        for match in LINK.finditer(content):
            href = urlsplit(match[1].strip("<>"))
            if href.scheme or href.netloc or not href.path or href.path.startswith("/"):
                continue
            target = (source.parent / unquote(href.path)).resolve()

            if not target.is_relative_to(root):
                continue
            links += 1
            name = target.relative_to(root).as_posix()
            if not target.exists() or (target.is_file() and name not in selected):
                line = content.count("\n", 0, match.start()) + 1
                findings.append(f"{relative}:{line}: local link is absent from public source: {name}")
    return sources, links, findings


def check_version_labels(root):
    root = Path(root)
    version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    label = f"v{version} · pre-release"
    findings = []
    package = (root / "tgwitness/__init__.py").read_text(encoding="utf-8")
    if not re.search(r'__version__\s*=\s*[\"\']' + re.escape(version) + r'[\"\']', package):
        findings.append("tgwitness/__init__.py: package version differs from pyproject.toml")
    readme = (root / "README.md").read_text(encoding="utf-8")
    if f'alt="{label}"' not in readme:
        findings.append("README.md: source-version badge differs from pyproject.toml")
    badge = ET.parse(root / "docs/assets/presentation/identity-meta-version.svg").getroot()
    title = badge.find("{http://www.w3.org/2000/svg}title")
    if title is None or title.text != label or not any(node.get("aria-label") == label for node in badge.iter()):
        findings.append("docs/assets/presentation/identity-meta-version.svg: regenerate the source-version badge")
    status = (root / "docs/STATUS.md").read_text(encoding="utf-8")
    if not re.search(r"Source version[:：]\s*\*\*" + re.escape(version) + r" preview\*\*[.．]", status):
        findings.append("docs/STATUS.md: update the source version")
    return findings


def check_catalogues(root):
    package = Path(root) / "tgwitness"
    findings = []

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key: " + key)
            result[key] = value
        return result

    try:
        tree = ast.parse((package / "i18n.py").read_text(encoding="utf-8"))
        languages = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                         and any(isinstance(target, ast.Name) and target.id == "LANGUAGES" for target in node.targets))
        expected = set(languages) - {"en"}
        paths = {path.stem: path for path in (package / "locales").glob("*.json")}
        if paths.keys() != expected:
            findings.append("Panel language files differ from the supported language selection")
        dictionaries = {lang: json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)
                        for lang, path in paths.items()}
        required = set(json.loads((package / "english_fallbacks.json").read_text(encoding="utf-8")))
        required.update(all_script_keys(package))
        required.update(json.loads((package / "guide_locales/keys.json").read_text(encoding="utf-8"))["keys"])
        for words in dictionaries.values():
            required.update(words)
        fields = lambda text: Counter(re.findall(r"\{\w+\}", text))
        for lang, words in sorted(dictionaries.items()):
            name = f"tgwitness/locales/{lang}.json"
            for key in sorted(required - words.keys()):
                findings.append(f"{name}: missing translation: {key}")
            for key, value in words.items():
                variants = value if isinstance(value, dict) else {"text": value}
                if isinstance(value, dict) and ("other" not in value or value.keys() - {"zero", "one", "two", "few", "many", "other"}):
                    findings.append(f"{name}: invalid plural forms: {key}")
                for form, text in variants.items():
                    if not isinstance(text, str) or not text.strip():
                        findings.append(f"{name}: empty translation ({form}): {key}")
                    elif fields(text) != fields(key):
                        findings.append(f"{name}: changed placeholders ({form}): {key}")
                    elif "\ufffd" in text or any(ord(char) < 32 and char not in "\n\r\t" for char in text):
                        findings.append(f"{name}: invalid translation characters ({form}): {key}")
    except (OSError, ValueError, TypeError, StopIteration) as exc:
        findings.append("Panel language catalogues could not be checked: " + str(exc))
    return findings


def check_git_index(root, sources):
    root = Path(root).resolve()

    def git(*args, **kwargs):
        return subprocess.run(["git", "-c", f"safe.directory={root.as_posix()}", *args],
                              cwd=root, check=True, capture_output=True, **kwargs).stdout

    entries = []
    for record in git("ls-files", "--stage", "-z").split(b"\0"):
        if record:
            metadata, name = record.split(b"\t", 1)
            mode, digest, stage = metadata.decode("ascii").split()
            entries.append((name.decode("utf-8"), mode, digest, stage))
    tracked = {name for name, _, _, _ in entries}
    selected = {p.relative_to(root).as_posix() for p in sources}
    findings = [f"Git index contains a non-public path: {p}" for p in sorted(tracked - selected)]
    findings.extend(f"Public file is missing from the Git index: {p}" for p in sorted(selected - tracked))
    unresolved = {name for name, _, _, stage in entries if stage != "0"}
    findings.extend(f"Git index has an unresolved merge: {p}" for p in sorted(unresolved))
    ordinary = []
    for name, mode, digest, stage in entries:
        if name not in selected or name in unresolved:
            continue
        if mode not in ("100644", "100755"):
            findings.append(f"Git index contains a non-regular public file: {name}")
            continue
        ordinary.append((name, digest))


    for offset in range(0, len(ordinary), 64):
        batch = ordinary[offset:offset + 64]
        hashes = git("hash-object", "--", *(name for name, _ in batch)).decode("ascii").splitlines()
        if len(hashes) != len(batch):
            raise ValueError("Git did not hash every public file")
        for (name, staged), working in zip(batch, hashes):
            if staged != working:
                findings.append(f"Git index differs from the reviewed working file: {name}")


    text_entries = [(name, digest) for name, digest in ordinary if Path(name).suffix.lower() not in BINARY]
    if text_entries:
        objects = git("cat-file", "--batch", input="".join(digest + "\n" for _, digest in text_entries).encode())
        stream = io.BytesIO(objects)
        for name, digest in text_entries:
            header = stream.readline().decode("ascii").split()
            if len(header) != 3 or header[:2] != [digest, "blob"]:
                raise ValueError("Git could not read a staged public file")
            data = stream.read(int(header[2]))
            if stream.read(1) != b"\n":
                raise ValueError("Incomplete staged public file")
            findings.extend(data_findings(data, "Git index " + name))
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git-index", action="store_true")
    args = parser.parse_args()
    sources, links, findings = check_sources(ROOT)
    findings.extend(check_version_labels(ROOT))
    findings.extend(check_catalogues(ROOT))
    if args.git_index:
        findings.extend(check_git_index(ROOT, sources))
    print(f"Checked {len(sources)} public files and {links} local documentation links.")
    for finding in findings:
        print(finding)
    if findings:
        raise SystemExit(1)
    print("Publication checks passed. Secret scan covers recognized formats only.")


if __name__ == "__main__":
    main()
