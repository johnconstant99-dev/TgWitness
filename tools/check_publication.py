"""Check public source, local Markdown links and recognizable secret formats.

This bounded check is not a comprehensive secret scanner. It never prints matches.
Use --git-index to check the staged contents and require the complete reviewed source.
"""
import argparse
import io
from pathlib import Path
from pathlib import PurePosixPath
import re
import subprocess
import zipfile
from urllib.parse import unquote, urlsplit

try:
    from .build_source import ROOT, public_sources
except ImportError:
    from build_source import ROOT, public_sources

BINARY = {".png", ".webp", ".gif", ".mp4", ".bin", ".tsq", ".tsr"}
PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    "Telegram bot token": re.compile(r"\b[0-9]{6,12}:[A-Za-z0-9_-]{35}\b"),
    "Telethon session": re.compile(r"(?<![A-Za-z0-9_-])1[A-Za-z0-9_-]{340,}={0,2}(?![A-Za-z0-9_-])"),
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


def check_git_index(root, sources):
    """Inspect actual index objects without changing the index or repository settings."""
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
