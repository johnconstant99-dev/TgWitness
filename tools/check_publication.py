"""Check public source, local Markdown links and recognizable secret formats.

This bounded check is not a comprehensive secret scanner. It never prints matches.
Use --git-index to check the staged contents and require the complete reviewed source.
"""
import argparse
import io
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote, urlsplit

try:
    from .build_source import ROOT, public_sources
except ImportError:
    from build_source import ROOT, public_sources

BINARY = {".png", ".webp", ".gif", ".mp4"}
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


def check_sources(root):
    root = Path(root).resolve()
    sources = public_sources(root)
    selected = {p.relative_to(root).as_posix() for p in sources}
    findings, links = [], 0
    for source in sources:
        if source.suffix.lower() in BINARY:
            continue
        content = source.read_text(encoding="utf-8")
        relative = source.relative_to(root).as_posix()
        findings.extend(secret_findings(content, relative))
        if source.suffix != ".md":
            continue
        for match in LINK.finditer(content):
            href = urlsplit(match[1].strip("<>"))
            if href.scheme or href.netloc or not href.path or href.path.startswith("/"):
                continue
            target = (source.parent / unquote(href.path)).resolve()
            # GitHub's ../../releases links intentionally resolve outside the checkout.
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

    # Rehash instead of trusting Git's cached stat data or assume-unchanged flags.
    # Git applies .gitattributes filters, including normal Windows line endings.
    for offset in range(0, len(ordinary), 64):
        batch = ordinary[offset:offset + 64]
        hashes = git("hash-object", "--", *(name for name, _ in batch)).decode("ascii").splitlines()
        if len(hashes) != len(batch):
            raise ValueError("Git did not hash every public file")
        for (name, staged), working in zip(batch, hashes):
            if staged != working:
                findings.append(f"Git index differs from the reviewed working file: {name}")

    # Scan the staged blobs too: cleaning a working file does not remove a secret
    # already staged for commit, and Git clean filters may transform its contents.
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
            try:
                content = data.decode("utf-8")
            except UnicodeError:
                findings.append(f"Git index contains invalid UTF-8 text: {name}")
                continue
            findings.extend(secret_findings(content, "Git index " + name))
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
