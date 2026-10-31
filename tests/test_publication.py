import shutil
import subprocess

import pytest

from tools.build_source import FILES
from tools.check_publication import check_sources


def public_tree(root):
    for name in FILES:
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text("Synthetic public source\n", encoding="utf-8")


@pytest.mark.parametrize("filename", ["README.md", "deploy/Dockerfile", "deploy/constraints.txt"])
def test_publication_finds_secret_without_printing_its_value(tmp_path, filename):
    public_tree(tmp_path)
    secret = "ghp_" + "a" * 36
    (tmp_path / filename).write_text("Example\n" + secret, encoding="utf-8")
    _, _, findings = check_sources(tmp_path)
    assert findings == [filename + ":2: possible GitHub token (value withheld)"]
    assert all(secret not in finding for finding in findings)


def test_publication_checks_linked_files_are_actually_shipped(tmp_path):
    public_tree(tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "data/private.md").write_text("Not public", encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "[Start](docs/QUICKSTART.md) [Missing](missing.md) [Private](data/private.md) "
        "[Release](../../releases) [External](https://example.org)", encoding="utf-8")
    _, links, findings = check_sources(tmp_path)
    assert links == 3
    assert len(findings) == 2
    assert findings[0].endswith("missing.md") and findings[1].endswith("data/private.md")


def test_only_named_public_tsa_fixtures_enter_the_source_package(tmp_path):
    public_tree(tmp_path)
    (tmp_path / "tests/tsa/freetsa.tsr").write_bytes(b"\xff\x00public fixture")
    private = tmp_path / "tests/tsa/unreviewed.bin"
    private.write_bytes(b"not in the release")
    sources, _, findings = check_sources(tmp_path)
    assert tmp_path / "tests/tsa/freetsa.tsr" in sources
    assert private not in sources
    assert not findings


@pytest.fixture
def staged_sources(tmp_path):
    if not shutil.which("git"):
        pytest.skip("Git is needed to check staged publication contents")
    public_tree(tmp_path)
    (tmp_path / ".gitattributes").write_text("* text=auto\n*.cmd text eol=crlf\n", encoding="utf-8")

    def git(*args, **kwargs):
        return subprocess.run(["git", "-c", f"safe.directory={tmp_path.as_posix()}", *args],
                              cwd=tmp_path, check=True, capture_output=True, **kwargs)

    git("init", "--quiet")
    git("add", "--all")
    return tmp_path, git


def index_findings(root):
    from tools.check_publication import check_git_index
    from tools.build_source import public_sources
    return check_git_index(root, public_sources(root))


def test_publication_requires_new_public_files_in_git(staged_sources):
    root, _ = staged_sources
    (root / "tgwitness").mkdir()
    (root / "tgwitness/new.py").write_text("# Required module\n", encoding="utf-8")
    assert index_findings(root) == ["Public file is missing from the Git index: tgwitness/new.py"]


def test_publication_scans_staged_secrets_even_after_working_file_is_clean(staged_sources):
    root, git = staged_sources
    secret = "ghp_" + "b" * 36
    (root / "README.md").write_text(secret + "\n", encoding="utf-8")
    git("add", "README.md")
    (root / "README.md").write_text("Clean working copy\n", encoding="utf-8")
    # Even Git's assume-unchanged hint must not hide the staged version from this check.
    git("update-index", "--assume-unchanged", "README.md")
    findings = index_findings(root)
    assert "Git index differs from the reviewed working file: README.md" in findings
    assert "Git index README.md:1: possible GitHub token (value withheld)" in findings
    assert all(secret not in finding for finding in findings)


def test_publication_rejects_private_index_paths(staged_sources):
    root, git = staged_sources
    (root / "panel-token.txt").write_text("synthetic private token", encoding="utf-8")
    git("add", "--force", "panel-token.txt")
    assert index_findings(root) == ["Git index contains a non-public path: panel-token.txt"]


def test_publication_accepts_git_line_ending_normalization(staged_sources):
    root, git = staged_sources
    (root / "Start.cmd").write_bytes(b"@echo off\r\npython start.py\r\n")
    git("add", "Start.cmd")
    assert not index_findings(root)


def test_publication_rejects_unmerged_index_entries(staged_sources):
    root, git = staged_sources
    digest = git("rev-parse", ":README.md").stdout.decode().strip()
    git("update-index", "--force-remove", "README.md")
    git("update-index", "--index-info", input=f"100644 {digest} 2\tREADME.md\n".encode())
    assert "Git index has an unresolved merge: README.md" in index_findings(root)
