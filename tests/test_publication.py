import shutil
import subprocess
import zipfile

import pytest

from tools.build_source import FILES
from tools.check_publication import check_sources


def public_tree(root):
    for name in FILES:
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        if name.endswith(".zip"):
            with zipfile.ZipFile(root / name, "w") as archive:
                archive.writestr("README.txt", "Synthetic public source\n")
        else:
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


def test_named_ui_regression_and_mcp_pins_ship_without_unreviewed_neighbors(tmp_path):
    public_tree(tmp_path)
    private_script = tmp_path / "tools/local-credentials.mjs"
    private_pins = tmp_path / "deploy/constraints-local.txt"
    private_script.write_text("// Private helper\n", encoding="utf-8")
    private_pins.write_text("private-package==1\n", encoding="utf-8")
    sources, _, findings = check_sources(tmp_path)
    assert tmp_path / "tools/check_writeonly_drafts.mjs" in sources
    assert tmp_path / "deploy/constraints-mcp.txt" in sources
    assert private_script not in sources and private_pins not in sources
    assert not findings


def test_only_named_demo_archives_ship_and_their_contents_are_scanned(tmp_path):
    public_tree(tmp_path)
    demo = tmp_path / "website/demo/downloads"
    unreviewed = demo / "private-export.zip"
    unreviewed.write_bytes(b"not reviewed")
    secret = "ghp_" + "c" * 36
    with zipfile.ZipFile(demo / "tgwitness-demo.zip", "w") as archive:
        archive.writestr("events.jsonl", secret)
        archive.writestr("../outside.txt", "unsafe path")
    sources, _, findings = check_sources(tmp_path)
    assert unreviewed not in sources
    assert findings == [
        "website/demo/downloads/tgwitness-demo.zip/events.jsonl:1: possible GitHub token (value withheld)",
        "website/demo/downloads/tgwitness-demo.zip: unsafe ZIP member path",
    ]
    assert all(secret not in finding for finding in findings)


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
