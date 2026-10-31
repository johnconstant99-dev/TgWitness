import asyncio
import hashlib

import pytest
from fastapi.testclient import TestClient

from tgwitness import source_check
from tgwitness.app import create_app
from tgwitness.network import NetworkConfig
from test_collector import FakeClient


def git_blob(content):
    return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()


@pytest.fixture
def github(monkeypatch):
    """A fake GitHub API: one commit whose tree holds the given files (LF, as git stores them)."""
    calls, repo = [], {"files": {}}

    async def fake(path, network):
        calls.append(path)
        if "/commits/" in path:
            if path.endswith("/commits/missing"):
                raise source_check.NotFound(path)
            return {"sha": "c" * 40}
        tree = [{"path": "tgwitness/" + name, "type": "blob", "sha": git_blob(content)}
                for name, content in repo["files"].items()]
        return {"sha": "c" * 40, "truncated": False, "tree": tree + [{"path": "README.md", "type": "blob", "sha": "0" * 40}]}

    monkeypatch.setattr(source_check, "github", fake)
    return repo, calls


def package(tmp_path, files):
    root = tmp_path / "tgwitness"
    for name, content in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(content)
    return root


def test_the_running_code_matches_the_commit_even_with_windows_line_endings(tmp_path, github):
    repo, calls = github
    repo["files"] = {"app.py": b"print(1)\nprint(2)\n", "static/app.js": b"x();\n", "locales/ru.json": b"{}\n"}
    root = package(tmp_path, {"app.py": b"print(1)\r\nprint(2)\r\n", "static/app.js": b"x();\n"})
    result = asyncio.run(source_check.check("https://github.com/someone/TgWitness-fork", "v1.0", NetworkConfig(kind="direct"), root))
    assert result["matches"] and result["files"] == 2 and result["commit"] == "c" * 40
    assert result["repository"] == "https://github.com/someone/TgWitness-fork"
    assert calls[0] == "someone/TgWitness-fork/commits/v1.0"


def test_a_changed_added_or_missing_program_file_is_a_difference(tmp_path, github):
    repo, _ = github
    repo["files"] = {"app.py": b"print(1)\n", "gone.py": b"pass\n"}
    root = package(tmp_path, {"app.py": b"print('changed')\n", "new.py": b"pass\n"})
    result = asyncio.run(source_check.check("someone/fork", "main", NetworkConfig(kind="direct"), root))
    assert not result["matches"] and result["differences"] == 3
    assert (result["changed"], result["extra"], result["missing"]) == (["app.py"], ["new.py"], ["gone.py"])


@pytest.mark.parametrize("text", ["", "not a repo", "https://gitlab.com/a/b", "a/b/c"])
def test_only_github_repositories_are_accepted(text):
    with pytest.raises(ValueError):
        source_check.repository(text)


def test_api_records_each_check_in_the_signed_journal(tmp_path, monkeypatch, github):
    repo, _ = github
    root = source_check.PACKAGE
    repo["files"] = {name: (root / name).read_bytes().replace(b"\r\n", b"\n") for name in source_check.source_files(root)}
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer " + app.state.vault.token
        assert c.get("/api/source-check").json()["last"] is None
        state = c.post("/api/source-check", json={"repository": "github.com/someone/fork", "ref": "v1.0"}).json()
        assert state["last"]["matches"] and state["current"]
        event = app.state.store.events(kind="source.checked")[0]
        assert event["payload"]["commit"] == "c" * 40 and event["payload"]["matches"]
        assert c.post("/api/source-check", json={"repository": "someone/fork", "ref": "missing"}).status_code == 422
        assert c.post("/api/source-check", json={"repository": "gitlab.com/a/b", "ref": "v1"}).status_code == 422
