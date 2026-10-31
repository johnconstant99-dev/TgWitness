"""Fork isolation and pinned workflow revisions."""
import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sealed_runner", ROOT / "scripts" / "sealed_runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_caller_and_verifier_pin_same_upstream_workflow_and_collector():
    policy = json.loads((ROOT / "tgwitness" / "sealed_policy.json").read_bytes())
    current = policy["releases"][0]
    caller = (ROOT / ".github" / "workflows" / "sealed-witness.yml").read_text()
    workflow = (ROOT / ".github" / "workflows" / "sealed-collector.yml").read_text()
    assert "uses: " + policy["workflow"] + "@" + current["workflow_sha"] in caller
    assert "repository: phishdestroy/TgWitness" in workflow
    assert "ref: " + current["collector_sha"] in workflow
    assert "persist-credentials: false" in workflow
    assert "runs-on: ubuntu-24.04" in workflow
    for action in re.findall(r"uses:\s*(\S+)", workflow):
        assert re.fullmatch(r"actions/[a-z-]+@[0-9a-f]{40}", action), action
    for forbidden in ("secrets: inherit", "actions/cache", "download-artifact", "github.sha", "inputs.image",
                      "inputs.script", "inputs.digest", "inputs.archive", "inputs.repository", "inputs.ref"):
        assert forbidden not in workflow
    uploads = re.findall(r"^\s+path:\s*(.+)", workflow, flags=re.MULTILINE)
    assert len(uploads) == 3
    assert uploads[1].endswith("/public/connection.tgwsealed")
    assert uploads[2].endswith("/public/delivery.tgwsealed")
    assert workflow.index("sealed_runner.py wait") < workflow.index("id: attest") < workflow.index("sealed_runner.py pack")


def test_runner_refuses_nonhosted_execution_and_path_escape(tmp_path, monkeypatch):
    monkeypatch.setattr(runner.sys, "platform", "linux")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted")
    with pytest.raises(RuntimeError, match="GitHub-hosted"):
        runner.location()
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_RUN_ID", "../outside")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    with pytest.raises(ValueError, match="identity"):
        runner.location()
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    directory, name = runner.location()
    assert directory.parent == tmp_path.resolve() and name == "tgwitness-sealed-123-1"


@pytest.mark.parametrize("recipient,minutes", [("$(bad)","30"),("A"*600,"30; bad"),("A"*600,"999")])
def test_runner_inputs_never_become_commands(tmp_path, monkeypatch, recipient, minutes):
    monkeypatch.setattr(runner, "location", lambda: (tmp_path / "capsule", "synthetic"))
    monkeypatch.setenv("RECIPIENT", recipient)
    monkeypatch.setenv("SESSION_MINUTES", minutes)
    monkeypatch.setattr(runner, "command", lambda *a, **k: pytest.fail("Invalid input reached a subprocess"))
    with pytest.raises(ValueError):
        runner.start()
    assert not (tmp_path / "capsule").exists()
