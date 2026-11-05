"""Check that stale GitHub release pins and later collector edits are rejected."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_sealed_release import CALLER, COLLECTOR, POLICY, WORKFLOW, validate


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def pair(root, signer, collector):
    write(root, POLICY, json.dumps({"format": "tgwitness-sealed-policy-v1", "workflow": WORKFLOW,
                                  "releases": [{"workflow_sha": signer, "collector_sha": collector}]}))
    write(root, CALLER, "jobs:\n  capture:\n    uses: " + WORKFLOW + "@" + signer + "\n")
    write(root, COLLECTOR, "jobs:\n  capture:\n    steps:\n      - uses: actions/checkout@" + "c" * 40
          + "\n        with:\n          repository: phishdestroy/TgWitness\n          ref: " + collector + "\n")


@pytest.mark.parametrize("name,before,after", [
    (CALLER, "a" * 40, "b" * 40),
    (COLLECTOR, "b" * 40, "d" * 40),
    (COLLECTOR, "phishdestroy/TgWitness", "synthetic/fork"),
    (CALLER, "a" * 40, "main"),
    (POLICY, "b" * 40, "b" * 7),
])
def test_mismatched_or_mutable_pin_rejected(tmp_path, name, before, after):
    pair(tmp_path, "a" * 40, "b" * 40)
    assert validate(tmp_path)["collector_sha"] == "b" * 40
    write(tmp_path, name, (tmp_path / name).read_text().replace(before, after))
    with pytest.raises(ValueError):
        validate(tmp_path)


@pytest.mark.parametrize("runtime_input", ["tgwitness/sealed.py", "deploy/containers/install-packages.sh",
                                         "deploy/containers/runtime-x86_64.lock", ".dockerignore"])
def test_pinned_commits_match_the_tested_runtime(tmp_path, runtime_input):
    def git(*args):
        return subprocess.check_output(["git", "-c", "core.autocrlf=false", "-c", "core.hooksPath=NUL",
                                        "-c", "commit.gpgsign=false", "-c", "user.name=Synthetic Test",
                                        "-c", "user.email=synthetic@example.invalid", *args], cwd=tmp_path).decode().strip()
    def commit():
        git("add", ".")
        git("commit", "--quiet", "-m", "Synthetic release fixture")
        return git("rev-parse", "HEAD")
    git("init", "--quiet")
    pair(tmp_path, "a" * 40, "b" * 40)
    write(tmp_path, runtime_input, "synthetic = 'reviewed collector'\n")
    collector = commit()
    pair(tmp_path, "a" * 40, collector)
    signer = commit()
    pair(tmp_path, signer, collector)
    commit()
    assert validate(tmp_path, git_history=True) == {"workflow_sha": signer, "collector_sha": collector}
    write(tmp_path, runtime_input, "synthetic = 'later collector edit'\n")
    with pytest.raises(ValueError, match="release inputs"):
        validate(tmp_path, git_history=True)
    git("restore", runtime_input)
    write(tmp_path, "tgwitness/untracked.py", "synthetic = 'not in the collector commit'\n")
    with pytest.raises(ValueError, match="release inputs"):
        validate(tmp_path, git_history=True)
    (tmp_path / "tgwitness/untracked.py").unlink()
    write(tmp_path, COLLECTOR, (tmp_path / COLLECTOR).read_text() + "# Later workflow edit\n")
    with pytest.raises(ValueError, match="pinned signer commit"):
        validate(tmp_path, git_history=True)
