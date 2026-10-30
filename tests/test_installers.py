"""Launch scripts must preserve arguments and fail before claiming readiness."""
import json
import os
import runpy
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_native_setup_uses_shipped_deployment_constraints(tmp_path, monkeypatch):
    project = tmp_path / "TgWitness source"
    (project / "deploy").mkdir(parents=True)
    shutil.copyfile(ROOT / "start.py", project / "start.py")
    shutil.copyfile(ROOT / "deploy/constraints.txt", project / "deploy/constraints.txt")
    (project / "pyproject.toml").write_text('[project]\nversion = "0.7.0"\n', encoding="utf-8")
    python = project / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    python.parent.mkdir(parents=True)
    python.touch()
    launcher = runpy.run_path(str(project / "start.py"))
    calls = []
    monkeypatch.setitem(launcher["main"].__globals__, "step", lambda command, failure: calls.append(command))
    monkeypatch.setattr(sys, "argv", [str(project / "start.py"), "--setup-only"])
    launcher["main"]()
    install = next(command for command in calls if "pip" in command)
    constraints = Path(install[install.index("-c") + 1])
    assert constraints == project / "deploy/constraints.txt"
    assert constraints.is_file() and not (project / "constraints.txt").exists()
    assert (project / ".venv/.tgwitness-ready").read_text() == "0.7.0"


def shell():
    executable = shutil.which("sh")
    if not executable and os.name == "nt":
        candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
        if candidate.exists():
            executable = str(candidate)
    if not executable:
        pytest.skip("A POSIX shell is unavailable on this host")
    return executable


@pytest.mark.parametrize("mode", ["start", "setup", "demo", "failure"])
def test_native_entrypoint_from_another_directory_with_spaces(tmp_path, mode):
    project = tmp_path / "TgWitness source"
    project.mkdir()
    (project / "start.py").write_text(
        "import json, os, sys\n"
        "print(json.dumps({'args': sys.argv[1:], 'cwd': os.getcwd()}))\n"
        "sys.exit(7 if '--fail' in sys.argv else 0)\n", encoding="utf-8")
    flags = {"start": [], "setup": ["--setup-only"], "demo": ["--demo"], "failure": ["--fail"]}[mode]
    arguments = [*flags, "--data-dir", "saved observations", "--port", "9001"]
    if os.name == "nt":
        (project / "scripts").mkdir()
        for name in ("Start.cmd", "scripts/Setup.cmd", "scripts/Demo.cmd"):
            shutil.copyfile(ROOT / name, project / name)
        entry = {"setup": "scripts/Setup.cmd", "demo": "scripts/Demo.cmd"}.get(mode, "Start.cmd")
        forwarded = "--fail " if mode == "failure" else ""
        command = ('cmd.exe /d /s /c ""' + str(project / entry) + '" ' + forwarded
                   + '--data-dir "saved observations" --port 9001"')
    else:
        shutil.copyfile(ROOT / "start.sh", project / "start.sh")
        command = [shell(), str(project / "start.sh"), *arguments]
    result = subprocess.run(command, cwd=tmp_path, input="\n", text=True,
                            capture_output=True, timeout=20)
    assert result.returncode == (7 if mode == "failure" else 0), result.stdout + result.stderr
    payload = json.loads(result.stdout.splitlines()[0])
    assert payload["args"] == arguments
    assert Path(payload["cwd"]).resolve() == project.resolve()


@pytest.mark.parametrize("failure", ["", "info", "version", "up"])
def test_docker_shell_waits_and_reports_only_successful_start(tmp_path, failure):
    project = tmp_path / "TgWitness source"
    project.mkdir()
    (project / "scripts").mkdir()
    shutil.copyfile(ROOT / "scripts/docker-start.sh", project / "scripts/docker-start.sh")
    executable = project / "docker"
    executable.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$INSTALLER_LOG\"\n"
        "case \"$*\" in\n"
        "  info) [ \"$FAIL_PHASE\" != info ] ;;\n"
        "  'compose version') [ \"$FAIL_PHASE\" != version ] ;;\n"
        "  *' up '*) [ \"$FAIL_PHASE\" != up ] ;;\n"
        "  *' port '*) printf '%s\\n' '127.0.0.1:9001' ;;\n"
        "  *) exit 9 ;;\n"
        "esac\n", encoding="utf-8", newline="\n")
    executable.chmod(0o755)
    log = tmp_path / "docker-calls.txt"
    environment = dict(os.environ, PATH=str(project) + os.pathsep + os.environ["PATH"],
                       INSTALLER_LOG=str(log), FAIL_PHASE=failure)
    result = subprocess.run([shell(), str(project / "scripts/docker-start.sh")], cwd=tmp_path,
                            env=environment, text=True, capture_output=True, timeout=20)
    calls = log.read_text().splitlines()
    assert result.returncode == (1 if failure else 0), result.stdout + result.stderr
    assert ("Panel: http://127.0.0.1:9001" in result.stdout) == (not failure)
    if failure in {"info", "version"}:
        assert not any(" up " in call for call in calls)
    else:
        assert "compose -f compose.yaml up -d --build --wait --wait-timeout 180" in calls
    if failure:
        assert not any(" port " in call for call in calls)
