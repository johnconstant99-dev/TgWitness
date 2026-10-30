import socket
import sys
import runpy
from pathlib import Path

import pytest

from tgwitness.doctor import inspect_environment


def check(report, name):
    return next(c for c in report["checks"] if c["name"] == name)


def test_diagnostics_do_not_create_data_or_disclose_secrets(tmp_path, monkeypatch):
    root = tmp_path / "new" / "data"
    monkeypatch.setenv("TGWITNESS_TOKEN", "synthetic-short")
    monkeypatch.setenv("TGWITNESS_VAULT_KEY_FILE", str(tmp_path / "missing-key"))
    report = inspect_environment(root)
    assert not report["ready"]
    assert check(report, "external_key")["status"] == "fail"
    assert check(report, "panel_token")["status"] == "fail"
    assert "synthetic-short" not in str(report)
    assert not root.exists() and not list(tmp_path.iterdir())


def test_busy_port_and_missing_key_detected(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_VAULT_KEY_FILE", raising=False)
    (tmp_path / "vault.external.json").write_text("{}")
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        report = inspect_environment(tmp_path, port=occupied.getsockname()[1])
    assert check(report, "listen_address")["status"] == "fail"
    assert check(report, "external_key")["status"] == "fail"


@pytest.mark.parametrize("argument", ["--help", "--check"])
def test_launcher_readonly_modes_never_install(monkeypatch, argument):
    import subprocess
    calls = []
    monkeypatch.setattr(sys, "argv", ["start.py", argument])
    monkeypatch.setattr(subprocess, "call", lambda args, **kwargs: calls.append(args) or 0)
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: pytest.fail("Installer must not run"))
    # Pretend an environment exists: portable across CI and source archives.
    monkeypatch.setattr(Path, "exists", lambda self: True)
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(Path(__file__).resolve().parents[1] / "start.py"), run_name="__main__")
    assert exc.value.code == 0
    assert argument in calls[0] and "pip" not in calls[0]


def test_invalid_port_environment_uses_parser_error(monkeypatch, capsys):
    from tgwitness.__main__ import main
    monkeypatch.setenv("TGWITNESS_PORT", "bad-value")
    monkeypatch.setattr(sys, "argv", ["tgwitness", "--check"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    assert "invalid int value" in capsys.readouterr().err
