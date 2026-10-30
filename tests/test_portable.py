"""The portable package ships only its own layout, never files left by an earlier build or instance."""
import contextlib
import io
import os
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import build_portable  # noqa: E402


def stage_with(root, *extra):
    stage = root / ("TgWitness-" + build_portable.VERSION)
    for relative in ("TgWitness.cmd", "README.txt", "LICENSE", "python/python.exe",
                     "python/Lib/site-packages/tgwitness/__init__.py", *extra):
        (stage / relative).parent.mkdir(parents=True, exist_ok=True)
        (stage / relative).write_text("synthetic", encoding="ascii")
    return stage


@pytest.mark.parametrize("relative", [
    "data/live/panel-token.txt", "python/data/note.txt", "notes.txt", "TgWitness.cmd/extra",
    "python/Lib/site-packages/x/account.session", "python/vault.key", "python/evidence.jsonl",
])
def test_private_or_unexpected_paths_are_refused(relative):
    assert build_portable.release_problem(relative)


@pytest.mark.parametrize("relative", ["LICENSE", "NOTICE", "TgWitness-Demo.cmd", "python/python.exe",
                                      "python/Lib/site-packages/certifi/cacert.pem"])
def test_package_layout_is_accepted(relative):
    assert build_portable.release_problem(relative) is None


def test_release_zip_contains_exactly_the_checked_files(tmp_path):
    stage = stage_with(tmp_path / "build")
    target = tmp_path / "package.zip"
    build_portable.write_release(stage, target)
    with zipfile.ZipFile(target) as archive:
        names = sorted(archive.namelist())
    assert names == sorted(stage.name + "/" + p.relative_to(stage).as_posix() for p in stage.rglob("*") if p.is_file())
    assert not target.with_name(target.name + ".part").exists()


def test_residual_data_stops_the_release_and_keeps_the_previous_artifact(tmp_path):
    stage = stage_with(tmp_path / "build", "data/private-marker.txt")
    target = tmp_path / "package.zip"
    target.write_bytes(b"previous release")
    with pytest.raises(SystemExit, match="Refusing .*data/private-marker.txt"):
        build_portable.write_release(stage, target)
    assert target.read_bytes() == b"previous release"


def test_linked_paths_are_refused(tmp_path):
    stage = stage_with(tmp_path / "build")
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (stage / "python" / "linked").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Symbolic links are unavailable on this host")
    with pytest.raises(SystemExit, match="linked path"):
        build_portable.release_files(stage)


@pytest.mark.skipif(os.name != "nt" or sys.version_info[:2] != (3, 12), reason="the builder runs on Windows/Python 3.12")
def test_rebuild_never_reuses_an_earlier_stage_with_a_locked_private_file(tmp_path):
    (tmp_path / "LICENSE").write_text("Synthetic license", encoding="ascii")
    (tmp_path / "NOTICE").write_text("Synthetic maintainer notice", encoding="ascii")
    old = tmp_path / "build/portable" / ("TgWitness-" + build_portable.VERSION) / "data/private-marker.txt"
    old.parent.mkdir(parents=True)
    old.write_text("SYNTHETIC PRIVATE DATA - DO NOT SHIP", encoding="ascii")
    runtime = tmp_path / "runtime.zip"
    with zipfile.ZipFile(runtime, "w") as archive:
        archive.writestr("python.exe", b"Synthetic runtime; never executed")
    # The open handle keeps the old file locked on Windows; installation and the runtime probe are stubbed.
    with old.open("rb"), patch.object(build_portable, "ROOT", tmp_path), \
            patch.object(build_portable, "embedded_runtime", return_value=runtime), \
            patch.object(build_portable.subprocess, "run", return_value=SimpleNamespace(
                returncode=0, stdout='{"ready":true}', stderr="")), \
            patch.object(sys, "argv", ["build_portable.py"]), contextlib.redirect_stdout(io.StringIO()):
        build_portable.main()
    artifact = next((tmp_path / "dist").glob("*-portable.zip"))
    with zipfile.ZipFile(artifact) as archive:
        names = archive.namelist()
    assert names and not any("/data/" in name for name in names)
    assert old.exists()
