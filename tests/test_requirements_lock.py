"""The hash locks that servers install from stay in step with the version constraints."""
import re
from pathlib import Path

from tgwitness import cloud

ROOT = Path(__file__).resolve().parents[1]


def pins(text):
    return {re.sub(r"[-_.]+", "-", name).lower(): version
            for name, version in re.findall(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", text, re.M)}


def entries(text):
    """Each pinned requirement with its hash lines."""
    return re.findall(r"^[A-Za-z0-9_.-]+==[^\n]*\\\n(?:\s+--hash=sha256:[0-9a-f]{64}[ \\]*\n?)+", text, re.M)


def test_the_lock_pins_exactly_the_constrained_versions():
    lock = (ROOT / "deploy/requirements.lock").read_text(encoding="utf-8")
    constraints = pins((ROOT / "deploy/constraints.txt").read_text(encoding="utf-8"))
    assert pins(lock) == constraints, "run python tools/lock_requirements.py after changing deploy/constraints.txt"


def test_every_locked_package_has_hashes():
    for name in ("requirements.lock", "build.lock"):
        text = (ROOT / "deploy" / name).read_text(encoding="utf-8")
        assert len(entries(text)) == len(pins(text)) > 0, name
    assert list(pins((ROOT / "deploy/build.lock").read_text(encoding="utf-8"))) == ["setuptools"]


def test_servers_and_the_image_install_only_hashed_packages():
    for text in (cloud.INSTALL, (ROOT / "deploy/Dockerfile").read_text(encoding="utf-8")):
        assert "--require-hashes -r " in text and "build.lock" in text and "requirements.lock" in text
        assert "constraints" not in text

        assert "--no-deps --no-build-isolation" in text
