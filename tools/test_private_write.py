"""Private state survives Windows readers without hiding persistent write errors."""
import errno
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import security


@pytest.mark.parametrize("winerror", [5, 32, 33, None])
@pytest.mark.parametrize("persistent", [False, True])
def test_atomic_replace_retries_only_bounded_windows_sharing_errors(tmp_path, monkeypatch, winerror, persistent):
    destination = tmp_path / "deployment.json"
    destination.write_bytes(b"previous")
    replace, calls, delays = security.os.replace, [], []

    def interrupted(source, target):
        calls.append((source, target))
        assert destination.read_bytes() == b"previous"
        assert Path(source).read_bytes() == b"complete new state"
        if persistent or len(calls) == 1:
            error = PermissionError(errno.EACCES, "Synthetic sharing failure")
            if winerror is not None:
                error.winerror = winerror
            raise error
        replace(source, target)

    monkeypatch.setattr(security.os, "replace", interrupted)
    monkeypatch.setattr(security.time, "sleep", delays.append)
    if persistent or winerror is None:
        with pytest.raises(PermissionError):
            security.private_write(destination, b"complete new state")
        assert destination.read_bytes() == b"previous"
        assert len(calls) == (6 if winerror is not None else 1)
    else:
        security.private_write(destination, b"complete new state")
        assert destination.read_bytes() == b"complete new state"
        assert len(calls) == 2 and not destination.with_suffix(".json.tmp").exists()
    assert len(delays) == len(calls) - 1
    assert sum(delays) <= .32
