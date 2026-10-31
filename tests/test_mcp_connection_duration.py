import time

import pytest
from pydantic import ValidationError

from tgwitness.archive import ConnectionSettings, Connections


def test_duration_uses_issue_time_and_public_rate_expires(journal, monkeypatch):
    _, vault = journal
    clock = [time.time()]
    monkeypatch.setattr("tgwitness.archive.time.time", lambda: clock[0])
    manager = Connections(vault)
    token, entry = manager.issue(ConnectionSettings(name="Minute", workspaces={"default": None}, expires_in_seconds=60))
    assert entry["expires_at"] == clock[0] + 60
    assert entry["requests_last_minute"] == 0
    # A long-lived connection can show a rolling count without persisting every request.
    token, entry = manager.issue(ConnectionSettings(name="Longer", workspaces={"default": None}, expires_in_seconds=3600))
    manager.resolve(token)
    manager.resolve(token, count=False)
    record = manager.entries[-1]
    assert manager.public(record)["requests_last_minute"] == 1
    clock[0] += 61
    public = manager.public(record)
    assert public["requests_last_minute"] == 0 and public["uses"] == 1
    assert public["rate_limit_per_minute"] == 60 and "sha256" not in public


@pytest.mark.parametrize("expiry", [{}, {"expires_in_seconds": 59}, {"expires_in_seconds": 90*86400+1},
    {"expires_in_seconds": 60.1}, {"expires_in_seconds": True},
    {"expires_in_seconds": 60, "expires_at": 9999999999}])
def test_duration_rejects_ambiguous_or_out_of_range_expiry(expiry):
    with pytest.raises(ValidationError):
        ConnectionSettings(name="Reader", workspaces={"default": None}, **expiry)
