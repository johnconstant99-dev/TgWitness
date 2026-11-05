"""Retry network failures while rejecting corrupt or unpinned OCR inputs."""
import hashlib
import http.client
import importlib.util
import io
from pathlib import Path
import urllib.error

import pytest

spec = importlib.util.spec_from_file_location("ocr_source_fetch", Path(__file__).resolve().parents[1] / "deploy/media-worker/fetch-sources.py")
fetcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetcher)
PAYLOAD = b"synthetic pinned OCR input"
ITEM = {"url": "https://example.invalid/pinned-source", "sha256": hashlib.sha256(PAYLOAD).hexdigest()}


@pytest.mark.parametrize("error", [TimeoutError("timeout"), urllib.error.URLError("connection reset"),
    urllib.error.HTTPError(ITEM["url"], 503, "temporary", {}, None), http.client.IncompleteRead(b"partial")])
def test_transient_failure_retries_but_publishes_only_verified_bytes(tmp_path, error):
    calls, sleeps = [], []
    def open_source(url, timeout):
        calls.append((url, timeout))
        if len(calls) < 3:
            raise error
        return io.BytesIO(PAYLOAD)
    target = tmp_path / "source.tar.gz"
    fetcher.fetch(ITEM, target, opener=open_source, sleep=sleeps.append)
    assert target.read_bytes() == PAYLOAD
    assert len(calls) == 3 and sleeps == [2, 4]
    assert not target.with_suffix(".gz.part").exists()
    fetcher.fetch(ITEM, target, opener=lambda *a, **k: pytest.fail("verified cache should be reused"))


@pytest.mark.parametrize("failure", ["permanent", "corrupt", "exhausted", "oversized"])
def test_failures_leave_no_partially_trusted_file(tmp_path, monkeypatch, failure):
    calls = []
    def open_source(*args, **kwargs):
        calls.append(1)
        if failure == "permanent":
            raise urllib.error.HTTPError(ITEM["url"], 404, "missing", {}, None)
        if failure == "exhausted":
            raise TimeoutError("timeout")
        return io.BytesIO(PAYLOAD if failure == "oversized" else b"changed")
    if failure == "oversized":
        monkeypatch.setattr(fetcher, "MAX_BYTES", 4)
    target = tmp_path / "source"
    with pytest.raises((ValueError, urllib.error.HTTPError, TimeoutError)):
        fetcher.fetch(ITEM, target, opener=open_source, sleep=lambda _: None)
    assert len(calls) == (3 if failure == "exhausted" else 1)
    assert not target.exists() and not target.with_suffix(".part").exists()
