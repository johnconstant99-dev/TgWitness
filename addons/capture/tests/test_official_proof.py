import copy
import json
from pathlib import Path
import subprocess

import pytest
from fastapi.testclient import TestClient

from tgwitness_capture.export import export_zip
from tgwitness_capture.format import canonical, digest
from tgwitness_capture.journal import Journal
from tgwitness_capture.official import OfficialOptions
from tgwitness_capture.sealed import create_sealed_app
from tgwitness_capture.verify import verify_zip
from tgwitness.sealed_verify import verify, DEFAULT_POLICY


def example(tmp_path, *, wrong_context=False, segments=(0, 1)):
    journal = Journal(tmp_path / "records")
    approved = json.loads(DEFAULT_POLICY.read_bytes())["releases"][0]
    context = {"collector_sha": "0" * 40 if wrong_context else approved["collector_sha"],
               "repository": "owner/example", "run_id": "123", "run_attempt": "1"}
    options = OfficialOptions(proxy_server="http://gateway:3128", drand=False).receipt()
    source = "https://web.telegram.org/a/#123"
    journal.append("official.sealed_started", {"client": "official_web", "context": context,
                   "session_import_allowed": False, "network": "isolated-required-proxy"})
    journal.append("official.opened", {"login_recorded": False})
    journal.append("official.started", {"settings": options, "settings_sha256": digest(canonical(options)),
                   "recording_starts_after_login": True, "source": source})
    journal.append("video.started", {"capture_id": "test-video"})
    for index in segments:
        artifact = journal.artifact(b"synthetic segment " + str(index).encode(), "screen_video_segment", "video/x-matroska")
        journal.append("video.segment", {"capture_id": "test-video", "segment_index": index}, [artifact])
    journal.append("video.stopped", {"capture_id": "test-video", "clean_exit": True,
                                    "requested_stop": True, "unsealed_segments": []})
    artifact = journal.artifact(b"synthetic visible text", "derived_rendered_text", "text/plain")
    journal.append("capture.saved", {}, [artifact])
    journal.append("official.finished", {"logout_confirmed": True})
    journal.append("official.sealed_finished", {"context": context, "profile_context_closed": True})
    expected = {"format": "tgwitness-official-selection-v1", "options": options, "source": source}
    return journal, expected


def test_independently_expected_settings_and_source_are_both_checked(tmp_path):
    journal, expected = example(tmp_path)
    try:
        archive = tmp_path / "evidence.zip"
        export_zip(journal, archive)
        result = verify_zip(archive, expected_settings=expected)
        assert result["official"]["procedure_status"] == "PASS"
        assert result["official"]["environment_status"] == "INCOMPLETE"
        altered = copy.deepcopy(expected)
        altered["options"]["mode"] = "paced"
        with pytest.raises(ValueError, match="settings differ"):
            verify_zip(archive, expected_settings=altered)
        altered = {**expected, "source": "https://web.telegram.org/a/#999"}
        with pytest.raises(ValueError, match="source differs"):
            verify_zip(archive, expected_settings=altered)
    finally:
        journal.close()


def test_approved_workflow_and_fresh_context_required(tmp_path):
    journal, expected = example(tmp_path)
    try:
        archive = tmp_path / "evidence.zip"
        export_zip(journal, archive)
        settings = tmp_path / "expected.json"
        settings.write_bytes(canonical(expected))
        calls = []

        def checked(command, **kwargs):
            # Synthetic attestation response only. Linux CI exercises real signer rejection separately.
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, '[{"verificationResult":"synthetic"}]', '')

        result = verify(archive, tmp_path / "bundle.jsonl", "owner/example", run=checked, expected_selection=settings)
        assert result["verified"] and result["mode"] == "official_web"
        assert result["journal"]["official"]["environment_status"] == "PASS"
        assert "--deny-self-hosted-runners" in calls[0]
        with pytest.raises(ValueError, match="complete account export"):
            verify(archive, tmp_path / "bundle.jsonl", "owner/example", run=checked, require_complete=True)
        with pytest.raises(ValueError, match="approved fresh"):
            verify(archive, tmp_path / "bundle.jsonl", "wrong/repository", run=checked)
        denied = lambda command, **kwargs: subprocess.CompletedProcess(command, 1, '', '')
        with pytest.raises(ValueError, match="attestation did not match"):
            verify(archive, tmp_path / "bundle.jsonl", "owner/example", run=denied)
    finally:
        journal.close()


@pytest.mark.parametrize("segments", [(1,), (0, 2), (0, 0)])
def test_missing_reordered_or_duplicate_video_segments_rejected(tmp_path, segments):
    journal, _ = example(tmp_path, segments=segments)
    try:
        with pytest.raises(ValueError, match="Video segment order"):
            export_zip(journal, tmp_path / "invalid.zip")
    finally:
        journal.close()


def test_sealed_client_never_reuses_a_profile_or_starts_automatically(tmp_path):
    session = {"client": "official_web", "seconds": 60, "token": "a" * 43,
               "public_origin": "https://fixture.trycloudflare.com", "context": {"collector_sha": "a" * 40},
               "upstream_public": {"server": "http://gateway:3128"}}
    root, output = tmp_path / "fresh", tmp_path / "out"
    with TestClient(create_sealed_app(root, output, session)) as client:
        status = client.get("/api/status", headers={"Authorization": "Bearer " + session["token"]}).json()
        assert not status["settings"]["enabled"] and status["official"]["phase"] == "created"
        assert not list(output.iterdir())
    with pytest.raises(ValueError, match="empty data"):
        create_sealed_app(root, output, session)
    assert not any("profile" in p.name for p in Path(root).iterdir())
