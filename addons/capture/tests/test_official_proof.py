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


def example(tmp_path, *, wrong_context=False, segments=(0, 1), direct=False, network=None):
    journal = Journal(tmp_path / "records")
    approved = json.loads(DEFAULT_POLICY.read_bytes())["releases"][0]
    context = {"collector_sha": "0" * 40 if wrong_context else approved["collector_sha"],
               "repository": "owner/example", "run_id": "123", "run_attempt": "1"}
    route = {"egress": "direct"} if direct else {"proxy_server": "http://gateway:3128"}
    options = OfficialOptions(**route, drand=False).receipt()
    source = "https://web.telegram.org/a/#123"
    journal.append("official.sealed_started", {"client": "official_web", "context": context,
                   "session_import_allowed": False,
                   "network": network or ("explicit-direct" if direct else "isolated-required-proxy")})
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


@pytest.mark.parametrize("direct", [False, True])
def test_independently_expected_settings_and_source_are_both_checked(tmp_path, direct):
    journal, expected = example(tmp_path, direct=direct)
    try:
        archive = tmp_path / "evidence.zip"
        export_zip(journal, archive)
        result = verify_zip(archive, expected_settings=expected)
        assert result["official"]["procedure_status"] == "PASS"
        assert result["official"]["environment_status"] == "INCOMPLETE"
        assert result["official"]["egress"] == ("direct" if direct else "http")
        altered = copy.deepcopy(expected)
        altered["options"]["mode"] = "paced"
        with pytest.raises(ValueError, match="settings differ"):
            verify_zip(archive, expected_settings=altered)
        altered = {**expected, "source": "https://web.telegram.org/a/#999"}
        with pytest.raises(ValueError, match="source differs"):
            verify_zip(archive, expected_settings=altered)
    finally:
        journal.close()


@pytest.mark.parametrize("direct", [False, True])
def test_approved_workflow_and_fresh_context_required(tmp_path, direct):
    journal, expected = example(tmp_path, direct=direct)
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


@pytest.mark.parametrize("direct", [False, True])
def test_sealed_client_never_reuses_a_profile_or_starts_automatically(tmp_path, direct):
    session = {"client": "official_web", "seconds": 60, "token": "a" * 43,
               "public_origin": "https://fixture.trycloudflare.com", "context": {"collector_sha": "a" * 40},
               "upstream_public": {"server": "http://gateway:3128"}}
    if direct:
        session.update(egress="direct", upstream_public={"server": "", "has_credentials": False})
    root, output = tmp_path / "fresh", tmp_path / "out"
    with TestClient(create_sealed_app(root, output, session)) as client:
        status = client.get("/api/status", headers={"Authorization": "Bearer " + session["token"]}).json()
        assert not status["settings"]["enabled"] and status["official"]["phase"] == "created"
        assert status["official"]["options"]["egress"] == ("direct" if direct else "http")
        assert not list(output.iterdir())
    with pytest.raises(ValueError, match="empty data"):
        create_sealed_app(root, output, session)
    assert not any("profile" in p.name for p in Path(root).iterdir())


@pytest.mark.parametrize("direct", [False, True])
def test_sealed_network_cannot_misrepresent_direct_as_proxy(tmp_path, direct):
    journal, _ = example(tmp_path, direct=direct,
                         network="isolated-required-proxy" if direct else "explicit-direct")
    try:
        archive = tmp_path / "evidence.zip"
        export_zip(journal, archive)
        checked = lambda command, **kwargs: subprocess.CompletedProcess(command, 0, '[{"verificationResult":"synthetic"}]', '')
        with pytest.raises(ValueError, match="approved fresh"):
            verify(archive, tmp_path / "bundle.jsonl", "owner/example", run=checked)
    finally:
        journal.close()


def test_direct_opened_without_recording_remains_explicit_and_incomplete():
    from tgwitness_capture.official_proof import official_report
    result = official_report([{"kind": "official.opened", "payload": {
        "settings": OfficialOptions(egress="direct").receipt()}}])
    assert result["egress"] == "direct" and result["procedure_status"] == "INCOMPLETE"


@pytest.mark.parametrize("direct", [False, True])
def test_hosted_network_is_explicit_and_proxy_secrets_stay_out_of_direct(tmp_path, monkeypatch, direct):
    from scripts import sealed_runner as runner
    for part in ("config", "data", "out", "public"):
        (tmp_path / part).mkdir()
    monkeypatch.setenv("OFFICIAL_EGRESS", "direct" if direct else "proxy")
    monkeypatch.setenv("OFFICIAL_PROXY_SERVER", "" if direct else "socks5://gateway:1080")
    monkeypatch.setenv("OFFICIAL_PROXY_USERNAME", "PRIVATE_USER")
    monkeypatch.setenv("OFFICIAL_PROXY_PASSWORD", "PRIVATE_PASSWORD")
    monkeypatch.delenv("OFFICIAL_EXPECTED_IP", raising=False)
    monkeypatch.setattr(runner.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(runner.os, "getgid", lambda: 1000, raising=False)
    commands = []
    monkeypatch.setattr(runner, "command", lambda args, **kwargs: commands.append(args) or "")
    monkeypatch.setattr(runner.subprocess, "run", lambda args, **kwargs:
                        subprocess.CompletedProcess(args, 0, 'https://fixture.trycloudflare.com', ''))
    monkeypatch.setattr(runner, "helper", lambda *args, **kwargs:
                        (tmp_path / "out/connection.tgwsealed").write_bytes(b"encrypted fixture"))
    runner.start_official(tmp_path, "fixture", {"seconds": 60})
    launch = next(cmd for cmd in commands if cmd[:3] == ["docker", "run", "--detach"]
                  and "fixture" == cmd[cmd.index("--name") + 1])
    assert launch[launch.index("--network") + 1] == ("fixture" if direct else "fixture-private")
    gateways = [cmd for cmd in commands if "fixture-gateway" in cmd]
    assert bool(gateways) is not direct
    assert (tmp_path / "config/gateway.json").exists() is not direct
    saved = (tmp_path / "config/session.json").read_text()
    assert "PRIVATE_USER" not in saved and "PRIVATE_PASSWORD" not in saved
    assert json.loads(saved)["egress"] == ("direct" if direct else "proxy")
