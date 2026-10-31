import hashlib
import asyncio
import time

from test_access import HARBOR, OTHER, issue, login, panel as panel
from tgwitness import media_analysis


def attachment(app, chat=HARBOR):
    data = b"synthetic attachment bytes"
    digest = hashlib.sha256(data).hexdigest()
    path = app.state.store.root / "media" / digest
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(data)
    event = app.state.store.append("media.saved", {"media_sha256": digest}, chat_id=chat, message_id=1)
    return {"workspace": "default", "chat_id": chat, "event_seq": event["seq"], "digest": digest,
            "engine": "ocr", "language": "eng"}, data


def test_derived_result_authorization_hash_and_search(panel, monkeypatch):
    app, admin = panel
    job, original = attachment(app)
    monkeypatch.setattr(media_analysis, "available", lambda: True)

    async def worker(path, request, ident):
        assert path.read_bytes() == original
        return {"text": "recognized example.org", "engine": "synthetic", "engine_version": "1",
                "model_version": "test", "language": "eng", "segments": [], "parameters": {}}
    monkeypatch.setattr(media_analysis, "run_container", worker)
    head = app.state.store.stats()["head"]
    started = admin.post("/api/analysis/media", json=job)
    assert started.status_code == 200, started.text
    ident = started.json()["id"]
    for _ in range(30):
        result = admin.get("/api/analysis/media/" + ident).json()
        if result["result"]:
            break
        time.sleep(.01)
    assert result["result"]["machine_recognition"]
    assert result["result"]["media_sha256"] == hashlib.sha256(original).hexdigest()
    assert (app.state.store.root / "media" / job["digest"]).read_bytes() == original
    assert app.state.store.stats()["head"] == head
    assert len(admin.get("/api/analysis/media?query=example.org&kind=ocr").json()["jobs"]) == 1
    assert not admin.get("/api/analysis/media?query=example.org&kind=transcription").json()["jobs"]
    token, _ = issue(admin, workspaces={"default": [OTHER]})
    viewer, _ = login(app, token)
    assert viewer.get("/api/analysis/media/" + ident).status_code == 403
    assert viewer.post("/api/analysis/media", json=job).status_code == 403
    assert not viewer.get("/api/analysis/media").json()["jobs"]


def test_container_is_local_networkless_and_resource_bounded(tmp_path, monkeypatch):
    monkeypatch.setenv("TGWITNESS_MEDIA_IMAGE", "tgwitness-media:test")
    job = media_analysis.MediaJob(chat_id=HARBOR, event_seq=1, digest="a" * 64, engine="ocr")
    command = media_analysis.container_command("tgw-media-test", tmp_path / "input", job)
    assert "--network=none" in command and "--read-only" in command
    assert "--cap-drop=ALL" in command and "--security-opt=no-new-privileges" in command
    assert "--memory=2g" in command and "--cpus=1" in command and "--pull=never" in command
    assert "unix:///var/run/docker.sock" in command
    assert not any("journal" in part or "vault" in part for part in command)


def test_wrong_source_and_unconfigured_worker_are_refused(panel, monkeypatch):
    app, admin = panel
    job, _ = attachment(app)
    monkeypatch.setattr(media_analysis, "available", lambda: False)
    assert admin.post("/api/analysis/media", json=job).status_code == 422
    job["digest"] = "a" * 64
    assert admin.post("/api/analysis/media", json=job).status_code == 403


def test_running_job_can_be_cancelled_and_retried_without_changing_original(panel, monkeypatch):
    app, admin = panel
    job, original = attachment(app)
    monkeypatch.setattr(media_analysis, "available", lambda: True)
    stopped = []

    async def waiting(path, request, ident):
        try:
            await asyncio.Event().wait()
        finally:
            stopped.append(ident)
    monkeypatch.setattr(media_analysis, "run_container", waiting)
    ident = admin.post("/api/analysis/media", json=job).json()["id"]
    for _ in range(30):
        if admin.get("/api/analysis/media/" + ident).json()["job"]["status"] == "running":
            break
        time.sleep(.01)
    assert admin.post("/api/analysis/media/" + ident + "/cancel").status_code == 200
    assert ident in stopped
    retried = admin.post("/api/analysis/media/" + ident + "/retry")
    assert retried.status_code == 200 and retried.json()["retry_of"] == ident
    admin.post("/api/analysis/media/" + retried.json()["id"] + "/cancel")
    assert (app.state.store.root / "media" / job["digest"]).read_bytes() == original
