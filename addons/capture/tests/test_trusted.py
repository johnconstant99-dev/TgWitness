import asyncio
import base64
import importlib.util
import io
import os
import shutil
import socket
import subprocess
import time
import threading
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from tgwitness_capture.continuity import analyze, parse_export, render
from tgwitness_capture.export import export_zip
from tgwitness_capture.format import canonical
from tgwitness_capture.service import Config
from tgwitness_capture.trusted_model import Choice, Scroll
from tgwitness_capture.trusted_runtime import LinuxClient, connector_config
from tgwitness_capture.trusted_service import TrustedRecorder, create_app
from tgwitness_capture.verify import verify_zip

PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aL1sAAAAASUVORK5CYII=')
CONNECTOR = {"label": "Synthetic test connector", "mode": "warp_proxy", "protocol": "socks5", "host": "192.0.2.5", "port": 1080}


def chat(kind="public_supergroup", ids=(1, 4), **changes):
    return {"id": 123, "type": kind, "name": "Synthetic <chat>", "messages": [
        {"id": mid, "date": "2026-01-01", "date_unixtime": str(1700000000 + n * 90000),
         "text": "Visible <script>alert(1)</script>", "from": "Fictional"} for n, mid in enumerate(ids)], **changes}


class Runtime:
    def __init__(self):
        self.inputs, self.scrolls = [], []
        self.stopped = False
        self.bad_route = self.bad_focus = False

    def launch(self, choice, connector, profile):
        profile.mkdir(parents=True)
        (profile / "synthetic-session-secret").write_text("NEVER_EXPORT_PROFILE")
        return self.route(connector)

    def route(self, connector):
        if self.bad_route:
            raise ValueError("Proxy unavailable")
        return {"synthetic": True, "endpoint_reachable": True}

    def arm(self):
        pass

    def frame(self):
        return PNG

    def scroll(self, direction):
        if self.bad_focus:
            raise ValueError("Focus moved")
        self.scrolls.append(direction)

    def setup_input(self, value):
        self.inputs.append(value)

    def stop(self):
        self.stopped = True


class Video:
    available = True
    last_segment_at = None
    error = None
    process = None

    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        self.process = object()

    def stop(self):
        self.process = None

    abort = stop

    def poll(self):
        pass


def config(tmp_path):
    exports = tmp_path / "inbox"
    exports.mkdir(exist_ok=True)
    return Config(kind="trusted", trusted={"connectors": {"chosen": CONNECTOR},
                  "profile_root": str(tmp_path / "profiles"), "export_root": str(exports)},
                  video_input_args=["-re", "-f", "lavfi", "-i", "testsrc=size=1280x720:rate=10"])


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setattr("tgwitness_capture.trusted_service.VideoCapture", Video)
    def offline(*args):
        raise ValueError("Synthetic test, no external beacon")
    monkeypatch.setattr("tgwitness_capture.trusted_anchor.observe", offline)
    runtime = Runtime()
    app = create_app(tmp_path / "recorder", config(tmp_path), runtime)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.recorder.tokens["control"]
        yield client, app.state.recorder, runtime


def begin(client, method="hybrid"):
    result = client.post("/api/begin", json={"case": "Synthetic case", "connector": "chosen", "method": method})
    assert result.status_code == 200, result.text
    return result


def save_export(tmp_path, value=None):
    path = tmp_path / "inbox" / "result.json"
    path.write_bytes(canonical(value or chat()))
    os.utime(path, (time.time() - 10, time.time() - 10))
    return path


@pytest.mark.parametrize("kind,expected", [("public_supergroup", True), ("private_channel", True),
                                           ("personal_chat", False), ("private_group", False), ("saved_messages", False)])
def test_message_id_scope_and_bounded_gaps(kind, expected):
    report = analyze(chat(kind, (1, 2**40)))
    intervals = [item for item in report["findings"] if item["kind"] == "id_interval_candidate"]
    assert bool(intervals) == expected
    if intervals:
        assert intervals[0]["cause"] == "unknown"
        assert len(intervals) == 1


def test_reply_outside_export_and_rendered_text_are_not_deletion_or_markup():
    value = chat()
    value["messages"][0]["reply_to_message_id"] = 100
    report = analyze(value)
    assert {item["kind"] for item in report["findings"]} == {"unresolved_reply", "id_interval_candidate", "time_interval"}
    output = render(value, report)
    assert b"<script>" not in output and b"&lt;script&gt;" in output
    assert b'role="note"' in output


@pytest.mark.parametrize("raw", [b'{}', b'{"id":1,"id":2}', canonical(chat(ids=(1, 1))),
                                canonical(chat(ids=(True,))), b'{"x":NaN}', canonical(chat(type="unknown"))])
def test_malformed_exports_rejected(raw):
    with pytest.raises(ValueError):
        parse_export(raw)


def test_visual_comparison_does_not_infer_absence_from_unseen_viewports():
    value = chat()
    assert analyze(value)["visual_comparison"] == "unavailable_no_annotated_frames"
    note = {"chat_id": 123, "message_id": 1, "text": "different", "frame_sha256": "a" * 64, "observed_at": "now"}
    report = analyze(value, [note])
    assert sum(item["kind"] == "source_mismatch" for item in report["findings"]) == 1
    assert all(item["kind"] != "deleted" for item in report["findings"])


@pytest.mark.parametrize("changes", [{"client": "web", "method": "hybrid"}, {"pause_min": 10., "pause_max": 2.},
                                    {"pause_min": 0.}, {"api_id": 123}, {"method": "api"}])
def test_invalid_choices(changes):
    with pytest.raises(ValidationError):
        Choice(case="case", connector="chosen", **changes)


@pytest.mark.parametrize("changes", [{"host": "proxy.example"}, {"host": "127.0.0.1"}, {"port": True},
                                    {"port": 0}, {"password": "secret"}, {"protocol": "direct"}])
def test_connector_rejects_unsafe_or_ambiguous_configuration(changes):
    with pytest.raises(ValueError):
        connector_config({"chosen": {**CONNECTOR, **changes}})


def test_auth_origin_stream_limit_and_witness_read_only(service):
    client, recorder, _ = service
    token = client.headers.pop("Authorization")
    assert client.get("/api/status").status_code == 401
    client.headers["Authorization"] = "Bearer " + recorder.tokens["witness"]
    assert client.get("/api/checkpoint?challenge=1234").status_code == 200
    assert client.get("/api/frame").status_code == 401
    assert client.post("/api/stop").status_code == 401
    client.headers["Authorization"] = token
    assert client.get("/api/status", headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/begin", content=b"x" * 65537).status_code == 413


def test_setup_secrets_not_recorded_and_capture_input_guard(service):
    client, recorder, runtime = service
    begin(client)
    secret = "synthetic-login-secret"
    assert client.post("/api/input", json={"action": "text", "text": secret}).status_code == 200
    assert client.get("/api/frame").status_code == 200
    assert not recorder.frames
    assert client.post("/api/start").status_code == 200
    for value in ({"action": "text", "text": "send"}, {"action": "key", "key": "Return"}, {"action": "click", "x": 1, "y": 1}):
        assert client.post("/api/input", json=value).status_code == 409
    assert len(runtime.inputs) == 1
    assert secret.encode() not in canonical(recorder.journal.events())
    assert client.post("/api/scroll", json={"direction": "up"}).status_code == 200
    assert client.post("/api/scroll", json={"direction": "up"}).status_code == 409
    assert runtime.scrolls == ["up"]


def test_unmapped_client_window_can_retry_setup_but_stops_collection(service):
    client, recorder, runtime = service
    linux = LinuxClient({})
    linux.process = SimpleNamespace(poll=lambda: None, pid=os.getpid())
    def unmapped(args, **kwargs):
        raise subprocess.CalledProcessError(1, args)
    linux.command = unmapped
    runtime.arm = linux.arm
    begin(client)
    result = client.post("/api/start")
    assert result.status_code == 409 and "not ready" in result.json()["detail"]
    assert recorder.phase == "setup" and not runtime.stopped and recorder.video.process is None
    runtime.arm = lambda: None
    assert client.post("/api/start").status_code == 200
    runtime.scroll = linux.scroll
    assert client.post("/api/scroll", json={"direction": "up"}).status_code == 409
    assert recorder.phase == "failed" and runtime.stopped


@pytest.mark.parametrize("failure", ["bad_route", "bad_focus"])
def test_route_or_focus_loss_stops_client(service, failure):
    client, recorder, runtime = service
    begin(client)
    assert client.post("/api/start").status_code == 200
    setattr(runtime, failure, True)
    assert client.post("/api/scroll", json={"direction": "down"}).status_code == 409
    assert runtime.stopped and recorder.phase == "failed" and recorder.video.process is None


def test_original_export_report_annotation_cleanup_and_offline_verification(service, tmp_path):
    client, recorder, runtime = service
    begin(client)
    client.post("/api/start")
    frame = client.get("/api/frame")
    note = {"chat_id": 123, "message_id": 1, "text": "Operator version", "frame_sha256": frame.headers["X-Frame-SHA256"]}
    assert client.post("/api/annotate", json={**note, "frame_sha256": "0" * 64}).status_code == 409
    assert client.post("/api/annotate", json=note).status_code == 200
    original = save_export(tmp_path).read_bytes()
    imported = client.post("/api/import", json={"name": "result.json"})
    assert imported.status_code == 200, imported.text
    assert imported.json()["visual_comparison"] == "operator_annotated"
    assert client.get("/api/transcript").status_code == 200
    assert client.post("/api/export").status_code == 409
    assert client.post("/api/finish").status_code == 200
    assert runtime.stopped and not recorder.profile.exists()
    checkpoint = client.get("/api/checkpoint").json()
    archive = client.post("/api/export")
    assert archive.status_code == 200
    result = verify_zip(io.BytesIO(archive.content), recorder.journal.fingerprint, checkpoint, require_final_anchor=True)
    assert result["valid"] and result["trusted_reports_checked"] == 1
    with zipfile.ZipFile(io.BytesIO(archive.content)) as saved:
        assert all("profile" not in name and "token" not in name for name in saved.namelist())
        assert original in [saved.read(name) for name in saved.namelist() if name.startswith("objects/")]
        assert b"NEVER_EXPORT_PROFILE" not in b"".join(saved.read(name) for name in saved.namelist())
    # A retained final boundary rejects deletion of the final event, even if its signer rebuilds the ZIP.
    events = recorder.journal.events()
    saved_head = events[-1]["hash"]
    recorder.journal.db.execute("DELETE FROM events WHERE seq >= ?", (checkpoint["body"]["seq"],))
    recorder.journal.db.commit()
    recorder.journal.seq = checkpoint["body"]["seq"] - 1
    recorder.journal.head = recorder.journal.events()[-1]["hash"]
    shorter = tmp_path / "shorter.zip"
    export_zip(recorder.journal, shorter)
    with pytest.raises(ValueError, match="shorter|disagrees"):
        verify_zip(shorter, recorder.journal.fingerprint, checkpoint)
    assert saved_head


def test_import_cannot_read_outside_inbox_or_switch_chat(service, tmp_path):
    client, _, _ = service
    begin(client)
    client.post("/api/start")
    outside = tmp_path / "result.json"
    outside.write_bytes(canonical(chat()))
    assert client.post("/api/import", json={"name": "../result.json"}).status_code == 409
    save_export(tmp_path)
    assert client.post("/api/import", json={"name": "result.json"}).status_code == 200
    save_export(tmp_path, chat(id=999))
    assert client.post("/api/import", json={"name": "result.json"}).status_code == 409


def test_signed_but_wrong_analysis_is_rejected(service, tmp_path):
    client, recorder, _ = service
    begin(client)
    client.post("/api/start")
    save_export(tmp_path)
    client.post("/api/import", json={"name": "result.json"})
    client.post("/api/pause")
    wrong = {**recorder.report, "messages": 999}
    artifacts = [recorder.journal.artifact(canonical(wrong), "continuity_report", "application/json"),
                 recorder.journal.artifact(render(recorder.chat, wrong), "annotated_chat", "text/html")]
    recorder.event("continuity_analyzed", {}, artifacts)
    with pytest.raises(ValueError, match="differs"):
        export_zip(recorder.journal, tmp_path / "invalid.zip")


def test_network_guard_drops_ipv6_dns_and_direct_egress():
    path = Path(__file__).parents[1] / "deploy" / "trusted-entrypoint.py"
    spec = importlib.util.spec_from_file_location("trusted_entrypoint", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    policy = module.firewall("192.0.2.5", 1080)
    assert "table inet" in policy and "policy drop" in policy
    assert "ip daddr 192.0.2.5 tcp dport 1080 accept" in policy
    assert "udp dport 53" not in policy and "ip6 daddr" not in policy
    with pytest.raises(ValueError):
        module.firewall("192.0.2.5; accept", 1080)


def test_public_source_includes_complete_trusted_runtime():
    from tools import build_source
    required = {"addons/capture/" + name for name in (
        "compose.trusted.yaml", "config/trusted.example.json", "deploy/Dockerfile.trusted",
        "deploy/trusted-entrypoint.py", "deploy/trusted-display.py", "tests/test_trusted.py", "tests/test_trusted_anchors.py")}
    public = {path.relative_to(build_source.ROOT.resolve()).as_posix() for path in build_source.public_sources(build_source.ROOT)}
    assert required <= public


def test_restart_archives_case_and_cannot_mix_accounts(tmp_path, monkeypatch):
    monkeypatch.setattr("tgwitness_capture.trusted_service.VideoCapture", Video)
    cfg = config(tmp_path)
    root = tmp_path / "same-case"
    with TestClient(create_app(root, cfg, Runtime())) as client:
        client.headers["Authorization"] = "Bearer " + (root / "control-token.txt").read_text()
        begin(client)
    with TestClient(create_app(root, cfg, Runtime())) as client:
        client.headers["Authorization"] = "Bearer " + (root / "control-token.txt").read_text()
        assert client.get("/api/status").json()["phase"] == "archived"
        assert client.post("/api/begin", json={"case": "another", "connector": "chosen"}).status_code == 409
        assert client.post("/api/export").status_code == 200


def test_kill_switch_stops_process_before_waiting_for_frame_lock(service):
    client, recorder, runtime = service
    begin(client)
    entered, released = threading.Event(), threading.Event()
    def blocked_frame():
        entered.set()
        assert released.wait(5), "Kill switch waited for the frame lock"
        return PNG
    def stop():
        runtime.stopped = True
        released.set()
    runtime.frame, runtime.stop = blocked_frame, stop
    worker = threading.Thread(target=lambda: client.get("/api/frame"))
    worker.start()
    assert entered.wait(3)
    try:
        assert client.post("/api/stop").status_code == 200
        assert runtime.stopped and recorder.phase == "failed"
    finally:
        released.set()
        worker.join(5)


def test_real_ffmpeg_video_segments_and_verified_trusted_bundle(tmp_path):
    cfg = config(tmp_path)
    cfg.ffmpeg_executable = shutil.which("ffmpeg")
    if not cfg.ffmpeg_executable:
        imageio_ffmpeg = pytest.importorskip("imageio_ffmpeg")
        cfg.ffmpeg_executable = imageio_ffmpeg.get_ffmpeg_exe()
    runtime = Runtime()
    recorder = TrustedRecorder(tmp_path / "real-video", cfg, runtime)

    async def exercise():
        await recorder.begin(Choice(case="Real encoder, synthetic display", connector="chosen", method="visual"))
        await recorder.start()
        await asyncio.sleep(2)
        await recorder.scroll(Scroll(direction="up"))
        await recorder.pause()
        await recorder.finish()
        path = tmp_path / "video.zip"
        boundary = recorder.journal.checkpoint()
        export_zip(recorder.journal, path)
        verified = verify_zip(path, recorder.journal.fingerprint, boundary, require_final_anchor=True)
        assert verified["valid"]
        events = recorder.journal.events()
        segments = [event for event in events if event["kind"] == "video.segment"]
        assert segments and segments[0]["artifacts"][0]["size"] > 100
        await recorder.close()

    asyncio.run(exercise())


def test_trusted_panel_real_browser_flow_and_mobile_layout(tmp_path, monkeypatch, request):
    if not request.config.getoption("--capture-browser"):
        pytest.skip("Use --capture-browser for the real Chromium acceptance test")
    import uvicorn
    from playwright.sync_api import expect, sync_playwright
    monkeypatch.setattr("tgwitness_capture.trusted_service.VideoCapture", Video)
    def offline(*args):
        raise ValueError("Synthetic test")
    monkeypatch.setattr("tgwitness_capture.trusted_anchor.observe", offline)
    cfg = config(tmp_path)
    save_export(tmp_path)
    root = tmp_path / "browser-case"
    app = create_app(root, cfg, Runtime())
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
    worker = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(.05)
        assert server.started
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
            page.goto("http://127.0.0.1:" + str(sock.getsockname()[1]))
            page.locator("#token").fill((root / "control-token.txt").read_text())
            page.locator("#login-form button").click()
            page.locator("#workspace").wait_for(state="visible")
            page.locator("#case").fill("Synthetic browser test")
            page.locator("#client").select_option("web")
            expect(page.locator('#method option[value="export"]')).to_have_js_property("disabled", True)
            expect(page.locator("#method")).to_have_value("visual")
            page.locator("#client").select_option("desktop")
            page.locator("#method").select_option("hybrid")
            page.locator("#begin").click()
            expect(page.locator("#phase")).to_have_text("Setup")
            page.locator("#start").click()
            expect(page.locator("#phase")).to_have_text("Collecting")
            expect(page.locator("#manual")).to_be_hidden()
            page.locator("#find-exports").click()
            expect(page.locator("#exports")).to_have_value("result.json")
            page.locator("#import").click()
            frame = page.frame_locator("#transcript")
            expect(frame.get_by_role("note").first).to_contain_text("absent from this export")
            assert frame.locator("body").evaluate("el => getComputedStyle(el).backgroundColor") == "rgb(16, 25, 35)"
            page.set_viewport_size({"width": 390, "height": 844})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.locator("#pause").click()
            expect(page.locator("#phase")).to_have_text("Paused")
            page.locator("#finish").click()
            expect(page.locator("#phase")).to_have_text("Completed")
            with page.expect_download() as downloaded:
                page.locator("#download").click()
            destination = tmp_path / "ui-export.zip"
            downloaded.value.save_as(destination)
            assert verify_zip(destination, app.state.recorder.journal.fingerprint)["trusted_reports_checked"] == 1
            assert not errors
            browser.close()
    finally:
        server.should_exit = True
        worker.join(30)
        sock.close()
        assert not worker.is_alive()
