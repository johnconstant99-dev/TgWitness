import os
import shutil
import time

import pytest

from tgwitness_capture.journal import Journal
from tgwitness_capture.video import VideoCapture


def test_video_seals_closed_segments_and_clean_final_segment(tmp_path, request):
    executable = request.config.getoption("--capture-ffmpeg") or os.environ.get("CAPTURE_TEST_FFMPEG") or shutil.which("ffmpeg")
    if not executable:
        pytest.skip("Set CAPTURE_TEST_FFMPEG or install FFmpeg for the real segment test")
    journal = Journal(tmp_path / "video")
    video = VideoCapture(journal, ["-re", "-f", "lavfi", "-i", "testsrc2=size=320x240:rate=10"], executable)
    try:
        video.start()
        deadline = time.monotonic() + 18
        while time.monotonic() < deadline:
            video.poll()
            if any(event["kind"] == "video.segment" for event in journal.events()):
                break
            time.sleep(0.25)
        assert video.process is not None
        during = [event for event in journal.events() if event["kind"] == "video.segment"]
        assert during, "No closed segment was sealed while recording continued"
        assert list(video.directory.glob("*.mkv")), "The open segment should remain outside the signed objects"
        video.stop()
        events = journal.events()
        assert events[-1]["kind"] == "video.stopped"
        assert events[-1]["payload"]["clean_exit"]
        segments = [event for event in events if event["kind"] == "video.segment"]
        assert len(segments) >= 2
        assert [event["payload"]["segment_index"] for event in segments] == list(range(len(segments)))
        assert all(event["artifacts"][0]["size"] > 0 for event in segments)
    finally:
        video.stop()
        journal.close()


def test_video_input_failure_is_reported_and_never_sealed(tmp_path, request):
    executable = request.config.getoption("--capture-ffmpeg") or os.environ.get("CAPTURE_TEST_FFMPEG") or shutil.which("ffmpeg")
    if not executable:
        pytest.skip("Set CAPTURE_TEST_FFMPEG or install FFmpeg for the real failure test")
    journal = Journal(tmp_path / "failed-video")
    video = VideoCapture(journal, ["-f", "lavfi", "-i", "missing_capture_fixture_filter"], executable)
    try:
        video.start()
        deadline = time.monotonic() + 5
        while video.process is not None and time.monotonic() < deadline:
            video.poll()
            time.sleep(0.05)
        assert video.process is None and video.error == "VideoExitedUnexpectedly"
        assert journal.events()[-1]["kind"] == "video.interrupted"
        assert not any(event["kind"] == "video.segment" for event in journal.events())
    finally:
        video.stop()
        journal.close()
