import os
import shutil
import subprocess
import uuid

from .format import utcnow


class VideoCapture:
    def __init__(self, journal, input_args, executable="ffmpeg"):
        self.journal = journal
        self.input_args = input_args
        self.executable = executable
        self.process = None
        self.sealed = set()
        self.started_at = None
        self.last_segment_at = None
        self.log = None
        self.error = None

    @property
    def available(self):
        return bool(self.input_args and shutil.which(self.executable))

    def start(self):
        if self.process is not None:
            raise ValueError("Video is already running")
        if not self.available:
            raise ValueError("Configure video_input_args and install FFmpeg before enabling video")
        self.capture_id = uuid.uuid4().hex
        self.directory = self.journal.pending / ("video-" + self.capture_id)
        self.directory.mkdir(mode=0o700)
        self.log = (self.directory / "ffmpeg.log").open("wb")
        command = [self.executable, "-hide_banner", "-loglevel", "error", "-y", *self.input_args,
                   "-map", "0:v:0", "-an", "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
                   "-pix_fmt", "yuv420p", "-force_key_frames", "expr:gte(t,n_forced*10)",
                   "-f", "segment", "-segment_time", "10", "-reset_timestamps", "1",
                   str(self.directory / "%09d.mkv")]
        self.started_at = utcnow()
        self.error = None
        self.sealed = set()
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                            stderr=self.log, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        except BaseException:
            self.log.close()
            self.log = None
            raise
        try:
            self.journal.append("video.started", {"capture_id": self.capture_id, "codec": "h264",
                                "audio": False, "segment_target_seconds": 10, "crf": 23,
                                "scope": "configured screen input, silent recording", "frames_verified": False})
        except BaseException:
            self.abort()
            raise

    def abort(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.error = "VideoAborted"
                self.process.kill()
                self.process.wait(timeout=3)
            self.process.stdin.close()
            self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def poll(self, final=False):
        if self.process is None:
            return
        result = self.process.poll()
        files = sorted(self.directory.glob("*.mkv"))
        # A segment is sealed only after FFmpeg opens its successor, or exits cleanly.
        complete = files if result == 0 else files[:-1]
        for path in complete:
            if path.name in self.sealed:
                continue
            with path.open("rb") as stream:
                artifact = self.journal.artifact_stream(stream, "screen_video_segment", "video/x-matroska")
            self.journal.append("video.segment", {"capture_id": self.capture_id, "segment_index": int(path.stem),
                                "recording_started_at": self.started_at, "closed_observed_at": utcnow(),
                                "timestamps": "container PTS; closure observed by poll; not independently timed"}, [artifact])
            self.sealed.add(path.name)
            self.last_segment_at = utcnow()
            path.unlink()
        if result is not None:
            self.error = None if result == 0 and final else "VideoExitedUnexpectedly"
            incomplete = [path.name for path in files if path.name not in self.sealed]
            self.journal.append("video.stopped" if result == 0 and final else "video.interrupted",
                                {"capture_id": self.capture_id, "exit_code": result, "unsealed_segments": incomplete,
                                 "requested_stop": final, "clean_exit": result == 0})
            self.process.stdin.close()
            self.log.close()
            self.process = self.log = None

    def stop(self):
        if self.process is None:
            return
        process = self.process
        try:
            process.stdin.write(b"q\n")
            process.stdin.flush()
            process.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        try:
            self.poll(final=True)
        finally:
            self.abort()
