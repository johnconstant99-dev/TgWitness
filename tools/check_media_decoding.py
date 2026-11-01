"""Real native-decoder regressions; no model, network, Telegram account or prerecorded media."""
import argparse
import errno
import hashlib
import importlib.util
from pathlib import Path
import random
import tempfile

import av
import numpy as np


def load_worker(path):
    spec = importlib.util.spec_from_file_location("media_worker_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def encoded(path, fmt, codec, seconds=1, channels=1, video=False):
    rate = 48000
    with av.open(str(path), "w", format=fmt) as output:
        stream = output.add_stream(codec, rate=rate)
        stream.layout = "mono" if channels == 1 else "stereo"
        if video:
            picture = output.add_stream("mpeg4", rate=5)
            picture.width = picture.height = 16
            picture.pix_fmt = "yuv420p"
            for i in range(5):
                frame = av.VideoFrame.from_ndarray(np.zeros((16, 16, 3), dtype=np.uint8), format="rgb24")
                frame.pts = i
                for packet in picture.encode(frame):
                    output.mux(packet)
            for packet in picture.encode(None):
                output.mux(packet)
        for offset in range(0, rate * seconds, 1024):
            count = min(1024, rate * seconds - offset)
            tone = (.1 * np.sin(2 * np.pi * 440 * (np.arange(count) + offset) / rate)).astype(np.float32)
            frame = av.AudioFrame.from_ndarray(np.stack([tone] * channels), format="fltp", layout=stream.layout.name)
            frame.sample_rate, frame.pts = rate, offset
            for packet in stream.encode(frame):
                output.mux(packet)
        for packet in stream.encode(None):
            output.mux(packet)


def refused(worker, path, seconds=10):
    try:
        worker.decode_audio(path, max_seconds=seconds)
    except (ValueError, av.error.FFmpegError):
        return
    except OSError as exc:
        # PyAV's Python IO callback propagates EINVAL for an invalid seek in malformed media.
        # Do not classify unrelated file/permission/resource failures as successful rejection.
        if exc.errno == errno.EINVAL:
            return
        raise
    raise AssertionError("Unsafe input was decoded: " + path.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, default=Path(__file__).resolve().parents[1] / "deploy/media-worker/worker.py")
    args = parser.parse_args()
    worker = load_worker(args.worker)
    with tempfile.TemporaryDirectory(prefix="media-decoder-check-") as temporary:
        root = Path(temporary)
        formats = [("voice.ogg", "ogg", "libopus", 1, False),
                   ("audio.mp3", "mp3", "libmp3lame", 2, False),
                   ("audio.m4a", "mp4", "aac", 2, False),
                   ("round.mp4", "mp4", "aac", 1, True),
                   ("audio.wav", "wav", "pcm_s16le", 2, False),
                   ("audio.flac", "flac", "flac", 1, False)]
        for name, fmt, codec, channels, video in formats:
            path = root / name
            encoded(path, fmt, codec, channels=channels, video=video)
            before = hashlib.sha256(path.read_bytes()).digest()
            samples = worker.decode_audio(path, max_seconds=3)
            assert samples.dtype == np.float32 and samples.ndim == 1 and np.isfinite(samples).all()
            assert abs(len(samples) - 16000) < 2048 and np.max(np.abs(samples)) > .01
            assert hashlib.sha256(path.read_bytes()).digest() == before
            print("Decoded generated " + name, flush=True)

        # Native decoder negative control: metadata claims 1s, but the frames contain 4s.
        forged = root / "forged-duration.flac"
        encoded(forged, "flac", "flac", seconds=4)
        data = bytearray(forged.read_bytes())
        assert data[:4] == b"fLaC" and data[4] & 0x7f == 0
        packed = int.from_bytes(data[18:26], "big")
        data[18:26] = ((packed & ~((1 << 36) - 1)) | 48000).to_bytes(8, "big")
        forged.write_bytes(data)
        with av.open(str(forged)) as old:
            assert 0 < old.duration / av.time_base <= 2  # Previous worker accepted this precheck.
            decoded = sum(frame.samples for frame in old.decode(audio=0))
            assert decoded == 4 * 48000
        refused(worker, forged, seconds=2)
        print("Rejected forged FLAC duration after positive old-decoder control", flush=True)

        # A concat manifest successfully opens a second local file under the old automatic decoder.
        playlist = root / "references.txt"
        playlist.write_text("ffconcat version 1.0\nfile 'audio.wav'\n", encoding="utf-8")
        with av.open(str(playlist)) as old:
            assert sum(frame.samples for frame in old.decode(audio=0)) > 0
        refused(worker, playlist)
        print("Rejected concat secondary file after positive old-decoder control", flush=True)
        for name, content in (("network.m3u8", b"#EXTM3U\n#EXT-X-TARGETDURATION:1\n#EXTINF:1,\nhttps://invalid.invalid/audio.ts\n#EXT-X-ENDLIST\n"),
                              ("network.mpd", b'<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><BaseURL>https://invalid.invalid/</BaseURL></MPD>')):
            path = root / name
            path.write_bytes(content)
            refused(worker, path)
        # Test the secondary-open barrier separately even if a supported container references another file.
        try:
            worker.deny_secondary_open(str(root / "audio.wav"), 1, {})
        except ValueError:
            pass
        else:
            raise AssertionError("Secondary file reference allowed")

        # Real parser corpus: reproducible structural truncations and header mutations, not token mocks.
        randomizer = random.Random(20261101)
        rejected, bounded = 0, 0
        original = (root / "audio.flac").read_bytes()
        for i in range(48):
            data = bytearray(original)
            if i < 24:
                data = data[:i * len(data) // 24]
            else:
                for _ in range(4):
                    position = randomizer.randrange(min(len(data), 160))
                    data[position] ^= 1 << randomizer.randrange(8)
            path = root / "mutated.flac"
            path.write_bytes(data)
            try:
                samples = worker.decode_audio(path, max_seconds=3)
            except (ValueError, av.error.FFmpegError):
                rejected += 1
            except OSError as exc:
                if exc.errno != errno.EINVAL:
                    raise
                rejected += 1
            else:
                assert len(samples) <= 3 * 16000 and np.isfinite(samples).all()
                bounded += 1  # Some metadata changes remain valid encodings; do not call them corrupt.
        assert rejected >= 24
    print(f"Native media decoding passed:6 formats, forged duration and external-reference controls; corpus48 ({rejected} rejected, {bounded} bounded valid decodes).")


if __name__ == "__main__":
    main()
