"""Runs inside the networkless media worker, never in the panel process."""
import hashlib
import importlib.metadata
import io
import itertools
import json
import math
from pathlib import Path
import re
import subprocess
import sys

MAX_AUDIO_SECONDS = 1800
SAMPLE_RATE = 16000
# Single-file formats only: no HLS, DASH, concat, image sequences or device demuxers.
AUDIO_FORMATS = "aac,aiff,amr,asf,avi,flac,flv,matroska,webm,mov,mp3,mpeg,mpegts,ogg,wav,w64"


def deny_secondary_open(*args):
    raise ValueError("Media references to other files or URLs are not allowed")


def decode_audio(path, max_seconds=MAX_AUDIO_SECONDS):
    """Decode once, bounding actual samples before copying or passing them to Whisper."""
    import av
    import numpy as np
    from fractions import Fraction

    if not 0 < max_seconds <= MAX_AUDIO_SECONDS:
        raise ValueError("Invalid audio duration limit")
    limit = int(max_seconds * SAMPLE_RATE)
    resampler = av.AudioResampler(format="s16", layout="mono", rate=SAMPLE_RATE)
    output, samples, elapsed = io.BytesIO(), 0, Fraction(0)
    with Path(path).open("rb") as source, av.open(source, mode="r", io_open=deny_secondary_open,
            options={"format_whitelist": AUDIO_FORMATS, "protocol_whitelist": "", "max_streams": "8"}) as audio:
        if not audio.duration or not 0 < audio.duration / av.time_base <= max_seconds:
            raise ValueError("Audio duration is unknown or exceeds its limit")
        if not audio.streams.audio:
            raise ValueError("No audio stream")
        stream = audio.streams.audio[0]
        stream.codec_context.thread_count = 1
        stream.codec_context.options = {"err_detect": "explode"}

        def frames():
            for packet in audio.demux(stream):
                if packet.is_corrupt:
                    raise ValueError("Corrupt audio packet")
                yield from packet.decode()

        for frame in itertools.chain(frames(), [None]):
            if frame is not None:
                if frame.is_corrupt:
                    raise ValueError("Corrupt audio frame")
                rate, channels = frame.sample_rate, len(frame.layout.channels)
                if not 0 < rate <= 192000 or not 0 < channels <= 8 or not 0 < frame.samples <= rate * 10:
                    raise ValueError("Audio frame exceeds decoding limits")
                elapsed += Fraction(frame.samples, rate)
                if elapsed > max_seconds:
                    raise ValueError("Decoded audio exceeds duration limit")
                # Preserve sample order without allocating silence for attacker-controlled timestamps.
                frame.pts = None
            for decoded in resampler.resample(frame):
                if decoded.samples > limit - samples:
                    raise ValueError("Decoded audio exceeds sample limit")
                samples += decoded.samples
                output.write(decoded.to_ndarray().tobytes())
    if not samples:
        raise ValueError("No decoded audio samples")
    # At most 57.6 MB of s16 PCM and 115.2 MB of float32 samples at the production limit.
    result = np.frombuffer(output.getbuffer(), dtype=np.int16).astype(np.float32)
    result /= 32768.0
    return result


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def recognize(engine, language):
    if engine not in ("ocr", "transcription") or not re.fullmatch(r"[a-z]{0,3}", language):
        raise ValueError("Invalid recognition request")
    if engine == "ocr":
        from PIL import Image
        Image.MAX_IMAGE_PIXELS = 20_000_000
        with Image.open("/input/media") as image:
            if image.width * image.height > Image.MAX_IMAGE_PIXELS:
                raise ValueError("Image exceeds pixel limit")
            image.convert("RGB").save("/tmp/image.png")
        language = language or "eng"
        output = subprocess.run(["tesseract", "/tmp/image.png", "stdout", "-l", language, "--psm", "3"],
                                check=True, capture_output=True, timeout=240)
        version = subprocess.check_output(["tesseract", "--version"], timeout=5).decode().splitlines()[0]
        trained = next(Path("/usr/share/tesseract-ocr").rglob(language + ".traineddata"))
        return {"text": output.stdout.decode()[:100000], "engine": "tesseract", "engine_version": version,
                "model_version": sha(trained), "language": language, "segments": [], "parameters": {"psm": 3}}
    samples = decode_audio("/input/media")
    from faster_whisper import WhisperModel
    model = WhisperModel("/model", device="cpu", compute_type="int8", cpu_threads=1, local_files_only=True)
    segments, info = model.transcribe(samples, language=language or None, beam_size=1)
    result, length = [], 0
    for segment in segments:
        length += len(segment.text)
        if (length > 100000 or len(result) >= 3000 or not math.isfinite(segment.start)
                or not math.isfinite(segment.end) or not 0 <= segment.start <= segment.end <= MAX_AUDIO_SECONDS):
            raise ValueError("Transcription exceeds result limit")
        result.append({"start": segment.start, "end": segment.end, "text": segment.text})
    return {"text": "".join(s["text"] for s in result), "engine": "faster-whisper",
            "engine_version": importlib.metadata.version("faster-whisper"), "model_version": sha("/model/model.bin"),
            "language": info.language, "segments": result,
            "parameters": {"compute_type": "int8", "beam_size": 1, "sample_rate": SAMPLE_RATE,
                           "decoded_samples": len(samples)}}


if __name__ == "__main__":
    print(json.dumps(recognize(sys.argv[1], sys.argv[2]), ensure_ascii=False))
