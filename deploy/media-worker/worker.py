"""Runs inside the networkless media worker, never in the panel process."""
import hashlib
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def recognize(engine, language):
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
    import av
    from faster_whisper import WhisperModel
    with av.open("/input/media") as audio:
        if not audio.duration or audio.duration / av.time_base > 1800:
            raise ValueError("Audio duration is unknown or exceeds 30 minutes")
    model = WhisperModel("/model", device="cpu", compute_type="int8", cpu_threads=1, local_files_only=True)
    segments, info = model.transcribe("/input/media", language=language or None, beam_size=1)
    result, length = [], 0
    for segment in segments:
        length += len(segment.text)
        if length > 100000 or len(result) >= 3000 or segment.end > 1800:
            raise ValueError("Transcription exceeds result limit")
        result.append({"start": segment.start, "end": segment.end, "text": segment.text})
    return {"text": "".join(s["text"] for s in result), "engine": "faster-whisper",
            "engine_version": importlib.metadata.version("faster-whisper"), "model_version": sha("/model/model.bin"),
            "language": info.language, "segments": result, "parameters": {"compute_type": "int8", "beam_size": 1}}


if __name__ == "__main__":
    print(json.dumps(recognize(sys.argv[1], sys.argv[2]), ensure_ascii=False))
