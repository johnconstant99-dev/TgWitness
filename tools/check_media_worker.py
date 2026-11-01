"""Check offline transcription imports and OCR in the real restricted worker."""
import asyncio
import hashlib
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.media_analysis import MediaJob, docker, run_container


def main():
    if os.name != "posix":
        raise SystemExit("This check requires the Linux container worker.")
    # OCR does not import the separately locked transcription dependencies. Check
    # their public entry points without downloading a model or contacting a service.
    imports = subprocess.run([*docker(), "run", "--rm", "--network=none", "--read-only",
                              "--cap-drop=ALL", "--security-opt=no-new-privileges",
                              "--user=65534:65534", "--memory=2g", "--pids-limit=64",
                              "--tmpfs=/tmp:rw,noexec,nosuid,size=128m",
                              "-e", "HF_HUB_OFFLINE=1", "-e", "TRANSFORMERS_OFFLINE=1",
                              "--entrypoint", "python", os.environ["TGWITNESS_MEDIA_IMAGE"],
                              "-c", "from faster_whisper import WhisperModel; import av; "
                              "from importlib.metadata import version; "
                              "assert callable(WhisperModel); assert callable(av.open); "
                              "print('faster-whisper=' + version('faster-whisper') + ' av=' + av.__version__)"],
                             check=True, capture_output=True, text=True, timeout=90)
    print("Offline transcription imports passed:", imports.stdout.strip(), flush=True)
    harness = Path(__file__).with_name("check_media_decoding.py").resolve()
    name = "tgw-media-decoder-check-" + secrets.token_hex(8)
    try:
        decoding = subprocess.run([*docker(), "run", "--rm", "--pull=never", "--name", name,
                                  "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                                  "--user=65534:65534", "--memory=2g", "--memory-swap=2g", "--cpus=1", "--pids-limit=64",
                                  "--ulimit=nofile=128:128", "--tmpfs=/tmp:rw,noexec,nosuid,size=128m",
                                  "-e", "OMP_NUM_THREADS=1", "-e", "OPENBLAS_NUM_THREADS=1",
                                  "--mount", "type=bind,src=" + str(harness) + ",dst=/checks/check_media_decoding.py,readonly",
                                  "--entrypoint", "python", os.environ["TGWITNESS_MEDIA_IMAGE"],
                                  "/checks/check_media_decoding.py", "--worker", "/worker.py"],
                                 capture_output=True, text=True, timeout=90)
    finally:
        # Killing a timed-out Docker CLI alone does not guarantee container termination.
        subprocess.run([*docker(), "rm", "--force", name], capture_output=True, timeout=10)
    print(decoding.stdout.strip(), flush=True)
    if decoding.returncode:
        raise RuntimeError("Native decoder check failed:\n" + decoding.stderr[-16384:])
    with tempfile.TemporaryDirectory(prefix="media-worker-check-") as scratch:
        path = Path(scratch) / "synthetic.png"
        image = Image.new("RGB", (1000, 140), "white")
        ImageDraw.Draw(image).text((40, 40), "ARCHIVE SOURCE 12345", font=ImageFont.load_default(size=40), fill="black")
        image.save(path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        result = asyncio.run(run_container(path, MediaJob(chat_id=1, event_seq=1, digest=digest,
                                                         engine="ocr", language="eng"), secrets.token_hex(16)))
        assert "ARCHIVE SOURCE 12345" in result["text"], result["text"]
        assert result["engine"] == "tesseract" and result["model_version"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    print("Isolated OCR passed on a generated image; original bytes unchanged.")


if __name__ == "__main__":
    main()
