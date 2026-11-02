import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import wave

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.media_analysis import MediaJob, docker, run_container
from prepare_media_test_model import FILES, REVISION, validate


def main():
    if os.name != "posix":
        raise SystemExit("This check requires the Linux container worker.")
    model = os.environ.get("TGWITNESS_WHISPER_MODEL_DIR")
    if not model:
        raise SystemExit("Prepare the pinned test model and set TGWITNESS_WHISPER_MODEL_DIR.")
    validate(Path(model))
    speech = shutil.which("espeak-ng") or shutil.which("espeak")
    if not speech:
        raise SystemExit("Install espeak-ng on the test host to generate the synthetic ASR input.")
    imports = subprocess.run([*docker(), "run", "--rm", "--network=none", "--read-only",
                              "--cap-drop=ALL", "--security-opt=no-new-privileges",
                              "--memory=2g", "--pids-limit=64",
                              "--tmpfs=/tmp:rw,noexec,nosuid,size=128m",
                              "-e", "HF_HUB_OFFLINE=1", "-e", "TRANSFORMERS_OFFLINE=1",
                              "--entrypoint", "python", os.environ["TGWITNESS_MEDIA_IMAGE"],
                              "-c", "from faster_whisper import WhisperModel; import av, hashlib, json, os; "
                              "from pathlib import Path; "
                              "from importlib.metadata import version; "
                              "assert callable(WhisperModel); assert callable(av.open); "
                              "assert os.geteuid() != 0 and os.getegid() != 0; "
                              "assert os.confstr('CS_GNU_LIBC_VERSION').startswith('glibc '); "
                              "root=Path(os.environ['TESSDATA_PREFIX']); "
                              "print(json.dumps({'faster_whisper':version('faster-whisper'),'av':av.__version__,"
                              "'traineddata':{lang:hashlib.sha256((root/(lang+'.traineddata')).read_bytes()).hexdigest()"
                              " for lang in ('eng','rus')}}))"],
                             check=True, capture_output=True, text=True, timeout=90)
    versions = json.loads(imports.stdout)
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
        subprocess.run([*docker(), "rm", "--force", name], capture_output=True, timeout=10)
    print(decoding.stdout.strip(), flush=True)
    if decoding.returncode:
        raise RuntimeError("Native decoder check failed:\n" + decoding.stderr[-16384:])
    with tempfile.TemporaryDirectory(prefix="media-worker-check-") as scratch:
        font = ImageFont.truetype(str(Path(__file__).resolve().parents[1] / "tgwitness/fonts/NotoSans-Regular.ttf"), 48)
        for language, text in (("eng", "ARCHIVE SOURCE 12345"), ("rus", "АРХИВ ДОКУМЕНТ 12345")):
            path = Path(scratch) / ("synthetic-" + language + ".png")
            image = Image.new("RGB", (1400, 160), "white")
            ImageDraw.Draw(image).text((40, 40), text, font=font, fill="black")
            image.save(path)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            result = asyncio.run(run_container(path, MediaJob(chat_id=1, event_seq=1, digest=digest,
                                                             engine="ocr", language=language), secrets.token_hex(16)))
            assert text in " ".join(result["text"].split()), (language, result["text"])
            assert result["engine"] == "tesseract" and result["language"] == language
            assert result["model_version"] == versions["traineddata"][language]
            assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
            print("Isolated real OCR passed on generated " + language + " image; input unchanged.", flush=True)
        path = Path(scratch) / "synthetic-speech.wav"
        phrase = "This is a voice recording. It is sunny today. The final report contains seven messages."
        subprocess.run([speech, "-v", "en-us", "-s", "135", "-w", str(path), phrase], check=True,
                       capture_output=True, timeout=20)
        with wave.open(str(path), "rb") as audio:
            expected_samples = audio.getnframes() * 16000 / audio.getframerate()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        result = asyncio.run(run_container(path, MediaJob(chat_id=1, event_seq=1, digest=digest,
                                                         engine="transcription", language="en"), secrets.token_hex(16)))
        required_words = {"voice", "recording", "sunny", "today", "final", "report", "contains", "seven", "messages"}
        assert required_words <= set(re.findall(r"[a-z]+", result["text"].lower())), result["text"]
        assert result["engine"] == "faster-whisper" and result["language"] == "en" and result["segments"]
        assert result["engine_version"] == versions["faster_whisper"]
        assert result["model_version"] == FILES["model.bin"][1]
        assert result["parameters"]["sample_rate"] == 16000
        assert abs(result["parameters"]["decoded_samples"] - expected_samples) <= 1
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
        validate(Path(model))
    print("Isolated real ASR passed on generated speech with pinned model " + REVISION + "; input and model unchanged.")


if __name__ == "__main__":
    main()
