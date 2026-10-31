"""Run OCR on a generated image in the real restricted local worker."""
import asyncio
import hashlib
import os
from pathlib import Path
import secrets
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.media_analysis import MediaJob, run_container


def main():
    if os.name != "posix":
        raise SystemExit("This check requires the Linux container worker.")
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
