"""Fetch pinned OCR build inputs with bounded retries and atomic publication."""
import argparse
import hashlib
import http.client
import json
from pathlib import Path
import time
import urllib.error
import urllib.request

MAX_BYTES = 256 * 1024**2


def fetch(item, target, *, opener=urllib.request.urlopen, sleep=time.sleep):
    target = Path(target)
    partial = target.with_suffix(target.suffix + ".part")
    if target.is_symlink() or partial.is_symlink():
        raise ValueError("Refusing linked OCR build input")
    if target.is_file():
        with target.open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() == item["sha256"]:
                return
    try:
        for attempt in range(3):
            measured, size = hashlib.sha256(), 0
            try:
                with opener(item["url"], timeout=60) as response, partial.open("wb") as output:
                    while block := response.read(1024**2):
                        size += len(block)
                        if size > MAX_BYTES:
                            raise ValueError("OCR source exceeds the build input size limit: " + target.name)
                        measured.update(block)
                        output.write(block)
                if measured.hexdigest() != item["sha256"]:
                    raise ValueError("Source checksum mismatch: " + target.name)
                partial.replace(target)
                return
            except (urllib.error.URLError, TimeoutError, ConnectionError, http.client.IncompleteRead) as exc:
                if (isinstance(exc, urllib.error.HTTPError) and exc.code not in (408, 429, 500, 502, 503, 504)) or attempt == 2:
                    raise
                print(f"Retrying OCR input {target.name} after {type(exc).__name__} ({attempt + 1}/3)", flush=True)
                sleep(2 ** (attempt + 1))
    finally:
        partial.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=Path("/build/ocr/sources.lock.json"))
    parser.add_argument("--output", type=Path, default=Path("/build/downloads"))
    args = parser.parse_args()
    lock = json.loads(args.lock.read_bytes())
    args.output.mkdir(parents=True, exist_ok=True)
    items = {"tesseract.tar.gz": lock["tesseract"], "tessdata.LICENSE": lock["traineddata"]["license"]}
    items.update({language + ".traineddata": item for language, item in lock["traineddata"]["files"].items()})
    for name, item in items.items():
        if Path(name).name != name or "\\" in name:
            raise ValueError("Invalid OCR input name")
        fetch(item, args.output / name)


if __name__ == "__main__":
    main()
