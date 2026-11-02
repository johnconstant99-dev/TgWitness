import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import urllib.request


MODEL = "Systran/faster-whisper-tiny.en"
REVISION = "0d3d19a32d3338f10357c0889762bd8d64bbdeba"
FILES = {
    "config.json": (2317, "14b1b421a90349bc551b881461426b561a874049cb9e4c4864f2ca384f6a7cc5"),
    "model.bin": (75537502, "1a5afae06a4db91c975c9a9d78be5cc110ee4ea022ad57d55492e4550e936b2a"),
    "tokenizer.json": (2128466, "929c5252409436dce1b38a75d1abbcb5e132d170d8e324e4e04ed915fa2d22df"),
    "vocabulary.txt": (422309, "ff77588746d3a2595d32ab5b69ffd7b95ce2441ac57533cb66fc3eb575a115cf"),
}
LICENSE = {"spdx": "MIT", "source": "https://huggingface.co/" + MODEL + "/blob/" + REVISION + "/README.md",
           "original_weights": "https://github.com/openai/whisper/blob/main/LICENSE"}


def validate(directory):
    if not directory.is_dir() or directory.is_symlink() or {path.name for path in directory.iterdir()} != set(FILES):
        raise ValueError("The pinned ASR test model must contain exactly its four model files")
    for name, (size, digest) in FILES.items():
        path = directory / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size != size:
            raise ValueError("Missing or unexpected pinned ASR model file: " + name)
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise ValueError("Pinned ASR model checksum mismatch: " + name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    for name, (size, digest) in FILES.items():
        target = args.output / name
        if target.is_symlink():
            raise ValueError("Refusing model symlink: " + name)
        if target.is_file() and target.stat().st_size == size:
            with target.open("rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() == digest:
                    continue
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=args.output, delete=False) as out:
                temporary = Path(out.name)
                measured, total = hashlib.sha256(), 0
                with urllib.request.urlopen("https://huggingface.co/" + MODEL + "/resolve/" + REVISION + "/" + name,
                                            timeout=60) as response:
                    while data := response.read(1024 * 1024):
                        total += len(data)
                        if total > size:
                            raise ValueError("Pinned model download exceeded its size: " + name)
                        measured.update(data)
                        out.write(data)
                if total != size or measured.hexdigest() != digest:
                    raise ValueError("Pinned model download failed checksum validation: " + name)
            temporary.replace(target)
            target.chmod(0o444)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    validate(args.output)
    print(json.dumps({"model": MODEL, "revision": REVISION, "bytes": sum(size for size, _ in FILES.values()),
                      "files_sha256": {name: digest for name, (_, digest) in FILES.items()}, "license": LICENSE}))


if __name__ == "__main__":
    main()
