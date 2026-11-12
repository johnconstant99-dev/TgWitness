import io
import lzma
import os
import struct
import sys
import tempfile
import zipfile
import zlib

import atheris

with atheris.instrument_imports():
    from cryptography.exceptions import InvalidSignature
    from tgwitness.verifier import common

REJECTED = (ValueError, KeyError, zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, RuntimeError,
            EOFError, OSError, zlib.error, lzma.LZMAError, struct.error, InvalidSignature)


def archive(data):
    handle, path = tempfile.mkstemp(suffix=".zip")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
        with common.open_archive(path, max_gib=0.01) as bundle:
            common.read_manifest(bundle)
    finally:
        os.unlink(path)


def document(data):
    common.strict_json(data)


def lines(data):
    for _ in common.bounded_lines(io.BytesIO(data)):
        pass


def TestOneInput(data):
    if not data:
        return
    try:
        (archive, document, lines)[data[0] % 3](data[1:])
    except REJECTED:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
