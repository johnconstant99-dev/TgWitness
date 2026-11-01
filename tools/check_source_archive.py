"""Offline source archive reproducibility, private-file and failed-write regressions."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
from unittest.mock import patch
import zipfile
from contextlib import redirect_stdout

SPEC = importlib.util.spec_from_file_location("build_source", Path(__file__).with_name("build_source.py"))
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def main():
    with tempfile.TemporaryDirectory(prefix="tgwitness-source-check-") as temporary:
        root = Path(temporary).resolve()
        source = root / "tgwitness"
        source.mkdir()
        original = {
            "README.md": "Public source — unchanged bytes\r\n".encode(),
            "tgwitness/sample.py": b"print('synthetic')\n",
            "tgwitness/locales/ru.json": '{"test":"пример"}\n'.encode(),
        }
        for name, data in original.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (source / "sessions.json").write_text("PRIVATE_CANARY", encoding="utf-8")
        (source / "data").mkdir()
        (source / "data" / "secrets.py").write_text("PRIVATE_CANARY", encoding="utf-8")
        target = root / "dist" / "TgWitness-0.0.0-source.zip"
        checksum = target.with_suffix(".zip.sha256")

        def build(clock):
            with patch.object(builder, "ROOT", root), patch.object(builder, "VERSION", "0.0.0"), \
                    patch.object(builder, "FILES", ["README.md"]), \
                    patch.object(builder, "DIRECTORIES", {"tgwitness": {".py", ".json"}}), \
                    patch("zipfile.time.localtime", return_value=clock), redirect_stdout(io.StringIO()):
                builder.main()

        build((2020, 1, 2, 3, 4, 6, 0, 2, 0))
        first, first_sum = target.read_bytes(), checksum.read_bytes()
        for name in original:
            os.utime(root / name, (1800000000, 1800000000))
        build((2030, 9, 8, 7, 6, 4, 0, 251, 0))
        assert target.read_bytes() == first, "Identical source bytes produced different archives"
        assert checksum.read_bytes() == first_sum
        digest = hashlib.sha256(first).hexdigest()
        assert first_sum == (digest + "  " + target.name + "\n").encode("utf-8")

        with zipfile.ZipFile(io.BytesIO(first)) as archive:
            expected = {"TgWitness/" + name for name in original} | {"TgWitness/SOURCE_SHA256SUMS"}
            assert set(archive.namelist()) == expected
            for name, data in original.items():
                assert archive.read("TgWitness/" + name) == data
            manifest = "".join(hashlib.sha256(data).hexdigest() + "  " + name + "\n"
                               for name, data in sorted(original.items()))
            assert archive.read("TgWitness/SOURCE_SHA256SUMS") == manifest.encode("utf-8")
            for member in archive.infolist():
                assert member.date_time == (1980, 1, 1, 0, 0, 0)
                assert member.create_system == 3
                assert member.external_attr >> 16 == 0o100644
                assert not member.extra and not member.comment
                assert b"PRIVATE_CANARY" not in archive.read(member)

        real_write = zipfile.ZipFile.writestr
        writes = 0

        def interrupted(archive, *args, **kwargs):
            nonlocal writes
            writes += 1
            if writes == 2:
                raise OSError("Synthetic disk failure")
            return real_write(archive, *args, **kwargs)

        try:
            with patch.object(zipfile.ZipFile, "writestr", interrupted):
                build((2024, 1, 1, 0, 0, 0, 0, 1, 0))
        except OSError as error:
            assert str(error) == "Synthetic disk failure"
        else:
            raise AssertionError("Injected write failure was ignored")
        assert target.read_bytes() == first, "Interrupted build destroyed the previous archive"
        assert checksum.read_bytes() == first_sum
        assert sorted(path.name for path in target.parent.iterdir()) == sorted([target.name, checksum.name])

        # A real source change must affect both the ZIP and its embedded manifest.
        (root / "README.md").write_bytes(b"Changed public source\n")
        build((2020, 1, 2, 3, 4, 6, 0, 2, 0))
        assert target.read_bytes() != first
        with zipfile.ZipFile(target) as archive:
            assert archive.read("TgWitness/README.md") == b"Changed public source\n"
    print("Source archive checks passed: repeatability, metadata, exact bytes, private exclusions and interrupted writes.")


if __name__ == "__main__":
    main()
