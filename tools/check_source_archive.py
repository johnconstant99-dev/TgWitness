"""Offline source archive, private-file, secret-scan and failed-write regressions."""
import hashlib
import base64
import csv
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import sys
from unittest.mock import patch
import zipfile
from contextlib import redirect_stdout

SPEC = importlib.util.spec_from_file_location("build_source", Path(__file__).with_name("build_source.py"))
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def check_publication_secrets():
    spec = importlib.util.spec_from_file_location("check_publication", Path(__file__).with_name("check_publication.py"))
    scanner = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"build_source": builder}):
        spec.loader.exec_module(scanner)
    # Assemble synthetic credentials so publication scanning never needs a fixture
    # exemption and no real key/environment variable is read by this regression.
    suffix = "SyntheticCanary0123" * 3
    uuid = "12345678" + "-1234" * 3 + "-123456789abc"
    values = ["sk-" + suffix, "sk-" + "proj-" + suffix, "sk-" + "svcacct-" + suffix,
              "sk-" + "ant-api03-" + suffix, "sk-" + "or-v1-" + "a" * 64,
              "gsk_" + suffix, "AIza" + "a" * 35, uuid + ":fx",
              "DEEPL_AUTH_KEY=" + uuid, '"deepl_api_key": "' + uuid + '"',
              "Authorization: DeepL-Auth-Key " + uuid,
              "-----" + "BEGIN ENCRYPTED PRIVATE KEY" + "-----"]
    for value in values:
        findings = scanner.secret_findings("public text\n" + value, "synthetic.py")
        assert len(findings) == 1 and "synthetic.py:2:" in findings[0]
        assert all(secret not in findings[0] for secret in (value, suffix, uuid)) and "value withheld" in findings[0]
        # The same guard must cover approved demonstration archives as well as source.
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("notes.txt", "public text\n" + value)
        archived = scanner.data_findings(payload.getvalue(), "synthetic.zip")
        assert len(archived) == 1 and "synthetic.zip/notes.txt:2:" in archived[0]
        assert all(secret not in archived[0] for secret in (value, suffix, uuid)) and "value withheld" in archived[0]
    for value in (uuid, "DEEPL_AUTH_KEY", 'os.environ["DEEPL_API_KEY"]',
                  '"DEEPL_AUTH_KEY": "your-key-here"', "sk-" + "example", "TRUSTED_SHA256"):
        assert scanner.secret_findings(value, "public.py") == []


def check_portable_metadata(root):
    spec = importlib.util.spec_from_file_location("build_portable", Path(__file__).with_name("build_portable.py"))
    portable = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(portable)
    site = root / "portable/python/Lib/site-packages"
    metadata = site / ("tgwitness-" + portable.VERSION + ".dist-info")
    files = {
        metadata / "METADATA": b"Name: tgwitness\n",
        metadata / "licenses/LICENSE, notice.txt": "Public licence — preserved\n".encode(),
        metadata / "direct_url.json": b'{"url":"file:///synthetic-private-builder"}',
        site / "dependency.dist-info/licenses/LICENSE": b"Dependency licence\n",
        site / "dependency.dist-info/direct_url.json": b'{"url":"https://example.invalid/dependency"}',
    }
    for path, data in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    record = metadata / "RECORD"
    launcher = (site / "../../bin/tgwitness.exe").resolve()
    assert launcher.is_relative_to(root)
    launcher.parent.mkdir(parents=True, exist_ok=True)
    launcher_data = b"Synthetic retained launcher\n"
    launcher.write_bytes(launcher_data)
    rows = [[path.relative_to(site).as_posix(),
             "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("="), str(len(data))]
            for path, data in files.items() if path.is_relative_to(metadata)]
    rows += [["../../bin/tgwitness.exe", "sha256=" + base64.urlsafe_b64encode(
                  hashlib.sha256(launcher_data).digest()).decode().rstrip("="), str(len(launcher_data))],
             ["../../bin/tgwitness-mcp.exe", "sha256=removed", "10"],
             [record.relative_to(site).as_posix(), "", ""]]
    with record.open("w", encoding="utf-8", newline="") as target:
        csv.writer(target).writerows(rows)
    portable.clean_app_install_metadata(site)
    assert not (metadata / "direct_url.json").exists()
    with record.open(encoding="utf-8", newline="") as source:
        kept = list(csv.reader(source))
    assert len(kept) == 4
    for name, digest, size in kept:
        path = site / name
        assert path.is_file()
        if path != record:
            data = path.read_bytes()
            assert int(size) == len(data)
            assert digest == "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
    for path, data in files.items():
        if path != metadata / "direct_url.json":
            assert path.read_bytes() == data, "Unrelated metadata or a licence was modified"
    cleaned = record.read_bytes()
    portable.clean_app_install_metadata(site)
    assert record.read_bytes() == cleaned, "Portable metadata cleanup is not idempotent"
    launcher.unlink()
    portable.clean_app_install_metadata(site)
    with record.open(encoding="utf-8", newline="") as source:
        assert list(csv.reader(source)) == [row for row in kept if row[0] != "../../bin/tgwitness.exe"]
    (metadata / "direct_url.json").write_bytes(files[metadata / "direct_url.json"])
    record.write_text("malformed,two columns\n", encoding="utf-8")
    try:
        portable.clean_app_install_metadata(site)
    except SystemExit:
        pass
    else:
        raise AssertionError("Malformed RECORD was accepted")
    assert (metadata / "direct_url.json").exists(), "Malformed metadata caused partial cleanup"


def main():
    check_publication_secrets()
    with tempfile.TemporaryDirectory(prefix="tgwitness-source-check-") as temporary:
        root = Path(temporary).resolve()
        check_portable_metadata(root)
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
        for name in ("Data/private.py", "BUILD/output.py", "nested/dist/generated.py",
                     ".tmp/scratch.py", ".TMP-audit/scratch.py", ".tmp-note.py", "nested/.tmp-notes.md"):
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("PRIVATE_CANARY", encoding="utf-8")
            assert not builder.is_public_file(path, source), name
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
    print("Source archive checks passed: repeatability, metadata, exact bytes, private exclusions, secret redaction, interrupted writes and portable metadata hygiene.")


if __name__ == "__main__":
    main()
