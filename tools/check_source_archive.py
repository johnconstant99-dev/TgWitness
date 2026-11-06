import hashlib
import base64
import csv
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import tomllib
import sys
from unittest.mock import patch
import zipfile
from contextlib import redirect_stdout

SPEC = importlib.util.spec_from_file_location("build_source", Path(__file__).with_name("build_source.py"))
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def check_container_inputs():
    root = builder.ROOT.resolve()
    public = {path.relative_to(root).as_posix() for path in builder.public_sources(root)}
    required = set(builder.CONTAINER_INPUTS)
    assert required <= public, "Container build inputs are missing from the public source archive"
    copied = {path.relative_to(root).as_posix() for path in (root / "deploy/containers").rglob("*")
              if path.is_file()}
    assert copied <= required, "The copied container input directory contains unlisted files: " + str(copied - required)
    return {name: (root / name).read_bytes() for name in required}


def check_website_inputs():
    root = builder.ROOT.resolve()
    public = {path.relative_to(root).as_posix() for path in builder.public_sources(root)}
    required = {"website/export-clinic/media/" + name for name in builder.EXPORT_CLINIC_ASSETS}
    assert required <= public, "Reviewed website assets are missing from the public source archive"
    return {name: (root / name).read_bytes() for name in required}


def check_package_inputs():
    root = builder.ROOT.resolve()
    public = {path.relative_to(root).as_posix() for path in builder.public_sources(root)}
    # The source ZIP must retain every application resource that the wheel installs.
    project = tomllib.loads((root / 'pyproject.toml').read_text(encoding='utf-8'))
    patterns = project['tool']['setuptools']['package-data']['tgwitness']
    required = {path.relative_to(root).as_posix() for pattern in patterns
                for path in (root / 'tgwitness').glob(pattern) if path.is_file()}
    assert required and required <= public, 'Installed application resources are missing from the source ZIP: ' + str(required - public)
    required.update({'docs/examples/narrative.json', 'tools/fixtures/narrative-events.json',
                     'tools/fixtures/narrative-golden.json'})
    assert required <= public, 'Narrative examples or test fixtures are missing from the source ZIP'
    return {name: (root / name).read_bytes() for name in required}


def check_publication_secrets():
    spec = importlib.util.spec_from_file_location("check_publication", Path(__file__).with_name("check_publication.py"))
    scanner = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"build_source": builder}):
        spec.loader.exec_module(scanner)
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
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("notes.txt", "public text\n" + value)
        archived = scanner.data_findings(payload.getvalue(), "synthetic.zip")
        assert len(archived) == 1 and "synthetic.zip/notes.txt:2:" in archived[0]
        assert all(secret not in archived[0] for secret in (value, suffix, uuid)) and "value withheld" in archived[0]
    for value in (uuid, "DEEPL_AUTH_KEY", 'os.environ["DEEPL_API_KEY"]',
                  '"DEEPL_AUTH_KEY": "your-key-here"', "sk-" + "example", "TRUSTED_SHA256"):
        assert scanner.secret_findings(value, "public.py") == []
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("comparison.jpg", b"\xff\xd8\xff\xd9")
        archive.writestr("notes.txt", "sk-" + suffix)
    findings = scanner.data_findings(payload.getvalue(), "synthetic.zip")
    assert len(findings) == 1 and "notes.txt" in findings[0] and "value withheld" in findings[0]


def check_portable_package(root):
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

    stage = root / "portable-layout"
    resources = (
        "python/Lib/site-packages/fpdf/data/__init__.py",
        "python/Lib/site-packages/fpdf/data/color_profiles/__init__.py",
        "python/Lib/site-packages/fpdf/data/color_profiles/sRGB2014.icc",
        "python/Lib/site-packages/fpdf/data/color_profiles/sRGB2014.icc.LICENSE",
        "python/Lib/site-packages/pymorphy3_dicts_ru/data/grammemes.json",
        "python/Lib/site-packages/pymorphy3_dicts_ru/data/gramtab-opencorpora-ext.json",
        "python/Lib/site-packages/pymorphy3_dicts_ru/data/gramtab-opencorpora-int.json",
        "python/Lib/site-packages/pymorphy3_dicts_ru/data/meta.json",
        "python/Lib/site-packages/pymorphy3_dicts_ru/data/p_t_given_w.intdawg",
        "python/Lib/site-packages/pymorphy3_dicts_ru/data/paradigms.array",
        "python/Lib/site-packages/pymorphy3_dicts_ru/data/prediction-suffixes-0.dawg",
        "python/Lib/site-packages/pymorphy3_dicts_ru/data/prediction-suffixes-1.dawg",
        "python/Lib/site-packages/pymorphy3_dicts_ru/data/prediction-suffixes-2.dawg",
        "python/Lib/site-packages/pymorphy3_dicts_ru/data/suffixes.json",
        "python/Lib/site-packages/pymorphy3_dicts_ru/data/words.dawg",
    )
    for name in resources:
        path = stage / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"Public dependency resource\n")
    archive = root / "portable.zip"
    portable.write_release(stage, archive)
    original = archive.read_bytes()
    with zipfile.ZipFile(archive) as released:
        assert set(released.namelist()) == {stage.name + "/" + name for name in resources}
    for name in (
        "data/vault.key",
        "python/Lib/site-packages/tgwitness/data/notes.txt",
        "python/Lib/site-packages/fpdf/data/extra.txt",
        "python/Lib/site-packages/fpdf/data/color_profiles/vault.key",
        "python/Lib/site-packages/fpdf/DATA/extra.txt",
        "python/Lib/site-packages/fpdf/data/color_profiles/__pycache__/module.pyc",
        "python/Lib/site-packages/pymorphy3_dicts_ru/data/extra.txt",
        "python/Lib/site-packages/pymorphy3_dicts_ru/data/notes.txt",
        "python/Lib/site-packages/pymorphy3_dicts_ru/data/vault.key",
        "python/Lib/site-packages/pymorphy3_dicts_ru/data/account.session",
        "python/Lib/site-packages/pymorphy3_dicts_ru/data/nested/grammemes.json",
        "python/Lib/site-packages/pymorphy3_dicts_ru/DATA/extra.txt",
    ):
        private = stage / name
        private.parent.mkdir(parents=True, exist_ok=True)
        private.write_bytes(b"PRIVATE_CANARY")
        try:
            portable.write_release(stage, archive)
        except SystemExit:
            pass
        else:
            raise AssertionError("Private portable path was accepted: " + name)
        finally:
            private.unlink()
        assert archive.read_bytes() == original, "Rejected input replaced a valid portable ZIP"


def main():
    check_publication_secrets()
    container_inputs = check_container_inputs()
    website_inputs = check_website_inputs()
    package_inputs = check_package_inputs()
    with tempfile.TemporaryDirectory(prefix="tgwitness-source-check-") as temporary:
        root = Path(temporary).resolve()
        check_portable_package(root)
        source = root / "tgwitness"
        source.mkdir()
        original = {
            "README.md": "Public source — unchanged bytes\r\n".encode(),
            "tgwitness/sample.py": b"print('synthetic')\n",
            "tgwitness/locales/ru.json": '{"test":"пример"}\n'.encode(),
            **container_inputs,
            **website_inputs,
            **package_inputs,
        }
        for name, data in original.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (source / "sessions.json").write_text("PRIVATE_CANARY", encoding="utf-8")
        (source / "data").mkdir()
        (source / "data" / "secrets.py").write_text("PRIVATE_CANARY", encoding="utf-8")
        for name in ("deploy/containers/unlisted.lock", "deploy/containers/unlisted.packages",
                     "deploy/containers/local-build.sh", "deploy/containers/local-state.json",
                     "deploy/media-worker/local-helper.py", "deploy/media-worker/local-source.json",
                     "website/export-clinic/media/unreviewed.jpg",
                     "website/export-clinic/media/private-state.json",
                     "website/export-clinic/media/local-recording.mp4",
                     "website/export-clinic/media/local-export.zip",
                     "website/export-clinic/media/local-notes.txt"):
            private = root / name
            private.parent.mkdir(parents=True, exist_ok=True)
            private.write_text("PRIVATE_CANARY", encoding="utf-8")
        for name in ('tgwitness/narrative/texts/local-private.json', 'tgwitness/narrative/profiles.json',
                     'docs/examples/local-evidence.json', 'tools/fixtures/local-evidence.json'):
            private = root / name
            private.parent.mkdir(parents=True, exist_ok=True)
            private.write_text('PRIVATE_CANARY', encoding='utf-8')
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
                    patch.object(builder, "FILES", ["README.md", *container_inputs, *website_inputs,
                                                    *(name for name in package_inputs
                                                      if not name.startswith('tgwitness/') or name in builder.FILES)]), \
                    patch.object(builder, "DIRECTORIES", {"tgwitness": builder.DIRECTORIES["tgwitness"],
                                                          "deploy": builder.DIRECTORIES["deploy"],
                                                          "website": builder.DIRECTORIES["website"]}), \
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
            assert set(archive.namelist()) == expected, {
                "missing": sorted(expected - set(archive.namelist())),
                "unexpected": sorted(set(archive.namelist()) - expected)}
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

        (root / "README.md").write_bytes(b"Changed public source\n")
        build((2020, 1, 2, 3, 4, 6, 0, 2, 0))
        assert target.read_bytes() != first
        with zipfile.ZipFile(target) as archive:
            assert archive.read("TgWitness/README.md") == b"Changed public source\n"
        previous = target.read_bytes()
        changed_input = sorted(container_inputs)[0]
        changed_bytes = container_inputs[changed_input] + b"\n# Synthetic build input change\n"
        (root / changed_input).write_bytes(changed_bytes)
        build((2020, 1, 2, 3, 4, 6, 0, 2, 0))
        assert target.read_bytes() != previous, "A changed container build input did not change the source archive"
        with zipfile.ZipFile(target) as archive:
            assert archive.read("TgWitness/" + changed_input) == changed_bytes
            assert (hashlib.sha256(changed_bytes).hexdigest() + "  " + changed_input + "\n").encode() \
                in archive.read("TgWitness/SOURCE_SHA256SUMS")
    print("Source archive checks passed: repeatability, metadata, exact bytes, container/website/narrative inputs and hashes, private exclusions, secret redaction, interrupted writes, portable metadata, PDF and dictionary resources.")


if __name__ == "__main__":
    main()
