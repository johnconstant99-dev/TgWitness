"""Apply archive limits before reading ZIP entries."""
import contextlib
import io
import json
import struct
import sys
import zipfile
from unittest.mock import patch

import pytest

from tgwitness import verify
from tgwitness.evidence import export_file
from tgwitness.store import Store
from tgwitness.witness import WitnessKey, export as witness_export


def advertise_large_member(path, member="README.txt"):
    """Keep the payload small but declare a 4 GiB member in the central directory."""
    with zipfile.ZipFile(path) as archive:
        offset = archive.start_dir
    data = bytearray(path.read_bytes())
    while data[offset:offset + 4] == b"PK\x01\x02":
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, offset + 28)
        if bytes(data[offset + 46:offset + 46 + name_len]).decode() == member:
            struct.pack_into("<I", data, offset + 24, 0xFFFFFFFE)
            path.write_bytes(bytes(data))
            return
        offset += 46 + name_len + extra_len + comment_len
    raise AssertionError("member not found: " + member)


@pytest.fixture
def witness_zip(tmp_path):
    root = tmp_path / "witness"
    key = WitnessKey(root)
    store = Store(root)
    store.bind(key)
    store.append("witness.started", {"interval_minutes": 10})
    store.close()
    path = tmp_path / "witness.zip"
    witness_export(root, path)
    return path


def run_cli(*argv):
    out = io.StringIO()
    with patch.object(sys, "argv", ["verify.py", *map(str, argv)]), contextlib.redirect_stdout(out), \
            contextlib.redirect_stderr(out), pytest.raises(SystemExit) as stopped:
        verify.main()
        raise SystemExit(0)
    return stopped.value.code, out.getvalue()


def test_witness_and_format_detection_refuse_a_declared_oversized_member(witness_zip):
    assert verify.verify_witness(witness_zip)["events"] == 1
    advertise_large_member(witness_zip)
    with pytest.raises(ValueError, match="size limit"):
        verify.verify_witness(witness_zip)
    with pytest.raises(ValueError, match="size limit"):
        verify.bundle_format(witness_zip)
    code, output = run_cli(witness_zip)
    assert code == 1 and "size limit" in output


def test_evidence_with_an_oversized_witness_is_refused(journal, witness_zip):
    store, vault = journal
    store.append("synthetic.event", {"test": True})
    bundle = export_file(store, vault, "zip")
    advertise_large_member(witness_zip)
    code, output = run_cli(bundle, "--witness", witness_zip)
    assert code == 1 and "size limit" in output


def test_format_detection_reads_nothing_beyond_the_limit(witness_zip):
    with patch.object(verify, "MAX_UNCOMPRESSED_GIB", 1 / 1024**3):
        with pytest.raises(ValueError, match="size limit"):
            verify.bundle_format(witness_zip)
        with pytest.raises(ValueError, match="size limit"):
            verify.verify_witness(witness_zip)


@pytest.mark.parametrize("setting, message", [
    ("MAX_MANIFEST_BYTES", "manifest.json exceeds"),
    ("MAX_RECORD_BYTES", "record exceeds"),
    ("MAX_MEMBERS", "more members"),
])
def test_manifest_records_and_member_count_are_bounded(journal, witness_zip, setting, message):
    store, vault = journal
    store.append("synthetic.event", {"text": "x" * 400})
    bundle = export_file(store, vault, "zip")
    verify.verify_bundle(bundle)
    limit = {"MAX_MANIFEST_BYTES": 64, "MAX_RECORD_BYTES": 64, "MAX_MEMBERS": 2}[setting]
    with patch.object(verify, setting, limit):
        for check in (verify.verify_bundle, verify.verify_witness):
            with pytest.raises(ValueError, match=message):
                check(bundle if check is verify.verify_bundle else witness_zip)


def test_actual_member_bytes_are_bounded_as_well_as_declared_size(tmp_path):
    path = tmp_path / "member.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", json.dumps({"format": "x" * 100}))
    with zipfile.ZipFile(path) as archive:
        archive.getinfo("manifest.json").file_size = 10
        with pytest.raises((zipfile.BadZipFile, ValueError)):
            verify.read_member(archive, "manifest.json", 20)


def test_profile_json_size_is_bounded(tmp_path):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({"statement": {"format": "tgwitness-dossier-v1"}, "pad": "x" * 200}), encoding="utf-8")
    with patch.object(verify, "MAX_JSON_BYTES", 100), pytest.raises(ValueError, match="size limit"):
        verify.verify_dossier(path)
