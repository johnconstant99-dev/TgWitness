import argparse
import errno
import json
import os
from pathlib import Path
import sys
import sysconfig
import tempfile
import uuid

import check_install


def restrictions():
    assert sys.platform == "linux", "Run inside the Linux container image"
    assert os.geteuid() != 0 and os.getegid() != 0, "The image default must be unprivileged"
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    assert int(status["CapEff"].strip(), 16) == 0
    assert status["NoNewPrivs"].strip() == "1"
    root_mount = next(line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()
                      if line.split()[4] == "/")
    assert "ro" in root_mount[5].split(","), "The root filesystem must be read-only"
    for directory in (Path("/app"), Path(sysconfig.get_path("purelib"))):
        probe = directory / (".container-write-check-" + uuid.uuid4().hex)
        try:
            probe.write_bytes(b"synthetic probe")
        except OSError as error:
            assert error.errno in (errno.EROFS, errno.EACCES), error
        else:
            probe.unlink()
            raise AssertionError("Container application files are writable")
    with tempfile.TemporaryDirectory(prefix="container-tmp-") as scratch:
        path = Path(scratch) / "synthetic"
        path.write_bytes(b"temporary processing works")
        assert path.read_bytes() == b"temporary processing works"
    return {"nonroot": True, "effective_capabilities": 0, "no_new_privileges": True, "read_only_root": True}


def package_and_pdf(output, source=Path("/app/tgwitness")):
    import tgwitness
    from tgwitness import evidence, report
    from tgwitness.provenance import SOURCE_POLICY, run_receipt, source_files, source_tree_sha256
    from tgwitness.security import Vault
    from tgwitness.store import Store
    from tgwitness.verify import fingerprint, verify_report

    installed = Path(tgwitness.__file__).resolve().parent
    expected = source_files(source)
    actual = source_files(installed)
    assert expected and actual == expected, "Installed package measurement differs from the image build inputs"
    with tempfile.TemporaryDirectory(prefix="container-pdf-", dir=output) as scratch:
        vault, store = Vault(Path(scratch)), Store(Path(scratch))
        store.bind(vault)
        try:
            receipt = run_receipt(store, vault)
            assert receipt["source_policy"] == SOURCE_POLICY
            assert receipt["source_files"] == expected
            assert receipt["source_tree_sha256"] == source_tree_sha256(expected)
            assert all(value != "unknown" for value in receipt["dependencies"].values())
            store.append("collector.started", receipt)
            texts = ("Synthetic archive message", "Синтетическая запись архива", "رسالة أرشيف تجريبية")
            store.set_target(-1001, "Synthetic multilingual source", "supergroup", True)
            for number, text in enumerate(texts, 1):
                store.append("message.new", {"text": text, "sender_id": 44}, -1001, number, 44)
            for language, design in (("en", "classic"), ("ru", "reading_series"), ("ar", "ledger_margin")):
                options = report.ReportOptions(design=design).model_dump() | {"language": language}
                pdf = evidence.export_file(store, vault, "pdf", options)
                raw = pdf.read_bytes()
                assert raw.startswith(b"%PDF-") and b"/FontFile2" in raw, "Expected embedded native PDF fonts"
                checked = verify_report(pdf, fingerprint(vault.public_key))
                assert checked["pdf_signature"] and checked["report_seal"]["subject"]["event_count"] == 4
            for name in ("panel-token.txt", "vault.key", "signing.enc"):
                path = Path(scratch) / name
                assert path.is_file(), "Missing private runtime file: " + name
                if sys.platform == "linux":
                    assert path.stat().st_uid == os.geteuid()
                    assert path.stat().st_mode & 0o077 == 0, name + " is not private"
        finally:
            store.close()
    return {"source_policy": SOURCE_POLICY, "source_tree_sha256": source_tree_sha256(actual),
            "measured_files": len(actual), "signed_native_pdf_languages": ["en", "ru", "ar"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    security = restrictions()
    check_install.main(["--installed", "--output", str(args.output)])
    receipt = {"passed": True, **security, **package_and_pdf(args.output)}
    (args.output / "container-receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
