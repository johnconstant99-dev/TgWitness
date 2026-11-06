"""Recipient workflows must preserve evidence, trust warnings and failure codes."""
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import chat_export, evidence, handover, report, verification_kit, verify  # noqa: E402
from tgwitness.security import Vault  # noqa: E402
from tgwitness.store import Store, canonical  # noqa: E402


@pytest.fixture
def package(tmp_path):
    vault, store = Vault(tmp_path / "source"), Store(tmp_path / "source")
    store.bind(vault)
    try:
        store.append("message.new", {"text": "SYNTHETIC verification fixture"}, -1001, 1)
        path = evidence.export_file(store, vault, "zip", compact=True)
        target = tmp_path / "Original renamed ZIP.zip"
        shutil.copyfile(path, target)
        yield target, verify.fingerprint(vault.public_key)
    finally:
        store.close()


def run_reader(path, answer, *options, script=None):
    return subprocess.run([sys.executable, "-I", "-B", "-X", "utf8",
                           str(script or ROOT / "tgwitness/verify.py"), str(path), "--interactive", *options],
                          input=answer, capture_output=True, text=True, encoding="utf-8", timeout=40)


def changed_zip(source, target, name):
    with zipfile.ZipFile(source) as incoming, zipfile.ZipFile(target, "w") as outgoing:
        for info in incoming.infolist():
            body = incoming.read(info.filename)
            outgoing.writestr(info.filename, body + b"changed" if info.filename == name else body)


def test_launcher_and_instructions_are_signed_and_renamed_archives_are_found(package, tmp_path):
    path, pin = package
    extracted = tmp_path / "Extracted case"
    with zipfile.ZipFile(path) as archive:
        archive.extractall(extracted)
        manifest = json.loads(archive.read("manifest.json"))
        assert set(verification_kit.files()) <= set(manifest["files"])
        assert archive.read("README.txt").startswith(verification_kit.quickstart())
        assert b"--lang en" in archive.read("VERIFY.cmd")
    assert verify.matching_archives(extracted) == [path]
    verify.verify_bundle(path, pin)
    bad = tmp_path / "changed launcher.zip"
    changed_zip(path, bad, "VERIFY.cmd")
    with pytest.raises(ValueError, match="File hash mismatch"):
        verify.verify_bundle(bad, pin)
    assert len(verify.matching_archives(extracted)) == 2  # Discovery is not verification.


@pytest.mark.parametrize("lang,warning", [("en", "SIGNER NOT CONFIRMED"), ("ru", "НЕ ПОДТВЕРЖД"), ("uk", "НЕ ПІДТВЕРДЖ")])
def test_blank_fingerprint_is_unconfirmed_and_saves_utf8_transcript(package, lang, warning):
    path, _ = package
    before = verify.file_sha256(path)
    result = run_reader(path, "\n", "--lang", lang)
    assert result.returncode == 0, result.stdout + result.stderr
    assert warning in result.stdout
    transcripts = list(path.parent.glob("verify-result-*.txt"))
    assert len(transcripts) == 1
    text = transcripts[0].read_text(encoding="utf-8")
    assert warning in text and "ZIP SHA-256: " + before in text
    assert "TgWitness SHA-256:" in text and verify.reader_message("exit", lang) + ": 0" in text and "\x1b" not in text
    assert verify.file_sha256(path) == before


@pytest.mark.parametrize("fault", ["wrong_key", "altered_file"])
def test_failure_is_nonzero_and_written_to_transcript(package, tmp_path, fault):
    path, pin = package
    if fault == "altered_file":
        bad = tmp_path / "damaged.zip"
        changed_zip(path, bad, "events.jsonl")
        path = bad
    else:
        pin = "0" * 64
    result = run_reader(path, pin + "\n", "--lang", "en")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "VERIFICATION FAILED" in result.stdout and "INTEGRITY VERIFIED" not in result.stdout
    text = next(path.parent.glob("verify-result-*.txt")).read_text(encoding="utf-8")
    assert "VERIFICATION FAILED" in text and "Exit code: 1" in text


def test_key_entry_accepts_grouped_hex_but_never_executes_text(package):
    path, pin = package
    grouped = ": ".join(pin[n:n + 4].upper() for n in range(0, 64, 4))
    result = run_reader(path, '& echo unexpected > owned.txt\n' + grouped + '\n', "--lang", "en")
    assert result.returncode == 0
    assert verify.reader_message("bad_key", "en") in result.stdout and "SIGNER NOT CONFIRMED" not in result.stdout
    assert not (path.parent / "owned.txt").exists()


@pytest.mark.parametrize("options", [("--strict",), ("--require-tier", "witnessed")])
def test_interactive_keeps_assurance_requirements(package, options):
    path, _ = package
    result = run_reader(path, "\n", "--lang", "en", *options)
    assert result.returncode == 2, result.stdout + result.stderr
    text = next(path.parent.glob("verify-result-*.txt")).read_text(encoding="utf-8")
    assert "Exit code: 2" in text and "SIGNER NOT CONFIRMED" in text


def test_interactive_rejects_unpaired_attestation_inputs(package, tmp_path):
    path, _ = package
    result = run_reader(path, "\n", "--sealed-policy", str(tmp_path / "policy.json"))
    assert result.returncode == 2 and "must be supplied together" in result.stderr
    assert not list(path.parent.glob("verify-result-*.txt"))


@pytest.mark.skipif(os.name == "nt", reason="Windows rejects control characters in file names")
def test_interactive_transcript_sanitizes_archive_path(package):
    path, pin = package
    escaped = path.with_name("case\x1b[2J.zip")
    path.rename(escaped)
    result = run_reader(escaped, pin + "\n", "--lang", "en", "--no-color")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "\x1b" not in result.stdout
    text = next(path.parent.glob("verify-result-*.txt")).read_text(encoding="utf-8")
    assert "\x1b" not in text and "case.zip" in text


def test_missing_runtime_does_not_claim_html_is_archive_verification(tmp_path):
    if os.name != "nt":
        pytest.skip("Windows launcher")
    script = tmp_path / "VERIFY.cmd"
    script.write_bytes(verification_kit.files()["VERIFY.cmd"])
    env = {**os.environ, "PATH": str(Path(os.environ["SystemRoot"]) / "System32"), "TGWITNESS_VERIFY_NO_PAUSE": "1"}
    result = subprocess.run([os.environ["COMSPEC"], "/d", "/c", str(script)],
                            cwd=tmp_path, env=env, capture_output=True, text=True, encoding="utf-8", timeout=20)
    assert result.returncode == 2, result.stdout + result.stderr
    assert verify.reader_message("not_verified", "en") in result.stdout and verify.reader_message("runtime", "en") in result.stdout


def test_actual_cmd_preserves_paths_failure_codes_and_ignores_adjacent_modules(package, tmp_path):
    if os.name != "nt":
        pytest.skip("Windows launcher")
    path, pin = package
    extracted = tmp_path / "100% ! & (копия)"
    with zipfile.ZipFile(path) as archive:
        archive.extractall(extracted)
    (extracted / "cryptography.py").write_text("raise RuntimeError('Untrusted adjacent module loaded')", encoding="utf-8")
    env = {**os.environ, "TGWITNESS_VERIFY_NO_PAUSE": "1"}
    command = '"' + os.environ["COMSPEC"] + '" /d /s /c ""' + str(extracted / "VERIFY.cmd") + '" "' + str(path) + '""'
    for key, code in ((pin, 0), ("0" * 64, 1)):
        result = subprocess.run(command, input=key + "\n", env=env, cwd=extracted, capture_output=True,
                                text=True, encoding="utf-8", timeout=40)
        assert result.returncode == code, result.stdout + result.stderr
        assert "Untrusted adjacent module" not in result.stdout + result.stderr
    assert len(list(path.parent.glob("verify-result-*.txt"))) == 2


def test_cancel_and_html_never_produce_success(package, tmp_path):
    path, _ = package
    assert run_reader(path, "").returncode == 2  # EOF is not approval or a blank key.
    html = tmp_path / "report.html"
    html.write_text("not a ZIP", encoding="utf-8")
    result = run_reader(html, "\n", "--lang", "en")
    assert result.returncode == 2 and "not a folder or HTML" in result.stdout
    assert not list(tmp_path.glob("verify-result-*.txt"))


def test_chat_and_handover_export_the_same_kit_with_report_language(tmp_path):
    vault, store = Vault(tmp_path / "source"), Store(tmp_path / "source")
    store.bind(vault)
    options = report.ReportOptions(language="uk").model_dump()
    try:
        store.append("message.new", {"text": "Synthetic"}, -1001, 1)
        scratch = tmp_path / "chat.jsonl"
        scratch.write_bytes(canonical({"id": 1, "text": "Synthetic", "date": "2026-11-06T00:00:00Z"}) + b"\n")
        chat = tmp_path / "chat.zip"
        chat_export.build_bundle(scratch, {"chat": {"id": -1001, "title": "Synthetic"}, "message_count": 1},
                                 vault, chat, options=options)
        hand, _ = handover.export(store, vault, handover.Options(purpose="Synthetic check", chats=[-1001]), options)
        for path, checker in ((chat, verify.verify_chat_export), (hand, verify.verify_handover)):
            checker(path, verify.fingerprint(vault.public_key))
            with zipfile.ZipFile(path) as archive:
                for name, body in verification_kit.files("uk").items():
                    assert archive.read(name) == body
    finally:
        store.close()


def test_no_automatic_choice_between_multiple_archives(package, tmp_path):
    path, _ = package
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(path) as archive:
        archive.extractall(extracted)
    shutil.copyfile(path, tmp_path / "second.zip")
    result = run_reader("", "\n", "--lang", "en", script=extracted / "verify.py")
    assert result.returncode == 2
    assert "Original ZIP path" in result.stdout and "Original ZIP found" not in result.stdout


def test_explain_does_not_change_machine_json(package):
    path, _ = package
    result = subprocess.run([sys.executable, str(ROOT / "tgwitness/verify.py"), str(path), "--json", "--explain"],
                            capture_output=True, text=True, encoding="utf-8", timeout=40)
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["verified"] and not data["signer_pinned"]


def test_witness_export_signs_launchers_without_claiming_collector_coverage(tmp_path):
    from tgwitness import witness
    root, path = tmp_path / "witness", tmp_path / "witness.zip"
    key = witness.WitnessKey(root)
    store = Store(root)
    try:
        store.bind(key)
        store.append("witness.started", {"interval_minutes": 10})
    finally:
        store.close()
    witness.export(root, path)
    result = verify.verify_witness(path, verify.fingerprint(key.public_key))
    assert result["events"] == 1
    with zipfile.ZipFile(path) as archive:
        for name, body in verification_kit.files().items():
            assert archive.read(name) == body


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
