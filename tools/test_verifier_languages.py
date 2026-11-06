"""Every panel language must reach real verification, failures and saved results."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import i18n, verification_kit, verify  # noqa: E402
from tools.sync_verifier_languages import embedded, validate, START, END  # noqa: E402

LANGUAGES = tuple(verify.VERIFIER_LANGUAGES)


def test_builder_starts_without_host_application_dependencies():
    result = subprocess.run([sys.executable, "-I", "-S", str(ROOT / "tools/build_verifier.py"), "--help"],
                            capture_output=True, text=True, encoding="utf-8", timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "--language" in result.stdout and "zh-Hant" in result.stdout


def test_catalogue_matches_panel_and_standalone_copy():
    catalogue = json.loads((ROOT / "tgwitness/verifier_languages.json").read_text(encoding="utf-8"))
    validate(catalogue)
    assert tuple(catalogue) == i18n.LANGUAGES == LANGUAGES
    assert catalogue == verify.VERIFIER_LANGUAGES
    source = (ROOT / "tgwitness/verify.py").read_text(encoding="utf-8")
    assert source[source.index(START):source.index(END) + len(END)] == embedded(catalogue)
    for code, entry in catalogue.items():
        if code == "en":
            continue
        for section in ("reader", "explain"):
            assert all(value != catalogue["en"][section][key] for key, value in entry[section].items()
                       if (code, section, key) != ("it", "reader", "found")), (code, section)  # "File" is also Italian.


@pytest.mark.parametrize("language", LANGUAGES)
@pytest.mark.parametrize("mode", ["unconfirmed", "wrong_key", "cancelled"])
def test_all_languages_cover_real_results_and_failures(tmp_path, language, mode):
    original = tmp_path / "Original archive.zip"
    shutil.copyfile(ROOT / "tools/fixtures/evidence-before-fulltext.zip", original)
    before = verify.file_sha256(original)
    # The trusted script remains standalone: no catalogue file or package beside it.
    script = tmp_path / "verify.py"
    shutil.copyfile(ROOT / "tgwitness/verify.py", script)
    args = [sys.executable, "-I", "-B", "-X", "utf8", str(script), str(original), "--interactive", "--no-color", "--lang", language]
    answer = "\n" if mode == "unconfirmed" else "0" * 64 + "\n" if mode == "wrong_key" else ""
    checked = subprocess.run(args, input=answer, capture_output=True, text=True, encoding="utf-8", timeout=30)
    expected = {"unconfirmed": 0, "wrong_key": 1, "cancelled": 2}[mode]
    assert checked.returncode == expected, checked.stdout + checked.stderr
    reader, words = verify.VERIFIER_LANGUAGES[language]["reader"], verify.SAY[language]
    assert reader["key"] in checked.stdout and reader["trust"] in checked.stdout
    assert verify.file_sha256(original) == before
    logs = list(tmp_path.glob("verify-result-*.txt"))
    if mode == "cancelled":
        assert reader["cancelled"] in checked.stdout and not logs
        return
    assert len(logs) == 1
    text = logs[0].read_text(encoding="utf-8")
    assert reader["unsigned"] in text and reader["exit"] + ": " + str(expected) in text
    assert reader["saved"] in checked.stdout and "ZIP SHA-256: " + before in text
    assert "\ufffd" not in text and "\x1b" not in text
    if mode == "unconfirmed":
        assert words["INTEGRITY VERIFIED · SIGNER NOT CONFIRMED"] in text
        assert "".join(verify.VERIFIER_LANGUAGES[language]["explain"]["Limits"].split()) in "".join(text.split())
    else:
        assert words["VERIFICATION FAILED"] in text and words["Key mismatch"] in text
        assert words["INTEGRITY VERIFIED"] not in text
    if language != "en":
        assert verify.reader_message("key", "en") not in checked.stdout
        assert verify.reader_message("unsigned", "en") not in text


@pytest.mark.parametrize("language", LANGUAGES)
def test_windows_missing_runtime_is_localized_before_python_starts(tmp_path, language):
    if os.name != "nt":
        pytest.skip("Windows bootstrap")
    script = tmp_path / "VERIFY.cmd"
    script.write_bytes(verification_kit.files(language)["VERIFY.cmd"])
    env = {**os.environ, "PATH": str(Path(os.environ["SystemRoot"]) / "System32"), "TGWITNESS_VERIFY_NO_PAUSE": "1"}
    checked = subprocess.run([os.environ["COMSPEC"], "/d", "/c", str(script)], cwd=tmp_path, env=env,
                             capture_output=True, text=True, encoding="utf-8", timeout=20)
    assert checked.returncode == 2, checked.stdout + checked.stderr
    for key in ("runtime", "not_verified", "instructions"):
        assert verify.reader_message(key, language) in checked.stdout, (language, key, checked.stdout)
    assert not list(tmp_path.glob("verify-result-*.txt"))


@pytest.mark.parametrize("language", LANGUAGES)
def test_export_launchers_and_instructions_retain_the_selected_language(language):
    kit = verification_kit.files(language)
    assert "--lang " + language in kit["VERIFY.cmd"].decode("utf-8")
    assert "--lang " + language in kit["VERIFY.sh"].decode("utf-8")
    reader = verify.VERIFIER_LANGUAGES[language]["reader"]
    assert reader["launch"] in kit["START_HERE.txt"].decode("utf-8")
    assert reader["output"] in kit["START_HERE.txt"].decode("utf-8")
    assert b"\r\r\n" not in kit["VERIFY.cmd"]
    assert "@SH_" not in kit["VERIFY.sh"].decode("utf-8") and "@LANG" not in kit["VERIFY.cmd"].decode("utf-8")


@pytest.mark.parametrize("tag,expected", [("de-DE", "de"), ("pt_BR.UTF-8", "pt"), ("zh_TW.UTF-8", "zh-Hant"),
                                         ("zh-HK", "zh-Hant"), ("zh-Hans", "zh"), ("Arabic_Egypt", "ar"),
                                         ("Japanese_Japan", "ja"), ("ru_RU", "ru")])
def test_language_tags_and_os_detection(tag, expected, monkeypatch):
    assert verify.verifier_language(tag) == expected
    monkeypatch.setenv("LC_ALL", tag)
    assert verify.console_language() == expected


def test_language_choice_retries_without_shell_evaluation(monkeypatch, capsys):
    answers = iter(["& echo unwanted", "zh_TW"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert verify.choose_verifier_language("en") == "zh-Hant"
    text = capsys.readouterr().out
    assert verify.reader_message("language_invalid", "en") in text
    assert all(entry["name"] in text for entry in verify.VERIFIER_LANGUAGES.values())
    with pytest.raises(ValueError, match="Unsupported"):
        verification_kit.files("unsupported-language")


def test_every_language_is_bound_into_actual_signed_exports(tmp_path):
    from tgwitness import evidence
    from tgwitness.security import Vault
    from tgwitness.store import Store
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        store.append("message.new", {"text": "Synthetic localization fixture"}, -1001, 1)
        pin = verify.fingerprint(vault.public_key)
        for lang in LANGUAGES:
            path = evidence.export_file(store, vault, "zip", {"language": lang}, compact=True)
            verify.verify_bundle(path, pin)
            with zipfile.ZipFile(path) as archive:
                assert "--lang " + lang in archive.read("VERIFY.cmd").decode("utf-8")
                assert archive.read("README.txt").startswith(verification_kit.quickstart(lang))
                assert archive.read("verify.py") == (ROOT / "tgwitness/verify.py").read_bytes()
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
