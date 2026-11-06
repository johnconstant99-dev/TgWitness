"""Terminal text is inert; an unknown format only earns an upgrade response after authentication."""
import base64
import io
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest
from cryptography.exceptions import InvalidSignature

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.security import Vault
from tgwitness.store import Store, canonical
from tgwitness.evidence import export_file
from tgwitness.verify import Console, VerifierTooOld, safe_text, verify_chat_export, verify_witness


def future(tmp_path, valid=True):
    vault = Vault(tmp_path / 'collector')
    manifest = {'format': 'tgwitness-witness-v999', 'public_key': vault.public_key}
    signature = vault.sign(canonical(manifest)) if valid else base64.b64encode(b'\0' * 64).decode()
    path = tmp_path / 'future.zip'
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('manifest.json', canonical(manifest))
        archive.writestr('manifest.sig', signature)
    return path


@pytest.mark.parametrize('verifier', [verify_witness, verify_chat_export])
def test_signature_before_format_and_before_required_payload_fields(tmp_path, verifier):
    with pytest.raises(InvalidSignature):
        verifier(future(tmp_path, False))
    with pytest.raises(VerifierTooOld):
        verifier(future(tmp_path, True))


def test_future_format_exit_codes(tmp_path):
    command = [sys.executable, '-m', 'tgwitness.verify', str(future(tmp_path)), '--json']
    assert subprocess.run(command, capture_output=True).returncode == 1
    result = subprocess.run(command + ['--strict'], capture_output=True)
    assert result.returncode == 3
    assert json.loads(result.stdout)['verified'] is False
    future(tmp_path, False)
    assert subprocess.run(command + ['--strict'], capture_output=True).returncode == 1


def test_unpinned_is_explicit_and_strict_is_opt_in(tmp_path):
    vault = Vault(tmp_path / 'collector')
    store = Store(tmp_path / 'collector')
    store.bind(vault)
    try:
        store.append('message.new', {'text': 'synthetic'})
        path = export_file(store, vault, 'zip', compact=True)
        command = [sys.executable, '-m', 'tgwitness.verify', str(path), '--json']
        assert subprocess.run(command, capture_output=True).returncode == 0
        result = subprocess.run(command + ['--strict'], capture_output=True)
        assert result.returncode == 2 and not json.loads(result.stdout)['signer_pinned']
    finally:
        store.close()


def test_all_c0_c1_controls_removed_except_newline_tab():
    controls = ''.join(chr(n) for n in range(160) if n < 32 or n >= 127)
    assert safe_text(controls) == '\t\n'
    assert safe_text('a\x1b[2Jb\x1b]8;;https://invalid\x07c\x1b]8;;\x07') == 'abc'


def test_console_cannot_execute_package_escape_sequences():
    stream = io.StringIO()
    console = object.__new__(Console)
    console.stream, console.color = stream, True
    console.say('file\x1b[2J\x1b[31mRED\x07\x85')
    assert stream.getvalue() == 'fileRED\n'
    stream.seek(0)
    stream.truncate()
    console.say(console.paint('safe\x1b[2J', 'bold'))
    assert '\x1b[2J' not in stream.getvalue()
    assert 'safe' in stream.getvalue() and 'TGWSTYLE' not in stream.getvalue()


def test_comparison_checks_both_pins_and_sanitizes_its_separate_output_path(tmp_path):
    from test_chat_comparison import archive, row
    first, pin = archive(tmp_path / 'first.zip', [{**row(), 'from': 'sender\x1b[2J\x85'}])
    second, other_pin = archive(tmp_path / 'second.zip', [])
    command = [sys.executable, '-m', 'tgwitness.verify', str(first), '--compare', str(second)]
    plain = subprocess.run(command + ['--plain'], capture_output=True, text=True, encoding='utf-8')
    assert plain.returncode == 0 and plain.stdout.startswith('ASSURANCE: self_attested')
    assert '\x1b' not in plain.stdout and '\x85' not in plain.stdout
    for flags, expected in [([], 2), (['--fingerprint', pin], 2),
                            (['--fingerprint', pin, '--compare-fingerprint', other_pin], 0)]:
        result = subprocess.run(command + ['--strict', '--json', *flags], capture_output=True)
        assert result.returncode == expected
        value = json.loads(result.stdout)
        assert value['signer_pinned'] == (expected == 0)
        assert value['result']['only_first'][0]['from'] == 'sender\x1b[2J\x85'


def test_comparison_authenticated_future_format_keeps_strict_exit_three(tmp_path):
    path = future(tmp_path)
    command = [sys.executable, '-m', 'tgwitness.verify', str(path), '--compare', str(path), '--strict', '--json']
    assert subprocess.run(command, capture_output=True).returncode == 3
