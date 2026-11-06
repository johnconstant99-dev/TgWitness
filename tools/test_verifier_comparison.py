"""Signed archives and strict CLI options must not produce false matches or checks."""
import io
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import chat_export, verify  # noqa: E402
from tgwitness.security import Vault  # noqa: E402
from tgwitness.store import canonical  # noqa: E402


@pytest.fixture
def archives(tmp_path):
    vault = Vault(tmp_path / "keys")
    def build(name, text, account=1, **extra):
        source = tmp_path / (name + '.jsonl')
        source.write_bytes(canonical({'id': 1, 'date': '2026-11-05T00:00:00+00:00', 'from_id': 42,
                                     'text': text, **extra}) + b'\n')
        target = tmp_path / (name + '.zip')
        chat_export.build_bundle(source, {'chat': {'id': -1000000000001, 'title': 'Synthetic'},
                                         'account': {'id': account}, 'message_count': 1}, vault, target)
        return target
    return build, verify.fingerprint(vault.public_key)


@pytest.mark.parametrize('rich', [False, True])
def test_comparison_uses_text_beyond_the_display_excerpt(archives, rich):
    build, key = archives
    prefix = 'same ' * 60
    a, b = prefix + 'PAY ALICE', prefix + 'PAY BOB'
    if rich:
        a, b = [prefix, {'type': 'bold', 'text': 'PAY ALICE'}], [prefix, {'type': 'bold', 'text': 'PAY BOB'}]
    result = verify.compare_chat_exports(build('a', a), build('b', b), key, key)
    assert len(result['changed']) == 1 and result['unchanged'] == 0
    assert len(result['changed'][0]['first']['text']) <= 300
    other = verify.compare_chat_exports(build('c', a), build('d', b, account=2), key, key)
    assert other['method'] == 'content' and other['unchanged'] == 0
    assert len(other['only_first']) == len(other['only_second']) == 1


def test_heuristic_pairs_still_compare_full_content(archives):
    build, key = archives
    # Equal visible text matches across accounts, but its recorded edit differs.
    result = verify.compare_chat_exports(build('a', 'same', edited='2026-11-01T00:00:00Z'),
                                        build('b', 'same', account=2, edited='2026-11-02T00:00:00Z'), key, key)
    assert result['unchanged'] == 0 and len(result['changed']) == 1


@pytest.mark.parametrize('field,first,second', [
    ('reply_to_message_id', 10, 20), ('from_id', 1001, 1002),
    ('date', '2026-11-05T00:00:00+00:00', '2026-11-05T10:00:00+00:00'),
    ('date_unixtime', '1793836800', '1793872800'),
    ('forwarded_from', 'Original source', 'Other source'),
    ('reactions', [{'reaction': '👍', 'count': 1}], [{'reaction': '👍', 'count': 2}]),
    ('entities', [{'type': 'text_url', 'url': 'https://example.test/a'}],
                 [{'type': 'text_url', 'url': 'https://example.test/b'}]),
    ('future_metadata', {'value': 1}, {'value': 2}),
])
def test_comparison_checks_every_recorded_metadata_field(archives, field, first, second):
    build, key = archives
    result = verify.compare_chat_exports(build('a', 'Да', **{field: first}),
                                        build('b', 'Да', **{field: second}), key, key)
    assert result['unchanged'] == 0 and len(result['changed']) == 1
    assert result['changed'][0]['changed_fields'] == [field]


def test_equal_records_ignore_object_key_order_but_distinguish_missing_fields(archives):
    build, key = archives
    a = build('a', 'same', details={'a': 1, 'b': 2})
    b = build('b', 'same', details={'b': 2, 'a': 1})
    assert verify.compare_chat_exports(a, b, key, key)['unchanged'] == 1
    result = verify.compare_chat_exports(build('c', 'same'), build('d', 'same', reply_to_message_id=None), key, key)
    assert result['unchanged'] == 0 and result['changed'][0]['changed_fields'] == ['reply_to_message_id']


@pytest.mark.parametrize('options', [
    ['--require-witness', '--witness', 'missing.zip', '--witness-fingerprint', 'f' * 64],
    ['--checkpoint', 'missing.json'], ['--tsa-ca', 'missing.pem'], ['--check-drand'],
    ['--witness', 'missing.zip'], ['--channel', 'missing.json'], ['--evidence', 'missing.zip'], ['--board'],
])
def test_comparison_rejects_checks_it_cannot_perform(archives, monkeypatch, capsys, options):
    build, key = archives
    first, second = build('a', 'same'), build('b', 'same')
    monkeypatch.setattr(sys, 'argv', ['verify.py', str(first), '--compare', str(second), '--fingerprint', key,
                                    '--compare-fingerprint', key, '--json', *options])
    with pytest.raises(SystemExit) as stopped:
        verify.main()
    assert stopped.value.code == 2
    output = capsys.readouterr()
    assert 'cannot be used with --compare' in output.err
    assert not output.out.strip(), 'A rejected comparison cannot print verified=true'


@pytest.mark.parametrize('status', ['pending', 'bitcoin-unverified', 'unknown'])
def test_ots_structure_only_does_not_get_a_positive_indicator(status):
    console = verify.Console(io.StringIO(), 'en', False)
    checks = []
    console.check = lambda state, label, detail: checks.append((state, label, detail))
    console.timestamps([{'kind': 'opentimestamps', 'checkpoint': 'synthetic', 'service': 'test', 'status': status}])
    assert checks[0][0] != 'ok'
    assert 'in Bitcoin:' not in checks[0][2]
    if status == 'unknown':
        assert 'unknown' in checks[0][2]


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-q']))
