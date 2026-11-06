"""The CI evidence suite must execute pytest bodies, not merely import their modules."""
import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_checks


def test_failing_pytest_body_and_plain_check_both_execute(tmp_path, monkeypatch):
    scripts = tmp_path / 'tools'
    scripts.mkdir()
    (scripts / 'test_failure.py').write_text('def test_reject():\n    assert False, "BODY_EXECUTED"\n')
    (scripts / 'check_plain.py').write_text('print("PLAIN_EXECUTED")\n')
    monkeypatch.setattr(run_checks, 'ROOT', tmp_path)
    monkeypatch.setitem(run_checks.SUITES, 'evidence', ('test_failure.py', 'check_plain.py'))
    output = tmp_path / 'results'
    passed, results = asyncio.run(run_checks.run_checks(run_checks.suite_checks('evidence'), output,
                                                       workers=1, timeout=60, cwd=tmp_path))
    assert not passed
    assert [(r['name'], r['status']) for r in results] == [('test_failure', 'failed'), ('check_plain', 'passed')]
    assert 'BODY_EXECUTED' in (output / 'test_failure.log').read_text()
    assert 'PLAIN_EXECUTED' in (output / 'check_plain.log').read_text()
