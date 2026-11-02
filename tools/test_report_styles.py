"""Layout changes must keep the same signed observations and report selection."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import zipfile

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.build_report_styles import build
from tgwitness import report, report_design
from tgwitness.verify import verify_report


def test_style_is_independent_of_contents_and_older_settings():
    assert report.ReportOptions().design == 'classic'
    base = report.ReportOptions(template='custom', timeline=False, chat_chart=False,
                                selection={'enabled': True, 'chats': [-1001], 'kinds': ['message.edited']})
    for design in report_design.DESIGNS:
        changed = report.ReportOptions.model_validate({**base.model_dump(), 'design': design})
        assert changed.model_dump(exclude={'design'}) == base.model_dump(exclude={'design'})
        for preset in ('dossier', 'brief', 'activity', 'custom'):
            assert report.ReportOptions.model_validate({**changed.model_dump(), 'template': preset}).design == design
    for bad in ('../custom.css', '<script>', 'unknown', None, ['classic']):
        with pytest.raises(ValidationError):
            report.ReportOptions(design=bad)


def test_early_studio_designs_migrate_without_resetting_private_settings():
    for old, design in report_design.LEGACY.items():
        saved = report.ReportOptions(design=old, case_title='Keep my case', review_findings='Keep my findings',
                                     activity_chart=False, selection={'enabled': True, 'chats': [-1001]})
        assert saved.design == design and saved.case_title == 'Keep my case'
        assert saved.review_findings == 'Keep my findings' and not saved.activity_chart
        assert saved.selection.enabled and saved.selection.chats == [-1001]
        assert report.report_analytics.Presentation(design=old).design == design


def test_untrusted_internal_style_does_not_become_html():
    output = report.head(report.Words('en'), title='Test', description='', meta=[], linked={}, theme='auto',
                         design='" onload="alert(1)')
    assert 'data-report-design="classic"' in output
    assert 'onload="alert(1)' not in output


def test_all_styles_preserve_source_and_pass_independent_verification(tmp_path):
    receipts = build(tmp_path / 'styles')
    common = None
    for design, receipt in receipts.items():
        folder = tmp_path / 'styles' / design
        with zipfile.ZipFile(folder / 'evidence.zip') as archive:
            source = archive.read('events.jsonl')
            data = json.loads(archive.read('report.json'))['report']
            assert json.loads(archive.read('manifest.json'))['report']['design'] == design
            assert data['presentation']['design'] == design
            assert data['custody']['export']['report_options']['design'] == design
            assert data['analytics']['source']['sha256'] == hashlib.sha256(source).hexdigest()
            body = archive.read('report.html').decode('utf-8')
            assert f'data-report-design="{design}"' in body
            assert 'version-compare' in body and 'Saved text before deletion' in body
            assert '20 November' in body and '27 November' in body
            assert 'Unobserved message IDs' in body
            facts = copy.deepcopy({key: data[key] for key in ('subject', 'summary', 'analytics', 'changes', 'examination')})
            if common is None:
                common = source, facts
            else:
                assert (source, facts) == common, design
        for suffix in ('html', 'json', 'pdf'):
            verify_report(folder / ('report.' + suffix), receipt['fingerprint'])


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-q']))
