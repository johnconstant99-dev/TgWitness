"""All shipped panel languages on the active export and recipient handoff path."""
import json
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

from check_account_export_browser import DEFAULTS
from check_browser import RunningApp, launch_browser
from tgwitness import i18n


def main():
    errors, outbound, starts, active_keys, unchanged = [], [], [], set(), {}
    filename = 'tgwitness-disclosure-synthetic-copy.zip'
    note_keys = [
        'File: {filename}',
        'Extract the ZIP and open index.html to read this sharing copy. Review its scope, omissions and disclosure settings.',
        'Keep the ZIP unchanged. Follow README.txt to check its integrity using a signing-key fingerprint obtained independently from the sender.',
        'TgWitness signs these files; Telegram does not. An integrity check does not establish whether a message is true or who wrote it.',
    ]
    completion_keys = {
        'zip': 'Extract the ZIP and open report.html. Review coverage gaps and personal information. README.txt explains how to check integrity with an independently obtained signing-key fingerprint.',
        'html': 'Open the HTML report in your browser. Review coverage gaps and personal information before sending the unchanged file.',
        'jsonl': 'Review this data file in a compatible tool. Download the signed ZIP when your recipient also needs the readable report and verification tools.',
    }
    recovery_keys = {
        'paused': 'Progress is saved. Choose Resume to continue this job.',
        'waiting': 'Saved progress is kept. When the Telegram waiting period ends, choose Resume.',
        'failed': 'Review the error below, then choose Resume to retry from saved progress.',
    }
    jobs = [{
        'id': 'synthetic-source', 'phase': 'partial', 'active': False, 'ready': True,
        'created_at': '2026-11-01T12:00:00Z', 'counts': {'messages_exported': 3},
        'coverage': {'failures': 1}, 'omissions': ['Synthetic omitted attachment'],
        'disclosures': [{'id': 'synthetic-copy', 'ready': True}],
    }, {
        'id': 'synthetic-recovery', 'phase': 'paused', 'active': False, 'ready': False,
        'wait_until': '2099-11-01T12:00:00Z', 'error': 'Synthetic interrupted connection',
    }]
    with tempfile.TemporaryDirectory(prefix='handoff-languages-') as scratch:
        with RunningApp(Path(scratch), demo=True) as server, sync_playwright() as playwright:
            browser = launch_browser(playwright)
            context = browser.new_context(viewport={'width': 1440, 'height': 1000},
                                          locale='en-US', reduced_motion='reduce')

            def route_request(route):
                url = urlsplit(route.request.url)
                if url.hostname not in ('127.0.0.1', 'localhost'):
                    outbound.append(url.hostname)
                    route.abort()
                elif url.path == '/api/account-export':
                    route.fulfill(json={'jobs': jobs, 'defaults': DEFAULTS,
                                        'capabilities': {'can_start': True}})
                elif url.path.endswith('/disclosure/preview'):
                    route.fulfill(json={
                        'preview_id': 'synthetic-preview', 'expires_at': 4070908800,
                        'summary': {'messages_before': 5, 'messages_after': 3},
                        'samples': [{'after': 'Synthetic message stays unchanged'}], 'warnings': [],
                    })
                else:
                    route.continue_()

            context.route('**/*', route_request)
            page = context.new_page()
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('request', lambda request: starts.append(urlsplit(request.url).path)
                    if request.method == 'POST' and urlsplit(request.url).path.endswith('/start') else None)

            for lang in i18n.LANGUAGES:
                words = i18n.words(lang)

                def word(key):
                    active_keys.add(key)
                    assert lang == 'en' or key in words, (lang, 'missing active key', key)
                    return words.get(key, key)

                page.set_viewport_size({'width': 1440, 'height': 1000})
                page.goto(server.url + '/start?lang=' + lang)
                expect(page.locator('html')).to_have_attribute('lang', lang)
                expect(page.locator('html')).to_have_attribute('dir', 'rtl' if lang in ('ar', 'fa', 'ur', 'he') else 'ltr')
                expect(page.locator('#view-start')).to_be_visible()
                page.locator('[data-workflow="account"]').click()
                expect(page.locator('#account-export-dialog')).to_be_visible()
                expect(page.locator('#account-export-dialog-title')).to_have_text(word('Choose what to save'))
                expect(page.locator('#account-export-purpose')).to_have_attribute(
                    'placeholder', word('Why this account snapshot is being collected'))
                page.locator('#account-export-purpose').fill('Synthetic private purpose stays unchanged')
                page.locator('#account-export-dismiss').click()
                expect(page.locator('.account-export-original h3')).to_have_text(word('Original account archive'))
                expect(page.locator('[data-account-export-action="download"]')).to_have_text(word('Download original archive'))
                handoff = page.locator('.account-export-handoff')
                expect(handoff.locator('summary')).to_have_text(word('Review & hand off'))
                handoff.locator('summary').focus()
                page.keyboard.press('Enter')
                expected_note = '\n\n'.join(word(key).replace('{filename}', filename) for key in note_keys)
                expect(handoff.locator('textarea')).to_have_value(expected_note)
                expect(handoff.locator('textarea')).to_have_attribute('aria-label', word('Recipient note'))
                expect(handoff.locator('button')).to_have_text(word('Copy recipient note'))
                assert 'Synthetic private purpose' not in expected_note
                for width in (1440, 320):
                    page.set_viewport_size({'width': width, 'height': 1000})
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1'), (lang, width, 'handoff')

                for phase, key in recovery_keys.items():
                    jobs[1]['phase'] = phase
                    page.evaluate('()=>loadAccountExport()')
                    expect(page.locator('.account-export-next')).to_have_text(word(key))
                page.locator('[data-account-export-action="disclosure"]').click()
                expect(page.locator('#account-disclosure-title')).to_have_text(word('Prepare a sharing copy'))
                expect(page.locator('#account-disclosure-purpose')).to_have_attribute('placeholder', word('Who needs this file, and why'))
                page.locator('#account-disclosure-purpose').fill('Synthetic recipient purpose stays unchanged')
                page.locator('#account-disclosure-check').click()
                expect(page.locator('#account-disclosure-create')).to_be_enabled()
                expect(page.locator('#account-disclosure-check')).to_have_text(word('Preview sharing copy'))
                expect(page.locator('#account-disclosure-create')).to_have_text(word('Create signed sharing copy'))
                expect(page.locator('#account-disclosure-samples')).to_contain_text('Synthetic message stays unchanged')
                expect(page.locator('#account-disclosure-purpose')).to_have_value('Synthetic recipient purpose stays unchanged')
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1'), (lang, 'preview')
                page.locator('#account-disclosure-dismiss').click()
                page.locator('#export-task-journal').click()
                for fmt, key in completion_keys.items():
                    # Download mechanics already have dedicated acceptance; render each completion state here.
                    page.evaluate("""async format=>{
                      const update=(await exportsReady).begin({format,encrypted:format==='zip'});
                      update({phase:'done',total:8,expected:8});
                    }""", fmt)
                    expect(page.locator('#exports-next-copy')).to_have_text(word(key))
                    expect(page.locator('#exports-next > strong')).to_have_text(word('Review before handoff'))
                    if fmt == 'zip':
                        expect(page.locator('#exports-next-encrypted')).to_have_text(word(
                            'Open the outer ZIP with your password first. Send the password through a separate channel.'))
                    else:
                        expect(page.locator('#exports-next-encrypted')).to_be_hidden()
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1'), (lang, 'completion')
                if lang != 'en':
                    unchanged[lang] = sorted(key for key in active_keys if words.get(key) == key)
                print(lang + ': active handoff and completion passed', flush=True)

            assert not errors, errors
            assert not outbound, outbound
            assert not starts, starts
            browser.close()
    print(json.dumps({'passed': True, 'languages': list(i18n.LANGUAGES), 'widths': [1440, 320],
                      'active_keys': len(active_keys), 'missing_active_keys': [],
                      'unchanged_active_translations': {lang: keys for lang, keys in unchanged.items() if keys},
                      'page_errors': errors, 'external_requests': outbound, 'collection_starts': starts}, indent=2))


if __name__ == '__main__':
    main()
