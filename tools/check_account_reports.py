"""Offline account/sharing report acceptance with synthetic accounts and fresh keys."""
import asyncio
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import sys
import tempfile
import tracemalloc
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import account_report, i18n
from tgwitness.account_export import AccountExport, AccountExportOptions, durable_write, read_json, sha
from tgwitness.disclosure import DisclosurePolicy, Disclosures
from tgwitness.report import RTL
from tgwitness.security import Vault
from tgwitness.store import Store, canonical
from tgwitness.verify import fingerprint, verify_account_disclosure, verify_account_export
from tools.check_disclosure_privacy import SECRET_METADATA, SyntheticTransport as PrivacyTransport
from tools.demo_account_export import SyntheticCollector

MESSAGE = 'UNCHANGED العربية 中文 Straße \u202e <img src=x onerror=window.reportXSS=1>\nSecond original line'


class ReportTransport(PrivacyTransport):
    async def page(self, task, cursor):
        rows, next_cursor, terminal = await super().page(task, cursor)
        for row, _ in rows:
            row['text'] = MESSAGE
        return rows, next_cursor, terminal


class Document(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.tags, self.links, self.root, self.details = [], [], {}, 0
        self.feed(source)
        self.close()
        assert source.startswith('<!doctype html>') and source.endswith('</html>')

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append(tag)
        assert tag not in ('script', 'iframe', 'img', 'video', 'audio', 'object', 'embed', 'form', 'link'), tag
        assert not any(key.startswith('on') or key in ('src', 'srcdoc') for key in attrs), attrs
        if tag == 'html':
            self.root = attrs
        if tag == 'a':
            href = attrs.get('href', '')
            assert '://' not in href and ':' not in href and not href.startswith('//'), href
            self.links.append(href)
        if tag == 'details':
            assert 'open' not in attrs, attrs
            self.details += 1
        if tag == 'meta' and attrs.get('http-equiv') == 'Content-Security-Policy':
            assert "default-src 'none'" in attrs['content'] and "base-uri 'none'" in attrs['content']


def pure_checks():
    for language in i18n.LANGUAGES:
        assert AccountExportOptions(report_language=language).report_language == language
        assert DisclosurePolicy(purpose='Synthetic', report_language=language).report_language == language
        context = {'report_language': language, 'counts': {'messages': 0}, 'policy': {'report_language': language},
                   'fingerprint': 'a' * 64, 'source_archive_sha256': 'b' * 64, 'limitations': []}
        rendered = b''.join(account_report.sharing_report(context, iter(()))).decode()
        parsed = Document(rendered)
        assert parsed.root == {'lang': language, 'dir': 'rtl' if language in RTL else 'ltr'}
        assert i18n.words(language).get('Messages', 'Messages') in rendered
    for model, extra in ((AccountExportOptions, {}), (DisclosurePolicy, {'purpose': 'Synthetic'})):
        for language in ('xx', '../ru', 'auto', '<script>', 'RU'):
            try:
                model(report_language=language, **extra)
            except ValueError:
                pass
            else:
                raise AssertionError('Invalid report language accepted')

    context = {'report_language': 'en', 'policy': {'purpose': 'Public purpose', 'sender_ids': ['SECRET_FILTER'],
               'text_contains': ['SECRET_TERM'], 'mapping': 'SECRET_MAPPING'}, 'counts': {'messages': 1},
               'fingerprint': 'a' * 64, 'source_archive_sha256': 'b' * 64, 'limitations': []}
    row = {'before': 'SECRET_SOURCE', 'chat': {'id': 'chat-1', 'title': 'Public chat', 'raw': 'SECRET_CHAT'},
           'message': {'id': 'message-1" onmouseover="window.reportXSS=3', 'sender': 'Participant-1', 'date': '2026-11-01T12:00:00Z', 'text': MESSAGE,
                       'forward': {'name': 'SECRET_FORWARD'}, 'reply': 'SECRET_REPLY', 'contact': 'SECRET_CONTACT',
                       'attachments': [{'outcome': 'saved', 'file': 'javascript:SECRET_URI'},
                                       {'outcome': 'saved', 'file': 'media/' + 'a' * 64, 'bytes': {'raw': 'SECRET_BYTES'},
                                        'filename': 'SECRET_FILENAME', 'sha256': {'raw': 'SECRET_DIGEST'}}]}}
    rendered = b''.join(account_report.sharing_report(context, iter([row]))).decode()
    parsed = Document(rendered)
    assert 'SECRET' not in rendered and parsed.details == 1
    assert 'media/' + 'a' * 64 in parsed.links
    assert '&lt;img' in rendered and MESSAGE not in rendered
    assert '<p class="message-text" dir="auto">UNCHANGED' in rendered

    consumed = [0]

    def records():
        for number in range(6000):
            consumed[0] += 1
            yield {'id': number + 1, 'sender': {'first_name': 'Synthetic'}, 'text': 'x' * 2048,
                   'date': '2026-11-01T12:00:00Z', 'attachments': []}

    report = account_report.account_chat({'report_language': 'en'}, {'id': 1, 'title': 'Stream'}, records())
    next(report)
    assert consumed[0] == 0, 'Renderer eagerly consumed messages before yielding its header'
    tracemalloc.start()
    total = 0
    for chunk in report:
        total += len(chunk)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert consumed[0] == 6000 and total > 20 * 1024**2
    assert peak < 6 * 1024**2, peak
    return peak


async def manager_checks(directory, output):
    vault, store = Vault(directory), Store(directory)
    store.bind(vault)
    store.set_setting('account', {'id': ReportTransport.account_id})
    collector = SyntheticCollector()
    collector.store = store
    exports = AccountExport(collector, store, vault)
    exports.transport_factory = ReportTransport
    disclosures = Disclosures(exports, vault)
    pin = fingerprint(vault.public_key)
    try:
        for language in ('en', 'ru', 'ar', 'zh'):
            job = await exports.start({'transport': 'regular', 'report_language': language,
                                       'purpose': 'Synthetic report <svg onload=window.reportXSS=2>',
                                       'include_profile': False, 'include_contacts': False, 'media_types': []})
            await asyncio.wait_for(asyncio.shield(exports.task), 30)
            assert exports.public(job['id'])['ready'], exports.public(job['id'])
            source = exports.result_path(job['id'])
            before = hashlib.sha256(source.read_bytes()).hexdigest()
            checked = verify_account_export(source, pin)
            assert checked['counts']['messages'] == 4 and checked['key_pinned']
            with zipfile.ZipFile(source) as archive:
                manifest = json.loads(archive.read('manifest.json'))
                assert manifest['report_language'] == manifest['options']['report_language'] == language
                for name in ('index.html', 'chats/101.html'):
                    body = archive.read(name).decode()
                    assert Document(body).root['lang'] == language
                    (output / f'account-{language}-{Path(name).name}').write_text(body, encoding='utf-8')
                rows = [json.loads(line) for name in archive.namelist() if name.startswith('data/')
                        for line in archive.read(name).splitlines()]
                assert all(row['text'] == MESSAGE for row in rows)
            policy = {'purpose': 'Public review SECRET_FILTER', 'report_language': language,
                      'text_contains': ['SECRET_FILTER', 'UNCHANGED'], 'identity_mode': 'pseudonymize_all'}
            preview = disclosures.preview(job['id'], policy, 'synthetic-reviewer')
            result = await disclosures.create(job['id'], preview['preview_id'], 'synthetic-reviewer')
            shared = disclosures.result_path(job['id'], result['id'])
            checked = verify_account_disclosure(shared, pin, source=source)
            assert checked['source_reference_checked'] and checked['counts']['messages'] == 4
            assert not checked['derivation_correctness_established']
            with zipfile.ZipFile(shared) as archive:
                manifest = json.loads(archive.read('manifest.json'))
                assert manifest['report_language'] == manifest['policy']['report_language'] == language
                assert 'text_contains' not in manifest['policy']
                body = archive.read('index.html').decode()
                assert Document(body).root['lang'] == language
                assert 'SECRET_FILTER' not in body and SECRET_METADATA not in body
                shared_rows = [json.loads(line) for line in archive.read('messages.jsonl').splitlines()]
                assert all(row['message']['text'] == MESSAGE.replace('Straße', '[redacted]') for row in shared_rows)
                (output / f'sharing-{language}.html').write_text(body, encoding='utf-8')
            assert hashlib.sha256(source.read_bytes()).hexdigest() == before
            await exports.resume(job['id'])
            assert hashlib.sha256(source.read_bytes()).hexdigest() == before, 'Resume rewrote a published archive'

        # Construct a valid pre-feature signed job before any acquisition. Resume must
        # retain the original raw options/hash rather than inserting a new default.
        job = await exports.start({'transport': 'regular', 'include_profile': False,
                                   'include_contacts': False, 'media_types': []})
        await exports.pause(job['id'])
        directory = exports.directory(job['id'])
        old_job = exports.verify_signed(read_json(directory / 'job.json'))
        old_job['options'].pop('report_language')
        old_job['options_sha256'] = sha(canonical(old_job['options']))
        original_job_bytes = canonical(exports.signed(old_job))
        durable_write(directory / 'job.json', original_job_bytes)
        exports.current['options'] = old_job['options']
        exports.persist()
        await exports.resume(job['id'])
        await asyncio.wait_for(asyncio.shield(exports.task), 30)
        assert exports.public(job['id'])['ready'], exports.public(job['id'])
        assert (directory / 'job.json').read_bytes() == original_job_bytes
        source = exports.result_path(job['id'])
        assert verify_account_export(source, pin)['counts']['messages'] == 4
        with zipfile.ZipFile(source) as archive:
            manifest = json.loads(archive.read('manifest.json'))
            assert manifest['report_language'] == 'en' and 'report_language' not in manifest['options']
            assert manifest['options_sha256'] == old_job['options_sha256']
    finally:
        await disclosures.close()
        await exports.close()
        store.close()


def browser_checks(output):
    from playwright.sync_api import sync_playwright
    errors, requests = [], []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, channel=os.environ.get('TGWITNESS_BROWSER_CHANNEL') or None)
        page = browser.new_page()
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.on('request', lambda request: requests.append(request.url))
        for language in ('en', 'ru', 'ar', 'zh'):
            for width in (320, 390, 1440):
                page.set_viewport_size({'width': width, 'height': 1000})
                for theme in ('light', 'dark'):
                    page.emulate_media(color_scheme=theme)
                    page.set_content((output / f'sharing-{language}.html').read_text(encoding='utf-8'))
                    assert page.evaluate('document.documentElement.scrollWidth<=innerWidth'), (language, width)
                    assert page.locator('script,img,iframe').count() == 0
                    assert page.locator('details[open]').count() == 0
                    assert page.evaluate('window.reportXSS ?? 0') == 0
                    if language in ('en', 'ar') and width in (390, 1440):
                        page.screenshot(path=str(output / f'sharing-{language}-{width}-{theme}.png'))
        assert not errors and not requests, (errors, requests)
        browser.close()


def main():
    output = ROOT / 'test-results/account-reports'
    output.mkdir(parents=True, exist_ok=True)
    peak = pure_checks()
    with tempfile.TemporaryDirectory(prefix='account-reports-') as scratch:
        asyncio.run(manager_checks(Path(scratch), output))
    browser_checks(output)
    receipt = {'passed': True, 'languages_validated': len(i18n.LANGUAGES), 'signed_languages': ['en', 'ru', 'ar', 'zh'],
               'browser_viewports': [320, 390, 1440], 'themes': ['light', 'dark'], 'streamed_messages': 6000,
               'peak_stream_bytes': peak, 'legacy_raw_options_preserved': True, 'source_archives_unchanged': True,
               'xss_and_external_resources': False, 'private_selection_criteria_in_html': False}
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
