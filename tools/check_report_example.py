"""The browsable fictional report must be the exact document in its signed ZIP."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import zipfile

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.site_test_server import site_server


def check_report_example(browser, url, output):
    output.mkdir(parents=True, exist_ok=True)
    context = browser.new_context(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
    page = context.new_page()
    errors, external = [], []
    page.on('pageerror', lambda error: errors.append(str(error)))
    def route_request(route):
        if route.request.url.startswith(url):
            route.continue_()
        else:
            external.append(route.request.url)
            route.abort()
    context.route('**/*', route_request)
    page.goto(url + 'demo/?lang=en', wait_until='networkidle')
    expect(page.locator('#demo-report-preview')).to_be_visible()
    page.locator('#demo-report-preview').click()
    expect(page).to_have_url(url + 'demo/report/')
    expect(page.locator('h1')).to_have_text('A report your recipient can read.')
    frame = page.frame_locator('iframe')
    expect(frame.locator('#record-000001')).to_be_visible()
    expect(frame.locator('body')).to_contain_text('SYNTHETIC DEMO')
    descriptor = page.request.get(url + 'demo/report/example.json').json()
    assert descriptor['synthetic'] is True and descriptor['language'] == 'en'
    report = page.request.get(url + 'demo/report/report.html').body()
    assert hashlib.sha256(report).hexdigest() == descriptor['report_sha256']
    with page.expect_download() as pending:
        page.locator('a[download]').click()
    archive = output / 'sharing-copy.zip'
    pending.value.save_as(archive)
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == descriptor['sha256']
    with zipfile.ZipFile(archive) as source:
        assert source.read('index.html') == report
        manifest = json.loads(source.read('manifest.json'))
        assert manifest['format'] == 'tgwitness-account-disclosure-v1'
        assert hashlib.sha256(base64.b64decode(manifest['public_key'], validate=True)).hexdigest() == \
            manifest['fingerprint'] == descriptor['fingerprint']
        assert set(source.namelist()) == set(manifest['files']) | {'manifest.json', 'manifest.sig'}
        assert len(source.namelist()) == len(set(source.namelist()))
        for name, checksum in manifest['files'].items():
            assert hashlib.sha256(source.read(name)).hexdigest() == checksum, name
        # Use the browser's native verifier so the site-only CI needs no app dependencies.
        def encoded(value):
            return base64.b64encode(json.dumps(value, ensure_ascii=False, sort_keys=True,
                separators=(',', ':'), allow_nan=False).encode('utf-8')).decode('ascii')
        changed = {**manifest, 'created_at': manifest['created_at'] + ' changed'}
        signed = page.evaluate('''async data => {
          const decode = text => Uint8Array.from(atob(text), char => char.charCodeAt(0));
          const key = await crypto.subtle.importKey('raw', decode(data.public_key), 'Ed25519', false, ['verify']);
          const verify = message => crypto.subtle.verify('Ed25519', key, decode(data.signature), decode(message));
          return {original: await verify(data.original), changed: await verify(data.changed)};
        }''', {'public_key': manifest['public_key'], 'signature': source.read('manifest.sig').decode('ascii'),
              'original': encoded(manifest), 'changed': encoded(changed)})
        assert signed == {'original': True, 'changed': False}, signed
        assert manifest['policy']['identity_mode'] == 'pseudonymize_all'
        assert not manifest['policy']['include_media']
        assert manifest['counts']['messages'] > 0
    for width in (390, 1440):
        page.set_viewport_size({'width': width, 'height': 1000})
        for theme in ('light', 'dark'):
            page.emulate_media(color_scheme=theme)
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
            assert frame.locator('html').evaluate('el=>el.scrollWidth <= el.clientWidth + 1')
            page.screenshot(path=str(output / f'example-{width}-{theme}.png'), full_page=True)
    assert errors == [] and external == [], (errors, external)
    context.close()
    (output / 'receipt.json').write_text(json.dumps({'passed': True, 'exact_archived_report': True,
        'signature_verified': True, 'tampered_signature_rejected': True, 'all_file_hashes_verified': True,
        'synthetic_label': True, 'mobile': True, 'external_requests': external}, indent=2) + '\n')


if __name__ == '__main__':
    with site_server(ROOT / 'dist/site') as url, sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        check_report_example(browser, url, ROOT / 'test-results/report-example')
        browser.close()
    print('Signed report example: exact archived HTML, valid signature, fictional labels and responsive preview passed.')
