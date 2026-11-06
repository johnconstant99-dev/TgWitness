"""The static demo must show a usable case and deliver actual verifiable sample files."""
import hashlib
import json
import os
from pathlib import Path
import zipfile

from playwright.sync_api import expect, sync_playwright

if __package__:
    from .browser_helpers import answer_panel_dialog
else:
    from browser_helpers import answer_panel_dialog


def check_secret_chat_demo(browser, url, output, route_request, errors, failed):
    context = browser.new_context(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
    context.route("**/*", route_request)
    page = context.new_page()
    calls = []
    page.on("request", lambda request: calls.append((request.method, request.url)))
    page.on("pageerror", lambda error: errors.append("secret chat demo: " + str(error)))
    page.on("response", lambda response: failed.append(response.url) if response.status >= 400 else None)
    page.goto(url + "demo/?lang=en", wait_until="networkidle")
    page.locator('#demo-banner [data-secret-demo-open]').click()
    dialog = page.locator('#secret-demo')
    expect(dialog).to_be_visible()
    expect(dialog).to_contain_text('These entries are not signed evidence.')
    expect(page.locator('#secret-demo-feed')).to_contain_text('Timer: 15 s')
    page.locator('[data-secret-action="delete"]').click()
    expect(page.locator('#secret-demo-feed .secret-demo-retained')).to_contain_text('15-second timer')
    expect(page.locator('#secret-demo-feed')).to_contain_text('copy retained')
    page.locator('[data-secret-action="file"]').click()
    with page.expect_download() as pending:
        page.locator('[data-secret-action="download"]').click()
    saved = output / 'fictional-secret-chat-note.txt'
    pending.value.save_as(saved)
    assert saved.read_text(encoding='utf-8').startswith('SYNTHETIC DEMONSTRATION\n')
    page.locator('#secret-demo-message').fill('<img src=x onerror="alert(1)">')
    page.locator('#secret-demo-send button').click()
    expect(page.locator('#secret-demo-feed .secret-demo-out')).to_contain_text('<img src=x')
    expect(page.locator('#secret-demo-feed img')).to_have_count(0)
    expect(page.locator('#secret-demo-feed')).to_contain_text('Scripted reply:')
    page.locator('[data-secret-action="end"]').click()
    expect(page.locator('#secret-demo-message')).to_be_disabled()
    expect(page.locator('#secret-demo-feed')).to_contain_text('Earlier entries remain visible.')
    page.locator('#secret-demo-user').fill('@new_sample')
    page.locator('#secret-demo-start button').click()
    expect(page.locator('#secret-demo-state')).to_contain_text('Waiting for peer')
    expect(page.locator('#secret-demo-message')).to_be_disabled()
    page.locator('[data-secret-action="peer-accept"]').click()
    expect(page.locator('#secret-demo-message')).to_be_enabled()
    page.locator('[data-secret-action="incoming"]').click()
    expect(page.locator('#secret-demo-state')).to_contain_text('Incoming request')
    page.locator('[data-secret-action="accept"]').click()
    expect(page.locator('#secret-demo-state')).to_contain_text('Active')
    page.locator('[data-secret-action="reset"]').click()
    expect(page.locator('#secret-demo-chats button')).to_have_count(2)
    expect(page.locator('#secret-demo-feed')).not_to_contain_text('<img src=x')
    for width, theme in ((1440, 'light'), (390, 'dark'), (320, 'light')):
        page.set_viewport_size({'width': width, 'height': 1000})
        page.evaluate('theme => document.documentElement.dataset.theme = theme', theme)
        assert dialog.evaluate('node => node.scrollWidth <= node.clientWidth + 1')
        assert dialog.evaluate('node => node.getBoundingClientRect().right <= innerWidth')
        page.screenshot(path=str(output / f'demo-secret-chat-{width}-{theme}.png'))
    page.keyboard.press('Escape')
    expect(dialog).not_to_be_visible()
    expect(page.locator('#demo-banner [data-secret-demo-open]')).to_be_focused()
    page.set_viewport_size({'width': 1440, 'height': 1000})
    page.locator('.sidebar [data-view="sources"]').click()
    page.locator('#view-sources [data-secret-demo-open]').click()
    expect(dialog).to_be_visible()
    page.reload(wait_until='networkidle')
    page.locator('#demo-banner [data-secret-demo-open]').click()
    expect(page.locator('#secret-demo-chats button')).to_have_count(2)
    assert not any(method != 'GET' or '/api/secret-chats' in path for method, path in calls), calls
    context.close()
    print('Secret Chat demo: requests, replies, attachment, retained deletion, reset, literal text, keyboard and mobile checks passed', flush=True)


def check_demo_downloads(browser, url, output, route_request, errors, failed):
    context = browser.new_context(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
    context.route("**/*", route_request)
    page = context.new_page()
    page.add_init_script("window.showSaveFilePicker = undefined;")
    page.on("pageerror", lambda error: errors.append("demo downloads: " + str(error)))
    page.on("response", lambda response: failed.append(response.url) if response.status >= 400 else None)
    files_requested = []
    page.on("request", lambda request: files_requested.append(request.url) if "/demo/downloads/" in request.url else None)
    page.goto(url + "demo/?lang=en", wait_until="networkidle")
    expect(page.locator("#chat-feed .sender").first).to_be_visible()
    assert "Unknown" not in page.locator("#chat-feed .sender").all_text_contents()
    assert files_requested == [], "Sample downloads should not slow the initial demo load"
    expect(page.locator('.sidebar [data-view="integrations"]')).to_be_hidden()
    page.locator('#nav-more > summary').click()
    page.locator('.sidebar [data-view="integrations"]').click()
    expect(page.locator("#view-integrations")).to_be_visible()
    expect(page.locator("#ai-settings")).to_be_hidden()
    page.locator('.sidebar [data-view="evidence"]').click()
    expect(page.locator("#view-evidence")).to_be_visible()
    expect(page.locator('#export-task-journal')).to_have_attribute('aria-pressed', 'true')
    expect(page.locator('#export-account-panel')).to_be_hidden()
    expect(page.locator('#view-evidence [data-export="html"]')).to_be_visible()
    expect(page.locator('#view-evidence [data-export="jsonl"]')).to_be_hidden()
    answers = page.request.get(url + "demo/fixtures.json").json()
    for fmt in ("zip", "html", "jsonl", "csv"):
        if fmt == "jsonl":
            page.locator('#export-more-formats > summary').click()
        with page.expect_download() as pending:
            page.locator(f'#view-evidence [data-export="{fmt}"]').click()
            answer_panel_dialog(page)
        download = pending.value
        assert download.failure() is None
        saved = output / ("demo-sample." + fmt)
        download.save_as(saved)
        data = saved.read_bytes()
        assert len(data) == answers["/api/export/" + fmt]["bytes"]
        assert hashlib.sha256(data).hexdigest() == answers["/api/export/" + fmt]["sha256"]
    checked = json.loads(answers["/api/verify"]["text"])
    with zipfile.ZipFile(output / "demo-sample.zip") as bundle:
        manifest = json.loads(bundle.read("manifest.json"))
        assert manifest["event_count"] == checked["events"]
        assert manifest["head_hash"] == checked["head_hash"]
        events = [json.loads(line) for line in bundle.read("events.jsonl").splitlines()]
    auxiliary = {}
    for endpoint in ("/api/checkpoint", "/api/run-receipt", "/api/anchor-request"):
        descriptor = answers[endpoint]
        response = page.request.get(url + "demo/" + descriptor["file"])
        assert response.status == 200
        body = response.body()
        assert len(body) == descriptor["bytes"]
        assert hashlib.sha256(body).hexdigest() == descriptor["sha256"]
        auxiliary[endpoint] = body
    receipt = json.loads(auxiliary["/api/run-receipt"])
    started = next(event for event in events if event["seq"] == receipt["statement"]["journal_event_seq"])
    assert started["kind"] == "process.started"
    assert started["payload"]["run"] == receipt["statement"]["run"]
    assert receipt["public_key"] == manifest["public_key"]
    signed = page.evaluate("""async receipt => {
      function canonical(value) {
        if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
        if (value !== null && typeof value === 'object') return '{' + Object.keys(value).sort()
          .map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
        if (typeof value === 'number' && !Number.isSafeInteger(value))
          throw new Error('Demo receipt number cannot be represented exactly in this browser');
        return JSON.stringify(value);
      }
      const decode = text => Uint8Array.from(atob(text), char => char.charCodeAt(0));
      const key = await crypto.subtle.importKey('raw', decode(receipt.public_key), 'Ed25519', false, ['verify']);
      const verify = statement => crypto.subtle.verify('Ed25519', key, decode(receipt.signature),
        new TextEncoder().encode(canonical(statement)));
      const changed = structuredClone(receipt.statement);
      changed.run.targets[0].title += ' changed';
      return {original: await verify(receipt.statement), changed: await verify(changed)};
    }""", receipt)
    assert signed == {"original": True, "changed": False}, signed
    account = json.loads(answers["/api/account-export"]["text"])["jobs"][0]
    assert account["ready"] and account["disclosures"][0]["ready"]
    page.locator('#export-task-account').click()
    expect(page.locator('#export-task-account')).to_have_attribute('aria-pressed', 'true')
    expect(page.locator('#account-export-card')).to_be_visible()
    expect(page.locator("#account-export-jobs")).to_contain_text(account["id"][:10])
    expect(page.locator("#account-export-jobs")).to_contain_text(account["disclosures"][0]["id"][:10])
    account_paths = {
        "download": f'/api/account-export/{account["id"]}/download',
        "disclosure-download": f'/api/account-export/{account["id"]}/disclosures/{account["disclosures"][0]["id"]}/download',
    }
    for action, path in account_paths.items():
        for repeat in range(2):
            with page.expect_download() as pending:
                page.locator(f'[data-account-export-action="{action}"]').click()
                answer_panel_dialog(page)
            sample = output / f'demo-{action}-{repeat}.zip'
            pending.value.save_as(sample)
            data = sample.read_bytes()
            assert len(data) == answers[path]["bytes"]
            assert hashlib.sha256(data).hexdigest() == answers[path]["sha256"]
    assert len(files_requested) == 8
    page.locator('#export-task-journal').click()
    expect(page.locator('#export-task-journal')).to_have_attribute('aria-pressed', 'true')
    page.locator("#verify-journal").click()
    expect(page.locator("#verification-result")).to_contain_text(f'Verified {checked["events"]} event signatures')
    assert page.evaluate("fetch('/api/collector/start', {method:'POST'}).then(r=>r.status)") == 403
    assert page.evaluate("fetch('/api/report-options', {method:'POST'}).then(r=>r.status)") == 403
    assert page.evaluate("fetch('/api/account-export/start', {method:'POST'}).then(r=>r.status)") == 403
    page.screenshot(path=str(output / "demo-exports-1440.png"))
    context.close()
    check_secret_chat_demo(browser, url, output, route_request, errors, failed)
    print("Online demo: named sample case, all nine download hashes, run receipt signature and tamper rejection, "
          "lazy downloads and read-only actions passed", flush=True)


def main():
    import argparse

    if __package__:
        from .site_test_server import site_server
    else:
        from site_test_server import site_server

    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site-root', type=Path, default=root / 'dist/site')
    parser.add_argument('--output', type=Path, default=root / 'test-results/demo-downloads')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    errors, external, failed = [], [], []
    with site_server(args.site_root) as url, sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, channel=os.environ.get('TGWITNESS_BROWSER_CHANNEL') or None)

        def local_only(route):
            if route.request.url.startswith(url):
                route.continue_()
            else:
                external.append(route.request.url)
                route.abort()

        check_demo_downloads(browser, url, args.output, local_only, errors, failed)
        assert errors == [], errors
        assert external == [], external
        assert failed == [], failed
        browser.close()
    receipt = {'passed': True, 'artifacts': 9, 'receipt_signature_and_tamper_rejection': True,
               'progressive_navigation': True, 'read_only': True, 'page_errors': errors,
               'external_requests': external, 'failed_requests': failed}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
