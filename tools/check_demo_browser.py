"""The static demo must show a usable case and deliver actual verifiable sample files."""
import hashlib
import json
import zipfile

from playwright.sync_api import expect


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
    page.locator('.sidebar [data-view="integrations"]').click()
    expect(page.locator("#view-integrations")).to_be_visible()
    expect(page.locator("#ai-settings")).to_be_hidden()
    page.locator('.sidebar [data-view="evidence"]').click()
    expect(page.locator("#view-evidence")).to_be_visible()
    answers = page.request.get(url + "demo/fixtures.json").json()
    for fmt in ("zip", "html", "jsonl", "csv"):
        with page.expect_download() as pending:
            page.locator(f'#view-evidence [data-export="{fmt}"]').click()
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
    assert len(files_requested) == 4
    page.locator("#verify-journal").click()
    expect(page.locator("#verification-result")).to_contain_text(f'Verified {checked["events"]} event signatures')
    assert page.evaluate("fetch('/api/collector/start', {method:'POST'}).then(r=>r.status)") == 403
    assert page.evaluate("fetch('/api/report-options', {method:'POST'}).then(r=>r.status)") == 403
    page.screenshot(path=str(output / "demo-exports-1440.png"))
    context.close()
    print("Online demo: named sample case, lazy downloads matching published hashes and read-only actions passed", flush=True)
