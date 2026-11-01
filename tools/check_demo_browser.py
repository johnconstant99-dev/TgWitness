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
        events = [json.loads(line) for line in bundle.read("events.jsonl").splitlines()]
    # Decode JSON from its original UTF-8 bytes, including non-ASCII target titles.
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
            sample = output / f'demo-{action}-{repeat}.zip'
            pending.value.save_as(sample)
            data = sample.read_bytes()
            assert len(data) == answers[path]["bytes"]
            assert hashlib.sha256(data).hexdigest() == answers[path]["sha256"]
    assert len(files_requested) == 8
    page.locator("#verify-journal").click()
    expect(page.locator("#verification-result")).to_contain_text(f'Verified {checked["events"]} event signatures')
    assert page.evaluate("fetch('/api/collector/start', {method:'POST'}).then(r=>r.status)") == 403
    assert page.evaluate("fetch('/api/report-options', {method:'POST'}).then(r=>r.status)") == 403
    assert page.evaluate("fetch('/api/account-export/start', {method:'POST'}).then(r=>r.status)") == 403
    page.screenshot(path=str(output / "demo-exports-1440.png"))
    context.close()
    print("Online demo: named sample case, all nine download hashes, run receipt signature and tamper rejection, "
          "lazy downloads and read-only actions passed", flush=True)
