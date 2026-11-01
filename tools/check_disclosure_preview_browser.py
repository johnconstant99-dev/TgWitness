"""Offline disclosure renderer regression; uses synthetic transformed samples only."""
import argparse
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
VIEWS = ROOT / "tgwitness" / "static" / "views"
HTML = b"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="/component.css"><style>
:root{--border:#d9dee6;--radius:8px;--surface:#fff;--surface-2:#f6f8fb;
--text:#1d2837;--muted:#596575;--warning-border:#e3b36f;--warning-soft:#fff6e7}
*{box-sizing:border-box}body{margin:16px;font:14px/1.5 system-ui;color:var(--text)}
main{max-width:820px;margin:auto}.hint{font-size:12px;color:var(--muted)}
.account-disclosure-warning{font-size:12px;overflow-wrap:anywhere}
</style><main id="view-evidence"><section id="account-disclosure-preview" hidden>
<h3>Review transformed sample</h3><div id="account-disclosure-summary"></div>
<div id="account-disclosure-samples"></div><div id="account-disclosure-warnings"></div>
<p id="account-disclosure-expiry" class="hint"></p></section></main>
<script type="module">
import {createDisclosurePreview} from '/component.js';
window.preview=createDisclosurePreview({root:document.querySelector('main'),
formatTime:value=>typeof value==='number'?'2026-11-01 21:15 UTC':value});
</script></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        files = {"/component.js": ("text/javascript", VIEWS / "disclosure-preview.js"),
                 "/component.css": ("text/css", VIEWS / "disclosure-preview.css")}
        if self.path == "/":
            mime, body = "text/html", HTML
        elif self.path in files:
            mime, path = files[self.path]
            body = path.read_bytes()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", mime + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "test-results" / "disclosure-preview")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    errors, external = [], []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = "http://127.0.0.1:" + str(server.server_port)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, channel=os.environ.get("TGWITNESS_BROWSER_CHANNEL") or None)
            page = browser.new_page(viewport={"width": 390, "height": 844})
            page.on("pageerror", lambda error: errors.append(str(error)))

            def local_only(route):
                if route.request.url.startswith(origin + "/"):
                    route.continue_()
                else:
                    external.append(route.request.url)
                    route.abort()

            page.route("**/*", local_only)
            page.goto(origin)
            page.wait_for_function("Boolean(window.preview)")
            sample = {
                "before": {"text": "SECRET SOURCE NAME", "phone": "SECRET SOURCE PHONE"},
                "after": {
                    "chat": {"id": "SECRET INTERNAL ID", "title": "Chat-123 <script>window.xss=1</script>"},
                    "message": {
                        "sender": "Participant-456 <img src=x onerror=window.xss=2>",
                        "date": "2026-11-01T20:00:00Z", "id": "SECRET MESSAGE ID",
                        "text": "Transformed text\n<svg onload=window.xss=3> & quoted content " + "x" * 2100 + "SECRET TRUNCATED TAIL",
                        "attachments": [{"file": "SECRET FILE NAME", "raw": "SECRET ATTACHMENT PAYLOAD"}],
                        "redacted_fields": ["sender_identity", "text", "SECRET REDACTION FIELD", "__proto__"],
                        "forward": {"name": "SECRET FORWARD PERSON"}, "raw": "SECRET RAW PAYLOAD",
                    },
                    "unknown": "SECRET AFTER METADATA",
                },
            }
            result = {
                "summary": {"messages_before": 99, "messages_after": 13, "chats_before": 4,
                            "chats_after": 2, "media_included": 1, "identities_pseudonymized": 3,
                            "trust_score": 100, "raw": "SECRET SUMMARY"},
                "samples": [sample], "expires_at": 1793567700,
                "warnings": ["Fictional warning <img src=x onerror=window.xss=4>",
                             {"text": "SECRET WARNING OBJECT"}],
            }
            assert page.evaluate("value=>{const before=JSON.stringify(value);preview.render(value);return before===JSON.stringify(value)}", result)
            preview = page.locator("#account-disclosure-preview")
            expect(preview).to_be_visible()
            expect(preview.locator(".disclosure-preview-count dd")).to_have_text(["99", "13", "4", "2", "1", "3"])
            expect(preview.locator(".disclosure-preview-caption")).to_have_text("Samples shown: 1 of 13 included messages.")
            assert "SECRET" not in preview.inner_text(), preview.inner_text()
            assert "trust_score" not in preview.inner_text()
            assert "not a review of the full sharing copy" in preview.inner_text()
            assert "download it and review its index.html" in preview.inner_text()
            assert "Included attachments: 1" in preview.inner_text()
            assert "Fields omitted or replaced: Sender identity, Message text." in preview.inner_text()
            assert "21:15 UTC" in preview.inner_text()
            assert preview.locator(".disclosure-preview-text").inner_text().startswith("Transformed text\n<svg")
            assert len(preview.locator(".disclosure-preview-text").inner_text()) == 2000
            assert preview.locator("img, svg, script, pre, a").count() == 0
            assert page.evaluate("window.xss ?? 0") == 0
            for width in (320, 390, 1440):
                page.set_viewport_size({"width": width, "height": 900})
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
                assert preview.locator(".disclosure-preview-message").evaluate("e=>e.scrollWidth<=e.clientWidth"), width
                page.screenshot(path=str(args.output / f"preview-{width}.png"))

            # All 12 server samples remain available (the previous renderer showed five).
            many = {"summary": {"messages_after": 99},
                    "samples": [{"after": f"Transformed legacy sample {i}"} for i in range(1, 15)]}
            page.evaluate("value=>preview.render(value)", many)
            expect(preview.locator(".disclosure-preview-message")).to_have_count(12)
            expect(preview.locator(".disclosure-preview-caption")).to_have_text("Samples shown: 12 of 99 included messages.")
            assert "legacy sample 12" in preview.inner_text() and "legacy sample 13" not in preview.inner_text()
            assert "Transformed text" not in preview.inner_text()

            # Zero is a known count; absent/invalid values must not become invented zeros.
            page.evaluate("()=>preview.render({summary:{messages_before:0,messages_after:0,chats_before:-1,chats_after:true},samples:[{before:'SECRET WITHOUT AFTER'},{after:{message:null}}]})")
            expect(preview.locator(".disclosure-preview-count dd")).to_have_text(["0", "0"])
            expect(preview.locator(".disclosure-preview-message")).to_have_count(0)
            assert "Samples shown: 0 of 0 included messages." in preview.inner_text()
            assert "SECRET" not in preview.inner_text()
            page.evaluate("()=>preview.render({summary:{},samples:[],expires_at:null})")
            assert "Summary counts are not available" in preview.inner_text()
            assert "Showing 0 transformed message samples." in preview.inner_text()
            page.evaluate("()=>preview.clear()")
            expect(preview).to_be_hidden()
            for target in ("summary", "samples", "warnings", "expiry"):
                assert page.locator("#account-disclosure-" + target).text_content() == ""
            assert not errors, errors
            assert not external, external
            browser.close()
        receipt = {"status": "passed", "viewports": [320, 390, 1440],
                   "checks": ["transformed allowlist", "literal markup and XSS", "no source or nested metadata",
                              "exact counts including zero", "12-sample boundary", "text limit and full-copy guidance",
                              "legacy transformed prose", "rerender and clear", "no external requests", "no horizontal overflow"]}
        (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        print("Disclosure preview: 10 focused checks passed at 320/390/1440; synthetic data only.")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
