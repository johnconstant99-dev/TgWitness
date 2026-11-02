"""Showcase publication, recipient reading and revocation with synthetic records only."""
import json
from pathlib import Path
import sys
import tempfile
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.check_browser import RunningApp, launch_browser, check_layout
from tools.check_showcase import MARKER, TEXT, seed
from tgwitness.showcase_verify import verify
from tgwitness.verify import fingerprint


def main():
    output = ROOT / "test-results/showcase"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="showcase-browser-") as scratch, \
            RunningApp(Path(scratch), demo=True) as server, sync_playwright() as p:
        seed(server.app.state.store)
        browser = launch_browser(p)
        # Neither a made-up fragment nor a stored credential can select permissions.
        for stored, fragment in ((None, "#access=tgwa_invalid"), ("tgws_invalid", ""),
                                 (server.app.state.vault.token, "")):
            denied = browser.new_context()
            if stored:
                denied.add_init_script("sessionStorage.setItem('tgwitness-showcase-session'," + json.dumps(stored) + ");")
            blocked = denied.new_page()
            reads = []
            blocked.on("request", lambda r: reads.append(r.url) if "/api/showcase" in r.url else None)
            blocked.goto(server.url + "/showcase.html" + fragment)
            expect(blocked.locator("#notice")).not_to_be_empty()
            expect(blocked.locator("#content")).to_be_hidden()
            expect(blocked.locator("#login")).to_be_visible()
            assert not reads, reads
            denied.close()
        admin = browser.new_context(viewport={"width": 1440, "height": 1000})
        admin.add_init_script("sessionStorage.setItem('tgwitness-token'," + json.dumps(server.app.state.vault.token) + ");")
        page = admin.new_page()
        errors, external = [], []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(server.url + "/showcase-manage.html")
        expect(page.locator("#publisher")).to_be_visible()
        expect(page.locator("#channels input")).to_have_count(1)
        page.locator("#channels input").check()
        page.locator("#label").fill("Public observation · synthetic test")
        page.locator("#ack").check()
        expect(page.locator("#publish")).to_be_disabled()
        page.locator("#preview-button").click()
        expect(page.locator("#publish")).to_be_enabled()
        assert not server.app.state.access.grants
        assert MARKER not in page.locator("#preview").inner_text()
        assert page.evaluate("window.injected") is None
        page.locator("#label").fill("Public record · synthetic test")
        expect(page.locator("#publish")).to_be_disabled()
        page.locator("#preview-button").click()
        expect(page.locator("#publish")).to_be_enabled()
        page.locator("#publish").click()
        expect(page.locator("#shared")).to_be_visible()
        link = page.locator("#share-link").input_value()
        assert "#access=tgwa_" in link
        page.screenshot(path=str(output / "publish-desktop.png"), full_page=True)
        visitor = browser.new_context(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
        view = visitor.new_page()
        view.on("pageerror", lambda e: errors.append(str(e)))
        view.on("request", lambda r: external.append(r.url) if urlsplit(r.url).hostname != "127.0.0.1" else None)
        view.goto(link)
        expect(view.locator("#content")).to_be_visible()
        expect(view.locator("#feed .event").first).to_contain_text("Deletion observed")
        expect(view.locator("#feed .event").first).to_contain_text("Meeting moved to 17:30.")
        assert not urlsplit(view.url).fragment
        assert MARKER not in view.locator("body").inner_text()
        assert view.locator("#feed img,#feed a").count() == 0
        assert view.evaluate("window.injected") is None
        expect(view.locator("#synthetic")).to_be_visible()
        view.locator("#filter").select_option("edited")
        expect(view.locator("#feed .event")).to_have_count(1)
        view.locator("#filter").select_option("deleted")
        expect(view.locator("#feed .event")).to_have_count(1)
        view.locator("#feed .event button").first.click()
        expect(view.locator("#feed .event")).to_have_count(3)
        expect(view.locator("#feed")).to_contain_text(TEXT)
        view.locator("#latest").click()
        view.locator("#filter").select_option("all")
        expect(view.locator("#feed .event")).to_have_count(30)
        view.locator("#older").click()
        expect(view.locator("#feed .event")).to_have_count(38)
        view.locator("#refresh").click()
        expect(view.locator("#feed .event")).to_have_count(30)
        view.locator("#collectors summary").click()
        with view.expect_download() as pending:
            view.locator("#collectors button").click()
        proof = json.loads(Path(pending.value.path()).read_text(encoding="utf-8"))
        assert verify(proof, fingerprint(server.app.state.vault.public_key))["projection_signature"] == "valid"
        for width in (1440, 390):
            view.set_viewport_size({"width": width, "height": 1000})
            for theme in ("light", "dark"):
                view.emulate_media(color_scheme=theme)
                check_layout(view)
                view.screenshot(path=str(output / f"showcase-{width}-{theme}.png"))
        page.locator("#grants button").click()
        expect(page.locator("#revoke-dialog")).to_be_visible()
        page.locator('#revoke-dialog button[value="cancel"]').click()
        assert len(server.app.state.access.grants) == 1
        page.locator("#grants button").click()
        page.locator('#revoke-dialog button[value="revoke"]').click()
        expect(page.locator("#notice")).to_contain_text("revoked")
        view.locator("#refresh").click()
        expect(view.locator("#login")).to_be_visible()
        expect(view.locator("#content")).to_be_hidden()
        assert not view.locator("#feed").inner_text()
        assert not view.locator("#collectors").inner_text()
        assert not errors, errors
        assert not external, external
        browser.close()
    print("Showcase browser: preview, link, redaction, versions, paging, signed download, responsive layouts and revocation passed.")


if __name__ == "__main__":
    main()
