"""Synthetic studio: real preview renderer, saved/exported choices, privacy and responsive charts."""
import json
from pathlib import Path
import tempfile
import zipfile

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, answer_panel_dialog, hold_api_response, launch_browser, release_api_response, unlock
from build_report_studio_example import seed
from tgwitness.verify import fingerprint, verify_bundle


def main():
    output = Path("test-results/report-studio")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="report-studio-") as scratch, RunningApp(Path(scratch)) as server:
        seed(server.app.state.store)
        server.app.state.store.set_setting("demo", False)
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1440, "height": 1100}, reduced_motion="reduce")
            page.add_init_script("window.showSaveFilePicker=undefined")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            unlock(page, server)
            page.evaluate("()=>navigate('evidence')")
            page.locator("#exports-tab-settings").click()
            expect(page.locator("#report-fields")).to_be_enabled()
            page.locator("#report-case-title").fill("Project Meridian — October review")
            page.locator("#report-case-id").fill("SYNTHETIC / MRD-2026")
            page.locator("#report-language").select_option("en")
            page.locator("#report-timeline").uncheck()
            page.locator("#report-chart-limit").fill("5")
            page.locator("#report-notes").fill("SYNTHETIC EXAMPLE · Fictional records, no Telegram connection.")
            for template in ("analytical", "editorial", "dossier"):
                page.locator(f'[name="report-design"][value="{template}"]').check()
                expect(page.locator("#report-design-preview-status")).to_contain_text("not signed", timeout=20000)
                frame = page.frame_locator("#report-preview-frame")
                expect(frame.locator("html")).to_have_attribute("data-template", template)
                expect(frame.locator(".chart-card")).to_have_count(5)
                expect(frame.locator(".rank-row").first).to_contain_text("Participant")
                # External stylesheet is actually applied under the panel CSP.
                assert frame.locator(".analytics-pair").evaluate("el=>getComputedStyle(el).display") == "grid"
                if template == 'editorial':
                    assert frame.locator('.facts b').first.evaluate('el=>getComputedStyle(el).color') == frame.locator('h1').evaluate('el=>getComputedStyle(el).color')
                assert frame.locator(".preview-watermark").inner_text() == "DRAFT PREVIEW · NOT SIGNED"
                page.locator("#report-form button[type=submit]").click()
                expect(page.locator("#report-status")).to_contain_text("Saved.")
                page.locator("#exports-tab-downloads").click()
                with page.expect_download() as transfer:
                    page.locator("#export-journal-panel [data-export=zip]").click()
                    answer_panel_dialog(page)
                destination = output / f"{template}.zip"
                transfer.value.save_as(destination)
                verified = verify_bundle(destination, fingerprint(server.app.state.vault.public_key))
                assert verified["key_pinned"] and verified["report_pdf"]
                with zipfile.ZipFile(destination) as archive:
                    html = archive.read("report.html").decode()
                    data = json.loads(archive.read("report.json"))["report"]
                    analytic = json.loads(archive.read("analytics.json"))
                    assert data["analytics"] == analytic
                    assert data["presentation"]["design"] == template
                    assert f'data-template="{template}"' in html
                    assert sum(row["total"] for row in analytic["activity"]["rows"]) == analytic["activity_events"]
                    (output / f"{template}.html").write_text(html, encoding="utf-8")
                page.locator("#exports-tab-settings").click()
            page.locator('[name="report-design"][value="analytical"]').check()
            expect(page.locator("#report-design-preview-status")).to_contain_text("not signed", timeout=20000)
            for width in (1440, 390):
                page.set_viewport_size({"width": width, "height": 1100 if width == 1440 else 844})
                for theme in ("light", "dark"):
                    page.evaluate("theme=>document.documentElement.dataset.theme=theme", theme)
                    page.locator("#report-form").screenshot(path=str(output / f"studio-{width}-{theme}.png"))
                    assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
            page.locator("#report-participant-chart").uncheck()
            expect(page.locator("#report-design-preview-status")).to_contain_text("not signed", timeout=20000)
            expect(page.frame_locator("#report-preview-frame").locator(".chart-participants")).to_have_count(0)
            # Preview never persists the draft or produces a signature.
            options = page.evaluate("json('report-options')")
            assert options["participant_chart"] and options["design"] == "dossier"
            hold_api_response(page, '/api/report-design-preview')
            page.locator('#report-case-title').fill('PRIVATE STALE DRAFT')
            page.wait_for_function("()=>typeof releaseAcceptanceResponse==='function'")
            page.evaluate("()=>lock()")
            release_api_response(page)
            assert page.evaluate("()=>!panelRoots.get('evidence').querySelector('#report-preview-frame').hasAttribute('srcdoc')")
            assert not errors, errors
            browser.close()
    print("Studio preview, 3 signed template exports, shared analytic data, selections, draft isolation, CSP styling, lock and responsive layouts PASS")


if __name__ == "__main__":
    main()
