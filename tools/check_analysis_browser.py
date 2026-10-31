"""Synthetic provider acceptance: review sources, generate, revise and export."""
import json
from pathlib import Path
import sys
import tempfile

from playwright.sync_api import sync_playwright, expect

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_browser import RunningApp, launch_browser, unlock, check_layout
from tgwitness import netclient


async def synthetic(method, url, network, **kwargs):
    assert url == "http://127.0.0.1:11434/api/chat"
    request = json.loads(kwargs["body"])
    data = json.loads(request["messages"][1]["content"])
    source = data["observations"][0]
    answer = {"claims": [{"text": "The saved observation includes example.org.",
                          "citations": [{"id": source["id"], "quote": "example.org"}]}]}
    return 200, {}, json.dumps({"message": {"content": json.dumps(answer)}, "done": True,
                               "prompt_eval_count": 50, "eval_count": 20}).encode()


def main():
    original = netclient.request
    netclient.request = synthetic
    try:
        with tempfile.TemporaryDirectory(prefix="analysis-check-") as scratch, RunningApp(Path(scratch)) as app:
            app.app.state.store.set_target(-1001, "Synthetic archive", "supergroup", True)
            app.app.state.store.append("message.new", {"text": "A saved link: example.org"}, chat_id=-1001, message_id=1)
            with sync_playwright() as p:
                browser = launch_browser(p)
                page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                unlock(page, app)
                page.locator('[data-view="analysis"]').click()
                expect(page.locator("#ai-status")).to_contain_text("AI disabled")
                page.locator("#ai-settings > summary").click()
                page.locator("#ai-enabled").check()
                page.locator("#ai-model").fill("synthetic-test")
                page.locator('#ai-settings-form button[type="submit"]').click()
                expect(page.locator("#ai-status")).to_contain_text("AI enabled")
                page.locator("#ai-settings > summary").click()
                page.locator('#ask-chats input[value="-1001"]').check()
                page.locator("#ask-question").fill("Where does example.org appear?")
                page.locator('#ask-form button[type="submit"]').click()
                expect(page.locator("#ask-sources")).to_contain_text("example.org")
                page.locator('#ask-sources button', has_text="Open chat context").click()
                expect(page.locator("#ask-sources")).to_contain_text("message.new")
                page.locator("#ask-consent").check()
                page.locator("#ask-generate").click()
                expect(page.locator("#ask-claims")).to_contain_text("The saved observation includes")
                expect(page.locator("#ask-usage")).to_contain_text("Input tokens: 50")
                page.locator("#ask-save-report").click()
                expect(page.locator("#ask-report")).to_be_visible()
                page.locator("#report-note").fill("Reviewed against the saved source.")
                page.locator('#ask-report-form button[type="submit"]').click()
                expect(page.locator("#ask-report-content")).to_contain_text("Reviewed against the saved source.")
                with page.expect_download() as download:
                    page.locator("#report-download").click()
                report = json.loads(Path(download.value.path()).read_text())
                assert report["analyst_revisions"] and report["sources"][0]["source"]["hash"]
                assert report["model_summary"][0]["category"] == "model_inference"
                for theme in ("light", "dark"):
                    page.locator('.sidebar [data-theme-choice="' + theme + '"]').click()
                    check_layout(page)
                    page.mouse.move(900, 20)
                    page.evaluate("scrollTo(0,0)")
                    dest = Path("test-results/analysis")
                    dest.mkdir(parents=True, exist_ok=True)
                    page.screenshot(path=str(dest / (theme + ".png")), full_page=True, animations="disabled")
                page.set_viewport_size({"width": 390, "height": 900})
                check_layout(page)
                assert not errors, errors
                browser.close()
    finally:
        netclient.request = original
    print("Analysis UI passed: explicit provider, scoped preview, verified sources, analyst revision and report download.")


if __name__ == "__main__":
    main()
