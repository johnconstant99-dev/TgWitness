"""Synthetic provider acceptance: review sources, generate, revise and export."""
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from playwright.sync_api import sync_playwright, expect

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_browser import (RunningApp, launch_browser, unlock, check_layout,
                                 hold_api_response, release_api_response)
from tools.check_analysis_settings_browser import check_settings
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
                check_settings(browser)
                page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
                errors = []
                calls = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.on("request", lambda request: calls.append(request.url) if "/api/analysis/" in request.url else None)
                unlock(page, app)
                expect(page.locator("#unlock-form button")).to_be_enabled()
                expect(page.locator('[data-view="analysis"]')).to_be_hidden()
                page.evaluate("async()=>{await refreshStatus();await refreshStatus();await TgWitnessAnalysis.load();await TgWitnessMedia.load();}")
                assert not calls, calls
                page.locator('[data-view="integrations"]').click()
                page.locator("#ai-settings > summary").click()
                expect(page.locator("#ai-status")).to_contain_text("AI disabled")
                page.locator("#ai-model").fill("synthetic-test")
                page.locator('#ai-settings-form button[type="submit"]').click()
                expect(page.locator('#ai-settings-form button[type="submit"]')).to_be_enabled()
                expect(page.locator('[data-view="analysis"]')).to_be_hidden()
                assert all("/provider" in url for url in calls), calls
                page.locator("#ai-enabled").check()
                page.locator('#ai-settings-form button[type="submit"]').click()
                expect(page.locator("#ai-status")).to_contain_text("AI enabled")
                page.locator("#ai-settings > summary").click()
                page.locator('[data-view="analysis"]').click()
                expect(page.locator("#media-analysis-section")).to_be_hidden()
                page.locator('#ask-chats input[value="-1001"]').check()
                page.evaluate("json('analysis/provider',{enabled:true,model:'synthetic-updated'},{root:true})")
                page.locator("#ask-question").fill("Where does example.org appear?")
                page.locator('#ask-form button[type="submit"]').click()
                expect(page.locator("#ask-sources")).to_contain_text("example.org")
                expect(page.locator("#ask-provider-status")).to_contain_text("synthetic-updated")
                expect(page.locator("#ask-provider-status")).to_contain_text("http://127.0.0.1:11434")
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
                page.set_viewport_size({"width": 1440, "height": 1000})
                page.locator('[data-view="integrations"]').click()
                page.locator("#ai-settings > summary").click()
                page.locator("#ai-enabled").uncheck()
                page.locator('#ai-settings-form button[type="submit"]').click()
                expect(page.locator('[data-view="analysis"]')).to_be_hidden()
                expect(page.locator("#ai-model")).to_have_value("synthetic-updated")
                baseline = len(calls)
                page.evaluate("async()=>{await refreshStatus();await refreshStatus();await TgWitnessAnalysis.load();await TgWitnessMedia.load();}")
                assert len(calls) == baseline, calls[baseline:]

                # Issued access follows the workspace capability, without provider controls.
                grant = page.evaluate("json('access/grants',{label:'Archive observer',workspaces:{default:[-1001]}},{root:true})")
                viewer_context = browser.new_context()
                viewer = viewer_context.new_page()
                viewer.on("pageerror", lambda error: errors.append(str(error)))
                viewer.goto(app.url)
                viewer.locator("#panel-token").fill(grant["token"])
                viewer.locator("#unlock-form button").click()
                expect(viewer.locator("#workspace")).to_be_visible()
                expect(viewer.locator("#unlock-form button")).to_be_enabled()
                expect(viewer.locator('[data-view="analysis"]')).to_be_hidden()
                expect(viewer.locator('[data-view="integrations"]')).to_be_hidden()
                page.evaluate("json('analysis/provider',{enabled:true,model:'synthetic-test'},{root:true})")
                viewer.evaluate("refreshStatus()")
                viewer.locator('[data-view="analysis"]').click()
                expect(viewer.locator("#ask-form")).to_be_visible()
                expect(viewer.locator("#ai-settings")).to_be_hidden()
                expect(viewer.locator('#ask-chats input[value="-1001"]')).to_be_visible()
                page.evaluate("json('analysis/provider',{enabled:false,model:'synthetic-test'},{root:true})")
                viewer.evaluate("refreshStatus()")
                expect(viewer.locator('[data-view="analysis"]')).to_be_hidden()
                expect(viewer.locator("#view-analysis")).to_be_hidden()
                viewer_context.close()

                # An explicitly configured local worker does not turn the LLM UI on.
                with patch("tgwitness.media_analysis.available", return_value=True), \
                        patch("tgwitness.media_analysis_api.available", return_value=True):
                    page.evaluate("refreshStatus()")
                    baseline = len(calls)
                    page.locator('[data-view="analysis"]').click()
                    expect(page.locator("#media-analysis-section")).to_be_visible()
                    expect(page.locator("#media-worker-status")).to_contain_text("Local worker")
                    expect(page.locator("#ask-form")).to_be_hidden()
                    expect(page.locator("#analysis-description")).to_be_hidden()
                    assert calls[baseline:] and all("/analysis/media" in url for url in calls[baseline:]), calls[baseline:]
                    held = "/api/analysis/media?query=&kind=&offset=0&workspace_id=default"
                    hold_api_response(page, held)
                    page.evaluate("()=>{window.pendingMediaList=TgWitnessMedia.load();}")
                    expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
                page.evaluate("refreshStatus()")
                release_api_response(page)
                page.evaluate("window.pendingMediaList")
                expect(page.locator('[data-view="analysis"]')).to_be_hidden()
                expect(page.locator("#view-analysis")).to_have_count(0)
                assert page.evaluate("()=>[$('media-jobs').childElementCount,$('media-jobs').textContent]") == [0, ""]

                # An open settings form belongs to one workspace, including late responses.
                second = page.evaluate("""async()=>{
                    const other=await json('profiles',{label:'Second synthetic workspace'},{root:true});
                    await json('analysis/provider?workspace_id='+other.id,{enabled:false,model:'workspace-b'},{root:true});
                    await json('analysis/provider?workspace_id=default',{enabled:true,model:'workspace-a'},{root:true});
                    await refreshStatus();await loadProfiles();return other.id;
                }""")
                page.locator('[data-view="integrations"]').click()
                if page.locator("#ai-settings").evaluate("el=>el.open"):
                    page.locator("#ai-settings > summary").click()
                page.locator("#ai-settings > summary").click()
                expect(page.locator("#ai-model")).to_have_value("workspace-a")
                page.evaluate("()=>{$('ask-question').value='Private draft A';$('ask-query').value='workspace-a-only';}")
                hold_api_response(page, "/api/analysis/provider?workspace_id=default")
                page.evaluate("()=>{window.pendingProviderSettings=TgWitnessAnalysis.loadSettings();}")
                expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
                page.evaluate("id=>switchProfile(id)", second)
                assert not page.locator("#ai-settings").evaluate("el=>el.open")
                assert page.locator("#ai-settings-form").evaluate("el=>el.inert")
                expect(page.locator("#ai-enabled")).not_to_be_checked()
                expect(page.locator("#ai-model")).to_have_value("")
                expect(page.locator("#view-analysis")).to_have_count(0)
                assert page.evaluate("()=>[$('ask-question').value,$('ask-query').value]") == ["", ""]
                assert page.evaluate("()=>[$('ask-chats').childElementCount,$('ask-chats').textContent]") == [0, ""]
                release_api_response(page)
                page.evaluate("window.pendingProviderSettings")
                expect(page.locator("#ai-model")).to_have_value("")
                page.locator("#ai-settings > summary").click()
                expect(page.locator("#ai-model")).to_have_value("workspace-b")
                expect(page.locator("#ai-enabled")).not_to_be_checked()
                page.locator('#ai-settings-form button[type="submit"]').click()
                expect(page.locator('#ai-settings-form button[type="submit"]')).to_be_enabled()
                saved = page.evaluate("json('analysis/provider?workspace_id='+state.profile,undefined,{root:true})")
                assert not saved["enabled"] and saved["model"] == "workspace-b", saved
                page.evaluate("switchProfile('default')")
                assert not page.locator("#ai-settings").evaluate("el=>el.open")
                page.locator("#ai-settings > summary").click()
                expect(page.locator("#ai-model")).to_have_value("workspace-a")
                expect(page.locator("#ai-enabled")).to_be_checked()

                page.locator("#ai-model").fill("workspace-a-saved")
                hold_api_response(page, "/api/analysis/provider?workspace_id=default")
                page.locator('#ai-settings-form button[type="submit"]').click()
                expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
                page.evaluate("id=>switchProfile(id)", second)
                release_api_response(page)
                # A late save cannot enable the next workspace's unloaded form.
                expect(page.locator('#ai-settings-form button[type="submit"]')).to_be_disabled()
                assert page.locator("#ai-settings-form").evaluate("el=>el.inert")
                expect(page.locator("#ai-model")).to_have_value("")
                baseline = len(calls)
                page.evaluate("""()=>{$('ai-settings-form').dispatchEvent(new SubmitEvent('submit',{
                    bubbles:true,cancelable:true,submitter:$('ai-settings-form').querySelector('button[type="submit"]')}));}
                """)
                assert len(calls) == baseline, calls[baseline:]
                page.locator("#ai-settings > summary").click()
                expect(page.locator("#ai-model")).to_have_value("workspace-b")
                expect(page.locator("#ai-enabled")).not_to_be_checked()
                assert not errors, errors
                browser.close()
    finally:
        netclient.request = original
    print("Analysis UI passed: disabled startup calls, explicit settings, archive workflow, disabled cleanup, issued access, local-worker-only mode and workspace-isolated settings/drafts/late responses.")


if __name__ == "__main__":
    main()
