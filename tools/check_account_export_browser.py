"""Synthetic account-export panel check; all export API responses are fictional."""
import json
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, launch_browser
from tgwitness import i18n


DEFAULTS = {
    "report_language": "en",
    "purpose": "", "sender_ids": [], "text_contains": [],
    "chat_kinds": ["private", "bot", "group", "supergroup", "channel"],
    "from_utc": None, "to_utc": None, "chat_ids": [], "own_messages_only": False,
    "include_archived": True,
    "media_types": ["photo", "video", "video_message", "voice", "audio", "document", "sticker", "animation"],
    "max_media_file_mib": 512, "max_total_gib": 16, "include_profile": True,
    "include_contacts": True, "include_profile_photos": False, "include_stories": False,
    "include_session_metadata": False, "include_other_data": False, "transport": "takeout",
}


def main():
    errors, starts, downloads, disclosure_previews, disclosure_creates = [], [], [], [], []
    jobs, fail_get = [], [False]
    with tempfile.TemporaryDirectory(prefix="account-export-browser-") as scratch:
        with RunningApp(Path(scratch), demo=True) as server, sync_playwright() as p:
            browser = launch_browser(p)
            page = browser.new_page(viewport={"width": 390, "height": 844}, reduced_motion="reduce",
                                       timezone_id="America/Los_Angeles",
                                       accept_downloads=True)
            page.on("pageerror", lambda error: errors.append(str(error)))

            def fake_api(route):
                path = urlsplit(route.request.url).path
                method = route.request.method
                if path == "/api/account-export" and method == "GET":
                    if fail_get[0]:
                        route.fulfill(status=503, json={"detail": "Fictional temporary outage"})
                    else:
                        route.fulfill(json={"jobs": jobs, "defaults": DEFAULTS, "capabilities": {"can_start": True}})
                elif path == "/api/account-export/start" and method == "POST":
                    starts.append(route.request.post_data_json)
                    job = {"id": "synthetic-job", "phase": "running", "active": True, "ready": False,
                           "created_at": "2026-11-01T12:00:00Z", "current_chat": {"title": "Fictional group"},
                           "counts": {"chats_discovered": 3, "chats_selected": 2, "chats_done": 0,
                                      "messages_exported": 8, "media_saved": 1, "media_skipped": 0},
                           "coverage": {"inventory_complete": True, "tasks_total": 4, "tasks_done": 1,
                                        "failures": 0, "scope": "visible to this account during acquisition"},
                           "omissions": []}
                    jobs[:] = [job]
                    route.fulfill(json=job)
                elif path == "/api/account-export/synthetic-job/pause" and method == "POST":
                    jobs[0].update(phase="paused", active=False)
                    route.fulfill(json=jobs[0])
                elif path == "/api/account-export/synthetic-job/resume" and method == "POST":
                    jobs[0].update(phase="running", active=True, wait_until=None)
                    route.fulfill(json=jobs[0])
                elif path == "/api/account-export/synthetic-job/download" and method == "GET":
                    downloads.append(path)
                    route.fulfill(status=200, body=b"PK\x03\x04fictional signed archive",
                                  headers={"Content-Type": "application/zip", "Content-Length": "28"})
                elif path == "/api/account-export/synthetic-job/disclosure/preview" and method == "POST":
                    disclosure_previews.append(route.request.post_data_json)
                    route.fulfill(json={"preview_id": "synthetic-preview", "expires_at": 4070908800,
                                        "summary": {"messages_before": 99, "messages_after": 3},
                                        "samples": [{"before": "SECRET RAW PERSON", "after": "[Person 1]: fictional event"}],
                                        "warnings": ["Names in quoted text may remain"]})
                elif path == "/api/account-export/synthetic-job/disclosure" and method == "POST":
                    disclosure_creates.append(route.request.post_data_json)
                    derivative = {"id": "fictional-derivative", "ready": True,
                                  "created_at": "2026-11-01T12:10:00Z",
                                  "summary": {"messages_included": 3},
                                  "download_url": "/api/account-export/synthetic-job/disclosures/fictional-derivative/download"}
                    jobs[0]["disclosures"] = [derivative]
                    route.fulfill(json=derivative)
                elif path == "/api/account-export/synthetic-job/disclosures/fictional-derivative/download" and method == "GET":
                    downloads.append(path)
                    route.fulfill(status=200, body=b"PK\x03\x04fictional disclosure",
                                  headers={"Content-Type": "application/zip", "Content-Length": "24"})
                elif path == "/api/account-export/synthetic-job" and method == "DELETE":
                    jobs.clear()
                    route.fulfill(status=204, body="")
                else:
                    route.fulfill(status=404, json={"detail": "Unknown synthetic export request"})

            page.route("**/api/account-export**", fake_api)
            page.goto(server.url)
            expect(page.locator("#workspace")).to_be_visible()
            page.evaluate("navigate('evidence')")
            expect(page.locator("#export-task-journal")).to_have_attribute("aria-pressed", "true")
            expect(page.locator("#export-journal-panel")).to_be_visible()
            expect(page.locator("#export-account-panel")).to_be_hidden()
            page.locator("#export-task-account").click()
            expect(page.locator("#export-task-account")).to_have_attribute("aria-pressed", "true")
            expect(page.locator("#account-export-card")).to_be_visible()
            keys = page.evaluate("pageKeys()")
            assert "Why this account snapshot is being collected" in keys
            assert "Who needs this file, and why" in keys
            expect(page.locator("#account-export-jobs")).to_contain_text("No account exports yet")
            page.locator("#account-export-configure").click()
            expect(page.locator("#account-export-dialog")).to_be_visible()
            expect(page.locator('#account-export-language')).to_have_value('en')
            expect(page.locator('#account-export-language option')).to_have_count(25)
            expect(page.locator("#account-export-kinds input:checked")).to_have_count(5)
            expect(page.locator("#account-export-media input:checked")).to_have_count(8)
            expect(page.locator("#account-export-archived")).to_be_checked()
            expect(page.locator("#account-export-transport")).to_have_value("takeout")
            expect(page.locator("#account-export-preview")).to_contain_text("Full visible history")
            page.locator("#account-export-minimize").click()
            expect(page.locator("#account-export-media input:checked")).to_have_count(0)
            expect(page.locator("#account-export-sections input:checked")).to_have_count(0)
            page.evaluate("accountExportDefaults(state.accountExportDefaults)")
            page.locator("#account-export-purpose").fill("Fictional preservation request")
            page.locator('#account-export-language').select_option('fr')
            page.locator("#account-export-from").fill("2026-01-01")
            page.locator("#account-export-through").fill("2026-01-31")
            page.locator("#account-export-ids").locator("xpath=ancestor::details").locator("summary").click()
            page.locator("#account-export-ids").fill("-100123, 42")
            expect(page.locator("#account-export-senders")).to_be_hidden()
            page.locator(".account-export-message-filters > summary").click()
            page.locator("#account-export-senders").fill("42, 55")
            page.locator("#account-export-phrases").fill("fictional phrase\nother phrase")
            page.locator("#account-export-own").check()
            page.locator('#account-export-media input[value="video"]').uncheck()
            page.locator("#account-export-file-limit").fill("64")
            page.locator("#account-export-total-limit").fill("8")
            expect(page.locator("#account-export-profile-photos")).to_be_hidden()
            page.locator("#account-export-advanced > summary").click()
            page.locator("#account-export-profile-photos").check()
            page.locator("#account-export-transport").select_option("regular")
            page.locator("#account-export-dismiss").click()
            page.evaluate("pollWorkspace()")
            page.locator("#account-export-configure").click()
            expect(page.locator("#account-export-file-limit")).to_have_value("64")
            expect(page.locator('#account-export-language')).to_have_value('fr')
            expect(page.locator('#account-export-preview')).to_contain_text('Français')
            expect(page.locator("#account-export-profile-photos")).to_be_checked()
            assert page.evaluate("state.accountExportDirty")
            page.locator("#account-export-start").click()
            expect(page.locator("#account-export-dialog")).to_be_hidden()
            expect(page.locator("#account-export-jobs")).to_contain_text("Fictional group")
            assert page.evaluate("accountExportTime('2026-11-01T12:00:00Z') === fmtTime(new Date('2026-11-01T12:00:00Z'))")
            started_utc = page.locator(".account-export-job-sub").inner_text()
            page.evaluate("() => { const select=document.getElementById('time-zone'); select.value='local'; select.dispatchEvent(new Event('change')); }")
            started_local = page.locator(".account-export-job-sub").inner_text()
            assert started_utc != started_local, (started_utc, started_local)
            assert page.evaluate("document.querySelector('.account-export-job-sub').textContent.includes(fmtTime(new Date('2026-11-01T12:00:00Z')))")
            assert len(starts) == 1
            assert starts[0]["chat_ids"] == [-100123, 42]
            assert starts[0]["purpose"] == "Fictional preservation request"
            assert starts[0]['report_language'] == 'fr'
            assert starts[0]["sender_ids"] == [42, 55]
            assert starts[0]["text_contains"] == ["fictional phrase", "other phrase"]
            assert starts[0]["from_utc"] == "2026-01-01T00:00:00Z"
            assert starts[0]["to_utc"] == "2026-02-01T00:00:00.000Z"
            assert starts[0]["own_messages_only"] is True
            assert starts[0]["max_media_file_mib"] == 64 and starts[0]["max_total_gib"] == 8
            assert starts[0]["transport"] == "regular" and starts[0]["include_profile_photos"] is True
            assert "video" not in starts[0]["media_types"]
            page.locator('[data-account-export-action="pause"]').click()
            expect(page.locator("#account-export-jobs")).to_contain_text("Paused")
            page.locator('[data-account-export-action="resume"]').click()
            expect(page.locator("#account-export-jobs")).to_contain_text("Reading Telegram")
            jobs[0].update(phase="waiting", active=False, wait_until="2099-11-02T12:00:00Z")
            page.evaluate("pollWorkspace()")
            expect(page.locator('[data-account-export-action="resume"]')).to_have_count(0)
            jobs[0]["wait_until"] = "2026-10-30T12:00:00Z"
            page.evaluate("pollWorkspace()")
            expect(page.locator('[data-account-export-action="resume"]')).to_be_visible()
            expect(page.locator('[data-account-export-action="pause"]')).to_have_count(0)
            page.locator('[data-account-export-action="resume"]').click()
            expect(page.locator("#account-export-jobs")).to_contain_text("Reading Telegram")
            jobs[0].update(phase="partial", active=False, ready=True, current_chat=None,
                           omissions=[{"section": "stories", "reason": "unavailable"}],
                           counts={**jobs[0]["counts"], "chats_done": 2, "messages_exported": 99,
                                   "media_saved": 4, "media_skipped": 1},
                           coverage={**jobs[0]["coverage"], "tasks_done": 4, "failures": 1})
            page.evaluate("pollWorkspace()")
            expect(page.locator("#account-export-jobs")).to_contain_text("Omissions and unavailable data (1)")
            expect(page.locator("#account-export-jobs")).to_contain_text("messages saved: 99")
            expect(page.locator('[data-account-export-action="resume"]')).to_have_count(0)
            fail_get[0] = True
            page.evaluate("pollWorkspace()")
            expect(page.locator("#account-export-status")).to_contain_text("Fictional temporary outage")
            fail_get[0] = False
            page.evaluate("pollWorkspace()")
            expect(page.locator("#account-export-status")).to_contain_text("Demo account export uses fictional data only")
            page.evaluate("window.showSaveFilePicker=undefined")
            for _ in range(2):
                with page.expect_download() as saved:
                    page.locator('[data-account-export-action="download"]').click()
                assert saved.value.suggested_filename == "tgwitness-account-export-synthetic-job.zip"
            assert len(downloads) == 2
            page.locator('[data-account-export-action="disclosure"]').click()
            expect(page.locator("#account-disclosure-dialog")).to_be_visible()
            page.locator("#account-disclosure-purpose").fill("Fictional narrow disclosure")
            page.locator("#account-disclosure-senders").fill("42")
            page.locator("#account-disclosure-phrases").fill("fictional phrase")
            page.locator("#account-disclosure-redact-terms").fill("private word\nsecond phrase")
            page.locator("#account-disclosure-identities").select_option("pseudonymize_third_parties")
            page.locator("#account-disclosure-disclose-ids").fill("42")
            page.locator("#account-disclosure-check").click()
            expect(page.locator("#account-disclosure-create")).to_be_enabled()
            included = page.locator("#account-disclosure-summary .disclosure-preview-count").filter(
                has=page.get_by_text("Included messages", exact=True))
            expect(included.locator("dd")).to_have_text("3")
            expect(page.locator(".disclosure-preview-caption")).to_have_text("Samples shown: 1 of 3 included messages.")
            expect(page.locator("#account-disclosure-samples")).to_contain_text("[Person 1]")
            assert "SECRET RAW PERSON" not in page.locator("#account-disclosure-preview").inner_text()
            page.locator("#account-disclosure-phrases").fill("other phrase")
            page.locator('#account-disclosure-language').select_option('ar')
            expect(page.locator("#account-disclosure-create")).to_be_disabled()
            page.locator("#account-disclosure-check").click()
            expect(page.locator("#account-disclosure-create")).to_be_enabled()
            page.once("dialog", lambda dialog: dialog.accept())
            page.locator("#account-disclosure-create").click()
            expect(page.locator("#account-disclosure-dialog")).to_be_hidden()
            expect(page.locator("#account-export-jobs")).to_contain_text("Signed sharing copies")
            assert len(disclosure_previews) == 2
            assert disclosure_previews[-1]["purpose"] == "Fictional narrow disclosure"
            assert disclosure_previews[-1]['report_language'] == 'ar'
            assert disclosure_previews[-1]["sender_ids"] == [42]
            assert disclosure_previews[-1]["text_contains"] == ["other phrase"]
            assert disclosure_previews[-1]["redact_terms"] == ["private word", "second phrase"]
            assert disclosure_previews[-1]["disclose_user_ids"] == [42]
            assert disclosure_previews[-1]["include_media"] is False
            assert disclosure_previews[-1]["include_contacts"] is False
            assert disclosure_creates == [{"preview_id": "synthetic-preview"}]
            for _ in range(2):
                with page.expect_download() as saved:
                    page.locator('[data-account-export-action="disclosure-download"]').click()
                assert saved.value.suggested_filename == "tgwitness-disclosure-fictional-derivative.zip"
            assert len(downloads) == 4
            page.once("dialog", lambda dialog: dialog.accept())
            page.locator('[data-account-export-action="delete"]').click()
            expect(page.locator("#account-export-jobs")).to_contain_text("No account exports yet")
            for width in (390, 320):
                page.set_viewport_size({"width": width, "height": 844})
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
                page.locator("#account-export-configure").click()
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
                page.locator("#account-export-close").click()
            page.evaluate("state.me.admin=false;applyAccess()")
            expect(page.locator("#account-export-card")).to_be_hidden()
            ru_page = browser.new_page()
            ru_page.goto(server.url + "/?lang=ru", wait_until="networkidle")
            expect(ru_page.locator("#workspace")).to_be_visible()
            # The shell can appear before the first status response has selected its view.
            ru_page.wait_for_function("state.me?.admin === true && !!state.status")
            ru_page.locator('.sidebar [data-view="evidence"]').click()
            ru_page.locator("#export-task-account").click()
            expect(ru_page.locator("#account-export-card")).to_be_visible()
            ru = i18n.words("ru")
            for selector, key in (("#account-export-purpose", "Why this account snapshot is being collected"),
                                  ("#account-disclosure-purpose", "Who needs this file, and why")):
                assert ru[key] and ru[key] != key
                expect(ru_page.locator(selector)).to_have_attribute("placeholder", ru[key])
            assert ru_page.evaluate("""() => {
              const area=document.createElement('textarea');
              area.placeholder='Synthetic placeholder';
              area.setAttribute('aria-label','Synthetic accessible label');
              area.title='Synthetic title';
              area.textContent='Default user text';
              area.value='Typed private text';
              document.body.append(area);
              const hidden=document.createElement('textarea');
              hidden.hidden=true;hidden.disabled=true;
              hidden.placeholder='Hidden synthetic placeholder';
              hidden.value='Hidden private text';document.body.append(hidden);
              const excluded=document.createElement('textarea');
              excluded.setAttribute('data-no-translate','');
              excluded.placeholder='Excluded synthetic placeholder';
              document.body.append(excluded);
              const keys=pageKeys();
              if(!['Synthetic placeholder','Synthetic accessible label','Synthetic title',
                   'Hidden synthetic placeholder'].every(key=>keys.includes(key)))return false;
              if(keys.includes('Default user text')||keys.includes('Typed private text')||
                 keys.includes('Excluded synthetic placeholder'))return false;
              Object.assign(DICT,{'Synthetic placeholder':'Синтетическая подсказка',
                'Synthetic accessible label':'Синтетическая метка',
                'Synthetic title':'Синтетический заголовок',
                'Hidden synthetic placeholder':'Скрытая подсказка',
                'Default user text':'Text that must never appear',
                'Excluded synthetic placeholder':'Must remain excluded'});
              translatePage();
              return area.placeholder==='Синтетическая подсказка'&&
                area.getAttribute('aria-label')==='Синтетическая метка'&&
                area.title==='Синтетический заголовок'&&
                area.value==='Typed private text'&&area.textContent==='Default user text'&&
                hidden.placeholder==='Скрытая подсказка'&&hidden.value==='Hidden private text'&&
                excluded.placeholder==='Excluded synthetic placeholder';
            }""")
            ru_page.close()
            assert not errors, errors
            browser.close()
    print(json.dumps({"passed": True, "starts": len(starts), "repeat_downloads": len(downloads),
        "scenarios": ["all kinds, Saved Messages and full history defaults", "minimize collection preset",
                      "purpose, sender/content filters and UTC dates",
                      "draft survives polling", "locale time formatting and zone switch",
                      "pause, idle waiting resume, sealed partial omissions",
                      "retryable job-list outage",
                      "repeat download and delete",
                      "transformed disclosure preview and invalidation", "signed derivative repeat download",
                      "320/390px layout", "restricted access hides account export",
                      "textarea attributes translate without touching typed content"], "page_errors": errors}, indent=2))


if __name__ == "__main__":
    main()
