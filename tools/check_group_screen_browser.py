import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

EXTRA = ("Open group", "Group", "Group exported", "This group has no accounts to export.",
         "Every account of the group must be available to export it.")
WIDTHS = (360, 600, 1024, 1440)
CHANNEL = -1001234567890


def group_keys():
    from i18n_keys import script_keys
    source = (ROOT / "tgwitness/static/views/group.js").read_text(encoding="utf-8")
    labels = re.findall(r"(?:button|pair)\('([^']+)'", source)
    return list(dict.fromkeys([*script_keys(source), *labels, *EXTRA]))


def check_translations():
    from tgwitness import i18n
    keys = group_keys()
    for lang in i18n.LANGUAGES[1:]:
        words = json.loads((ROOT / "tgwitness/locales" / (lang + ".json")).read_text(encoding="utf-8"))
        missing = [key for key in keys if key not in words]
        assert not missing, (lang, missing[:8])
    return f"ok  translations: {len(keys)} strings"


def overflow(page):
    return page.evaluate("""() => [...document.querySelectorAll('#view-group *')].filter(e => {
        const r = e.getBoundingClientRect();
        if (!r.width || (r.right <= innerWidth + 1 && r.left >= -1)) return false;
        for (let p = e.parentElement; p && p.id !== 'view-group'; p = p.parentElement)
          if (['auto', 'scroll'].includes(getComputedStyle(p).overflowX)) return false;
        return true;
    }).map(e => e.className || e.tagName).slice(0, 5)""")


def check_browser(directory, output):
    from check_browser import RunningApp, launch_browser, navigate_panel, unlock
    from playwright.sync_api import expect, sync_playwright
    from tgwitness import i18n
    errors = []
    with RunningApp(directory / "panel") as server, sync_playwright() as p:
        registry = server.app.state.profiles
        browser = launch_browser(p)
        context = browser.new_context(viewport={"width": 1440, "height": 1000}, locale="en-US", reduced_motion="reduce")
        page = context.new_page()
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
        page.route("**/api/chats/*/scale", lambda route: route.fulfill(json={
            "total": 1200, "missing_ids": 0, "last_message_id": 1200, "estimate_seconds": 120}))
        unlock(page, server)
        group = page.evaluate("json('profile-groups',{label:'Harbor case'},{root:true}).then(r=>r.groups[0].id)")
        alpha = page.evaluate("g=>json('profiles',{label:'Alpha',group:g},{root:true}).then(r=>r.id)", group)
        beta = page.evaluate("g=>json('profiles',{label:'Beta',group:g},{root:true}).then(r=>r.id)", group)
        store = lambda pid: registry.entries[pid]["app"].state.store
        for pid, name in ((alpha, "alpha_watch"), (beta, "beta_watch")):
            store(pid).set_setting("account", {"id": 1000 + len(name), "username": name})
            store(pid).set_target(CHANNEL, "Harbor channel", "channel", True)
            vault = registry.entries[pid]["app"].state.vault
            vault.save("credentials", {**vault.read("credentials"), "session": "synthetic"})
        store(alpha).append("message.new", {"text": "hello", "sender": {"id": 5}}, chat_id=CHANNEL, message_id=7)
        page.evaluate("loadProfiles()")

        navigate_panel(page, "accounts")
        page.locator("#accounts-groups").evaluate("element=>element.open=true")
        page.locator('[data-action="open-group"]').click()
        expect(page.locator("#view-group h1")).to_have_text("Harbor case")
        assert page.url.split("?")[0].endswith("/groups/" + group), page.url
        expect(page.locator("#view-group .group-goal")).to_contain_text("No goal yet")
        expect(page.locator("#view-group .group-account")).to_have_count(2)
        card = page.locator(f'#view-group .group-account[data-profile="{alpha}"]')
        expect(card).to_contain_text("@alpha_watch")
        expect(card.locator('[data-field="route"]')).to_contain_text("not checked")
        expect(card.locator('[data-field="last"]')).not_to_contain_text("none yet")
        expect(page.locator(f'#view-group .group-account[data-profile="{beta}"] [data-field="last"]')).to_contain_text("none yet")

        chat = page.locator("#view-group .group-chat")
        expect(chat).to_have_count(1)
        expect(chat).to_contain_text("2 of 2 accounts see it")
        expect(chat).to_contain_text("No workspace observation in the last 7 days")
        store(alpha).append("observation.started", {"parameters": {"heartbeat_seconds": 60}})
        page.evaluate("g=>window.TgWitnessOpenGroup(g)", group)
        expect(chat).to_contain_text("Workspace observation: no interruptions in the available period")
        # Workspace activity does not mean this source is currently recorded.
        for pid in (alpha, beta):
            store(pid).set_target(CHANNEL, "Harbor channel", "channel", False)
        page.evaluate("g=>window.TgWitnessOpenGroup(g)", group)
        expect(chat).to_contain_text("none of them records it")
        expect(chat).not_to_contain_text("Workspace observation:")
        for pid in (alpha, beta):
            store(pid).set_target(CHANNEL, "Harbor channel", "channel", True)
        page.evaluate("g=>window.TgWitnessOpenGroup(g)", group)
        expect(chat).to_contain_text("Workspace observation: no interruptions in the available period")
        expect(chat.get_by_role("button", name="Export with 2 accounts")).to_be_visible()
        chat.get_by_role("button", name="Open chat").click()
        expect(page.locator("#view-chats")).to_be_visible()
        page.wait_for_url(re.compile(r"/chats/%d\?ws=%s" % (CHANNEL, alpha)))
        page.go_back()
        expect(page.locator("#view-group h1")).to_have_text("Harbor case", timeout=20000)
        page.locator("#view-group .group-chat").get_by_role("button", name="Export with 2 accounts").click()
        dialog = page.locator("#export-dialog")
        expect(dialog).to_be_visible()
        expect(dialog.locator("#export-dialog-accounts input:checked")).to_have_count(2)
        page.locator("#export-dialog-cancel").click()

        page.evaluate("g=>window.TgWitnessOpenGroup(g)", group)
        expect(page.locator("#view-group h1")).to_have_text("Harbor case")
        page.evaluate("window.showSaveFilePicker=undefined")
        page.locator("#view-group .group-actions").get_by_role("button", name="Export group").click()
        confirm = page.locator("dialog.panel-dialog[open]")
        expect(confirm).to_contain_text("Export the records of every account in the group Harbor case?")
        with page.expect_download() as download:
            confirm.locator("button[type=submit]").click()
        assert download.value.suggested_filename == "tgwitness-group-Harbor-case.zip"
        expect(page.locator("#toast")).to_contain_text("Group export saved")
        assert "profile_group.exported" in {r[0] for r in server.app.state.store.db.execute("SELECT kind FROM events")}

        page.goto(server.url + "/groups/" + group + "?ws=default")
        expect(page.locator("#view-group h1")).to_have_text("Harbor case", timeout=20000)
        pause = page.locator("#view-group .group-actions").get_by_role("button", name="Pause all")
        if pause.is_enabled():
            pause.click()
            confirm = page.locator("dialog.panel-dialog[open]")
            expect(confirm).to_contain_text("Pause")
            confirm.locator("button[value=cancel], button:not([type=submit])").first.click()
        assert page.goto(server.url + "/groups/" + "0" * 31 + "x?ws=default").status == 404
        page.goto(server.url + "/groups/" + "0" * 32 + "?ws=default")
        expect(page.locator("#toast")).to_contain_text("Unknown account group.", timeout=20000)

        for lang in ("en", "ru"):
            context.add_cookies([{"name": i18n.COOKIE, "value": lang, "url": server.url}])
            page.goto(server.url + "/groups/" + group + "?ws=default&lang=" + lang)
            expect(page.locator("#view-group h1")).to_have_text("Harbor case", timeout=20000)
            expect(page.locator("#view-group .group-chat")).to_have_count(1)
            for width in WIDTHS:
                page.set_viewport_size({"width": width, "height": 900})
                page.wait_for_timeout(150)
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), (lang, width)
                assert not overflow(page), (lang, width, overflow(page))
                page.screenshot(path=str(output / f"group-{lang}-{width}.png"), full_page=True)
            if lang == "ru":
                expect(page.locator("#view-group .group-section")).to_have_text(i18n.words("ru")["Accounts"])
        browser.close()
    errors = [e for e in errors if not re.fullmatch(r"Failed to load resource: .* status of (400|404) .*", e)]
    assert not errors, errors
    return "ok  browser"


def main():
    output = ROOT / "test-results" / "group-screen-check"
    output.mkdir(parents=True, exist_ok=True)
    print(check_translations())
    with tempfile.TemporaryDirectory() as tmp:
        print(check_browser(Path(tmp), output))
    print("group screen checks passed")


if __name__ == "__main__":
    main()
