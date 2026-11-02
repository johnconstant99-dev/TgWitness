"""Check group settings (group_settings.py, views/group-settings.js) in a browser; tools/test_group_settings.py
covers the server rules.

Every new string is translated in each panel language. A group shares a goal: the preview lists the accounts
with a different value; Settings of an account then marks each value 🔗 from the group or ✏️ its own and
returns it to the group's; an account's own value is kept when the group changes; a value one account has
becomes the group's; moving an account into the group offers the group's values; an access can open a group;
the journal names the new records. The group page and the marked Settings at 360, 600, 1024 and 1440 pixels
in English and Russian, without horizontal overflow or console errors.
"""
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

# Strings of group settings outside views/group-settings.js: Settings, Accounts, Access, the journal and the server.
EXTRA = (
    "From the group", "Own value", "Return to the group value", "This account is in the group {name}.",
    "🔗 marks a value from the group; ✏️ marks this account’s own value.", "Group settings", "Shared with the group",
    "Settings the group shares besides those in the other sections:",
    "The group shares only settings shown in the other sections.", "VPN",
    "{n} setting of this account differs from the group {name}:", "{n} settings of this account differ from the group {name}:",
    "and {n} more", "Take the group's values? Otherwise the account keeps its own and Settings marks them ✏️.",
    "Take the shared settings?", "Take the group's values", "The account now follows the group.",
    "Copy settings from one account", "Shared settings",
    "Apply copies these settings from the chosen account to every other member, and the group then shares them: "
    "accounts added later start with them. Each member records what it received in its signed journal; an observing "
    "account keeps its IP mode until it is paused.",
    "Group {name}: every account", "Group {name}", "{n} account", "{n} accounts",
    "Account groups: every account of the group, including ones added to it later.",
    "Group settings taken", "Group settings changed", "Accounts returned to the group settings",
    "Group settings not applied", "Group shares its copied settings",
    "Choose a goal for the group first; its settings come together.",
    "These group settings conflict. Review external requests and timestamps.",
    "The group does not share this setting.", "This workspace is not in the group.", "Workspace unavailable",
    "Unknown shared setting.",
)
WIDTHS = (360, 600, 1024, 1440)


def group_keys():
    from i18n_keys import script_keys
    from tgwitness import group_settings
    source = (ROOT / "tgwitness/static/views/group-settings.js").read_text(encoding="utf-8")
    keys = script_keys(source)
    keys += re.findall(r"\['[a-z_]+','([^']+)'\]", re.search(r"const OTHER=\[(.*?)\];", source, re.S).group(1))
    keys += re.findall(r"(?:button|message)\('([^']+)'", source)
    # The names of the shared settings come from the server, Parameters included.
    keys += list(group_settings.LABELS.values())
    return list(dict.fromkeys([*keys, *EXTRA]))


def check_translations():
    from tgwitness import i18n
    keys = group_keys()
    for lang in i18n.LANGUAGES[1:]:
        words = json.loads((ROOT / "tgwitness/locales" / (lang + ".json")).read_text(encoding="utf-8"))
        missing = [key for key in keys if key not in words]
        assert not missing, (lang, missing[:8])
    return f"ok  translations: {len(keys)} group-settings strings in {len(i18n.LANGUAGES) - 1} languages"


def overflow(page):
    """Elements past the screen edge, except inside their own scrolling box."""
    return page.evaluate("""() => [...document.querySelectorAll('#view-settings *')].filter(e => {
        const r = e.getBoundingClientRect();
        if (!r.width || (r.right <= innerWidth + 1 && r.left >= -1)) return false;
        for (let p = e.parentElement; p && p.id !== 'view-settings'; p = p.parentElement)
          if (['auto', 'scroll'].includes(getComputedStyle(p).overflowX)) return false;
        return true;
    }).map(e => e.className || e.tagName).slice(0, 5)""")


def answer(page, ticks=None):
    """Confirm the group change preview; ticks maps an account label to its wanted checkbox state."""
    from playwright.sync_api import expect
    dialog = page.locator("dialog.panel-dialog[open]")
    expect(dialog).to_have_count(1)
    for name, wanted in (ticks or {}).items():
        box = dialog.locator(".panel-dialog-choices label", has_text=name).locator("input")
        box.set_checked(wanted)
    dialog.locator("button[type=submit]").click()
    expect(dialog).to_have_count(0)


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
        unlock(page, server)
        group = page.evaluate("json('profile-groups',{label:'Harbor case'},{root:true}).then(r=>r.groups[0].id)")
        alpha = page.evaluate("g=>json('profiles',{label:'Alpha',group:g},{root:true}).then(r=>r.id)", group)
        beta = page.evaluate("json('profiles',{label:'Beta'},{root:true}).then(r=>r.id)")
        page.evaluate("async g=>{await json('profiles/default/group',{group:g},{root:true,method:'PUT'});await loadProfiles();}", group)
        store = lambda pid: registry.entries[pid]["app"].state.store

        # The group's page opens from Accounts; the group starts sharing a goal, by default for every account.
        navigate_panel(page, "accounts")
        page.locator("#accounts-groups").evaluate("element=>element.open=true")
        page.locator('[data-action="shared-settings"]').click()
        heading = page.locator("#view-settings h1")
        expect(heading).to_have_text("Shared settings: Harbor case")
        expect(page.locator("#view-settings .group-members li")).to_have_count(2)
        page.locator('#view-settings [data-answer="watch"]').click()
        dialog = page.locator("dialog.panel-dialog[open]")
        expect(dialog).to_contain_text("Applies to 2 of 2 accounts.")
        expect(dialog.locator(".panel-dialog-choices input:checked")).to_have_count(2)
        answer(page)
        expect(page.locator("#toast")).to_contain_text("Applied to 2 accounts")
        expect(page.locator('#view-settings [data-answer="watch"]')).to_have_attribute("aria-pressed", "true")
        assert all(store(pid).get_setting("goal_preset")["goal"] == "watch" for pid in ("default", alpha))

        page.locator('#view-settings [data-setting="files"] select').select_option("all")
        expect(dialog).to_contain_text("Saved files: Photos and videos up to 60 seconds / 20 MB → All files up to 1 GB")
        answer(page)
        expect(page.locator('#view-settings [data-setting="files"] select')).to_have_value("all")

        # The account's Settings: 🔗 from the group, ✏️ its own value, and back.
        page.get_by_role("button", name="Back to account settings").click()
        expect(page.locator("#view-settings .hub-group-note")).to_contain_text("This account is in the group Harbor case.")
        page.locator('#view-settings .hub-summary[data-section="collection"]').click()
        mark = page.locator('#view-settings [data-setting="files"] .inherit-mark')
        expect(mark).to_have_attribute("data-inherit", "group")
        expect(mark).to_contain_text("From the group")
        page.locator('#view-settings [data-setting="files"] select').select_option("photos")
        expect(mark).to_have_attribute("data-inherit", "own")
        mark.get_by_role("button", name="Return to the group value").click()
        expect(mark).to_have_attribute("data-inherit", "group")
        assert store("default").get_setting("capture")["max_media_mb"] == 1000

        # Alpha keeps its own value when the group changes, unless ticked.
        result = page.evaluate("""async id=>{const s=await json('settings',undefined,{profile:id});
            return json('settings/edit',{key:'files',value:'photos',revision:s.revision},{profile:id});}""", alpha)
        assert result["inheritance"]["keys"]["files"]["source"] == "own"
        page.locator('#view-settings .hub-group-note').get_by_role("button", name="Group settings").click()
        expect(page.locator("#view-settings .group-members")).to_contain_text("Alpha · 1 own value")
        page.locator('#view-settings [data-setting="files"] select').select_option("short_media")
        expect(dialog.locator(".panel-dialog-choices input")).to_have_count(1)
        expect(dialog.locator(".panel-dialog-choices")).to_contain_text("Alpha · own value: Saved files Photos up to 20 MB")
        expect(dialog).to_contain_text("Applies to 1 of 2 accounts.")
        answer(page)
        expect(page.locator("#toast")).to_contain_text("1 account kept its own value.")
        assert store(alpha).get_setting("capture")["max_media_mb"] == 20
        assert store(alpha).get_setting("capture")["types"]["video"]["enabled"] is False

        # A value one account has becomes the group's.
        page.evaluate("json('parameters',{values:{snapshot_max:777}})")
        page.get_by_role("button", name="Back to account settings").click()
        page.locator('#view-settings .hub-group-note').get_by_role("button", name="Group settings").click()
        row = page.locator('#view-settings [data-setting="parameters"]')
        expect(row).to_contain_text("Not shared: each account keeps its own value.")
        row.locator("select").select_option("default")
        row.get_by_role("button", name="Share this value").click()
        expect(dialog).to_contain_text("Parameters:")
        answer(page)
        expect(row).to_contain_text("2 of 2 accounts follow the group")
        assert store(alpha).get_setting("parameters")["snapshot_max"] == 777

        # Moving an account into the group offers the group's values.
        navigate_panel(page, "accounts")
        page.locator(f'.account-card[data-profile="{beta}"] .fleet-card-group').select_option(group)
        expect(dialog).to_contain_text("Take the group's values?")
        dialog.locator("button[type=submit]").click()
        expect(page.locator("#toast")).to_contain_text("The account now follows the group.")
        assert store(beta).get_setting("goal_preset")["goal"] == "watch"
        assert store(beta).get_setting("parameters")["snapshot_max"] == 777

        # An access can open the whole group, including accounts added to it later.
        navigate_panel(page, "access")
        expect(page.locator("#access-groups")).to_be_visible()
        expect(page.locator("#access-group-list")).to_contain_text("Group Harbor case · 3 accounts")

        kinds = {row["kind"] for row in server.app.state.store.db.execute("SELECT kind FROM events")}
        assert {"profile_group.settings_changed", "profile_group.settings_adopted"} <= kinds, kinds
        assert "group.settings_inherited" in {row["kind"] for row in store(alpha).db.execute("SELECT kind FROM events")}
        labels = set(page.evaluate("Object.keys(labels)"))
        assert {"group.settings_inherited", "profile_group.settings_changed", "profile_group.settings_adopted",
                "profile_group.settings_failed", "profile_group.migrated"} <= labels

        # The group page and the marked Settings at four widths, in English and Russian.
        for lang in ("en", "ru"):
            context.add_cookies([{"name": i18n.COOKIE, "value": lang, "url": server.url}])
            page.goto(server.url + "/settings?ws=default&lang=" + lang)
            expect(page.locator("#view-settings .hub-group-note")).to_be_visible(timeout=20000)
            for width in WIDTHS:
                page.set_viewport_size({"width": width, "height": 900})
                for scope in ("account", "group"):
                    if scope == "group":
                        page.evaluate("g=>settingsHub.openGroup(g)", group)
                        expect(page.locator("#view-settings .group-members")).to_be_visible()
                    else:
                        back = page.locator("#view-settings .hub-heading button.text-link")
                        if back.count():
                            back.click()
                        page.locator('#view-settings .hub-summary[data-section="collection"]').click()
                        expect(page.locator('#view-settings [data-setting="files"] .inherit-mark')).to_be_visible()
                    page.wait_for_timeout(150)
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), (lang, width, scope)
                    assert not overflow(page), (lang, width, scope, overflow(page))
                    page.screenshot(path=str(output / f"{scope}-{lang}-{width}.png"), full_page=True)
            if lang == "ru":
                expect(page.locator("#view-settings h1")).to_have_text(
                    i18n.words("ru")["Shared settings: {name}"].replace("{name}", "Harbor case"))
        browser.close()
    assert not errors, errors
    return "ok  browser: group goal and values, 🔗/✏️ marks and return, own value kept, shared from an account, " \
           "move into group, access by group, journal; en ru at 4 widths"


def main():
    output = ROOT / "test-results" / "group-settings-check"
    output.mkdir(parents=True, exist_ok=True)
    print(check_translations())
    with tempfile.TemporaryDirectory() as tmp:
        print(check_browser(Path(tmp), output))
    print("group settings checks passed")


if __name__ == "__main__":
    main()
