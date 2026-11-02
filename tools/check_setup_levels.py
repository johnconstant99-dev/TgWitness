"""Check setup by goal and the credibility and reliability scales (levels.py, views/setup.js)."""
import argparse
import json
import sys
import tempfile
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from tgwitness import levels
from tgwitness.anchoring import EvidenceMode
from tgwitness.monitoring import MEDIA_DEFAULT_MB, MEDIA_TYPES
from tgwitness.tuning import BY_KEY

DEFAULT_CAPTURE = {"download_media": True, "record_disabled_media": True, "max_media_mb": 20,
                   "types": {kind: {"enabled": True, "max_mb": MEDIA_DEFAULT_MB[kind]} for kind in MEDIA_TYPES}}
DEFAULT_PARAMETERS = {key: parameter.initial() for key, parameter in BY_KEY.items()}
NO_REPLICA = {"enabled": False, "retention_days": 0}
NO_ALERTS = {"enabled": False, "problems": True}


def setup(**values):
    return levels.Setup(**{"goal": "evidence", "size": "small", "files": "media", "place": "computer", **values})


def check_levels():
    evidence = EvidenceMode().model_dump()
    assert levels.files_choice(DEFAULT_CAPTURE) == "media"
    assert levels.files_choice({**DEFAULT_CAPTURE, "download_media": False}) == "text"
    assert levels.size_choice(1000) == "small" and levels.size_choice(2000) == "medium" \
        and levels.size_choice(5000) == "large"

    planned = levels.plan(setup(timestamps=True, drand=True, devices=True), evidence, DEFAULT_CAPTURE,
                          DEFAULT_PARAMETERS)
    assert planned["evidence"]["enabled"] and planned["evidence"]["drand"] and planned["evidence"]["devices"]
    assert planned["evidence"]["interval_minutes"] == 10 and planned["capture"] is None and planned["parameters"] == {}
    assert planned["evidence"]["tsa_urls"] == evidence["tsa_urls"], "the timestamp services stay as they are"

    on = {**evidence, "enabled": True, "interval_minutes": 45}
    kept = levels.plan(setup(goal="investigation", timestamps=True), on, DEFAULT_CAPTURE, DEFAULT_PARAMETERS)
    assert kept["evidence"] is None or kept["evidence"]["interval_minutes"] == 45, "a chosen interval is kept"
    off = levels.plan(setup(goal="personal"), on, DEFAULT_CAPTURE, DEFAULT_PARAMETERS)
    assert off["evidence"]["enabled"] is False, "an unticked option is switched off"
    try:
        levels.plan(setup(drand=True), evidence, DEFAULT_CAPTURE, DEFAULT_PARAMETERS)
        raise AssertionError("drand without timestamps must be refused")
    except ValueError:
        pass

    big = levels.plan(setup(size="large", files="all"), evidence, DEFAULT_CAPTURE, DEFAULT_PARAMETERS)
    assert big["parameters"] == {"dialog_limit": 20000, "media_min_free_mb": levels.LARGE_MEDIA_RESERVE_MB}
    assert all(rule["enabled"] for rule in big["capture"]["types"].values())
    assert big["capture"]["types"]["video"]["max_mb"] == 1000
    text = levels.plan(setup(files="text"), evidence, DEFAULT_CAPTURE, DEFAULT_PARAMETERS)
    assert text["capture"]["download_media"] is False and text["capture"]["types"] == DEFAULT_CAPTURE["types"]
    own = levels.plan(setup(size="medium"), evidence, DEFAULT_CAPTURE, {**DEFAULT_PARAMETERS, "dialog_limit": 2000})
    assert own["parameters"] == {}, "a limit the person set within the chosen size stays"

    basic = levels.assess(evidence, NO_REPLICA, NO_ALERTS, [], None, {}, [], "computer")
    assert basic["credibility"]["level"] == "basic" and basic["credibility"]["score"] == 1
    assert basic["reliability"]["score"] == 0 and basic["reliability"]["level"] == "basic"
    full = levels.assess({**evidence, "enabled": True, "drand": True, "devices": True, "gateway": True},
                         {"enabled": True, "retention_days": 30}, {"enabled": True, "problems": True},
                         ["tgram://x"], {"mode": "hetzner"}, {"current": True, "last": {"matches": True}},
                         [{"last_poll": {"at": "now"}, "overdue": False}], "computer", gateway_log=True)
    unset = levels.assess({**evidence, "enabled": True, "gateway": True}, NO_REPLICA, NO_ALERTS, [], None, {}, [],
                          "computer", gateway_log=False)
    assert not next(i for i in unset["credibility"]["items"] if i["id"] == "gateway_log")["on"],         "the Gateway log counts only with its token saved"
    assert full["credibility"]["percent"] == 100 and full["credibility"]["level"] == "maximum"
    assert full["reliability"]["percent"] == 100
    mid = levels.assess({**evidence, "enabled": True}, NO_REPLICA, {"enabled": True, "problems": True}, [],
                        None, {"current": False, "last": {"matches": True}}, [{"last_poll": None}], "server")
    assert [i["id"] for i in mid["credibility"]["items"] if i["on"]] == ["journal", "timestamps"]
    assert [i["id"] for i in mid["reliability"]["items"] if i["on"]] == ["always_on"], \
        "notifications without a destination and an outdated code check do not count"
    return "ok  levels: proposals per goal, what Apply changes, settings kept, both scales"


def check_api(directory):
    from check_browser import RunningApp
    with RunningApp(directory / "api") as server:
        store = server.app.state.store
        session = requests.post(server.url + "/api/access/login", json={"token": server.app.state.vault.token},
                                timeout=10).json()["session"]
        headers = {"Authorization": "Bearer " + session}
        get = lambda path: requests.get(server.url + path, headers=headers, timeout=10).json()
        post = lambda path, body: requests.post(server.url + path, json=body, headers=headers, timeout=10)
        assert get("/api/status")["setup_answered"] is False
        state = get("/api/setup")
        assert state["saved"] is None and state["current"] == {"size": "small", "files": "media", "place": "computer"}
        assert state["assessment"]["credibility"]["level"] == "basic"
        refused = post("/api/setup", {"goal": "evidence", "size": "small", "files": "media", "place": "computer",
                                      "drand": True})
        assert refused.status_code == 422, refused.text
        assert store.get_setting("setup", None) is None, "a refused setup saves nothing"
        answer = post("/api/setup", {"goal": "evidence", "size": "large", "files": "all", "place": "server",
                                     "timestamps": True, "drand": True, "devices": True})
        assert answer.ok, answer.text
        result = answer.json()
        assert result["changed"] == ["evidence", "capture", "parameters"], result["changed"]
        assert result["saved"]["goal"] == "evidence" and result["current"]["size"] == "large"
        assert result["current"]["files"] == "all" and result["current"]["place"] == "server"
        evidence = store.get_setting("evidence")
        assert evidence["enabled"] and evidence["drand"] and evidence["devices"] and evidence["interval_minutes"] == 10
        assert store.get_setting("parameters")["dialog_limit"] == 20000
        kinds = [row["kind"] for row in store.db.execute("SELECT kind FROM events ORDER BY seq")]
        for kind in ("evidence.changed", "capture.changed", "parameters.changed", "setup.applied"):
            assert kind in kinds, kind
        applied = json.loads(store.db.execute("SELECT payload FROM events WHERE kind='setup.applied'").fetchone()[0])
        assert applied["goal"] == "evidence" and applied["changed"] == result["changed"]
        credibility = result["assessment"]["credibility"]
        assert [i["id"] for i in credibility["items"] if i["on"]] == ["journal", "timestamps", "drand", "devices"]
        assert result["assessment"]["reliability"]["items"][0] == {"id": "always_on", "weight": 3, "on": True,
                                                                   "extra": "cloud"}
        again = post("/api/setup", {"goal": "evidence", "size": "large", "files": "all", "place": "server",
                                    "timestamps": True, "drand": True, "devices": True}).json()
        assert again["changed"] == [], "applying the same answers changes nothing"
        assert get("/api/status")["setup_answered"] is True
    with RunningApp(directory / "skip") as server:
        session = requests.post(server.url + "/api/access/login", json={"token": server.app.state.vault.token},
                                timeout=10).json()["session"]
        skipped = requests.post(server.url + "/api/setup/skip", json={}, timeout=10,
                                headers={"Authorization": "Bearer " + session}).json()
        assert skipped["saved"]["skipped"] is True
        assert server.app.state.store.get_setting("evidence", None) is None, "skipping changes no setting"
    return "ok  api: refused combination saves nothing, Apply changes and records each part, repeat is a no-op, skip"


def check_browser(directory, output):
    from check_browser import RunningApp, answer_panel_dialog, check_layout, launch_browser, navigate_panel, unlock
    from playwright.sync_api import expect, sync_playwright
    errors = []
    with RunningApp(directory / "panel") as server, sync_playwright() as p:
        store = server.app.state.store
        browser = launch_browser(p)
        page = browser.new_page(viewport={"width":1280,"height":900},reduced_motion="reduce")
        page.on("pageerror",lambda exc:errors.append(str(exc)))
        unlock(page,server,start=True)
        expect(page.locator('#setup-start')).to_be_hidden()
        navigate_panel(page,'settings')
        page.locator('[data-section="goal"]').click()
        page.locator('[data-answer="evidence"]').click()
        expect(page.locator('dialog.panel-dialog[open]')).to_contain_text('Independent timestamps')
        answer_panel_dialog(page,accept=False)
        assert store.get_setting('goal_preset',None) is None
        page.locator('[data-answer="evidence"]').click()
        answer_panel_dialog(page)
        expect(page.locator('[data-answer="evidence"]')).to_have_attribute('aria-pressed','true')
        assert store.get_setting('goal_preset')['goal']=='evidence'
        assert store.get_setting('evidence')['enabled'] and store.get_setting('evidence')['drand']
        page.locator('[data-section="collection"]').click()
        page.locator('[data-setting="files"] select').select_option('photos')
        expect(page.locator('[data-setting="files"] .modified-tag')).to_have_text('Changed by you')
        page.locator('[data-setting="files"]').get_by_role('button',name='Restore goal value').click()
        expect(page.locator('[data-setting="files"] select')).to_have_value('all')
        expect(page.locator('[data-setting="files"] .modified-tag')).to_have_count(0)
        for width in (390,1280):
            page.set_viewport_size({'width':width,'height':900});check_layout(page)
            page.screenshot(path=str(output / f'settings-goal-{width}.png'),full_page=True)
        page.evaluate("setLanguage('ru')")
        expect(page.locator('#view-settings h1')).to_have_text('Настройки')
        assert store.get_setting('ui_preferences:admin')['language']=='ru'
        assert store.get_setting('goal_preset')['goal']=='evidence'
        browser.close()
    assert not errors,errors
    return 'ok  browser: goal diff, cancellation, apply, manual override, restore, mobile layout and saved language'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    output = ROOT / "test-results" / "setup-levels"
    output.mkdir(parents=True, exist_ok=True)
    print(check_levels())
    with tempfile.TemporaryDirectory() as tmp:
        print(check_api(Path(tmp)))
        print(check_browser(Path(tmp), output))
    print("setup and level checks passed")


if __name__ == "__main__":
    main()
