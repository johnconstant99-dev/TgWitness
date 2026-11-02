"""Check setup by goal and the credibility and reliability scales (levels.py, views/setup.js).

The proposal for each goal, what Apply changes and records in the signed journal, and the scales
from the actual settings. Then the panel in a browser: the goal card on Start here, the
proposal with its predicted scales, Apply, the Extras card, both widths and Russian.
"""
import argparse
import json
import sys
import tempfile
import time
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
    from check_browser import RunningApp, check_layout, launch_browser, navigate_panel, reload_panel, unlock
    from playwright.sync_api import expect, sync_playwright
    from tgwitness import i18n
    errors = []
    with RunningApp(directory / "panel") as server, sync_playwright() as p:
        store = server.app.state.store
        browser = launch_browser(p)
        context = browser.new_context(viewport={"width": 1280, "height": 900}, reduced_motion="reduce")
        page = context.new_page()
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        unlock(page, server, start=True)
        expect(page.locator("#view-start")).to_be_visible()
        expect(page.locator("#setup-start")).to_be_visible()
        check_layout(page)
        page.screenshot(path=str(output / "setup-start-en.png"))
        page.set_viewport_size({"width": 390, "height": 844})
        check_layout(page)
        page.set_viewport_size({"width": 1280, "height": 900})

        page.locator('[data-setup-goal="evidence"]').click()
        expect(page.locator("#extras-setup")).to_be_visible()
        expect(page.locator('input[name="setup-goal"][value="evidence"]')).to_be_checked()
        expect(page.locator('input[name="setup-size"][value="small"]')).to_be_checked()
        expect(page.locator('input[name="setup-files"][value="media"]')).to_be_checked()
        expect(page.locator("#setup-proposal")).to_be_visible()
        for name in ("timestamps", "drand", "devices"):
            expect(page.locator("#setup-" + name)).to_be_checked()
        expect(page.locator('#setup-steps li[data-step="server"] .setup-tag')).to_have_text("Recommended")
        scale = page.locator('#setup-scales .level-scale').first
        expect(scale.locator(".level-name")).to_have_text("High")
        expect(scale.locator(".level-was")).to_have_text("now: Basic")
        page.locator("#setup-timestamps").uncheck()
        expect(page.locator("#setup-drand")).to_be_disabled()
        expect(page.locator("#setup-drand")).not_to_be_checked()
        expect(scale.locator(".level-was")).to_have_count(0)
        page.locator("#setup-timestamps").check()
        page.locator("#setup-drand").check()
        page.locator("#setup-devices").check()
        page.locator('input[name="setup-place"][value="server"]').check()
        page.locator('input[name="setup-files"][value="all"]').check()
        expect(page.locator("#setup-facts")).to_contain_text("everything up to 1 GB each")
        page.screenshot(path=str(output / "setup-proposal-en.png"), full_page=True)
        for width in (390, 1440):
            page.set_viewport_size({"width": width, "height": 1000})
            check_layout(page)
        page.set_viewport_size({"width": 1280, "height": 900})
        page.locator("#setup-form button[type=submit]").click()
        deadline = time.monotonic() + 15
        while store.get_setting("setup", None) is None and time.monotonic() < deadline:
            time.sleep(.1)
        saved = store.get_setting("setup")
        assert saved["goal"] == "evidence" and saved["place"] == "server" and saved["files"] == "all", saved
        expect(page.locator("#setup-status")).to_contain_text("Evidence for a case")
        expect(page.locator("#setup-skip")).to_be_hidden()

        page.locator('[data-extra-close="setup"]').click()
        expect(page.locator("#extra-setup-badge")).to_have_text("Evidence for a case")
        expect(page.locator("#setup-overview-scales .level-scale")).to_have_count(2)
        expect(page.locator("#setup-overview-scales .level-scale").first.locator(".level-name")).to_have_text("High")
        page.locator(".extra-card.extra-setup").screenshot(path=str(output / "setup-card-en.png"))
        navigate_panel(page, "start")
        expect(page.locator("#setup-start")).to_be_hidden()

        context.add_cookies([{"name": i18n.COOKIE, "value": "ru", "url": server.url}])
        reload_panel(page)
        expect(page.locator("#view-start")).to_be_visible()
        navigate_panel(page, "witness")
        words = i18n.words("ru")
        expect(page.locator("#extra-setup-badge")).to_have_text(words["Evidence for a case"])
        page.locator("#extras-open-setup").click()
        expect(page.locator("#setup-scales .level-scale").first.locator("strong")).to_have_text(words["Credibility"])
        page.screenshot(path=str(output / "setup-proposal-ru.png"), full_page=True)
        browser.close()
    assert not errors, errors
    return "ok  browser: goal card on Start here, proposal with predicted scales, Apply, Extras card; English and Russian"


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
