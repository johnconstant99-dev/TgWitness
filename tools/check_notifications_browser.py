"""Notification grouping, scoped navigation and viewport checks with synthetic records."""
import argparse
import re
from pathlib import Path
import sys
import tempfile

from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_browser import RunningApp, launch_browser, unlock, check_layout


HARBOR, OTHER = -1001, -1002
SHOTS = Path("build/notifications-review")


def seed(app):
    store = app.app.state.store
    for chat_id, title in ((HARBOR, "Harbor research"), (OTHER, "Separate workspace notes")):
        store.set_target(chat_id, title, "supergroup", True)
        store.append("message.new", {"text": "Synthetic observation", "sender_id": 7}, chat_id, 1)
    for _ in range(12):
        store.append("replica.completed", {"error": "TimeoutError", "destination": "https://copy.example/archive"})
    for _ in range(4):
        store.append("collector.error", {"operation": "recheck", "error_type": "TimeoutError"}, HARBOR)
    store.append("storage.ok", {"free_bytes": 2000000000})
    store.append("message.edited", {"text": "Updated synthetic observation"}, HARBOR, 1)
    store.append("message.deleted", {}, HARBOR, 1)
    store.append("source.discovered", {"title": "Separate workspace notes"}, OTHER)


def capture(page, label):
    SHOTS.mkdir(parents=True, exist_ok=True)
    for width, height in ((1440, 1000), (390, 844)):
        page.set_viewport_size({"width": width, "height": height})
        for theme in ("light", "dark"):
            page.evaluate("theme => document.documentElement.dataset.theme=theme", theme)
            page.mouse.move(20, 20)
            if not page.locator("#notify-panel").is_visible():
                page.locator("#notify-toggle").click()
            expect(page.locator("#notify-panel")).to_be_visible()
            page.wait_for_timeout(160)
            page.screenshot(path=str(SHOTS / f"{label}-{width}-{theme}.png"), animations="disabled")
            if label != "before":
                fit(page)
                check_layout(page)


def fit(page):
    bounds = page.locator("#notify-panel").bounding_box()
    assert bounds and bounds["x"] >= 0 and bounds["y"] >= 0, bounds
    assert bounds["x"] + bounds["width"] <= page.viewport_size["width"] + 1, bounds
    assert bounds["y"] + bounds["height"] <= page.viewport_size["height"] + 1, bounds
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "Notifications overflow horizontally"


def open_panel(page):
    if not page.locator("#notify-panel").is_visible():
        page.locator("#notify-toggle").click()
    expect(page.locator("#notify-panel")).to_be_visible()
    expect(page.locator("#notify-status")).to_have_text("")


def close_panel(page):
    if page.locator("#notify-panel").is_visible():
        page.locator("#notify-close").click()


def api(page, server, path, body):
    result = page.request.post(server.url + path, headers={"Authorization": "Bearer " + server.app.state.vault.token}, data=body)
    assert result.ok, result.text()
    return result.json()


def check_behavior(page, server, browser):
    page.set_viewport_size({"width": 1440, "height": 1000})
    close_panel(page)
    open_panel(page)
    expect(page.locator(".notice-card")).to_have_count(5)
    expect(page.locator(".notice-card", has_text="Off-site copy stopped").locator(".notice-repeat")).to_have_text("12 records")
    page.locator("#notify-tab-problems").click()
    expect(page.locator(".notice-card")).to_have_count(3)
    page.locator("#notify-tab-problems").press("ArrowRight")
    expect(page.locator("#notify-tab-changes")).to_be_focused()
    expect(page.locator(".notice-card")).to_have_count(2)
    page.locator("#notify-tab-all").click()
    error_card = page.locator(".notice-card", has_text="Collection error during recheck")
    error_card.locator(".notice-ack").click()
    expect(error_card).not_to_have_class(re.compile(r"\bunread\b"))
    expect(page.locator("#notify-count")).to_have_text("4")
    close_panel(page)
    page.reload()
    expect(page.locator("#workspace")).to_be_visible()
    page.locator('[data-view="observations"]').click()
    open_panel(page)
    expect(error_card.locator(".notice-ack")).to_have_text("Read")
    close_panel(page)
    server.app.state.store.append("collector.error", {"operation": "recheck", "error_type": "TimeoutError"}, HARBOR)
    open_panel(page)
    expect(error_card.locator(".notice-ack")).to_have_text("Mark as read")
    expect(error_card.locator(".notice-repeat")).to_have_text("5 records")
    page.locator("#notify-read").click()
    expect(page.locator("#notify-count")).to_be_hidden()
    page.evaluate("loadNotifications()")
    expect(page.locator("#notify-count")).to_be_hidden()
    page.keyboard.press("Escape")
    expect(page.locator("#notify-panel")).to_be_hidden()
    expect(page.locator("#notify-toggle")).to_be_focused()

    # Acknowledging the default workspace must not acknowledge a second account's same error.
    profile = api(page, server, "/api/profiles", {"label": "Second workspace"})["id"]
    other_store = server.app.state.profiles.entries[profile]["app"].state.store
    other_store.append("collector.error", {"operation": "recheck", "error_type": "TimeoutError"}, HARBOR)
    page.reload()
    expect(page.locator("#workspace")).to_be_visible()
    page.locator('[data-view="observations"]').click()
    page.locator("#profile-select").select_option(profile)
    page.wait_for_function("() => !document.querySelector('#workspace').inert")
    expect(page.locator("#notify-count")).to_have_text("1")
    expect(page.locator("#notify-count")).to_be_visible()
    open_panel(page)
    page.locator("#notify-read").click()
    close_panel(page)
    page.locator("#profile-select").select_option("default")
    page.wait_for_function("() => !document.querySelector('#workspace').inert")
    open_panel(page)
    expect(page.locator("#notify-count")).to_be_hidden()

    # Rules are navigation, and preserve an unsaved settings draft.
    page.locator("#notify-rules").click()
    expect(page.locator("#extras-alerts")).to_be_visible()
    page.locator("#alerts-advanced summary").click()
    page.locator("#alerts-urls").fill("jsons://notify.example/unsaved-draft")
    mutations = []
    page.on("request", lambda request: mutations.append(request.url) if request.method != "GET" and "/api/alerts" in request.url else None)
    open_panel(page)
    page.locator("#notify-rules").click()
    expect(page.locator("#alerts-urls")).to_have_value("jsons://notify.example/unsaved-draft")
    assert not mutations, mutations

    # Lower-bound counts are visibly qualified, including old demo data without metadata.
    def partial(route):
        response = route.fetch()
        data = response.json()
        data["items"][0].update(count=3, count_exact=False, scan_limit=3)
        route.fulfill(response=response, json=data)
    page.route("**/api/notifications", partial)
    open_panel(page)
    expect(page.locator(".notice-card").first.locator(".notice-repeat")).to_have_text("3+ records")
    page.unroute("**/api/notifications", partial)
    close_panel(page)

    # Exact chat IDs are used; a read-only scoped viewer never receives hidden titles or settings actions.
    secret = "HIDDEN-NOTICE-SECRET"
    server.app.state.store.append("collector.error", {"operation": secret, "error_type": "OSError"}, OTHER)
    xss = '<img src=x onerror="window.noticeXss=1">'
    server.app.state.store.append("collector.error", {"operation": xss, "error_type": "OSError"}, HARBOR)
    grant = api(page, server, "/api/access/grants", {"label": "Scoped reader", "workspaces": {"default": [HARBOR]}})
    reader = browser.new_page(viewport={"width": 390, "height": 844})
    reader_requests = []
    reader.on("request", lambda request: reader_requests.append(request.url))
    reader.goto(server.url)
    reader.locator("#panel-token").fill(grant["token"])
    with reader.expect_response(
        lambda response: response.url == server.url + "/api/status"
        and response.request.method == "GET", timeout=20000,
    ) as ready:
        reader.get_by_role("button", name="Open workspace", exact=True).click()
    assert ready.value.ok, ready.value.status
    expect(reader.locator("#workspace")).to_be_visible()
    open_panel(reader)
    expect(reader.locator("#notify-list")).to_contain_text(xss)
    assert secret not in reader.locator("#notify-list").inner_text()
    assert not reader.locator("#notify-list img").count() and reader.evaluate("window.noticeXss") is None
    expect(reader.locator("#notify-rules")).to_be_hidden()
    fit(reader)
    reader.locator("#notify-tab-changes").click()
    reader.locator(".notice-card .notice-action", has_text="Open chat").click()
    expect(reader.locator("#chat-feed")).to_contain_text("Updated synthetic observation")
    assert reader.evaluate("state.chat") == HARBOR
    assert not any("/api/multi-export/current" in url for url in reader_requests), reader_requests
    reader.close()

    # A popover near the screen edge flips above its trigger and remains in the viewport.
    page.locator('[data-view="observations"]').click()
    open_panel(page)
    page.evaluate("""() => {
      Object.assign(document.querySelector('#notify-toggle').style,{position:'fixed',right:'8px',bottom:'8px'});
      dispatchEvent(new Event('resize'));
    }""")
    fit(page)
    panel_box, trigger_box = page.locator("#notify-panel").bounding_box(), page.locator("#notify-toggle").bounding_box()
    assert panel_box["y"] + panel_box["height"] < trigger_box["y"], (panel_box, trigger_box)
    page.evaluate("document.querySelector('#notify-toggle').removeAttribute('style')")
    page.mouse.click(20, 20)
    expect(page.locator("#notify-panel")).to_be_hidden()

    # A delayed old response cannot replace a more recent refresh or reopen a locked popup.
    held = []
    def delay(route):
        if not held:
            held.append((route, route.fetch()))
        else:
            route.continue_()
    page.route("**/api/notifications", delay)
    page.evaluate("() => {void loadNotifications().catch(()=>{});}")
    for _ in range(100):
        if held:
            break
        page.wait_for_timeout(50)
    assert held, "Notification read was not intercepted"
    page.evaluate("loadNotifications()")
    route, response = held[0]
    old = response.json()
    old["items"][0]["text"] = "STALE-RESPONSE-SECRET"
    route.fulfill(response=response, json=old)
    page.wait_for_timeout(150)
    assert "STALE-RESPONSE-SECRET" not in page.locator("#notify-list").inner_text()
    page.unroute("**/api/notifications", delay)
    held.clear()
    page.route("**/api/notifications", delay)
    page.locator("#notify-toggle").click()
    for _ in range(100):
        if held:
            break
        page.wait_for_timeout(50)
    assert held
    page.locator("#top-lock").click()
    expect(page.locator("#gate")).to_be_visible()
    route, response = held[0]
    route.fulfill(response=response)
    page.wait_for_timeout(150)
    expect(page.locator("#notify-panel")).to_be_hidden()
    assert not page.locator(".notice-card").count()
    page.unroute("**/api/notifications", delay)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--before", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="notice-check-") as scratch, RunningApp(Path(scratch)) as server:
        seed(server)
        with sync_playwright() as p:
            browser = launch_browser(p)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            unlock(page, server)
            if not args.before:
                error = page.evaluate("noticesReady.then(() => null, error => error.stack)")
                assert not error, error
            page.locator('[data-view="observations"]').click()
            capture(page, "before" if args.before else "after")
            if not args.before:
                check_behavior(page, server, browser)
                assert not errors, errors
            browser.close()
    print("Notifications passed: groups, scope, read state, drafts, safe navigation, races and responsive layout.")


if __name__ == "__main__":
    main()
