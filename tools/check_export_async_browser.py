"""Export progress survives network failures without restarting work or crossing sessions."""
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, launch_browser


def new_case(browser, url):
    page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
    page.add_init_script("""(() => {
      const interval = window.setInterval;
      window.setInterval = (callback, delay, ...args) =>
        delay === 5000 ? 0 : interval(callback, delay, ...args);
    })();""")
    page.route("**/api/multi-export/current", lambda route: route.fulfill(json={"phase": "none"}))
    with page.expect_response(
        lambda response: "/api/chats/" in urlsplit(response.url).path
        and urlsplit(response.url).path.endswith("/messages")
        and response.request.method == "GET", timeout=20000,
    ) as initial_messages:
        page.goto(url)
    assert initial_messages.value.ok, initial_messages.value.status
    expect(page.locator("#chat-feed .msg").first).to_be_visible()
    page.evaluate("""() => {
      clearTimeout(multiPoll); multiPoll = null;
      const original = window.fetch;
      window.exportChecks = {requests: [], replies: {}, held: {}};
      window.fetch = async (url, options = {}) => {
        const path = String(url).split('/api/multi-export/')[1];
        if (path === undefined) return original(url, options);
        exportChecks.requests.push({path, method: options.method || 'GET'});
        if (options.method && options.method !== 'GET')
          throw new Error('Polling must never create or change an export');
        const responses = exportChecks.replies[path];
        if (!responses) throw new Error('Unexpected export request: ' + path);
        const reply = responses.length > 1 ? responses.shift() : responses[0];
        if (reply.held) await new Promise(resolve => {
          exportChecks.held[path] = resolve;
          document.documentElement.dataset.exportHeld = path;
        });
        if (reply.network) throw new TypeError('Synthetic connection interruption');
        return new Response(JSON.stringify(reply.body || {detail: 'Synthetic temporary failure'}),
                            {status: reply.status || 200, headers: {'Content-Type': 'application/json'}});
      };
    }""")
    return page


def job(page, job_id="synthetic-export", phase="running"):
    return page.evaluate("""({id, phase}) => ({
      id, phase, chat_id: state.chat, lead: state.profile, title: 'Synthetic export',
      captured: phase === 'done' ? 100 : 10, total: 100, ready: phase === 'done', workers: []
    })""", {"id": job_id, "phase": phase})


def configure(page, responses):
    page.evaluate("replies => {exportChecks.replies = replies;}", responses)


def request_count(page, path):
    return page.evaluate("path => exportChecks.requests.filter(r => r.path === path).length", path)


def finish(page):
    assert page.evaluate("exportChecks.requests.every(r => r.method === 'GET')"), "Polling changed an export"
    page.close()


def check_progress_recovery(browser, url):
    page = new_case(browser, url)
    running, done = job(page), job(page, phase="done")
    configure(page, {running["id"]: [{"status": 503}, {"body": done}]})
    page.evaluate("x => {state.multi = x; renderMulti(); return pollMulti(x.id);}", running)
    expect(page.locator("#export-box")).to_contain_text("10 of 100")
    expect(page.locator("#export-box")).to_contain_text("Export ready: 100 messages", timeout=12000)
    assert request_count(page, running["id"]) == 2
    assert page.evaluate("multiPoll === null"), "Completed export kept polling"
    finish(page)


def check_discovery_recovery(browser, url):
    page = new_case(browser, url)
    done = job(page, phase="done")
    configure(page, {"current": [{"network": True}, {"body": done}]})
    page.evaluate("state.multiChecked = false; resumeMulti()")
    expect(page.locator("#chat-export-get")).to_be_visible(timeout=12000)
    assert request_count(page, "current") == 2
    assert page.evaluate("state.multiChecked")
    finish(page)


def check_late_discovery(browser, url):
    page = new_case(browser, url)
    old, newer = job(page, "older", "done"), job(page, "newer", "done")
    configure(page, {"current": [{"body": old, "held": True}], "newer": [{"body": newer}]})
    page.evaluate("state.multiChecked = false; window.pendingDiscovery = resumeMulti(); void 0")
    expect(page.locator("html")).to_have_attribute("data-export-held", "current")
    page.evaluate("window.duplicateDiscovery = resumeMulti(); void 0")
    assert request_count(page, "current") == 1, "Repeated navigation duplicated discovery"
    page.evaluate("x => {state.multi = x; return pollMulti(x.id);}", newer)
    page.evaluate("async () => {exportChecks.held.current(); await pendingDiscovery; await duplicateDiscovery;}")
    assert page.evaluate("state.multi.id") == "newer", "Late discovery replaced a newer export"
    assert page.evaluate("multiPoll === null")
    finish(page)


def check_late_poll(browser, url):
    page = new_case(browser, url)
    running, newer = job(page), job(page, phase="done")
    configure(page, {running["id"]: [{"body": running, "held": True}, {"body": newer}]})
    page.evaluate("x => {state.multi = x; window.pendingPoll = pollMulti(x.id);}", running)
    expect(page.locator("html")).to_have_attribute("data-export-held", running["id"])
    page.evaluate("pollMulti(state.multi.id)")
    page.evaluate("async () => {exportChecks.held[state.multi.id](); await pendingPoll;}")
    assert page.evaluate("state.multi.phase") == "done", "An older poll rewound completed progress"
    assert page.evaluate("multiPoll === null"), "An older poll restarted a completed timer"
    finish(page)


def check_lock_and_switch(browser, url):
    for action in ("lock()", "await switchProfile('default')"):
        page = new_case(browser, url)
        running, done = job(page), job(page, phase="done")
        configure(page, {running["id"]: [{"body": done, "held": True}], "current": [{"body": {"phase": "none"}}]})
        page.evaluate("x => {state.multi = x; window.pendingPoll = pollMulti(x.id);}", running)
        expect(page.locator("html")).to_have_attribute("data-export-held", running["id"])
        page.evaluate("async () => {" + action + ";}")
        page.evaluate("async id => {exportChecks.held[id](); await pendingPoll;}", running["id"])
        assert not page.evaluate("state.multi?.phase === 'done'"), "A prior workspace updated this view"
        assert page.evaluate("multiPoll === null"), "A prior workspace restarted polling"
        if action == "lock()":
            expect(page.locator("#gate")).to_be_visible()
        else:
            assert page.evaluate("state.multi === null"), "An absent job kept stale progress"
        finish(page)


def check_denied_access(browser, url):
    for status in (401, 403, 404):
        page = new_case(browser, url)
        running = job(page)
        configure(page, {running["id"]: [{"status": status}]})
        page.evaluate("x => {state.multi = x; return pollMulti(x.id);}", running)
        assert page.evaluate("multiPoll === null"), f"HTTP {status} scheduled a retry"
        assert request_count(page, running["id"]) == 1
        if status == 401:
            expect(page.locator("#gate")).to_be_visible()
        finish(page)
    page = new_case(browser, url)
    configure(page, {"current": [{"status": 403}]})
    page.evaluate("state.multiChecked = false; resumeMulti()")
    page.evaluate("resumeMulti()")
    assert request_count(page, "current") == 1, "Denied discovery repeated on every refresh"
    assert page.evaluate("multiPoll === null")
    finish(page)


def main():
    with tempfile.TemporaryDirectory(prefix="export-async-check-") as scratch, RunningApp(
            Path(scratch), demo=True) as server, sync_playwright() as p:
        browser = launch_browser(p)
        check_progress_recovery(browser, server.url)
        check_discovery_recovery(browser, server.url)
        check_late_discovery(browser, server.url)
        check_late_poll(browser, server.url)
        check_lock_and_switch(browser, server.url)
        check_denied_access(browser, server.url)
        browser.close()
    print("Export checks passed: recovery, single discovery, newest progress, workspace guards and access denial.")


if __name__ == "__main__":
    main()
