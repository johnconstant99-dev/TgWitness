"""Record the synthetic demo's API answers for the read-only online demo on the website.

python tools/capture_demo.py      # writes website/demo/fixtures.json

Runs the local demo (fictional records, no Telegram connection), walks every panel view
in Chromium and stores each GET answer the interface asked for. The website serves the
real panel files with these answers; nothing on the website can change data.
"""
import base64
import json
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright, expect

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_browser import ROOT, RunningApp, launch_browser

OUTPUT = ROOT / "website/demo/fixtures.json"
API = re.compile(r"^/(?:profiles/[a-f0-9]{32}/)?api/")
TEXT_TYPES = ("application/json", "text/", "application/javascript", "image/svg+xml")


def main():
    run = Path(tempfile.mkdtemp(prefix="demo-capture-", dir=ROOT / "test-results"))
    answers = {}

    def record(response):
        request = response.request
        parts = urlsplit(response.url)
        if request.method != "GET" or not API.match(parts.path) or response.status >= 400:
            return
        kind = (response.headers.get("content-type") or "application/octet-stream").split(";")[0].strip()
        body = response.body()
        key = parts.path + ("?" + parts.query if parts.query else "")
        if kind.startswith(TEXT_TYPES):
            answers[key] = {"type": kind, "text": body.decode("utf-8")}
        else:
            answers[key] = {"type": kind, "base64": base64.b64encode(body).decode("ascii")}

    with RunningApp(run / "demo", demo=True) as demo, sync_playwright() as p:
        browser = launch_browser(p)
        for scheme in ("light", "dark"):
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, color_scheme=scheme, reduced_motion="reduce")
            page.on("response", record)
            page.goto(demo.url)
            expect(page.locator("#chat-feed .msg").first).to_be_visible()
            walk(page)
            page.close()
        browser.close()
        root = str((run / "demo").resolve())
    neutralize(answers)
    text = json.dumps(dict(sorted(answers.items())), ensure_ascii=False, indent=0, sort_keys=True)
    # Local paths of the temporary demo directory must not reach the website.
    for form in (root, root.replace("\\", "\\\\"), root.replace("\\", "/")):
        text = text.replace(form, "data/demo")
    leaks = [w for w in ("Administrator", "\\\\Users\\\\", "/Users/", "test-results", "demo-capture-") if w in text]
    if leaks:
        raise SystemExit("Captured answers still contain local details: " + ", ".join(leaks))
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(text + "\n", encoding="utf-8")
    print("Recorded", len(answers), "answers,", round(OUTPUT.stat().st_size / 1024), "KiB:", OUTPUT.relative_to(ROOT))


def neutralize(answers):
    """Remove what describes the capturing machine or third parties rather than the demo."""
    access = answers.get("/api/demo-access")
    if access:
        access["text"] = json.dumps({"available": True, "token": "online-demo"})
    catalog = answers.get("/api/network/catalog")
    if catalog:
        # The bundled public proxy list is not republished on the website.
        value = json.loads(catalog["text"])
        value.update(sources=[], proxies=[])
        catalog["text"] = json.dumps(value)
    for answer in answers.values():
        if "text" in answer:
            # Free space of the capturing disk, replaced by a round illustrative figure.
            answer["text"] = re.sub(r'"disk_free_bytes":\s*\d+', '"disk_free_bytes":536870912000', answer["text"])


def settle(page, ms=500):
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(ms)


def walk(page):
    # Every chat, with each message filter.
    for index in range(page.locator("#chats-list .chat-item").count()):
        page.locator("#chats-list .chat-item").nth(index).click()
        settle(page)
        for f in range(page.locator("#chat-status .filter").count()):
            page.locator("#chat-status .filter").nth(f).click()
            settle(page, 250)
        for summary in page.locator("#view-chats details > summary").all():
            if summary.is_visible():
                summary.click()
                settle(page, 250)
    # Every view, then the journal filters and a few record details.
    for view in ("observations", "sources", "evidence", "witness", "parameters", "connection", "accounts", "chats"):
        page.locator(f'[data-view="{view}"]').first.click()
        settle(page)
        if view == "observations":
            for tab in page.locator("#view-observations button.filter").all():
                if tab.is_visible():
                    tab.click()
                    settle(page, 300)
                    for row in range(page.locator("#events-body tr").count()):
                        page.locator("#events-body tr").nth(row).click()
                        settle(page, 300)
                        page.keyboard.press("Escape")
    page.locator("#notify-toggle").click()
    settle(page, 300)
    page.keyboard.press("Escape")


if __name__ == "__main__":
    main()
