"""Record the synthetic demo's API answers for the read-only online demo on the website.

python tools/capture_demo.py      # writes website/demo/fixtures.json

Runs the local demo (fictional records, no Telegram connection), walks every panel view
in Chromium and stores each GET answer the interface asked for. The website serves the
real panel files with these answers; nothing on the website can change data.
"""
import base64
import hashlib
import io
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright, expect

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_browser import ROOT, RunningApp, launch_browser
from demo_account_export import build_demo_account_exports

OUTPUT = ROOT / "website/demo/fixtures.json"
DOWNLOADS = OUTPUT.parent / "downloads"
API = re.compile(r"^/(?:profiles/[a-f0-9]{32}/)?api/")
TEXT_TYPES = ("application/json", "text/", "application/javascript", "image/svg+xml")


def answer_of(body, kind):
    if kind.startswith(TEXT_TYPES):
        return {"type": kind, "text": body.decode("utf-8")}
    return {"type": kind, "base64": base64.b64encode(body).decode("ascii")}


def capture_downloads(page, demo, answers, account_job, disclosure_id):
    """Build real exports once; the online demo downloads these files on demand."""
    headers = {"Authorization": "Bearer " + demo.app.state.vault.token}
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    paths = {f"/api/export/{fmt}": f"tgwitness-demo.{fmt}" for fmt in ("zip", "jsonl", "csv", "html")}
    paths.update({"/api/checkpoint": "tgwitness-demo-checkpoint.json",
                  "/api/run-receipt": "tgwitness-demo-run-receipt.json",
                  "/api/anchor-request": "tgwitness-demo-timestamp-request.zip"})
    paths.update({f"/api/account-export/{account_job}/download": "tgwitness-demo-account-export.zip",
                  f"/api/account-export/{account_job}/disclosures/{disclosure_id}/download":
                    "tgwitness-demo-minimized-disclosure.zip"})
    for path, filename in paths.items():
        response = page.request.get(demo.url + path, headers=headers)
        if response.status != 200:
            raise RuntimeError(f"Could not capture {path}: HTTP {response.status}")
        body = response.body()
        (DOWNLOADS / filename).write_bytes(body)
        answers[path] = {"type": response.headers["content-type"].split(";")[0],
                         "file": "downloads/" + filename, "bytes": len(body),
                         "sha256": hashlib.sha256(body).hexdigest()}
    # This POST only verifies the synthetic journal; it does not change any records.
    response = page.request.post(demo.url + "/api/verify", headers=headers, data={})
    if response.status != 200:
        raise RuntimeError("Could not verify the captured synthetic journal")
    answers["/api/verify"] = answer_of(response.body(), "application/json")
    from tgwitness.verify import verify_account_disclosure, verify_account_export, verify_bundle, verify_report
    verified = verify_bundle(DOWNLOADS / "tgwitness-demo.zip")
    verify_report(DOWNLOADS / "tgwitness-demo.html", expected_fingerprint=verified["fingerprint"])
    if verified["events"] != response.json()["events"]:
        raise RuntimeError("The sample archive and journal verification cover different records")
    account_file = DOWNLOADS / "tgwitness-demo-account-export.zip"
    disclosure_file = DOWNLOADS / "tgwitness-demo-minimized-disclosure.zip"
    verify_account_export(account_file, verified["fingerprint"])
    verify_account_disclosure(disclosure_file, verified["fingerprint"], source=account_file)
    print("Verified synthetic exports:", verified["events"], "records", flush=True)


def main():
    (ROOT / "test-results").mkdir(exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="demo-capture-", dir=ROOT / "test-results"))
    answers = {}
    account_job, disclosure_id = build_demo_account_exports(run / "demo")

    def record(response):
        request = response.request
        parts = urlsplit(response.url)
        if request.method != "GET" or not API.match(parts.path) or response.status >= 400:
            return
        kind = (response.headers.get("content-type") or "application/octet-stream").split(";")[0].strip()
        body = response.body()
        key = parts.path + ("?" + parts.query if parts.query else "")
        answers[key] = answer_of(body, kind)

    with RunningApp(run / "demo", demo=True) as demo, sync_playwright() as p:
        browser = launch_browser(p)
        page = browser.new_page(viewport={"width": 1440, "height": 1000}, color_scheme="dark", reduced_motion="reduce")
        page.on("response", record)
        page.goto(demo.url)
        expect(page.locator("#chat-feed .msg").first).to_be_visible()
        walk(page)
        capture_downloads(page, demo, answers, account_job, disclosure_id)
        page.close()
        browser.close()
        root = str((run / "demo").resolve())
    neutralize(answers)
    scan_downloads(answers, root)
    text = json.dumps(dict(sorted(answers.items())), ensure_ascii=False, indent=0, sort_keys=True)

    for form in (root, root.replace("\\", "\\\\"), root.replace("\\", "/")):
        text = text.replace(form, "data/demo")
    leaks = [w for w in ("Administrator", "\\\\Users\\\\", "/Users/", "test-results", "demo-capture-") if w in text]
    if leaks:
        raise SystemExit("Captured answers still contain local details: " + ", ".join(leaks))
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(text + "\n", encoding="utf-8")
    print("Recorded", len(answers), "answers,", round(OUTPUT.stat().st_size / 1024), "KiB:", OUTPUT.relative_to(ROOT))


def scan_downloads(answers, root):
    """Do not publish signed sample archives containing capture-host details."""
    markers = [root, root.replace("\\", "/"), root.replace("\\", "\\\\"),
               "Administrator", "\\Users\\", "/Users/", "test-results", "demo-capture-"]
    markers = [value.lower().encode("utf-8") for value in markers]
    for route, answer in answers.items():
        if not answer.get("file"):
            continue
        body = (OUTPUT.parent / answer["file"]).read_bytes()
        payloads = [body]
        if answer["type"] == "application/zip":
            with zipfile.ZipFile(io.BytesIO(body)) as archive:
                payloads.extend(archive.read(name) for name in archive.namelist())
        if any(marker in payload.lower() for payload in payloads for marker in markers):
            raise ValueError("Sample download contains capture-host details: " + route)


def neutralize(answers):
    """Remove what describes the capturing machine or third parties rather than the demo."""
    access = answers.get("/api/demo-access")
    if access:
        access["text"] = json.dumps({"available": True, "token": "online-demo"})
    if "/api/access" in answers:
        console = {"type": "application/json", "text": json.dumps({"lines": [], "last": 0})}
        answers["/api/access/console"] = console
        for key in list(answers):
            if key.startswith("/api/access/console?"):
                answers[key] = console
    catalog = answers.get("/api/network/catalog")
    if catalog:

        value = json.loads(catalog["text"])
        value.update(sources=[], proxies=[])
        catalog["text"] = json.dumps(value)
    for path, answer in answers.items():
        if "text" in answer and path in ("/api/status", "/api/profiles"):
            # A static recording cannot describe the viewer's disk; never alter signed records.
            answer["text"] = re.sub(r'"disk_free_bytes":\s*\d+', '"disk_free_bytes":null', answer["text"])


def settle(page, ms=50):
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(ms)


def walk(page):

    for index in range(page.locator("#chats-list .chat-item").count()):
        page.locator("#chats-list .chat-item").nth(index).click()
        settle(page)
        page.locator('#chat-status [data-chat-view="people"]').click()
        settle(page)
        page.locator('#chat-status [data-chat-view="messages"]').click()
        page.locator('#chat-status [data-chat-filter="all"]').click()
        for summary in page.locator("#view-chats details > summary").all():
            if summary.is_visible():
                summary.click()
                settle(page)

    views = page.locator('.sidebar [data-view]:visible').evaluate_all('nodes=>nodes.map(n=>n.dataset.view)')
    for view in dict.fromkeys([*views, "chats"]):
        page.locator(f'[data-view="{view}"]').first.click()
        settle(page)
        if view == "observations":
            for tab in page.locator("#view-observations button.filter").all():
                if tab.is_visible():
                    tab.click()
                    settle(page)
    page.locator("#notify-toggle").click()
    settle(page)
    page.keyboard.press("Escape")


if __name__ == "__main__":
    main()
