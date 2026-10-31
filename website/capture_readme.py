"""Capture the actual read-only demo for the README.

Run tools/build_site.py first, then this script with Playwright, Chromium and
Pillow installed. Only the generated local demo and its fictional fixtures are
used. Nothing is sent to Telegram or to an external service.
"""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
import threading
from urllib.parse import urlsplit

from PIL import Image
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "dist/site"
OUT = ROOT / "docs/assets/presentation"


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


def capture(page, mobile):
    """Use the desktop viewport or a readable crop of the phone conversation."""
    page.locator("#chat-feed").evaluate("el => el.scrollTop = 0")
    if mobile:
        page.locator("#chat-status").evaluate(
            "el => window.scrollTo(0, el.getBoundingClientRect().top + scrollY)"
        )
    else:
        page.evaluate("scrollTo(0, 0)")
    page.wait_for_timeout(350)
    clip = {"x": 14, "y": 0, "width": 362, "height": 720} if mobile else None
    return Image.open(BytesIO(page.screenshot(clip=clip))).convert("RGB")


def save_sequence(name, states):


    frames, durations = [], []
    for index, frame in enumerate(states):
        frames.append(frame)
        durations.append(5000 if index == 1 else 3500)
        following = states[(index + 1) % len(states)]
        for step in range(1, 5):
            frames.append(Image.blend(frame, following, step / 5))
            durations.append(80)
    target = OUT / f"{name}.webp"
    frames[0].save(target, save_all=True, append_images=frames[1:], duration=durations,
                   loop=0, quality=86, method=6, minimize_size=True)

    states[1].save(OUT / f"{name}-still.webp", quality=91, method=6)
    with Image.open(target) as result:
        assert result.n_frames == len(frames), (name, result.n_frames)
        assert result.info["loop"] == 0
    print(f"{name}: {len(frames)} frames, {sum(durations) / 1000:.2f}s, {target.stat().st_size:,} bytes", flush=True)


def main():
    assert (SITE / "demo/fixtures.json").read_bytes() == (ROOT / "website/demo/fixtures.json").read_bytes(), "Build the current site first."
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Quiet, directory=str(SITE)))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    errors = []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            for mobile in (False, True):
                for theme in ("dark", "light"):
                    page = browser.new_page(
                        viewport={"width": 390 if mobile else 1440, "height": 900},
                        device_scale_factor=2 if mobile else 1,
                        color_scheme=theme, reduced_motion="reduce",
                        locale="en-US", timezone_id="UTC",
                    )
                    page.on("pageerror", lambda error: errors.append(str(error)))

                    def local_only(route):
                        if urlsplit(route.request.url).hostname != "127.0.0.1":
                            errors.append("Unexpected external request")
                            route.abort()
                        else:
                            route.continue_()

                    page.route("**/*", local_only)
                    page.goto(f"http://127.0.0.1:{server.server_port}/demo/?lang=en", wait_until="networkidle")
                    page.locator('[data-view="chats"]').click()
                    page.locator("button.pill-edited").first.wait_for()
                    assert "Fictional records" in page.locator("body").inner_text()
                    states = [capture(page, mobile)]
                    page.locator(".chat-filters").get_by_role("button", name="Edited", exact=True).click()
                    page.locator("button.pill-edited").first.click()
                    assert "16:00 UTC" in page.locator(".versions").inner_text()
                    assert "17:30 UTC" in page.locator(".versions").inner_text()
                    states.append(capture(page, mobile))
                    page.locator(".chat-filters").get_by_role("button", name="Deleted", exact=True).click()
                    assert page.locator("#chat-feed .pill-deleted").count() == 2
                    states.append(capture(page, mobile))
                    save_sequence("readme-workspace-" + ("mobile-" if mobile else "") + theme, states)
                    page.close()
            browser.close()
        assert not errors, errors
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


if __name__ == "__main__":
    main()
