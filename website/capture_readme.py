from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
import argparse
import json
import re
import threading
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "dist/site"
OUT = ROOT / "docs/assets/presentation"


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


def capture(page, mobile):
    from PIL import Image

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
    from PIL import Image
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


def review_repository(repository, revision):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Use an owner/repository name.")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Use the complete commit SHA.")
    output = ROOT / "test-results/readme"
    output.mkdir(parents=True, exist_ok=True)
    records = []
    paths = ("README.md", "docs/README.md", "docs/ru/README.md", "website/validation/audit/README.md")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page(viewport={"width": 1440, "height": 1100}, locale="en-US")
            for path in paths:
                response = page.goto(f"https://github.com/{repository}/blob/{revision}/{path}", wait_until="domcontentloaded")
                assert response and response.ok, (path, response.status if response else None)
                article = page.locator("article.markdown-body").first
                article.wait_for(timeout=30000)
                for width in (1440, 390):
                    page.set_viewport_size({"width": width, "height": 1100})
                    for theme in ("light", "dark"):
                        page.emulate_media(color_scheme=theme, reduced_motion="reduce")
                        page.evaluate("""theme => {
                            const root = document.documentElement;
                            root.dataset.colorMode = theme;
                            root.dataset.lightTheme = 'light';
                            root.dataset.darkTheme = 'dark';
                        }""", theme)
                        article.scroll_into_view_if_needed()
                        article.locator("img").evaluate_all("images => images.forEach(img => img.loading = 'eager')")
                        page.wait_for_function("""() => [...document.querySelectorAll('article.markdown-body img')]
                            .filter(img => img.getClientRects().length)
                            .every(img => img.complete && img.naturalWidth > 0)""", timeout=30000)
                        page.wait_for_timeout(350)
                        images = article.locator("img").evaluate_all("""images => images
                            .filter(img => img.getClientRects().length)
                            .map(img => ({alt: img.alt, source: img.currentSrc, width: img.clientWidth}))""")
                        size = article.evaluate("el => ({width: el.clientWidth, scroll: el.scrollWidth})")
                        assert size["scroll"] <= size["width"] + 2, (path, width, theme, size)
                        if path in ("README.md", "docs/ru/README.md"):
                            cover = "readme-intro-mobile.svg" if width < 640 else "readme-intro.svg"
                            assert cover in images[0]["source"], (path, width, images[0])
                        if path == "README.md":
                            demo = next(img for img in images if "readme-workspace" in img["source"])
                            expected = "readme-workspace-mobile-dark-still.webp" if width < 640 else "readme-workspace-dark-still.webp"
                            assert expected in demo["source"], (width, demo)
                        name = path.replace("/", "-").removesuffix(".md") + f"-{width}-{theme}"
                        article.screenshot(path=str(output / f"{name}.png"), animations="disabled")
                        records.append({"path": path, "viewport": width, "theme": theme, "images": images, **size})
                        if path == "README.md":
                            page.emulate_media(reduced_motion="no-preference")
                            animated = expected.replace("-still", "")
                            page.wait_for_function("""expected => [...document.querySelectorAll('article.markdown-body img')]
                                .some(img => img.currentSrc.includes(expected) && img.complete && img.naturalWidth > 0)""", arg=animated)
                            records[-1]["motion_source"] = animated
                        print(f"Reviewed {path}: {width}px, {theme}", flush=True)
        finally:
            browser.close()
            (output / "review.json").write_text(json.dumps({"revision": revision, "pages": records}, indent=2) + "\n", encoding="utf-8")


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
    parser = argparse.ArgumentParser(description="Capture the fictional demo or review published GitHub READMEs.")
    parser.add_argument("--repository", help="Review GitHub READMEs for owner/repository instead of recording the demo.")
    parser.add_argument("--revision", help="Complete commit SHA for a repository review.")
    args = parser.parse_args()
    if bool(args.repository) != bool(args.revision):
        parser.error("Use --repository and --revision together.")
    if args.repository:
        review_repository(args.repository, args.revision)
    else:
        main()
