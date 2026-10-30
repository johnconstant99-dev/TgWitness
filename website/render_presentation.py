"""Render the current investigation artwork into GitHub and website preview PNGs.

Uses reviewed, self-contained SVG artwork. No application imports or network access.
"""
import argparse
import base64
import os
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
FORMATS = {"github": (1280, 640), "social": (1200, 630)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=FORMATS, action="append")
    args = parser.parse_args()
    source = ROOT / "docs/assets/presentation/technical-hero-static.svg"
    data = base64.b64encode(source.read_bytes()).decode("ascii")
    document = (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<title>TgWitness presentation preview</title><style>'
        '*{box-sizing:border-box}html,body{margin:0;width:100%;height:100%;background:#050b12}'
        'img{display:block;width:100%;height:100%;object-fit:contain}</style>'
        '<img alt="TgWitness — Follow the trail. Preserve the evidence." '
        'src="data:image/svg+xml;base64,' + data + '"></html>'
    )
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True, channel=os.environ.get("TGWITNESS_BROWSER_CHANNEL") or None,
        )
        page = browser.new_page(device_scale_factor=1, reduced_motion="reduce")
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.route("http://**/*", lambda route: route.abort())
        page.route("https://**/*", lambda route: route.abort())
        for name in args.format or FORMATS:
            width, height = FORMATS[name]
            page.set_viewport_size({"width": width, "height": height})
            page.set_content(document)
            page.wait_for_function("document.images[0].complete && document.images[0].naturalWidth > 0")
            target = source.parent / ("preview-" + name + ".png")
            page.screenshot(path=str(target))
            if name == "github" and target.stat().st_size >= 1_000_000:
                raise ValueError("GitHub preview must be smaller than 1 MB")
            print(target)
        assert not errors, errors
        browser.close()


if __name__ == "__main__":
    main()
