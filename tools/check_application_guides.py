"""Check the translated guides served by the live application."""
import argparse
import os
from pathlib import Path
import sys
import tempfile

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.browser_helpers import launch_browser
from tools.check_browser import RunningApp
from tools.check_guide_languages import check_guides


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "test-results/application-guides")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    os.environ.pop("TGWITNESS_TOKEN", None)
    with tempfile.TemporaryDirectory(prefix="application-guides-", dir=args.output) as scratch:
        with RunningApp(Path(scratch) / "application", demo=True) as app, sync_playwright() as pw:
            browser = launch_browser(pw)
            check_guides(browser, app.url + "/", args.output, "application")
            browser.close()
    print("Application guide languages passed: 26 bundled guide languages, local routes and browser preferences.")


if __name__ == "__main__":
    main()
