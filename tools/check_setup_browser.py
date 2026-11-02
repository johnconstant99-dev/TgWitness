"""Witness configuration and proxy setup acceptance; local fixtures only."""
import json
import os
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from check_browser import RunningApp, unlock, check_layout, launch_browser, navigate_panel
from playwright.sync_api import expect, sync_playwright
from tgwitness import i18n


def main():
    output = ROOT / "test-results/setup-browser"
    output.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="run-", dir=output))
    secret = "a7" * 16
    catalog = run / "catalog.json"
    catalog.write_text(json.dumps({"format": "tgwitness-proxy-catalog-v1", "proxies": [{"id": "project-a",
        "label": "Project proxy · synthetic fixture", "link": "tg://proxy?server=proxy.example.org&port=443&secret=" + secret}]}))
    previous = os.environ.get("TGWITNESS_PROXY_CATALOG")
    os.environ["TGWITNESS_PROXY_CATALOG"] = str(catalog)
    errors, external, writes, catalog_reads = [], [], [], []
    try:
        with RunningApp(run / "collector") as server, sync_playwright() as p:
            browser = launch_browser(p)
            context = browser.new_context(viewport={"width": 1440, "height": 1060}, reduced_motion="reduce")
            page = context.new_page()
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on("request", lambda req: external.append(req.url) if urlsplit(req.url).hostname != "127.0.0.1" else None)
            page.on("request", lambda req: writes.append(req.url) if req.method not in ("GET", "HEAD", "OPTIONS") else None)
            page.on("request", lambda req: catalog_reads.append(req.url)
                    if urlsplit(req.url).path.endswith("/api/network/catalog") else None)
            unlock(page, server)

            keys = page.evaluate("""async () => {
                const keys = [];
                for (const path of ['/', '/guide.html']) {
                    const source = await (await fetch(path)).text(), doc = new DOMParser().parseFromString(source, 'text/html');
                    keys.push(doc.title); walkPage((item, whole) => {keys.push(item.key); return whole;}, doc.body);
                } return keys;
            }""")
            (output / "page-keys.json").write_text(json.dumps(keys, ensure_ascii=False), encoding="utf-8")
            for lang in i18n.LANGUAGES[1:]:
                missing = sorted(set(keys) - set(i18n.words(lang)))
                assert not missing, (lang, missing)
            navigate_panel(page, "witness")
            expect(page.locator("#witness-form")).to_be_hidden()
            expect(page.locator(".extra-card")).to_have_count(6)
            before = len(writes)
            for name in ("setup", "alerts", "evidence", "cloud", "github"):
                opener = page.locator("#extras-open-" + name)
                opener.focus()
                page.keyboard.press("Enter")
                expect(page.locator("#extras-" + name + "-title")).to_be_focused()
                expect(opener).to_have_attribute("aria-expanded", "true")
                page.locator('[data-extra-close="' + name + '"]').click()
                expect(opener).to_be_focused()
            assert len(writes) == before, "Opening an extra must not connect a service"
            page.locator("#extras-open-bot").click()
            expect(page.locator("#witness-policy")).to_be_hidden()
            expect(page.locator("#witness-start-command")).to_be_hidden()
            expect(page.locator("#witness-address")).to_have_value(server.url)
            page.locator("#witness-label").fill("Independent operator · fixture")
            page.locator('#witness-form [type="submit"]').click()
            expect(page.locator("#witness-token-download")).to_be_enabled()
            token = page.locator("#witness-token").inner_text()
            with page.expect_download() as download:
                page.locator("#witness-token-download").click()
            assert Path(download.value.path()).read_text().strip() == token
            page.locator("#witness-channel").fill("@synthetic_proof")
            page.locator('[data-extra-close="bot"]').click()
            page.locator("#extras-open-github").click()
            page.locator('[data-extra-close="github"]').click()
            page.locator("#extras-open-bot").click()
            expect(page.locator("#witness-channel")).to_have_value("@synthetic_proof")
            expect(page.locator("#extras-github")).to_be_hidden()
            page.locator("#witness-interval").fill("5")
            expect(page.locator("#witness-volume")).to_contain_text("288")
            with page.expect_download() as download:
                page.locator('#witness-setup-form [type="submit"]').click()
            config = json.loads(Path(download.value.path()).read_text())
            assert config["collector_fingerprint"] == page.evaluate("state.status.fingerprint")
            assert config["collector"] == server.url and config["channel"] == "@synthetic_proof"
            assert config["token_file"] == "witness-token.txt" and config["bot_token_file"] == "bot-token.txt"
            assert token not in json.dumps(config) and config["post"] == "all"
            expect(page.locator("#witness-setup-result")).to_contain_text("Configuration saved")
            expect(page.locator("#witness-start-command")).to_be_visible()

            page.evaluate("lock()")
            assert page.evaluate("state.witnessToken") is None
            assert token not in page.locator("body").inner_text()
            unlock(page, server)
            navigate_panel(page, "connection")
            page.locator("#entry-settings").click()
            page.locator("#network-details > summary").click()
            expect(page.locator("#network-kind")).to_have_value("mtproxy_auto")
            expect(page.locator(".proxy-catalog")).to_be_hidden()
            assert not catalog_reads, "Automatic routing must not load the fixed MTProxy picker"
            page.locator("#network-kind").select_option("mtproxy")
            expect(page.locator(".proxy-catalog")).to_be_visible()
            expect(page.locator("#proxy-catalog-select")).to_have_value("project-a")
            assert catalog_reads, "Selecting MTProxy must load its catalog"
            assert page.locator("#network-secret").input_value() == ""
            page.locator("#proxy-catalog-apply").click()
            expect(page.locator("#route-detail")).to_contain_text("proxy.example.org:443")
            assert server.app.state.collector.network_config().secret == secret
            if page.locator("#entry-settings").get_attribute("aria-expanded") != "true":
                page.locator("#entry-settings").click()
            if not page.locator("#network-link").is_visible():
                page.locator("#network-details > summary").click()
            page.locator("#network-link").fill("https://t.me/proxy?server=own.example.org&port=8443&secret=" + secret)
            page.locator("#network-import").click()
            expect(page.locator("#network-host")).to_have_value("own.example.org")
            expect(page.locator("#network-secret")).to_have_value(secret)
            assert server.app.state.collector.network_config().host == "proxy.example.org"
            page.locator('#network-form [type="submit"]').click()
            expect(page.locator("#route-detail")).to_contain_text("own.example.org:8443")
            expect(page.locator("#network-secret")).to_have_value("")
            for lang in ("en", "ru"):
                context.add_cookies([{"name": "tgwitness-lang", "value": lang, "url": server.url}])
                page.reload()
                expect(page.locator("#workspace")).to_be_visible()
                for width in (390, 1440):
                    page.set_viewport_size({"width": width, "height": 1060})
                    navigate_panel(page, "witness")
                    for theme in ("light", "dark"):
                        page.emulate_media(color_scheme=theme)
                        page.evaluate("selectExtra(null)")
                        check_layout(page)
                        page.evaluate("window.scrollTo(0,0)")
                        page.screenshot(path=str(output / f"extras-{lang}-{theme}-{width}.png"), full_page=True)
                        for name in ("bot", "github"):
                            page.locator("#extras-open-" + name).click()
                            check_layout(page)
                            if name == "bot":
                                page.evaluate("window.scrollTo(0,0)")
                                page.screenshot(path=str(output / f"witness-{lang}-{theme}-{width}.png"), full_page=True)
                            page.locator('[data-extra-close="' + name + '"]').click()
                    navigate_panel(page, "connection")
                    if page.locator("#entry-settings").get_attribute("aria-expanded") != "true":
                        page.locator("#entry-settings").click()
                    if not page.locator("#network-link").is_visible():
                        page.locator("#network-details > summary").click()
                    if page.evaluate("document.documentElement.scrollWidth > innerWidth"):
                        print(json.dumps(page.evaluate("""() => [...document.querySelectorAll('body *')].filter(e=>{
                            const r=e.getBoundingClientRect();return r.width && r.right>innerWidth;
                        }).map(e=>({tag:e.tagName,id:e.id,cls:e.className,right:e.getBoundingClientRect().right,text:e.textContent.slice(0,100)}))""")), flush=True)
                        page.screenshot(path=str(output / "overflow.png"), full_page=True)
                    check_layout(page)
                    page.evaluate("window.scrollTo(0,0)")
                    page.screenshot(path=str(output / f"proxy-{lang}-{width}.png"), full_page=True)
                guide = context.new_page()
                guide.on("pageerror", lambda e: errors.append(str(e)))
                for width in (390, 1440):
                    guide.set_viewport_size({"width": width, "height": 1060})
                    for name in ("extras", "witness", "github"):
                        response = guide.goto(server.url + "/guide.html#" + name)
                        if response is not None:
                            assert response.status == 200
                        expect(guide.locator("html")).to_have_attribute("lang", lang)
                        expect(guide.locator("#" + name)).to_be_in_viewport()
                        for theme in ("light", "dark"):
                            guide.emulate_media(color_scheme=theme)
                            check_layout(guide)
                guide.close()
            assert not errors, errors
            assert not external, external
            browser.close()
        receipt = {"scope": "synthetic setup only; no Telegram connection or publication", "witness_config_download": True,
            "pinned_key": True, "token_clear_on_lock": True, "public_catalog_selection": True,
            "custom_link_preview_then_save": True, "languages": ["en", "ru"], "widths": [390, 1440],
            "themes": ["light", "dark"], "extras_no_implicit_connection": True,
            "keyboard_focus": True, "setup_draft_retained": True, "local_guide_links": True,
            "javascript_errors": errors, "external_browser_requests": external}
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        print(json.dumps(receipt))
    finally:
        if previous is None:
            os.environ.pop("TGWITNESS_PROXY_CATALOG", None)
        else:
            os.environ["TGWITNESS_PROXY_CATALOG"] = previous


if __name__ == "__main__":
    main()
