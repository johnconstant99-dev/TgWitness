"""Public-list UI acceptance with a local collector and synthetic download/transport fixtures."""
import ipaddress
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

from check_browser import ROOT, RunningApp, check_layout, hold_api_response, launch_browser, release_api_response, unlock
from tgwitness import i18n, proxy_catalog as catalogs


def settings(page):
    page.locator('[data-view="connection"]').click()
    if page.locator("#entry-settings").get_attribute("aria-expanded") != "true":
        page.locator("#entry-settings").click()
    if not page.locator("#network-details").get_attribute("open") == "":
        page.locator("#network-details > summary").click()


def main():
    output = ROOT / "test-results/public-proxies-browser"
    output.mkdir(parents=True, exist_ok=True)
    calls, errors, external = [], [], []
    fail = [False]

    async def download(source, network):
        assert network.kind == "socks5" and network.host == "proxy.example"
        calls.append(source["id"])
        if fail[0]:
            raise OSError("Synthetic offline source")
        host = "9.9.9.9" if source["id"] == "solispirit" else "8.8.4.4"
        if source.get("format") == "json":
            return json.dumps([{"query": {"server": host, "port": 443, "secret": "a7" * 16}}])
        return "tg://proxy?server=" + host + "&port=443&secret=" + "a7" * 16

    env = {key: value for key, value in os.environ.items() if key not in ("TGWITNESS_PROXY_CATALOG", "TGWITNESS_PROXY_FEED_PROXY")}
    # The default hide-address policy requires an explicit route outside Telegram.
    # This proxy is never contacted: download() above is the synthetic transport.
    env["TGWITNESS_PROXY_FEED_PROXY"] = "socks5://proxy.example:1080"
    with patch.dict(os.environ, env, clear=True), patch.object(catalogs, "download", download), patch.object(catalogs, "REFRESH_SECONDS", 0):
        with tempfile.TemporaryDirectory(prefix="proxy-browser-") as scratch:
            with RunningApp(Path(scratch)) as server, sync_playwright() as p:
                browser = launch_browser(p)
                context = browser.new_context(viewport={"width": 1440, "height": 1060}, reduced_motion="reduce")
                page = context.new_page()
                page.on("pageerror", lambda exc: errors.append(str(exc)))
                page.on("request", lambda req: external.append(req.url) if urlsplit(req.url).hostname != "127.0.0.1" else None)
                unlock(page, server)
                keys = page.evaluate("""async () => {
                    const keys=[];
                    for(const path of ['/', '/guide.html']){
                        const doc=new DOMParser().parseFromString(await (await fetch(path)).text(),'text/html');
                        keys.push(doc.title);walkPage((item,whole)=>{keys.push(item.key);return whole;},doc.body);
                    }return keys;
                }""")
                for lang in i18n.LANGUAGES[1:]:
                    assert not (set(keys) - set(i18n.words(lang))), (lang, sorted(set(keys) - set(i18n.words(lang))))
                settings(page)
                expect(page.locator("#proxy-catalog-status")).to_contain_text("compatible public proxies")
                assert not calls, "Opening settings must not fetch external subscriptions"
                assert page.locator("#proxy-catalog-select option").count() > 0
                expect(page.locator("#network-test")).to_be_enabled()
                assert not server.app.state.collector.status()["has_session"]

                listing = page.evaluate("json('network/catalog')")
                row = next(row for row in listing["proxies"] if is_ip(row["host"]))
                page.locator("#proxy-catalog-select").select_option(row["id"])
                page.locator("#proxy-catalog-apply").click()
                expect(page.locator("#route-detail")).to_contain_text(row["host"])
                settings(page)
                page.locator("#network-test").click()
                expect(page.locator("#network-result")).to_contain_text("Telegram transport connected")
                assert not server.app.state.collector.status()["has_session"]
                route_before = server.app.state.collector.network_config()
                page.locator("#proxy-catalog-refresh").click()
                expect(page.locator("#proxy-catalog-status")).to_contain_text("Public lists updated")
                expect(page.locator("#proxy-catalog-select option")).to_have_count(2)
                assert sorted(calls) == sorted(source["id"] for source in catalogs.SOURCES)
                assert server.app.state.collector.network_config() == route_before
                fail[0] = True
                page.locator("#proxy-catalog-refresh").click()
                expect(page.locator("#proxy-catalog-status")).to_contain_text("previous list is still available")
                expect(page.locator("#proxy-catalog-select option")).to_have_count(2)
                assert server.app.state.collector.network_config() == route_before
                # A late refresh belongs to the old workspace, including its saved cache.
                child = page.evaluate("async()=>{const p=await json('profiles',{label:'Separate account'});await loadProfiles();return p.id;}")
                hold_api_response(page, "/api/network/catalog/refresh")
                page.locator("#proxy-catalog-refresh").click()
                expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
                page.locator("#profile-select").select_option(child)
                settings(page)
                expect(page.locator("#proxy-catalog-status")).to_contain_text("compatible public proxies")
                release_api_response(page)
                expect(page.locator("#proxy-catalog-status")).to_contain_text("compatible public proxies")
                expect(page.locator("#network-kind")).to_have_value("mtproxy_auto")
                assert page.locator("#proxy-catalog-select option").count() == len(listing["proxies"])

                for lang in ("en", "ru"):
                    context.add_cookies([{"name": "tgwitness-lang", "value": lang, "url": server.url}])
                    page.reload()
                    expect(page.locator("#workspace")).to_be_visible()
                    settings(page)
                    for width in (390, 1440):
                        page.set_viewport_size({"width": width, "height": 1060})
                        for theme in ("light", "dark"):
                            page.emulate_media(color_scheme=theme)
                            check_layout(page)
                            page.evaluate("window.scrollTo(0,0)")
                            page.screenshot(path=str(output / f"public-proxies-{lang}-{theme}-{width}.png"), full_page=True)
                            page.locator(".proxy-sources > summary").click()
                            check_layout(page)
                            expect(page.locator("#proxy-catalog-sources a")).to_have_count(len(catalogs.SOURCES))
                            assert page.locator("#proxy-catalog-sources").inner_text().find("SoliSpirit") >= 0
                            page.locator(".proxy-sources > summary").click()
                assert not errors, errors
                assert not external, external
                browser.close()
    receipt = {"scope": "synthetic source refresh and Telegram transport; no live account", "bundled_list": True,
               "refresh_keeps_route": True, "failed_refresh_keeps_cache": True, "no_startup_fetch": True,
               "probe_before_login": True, "late_response_isolation": True, "languages": ["en", "ru"],
               "widths": [390, 1440], "themes": ["light", "dark"], "page_errors": errors, "external_requests": external}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(json.dumps(receipt))


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    main()
