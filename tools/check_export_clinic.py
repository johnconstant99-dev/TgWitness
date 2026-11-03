"""Check the actual research-page files, downloads, comparisons and video controls."""
import argparse
from contextlib import ExitStack
import hashlib
from io import BytesIO
import json
from pathlib import Path
import tempfile
from urllib.parse import urljoin
from zipfile import ZipFile

from playwright.sync_api import expect, sync_playwright

from site_export_clinic import DOWNLOAD_BASE, DOWNLOADS, FILES, PATH
from site_test_server import site_server
from export_clinic_preview import media_server

ROOT = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check_archive(archive):
    assert archive.testzip() is None
    sums = archive.read("SHA256SUMS.txt").decode("utf-8").splitlines()
    listed = set()
    for row in sums:
        expected, name = row.split("  ", 1)
        assert not name.startswith("/") and ".." not in Path(name).parts
        assert digest(archive.read(name)) == expected, name
        listed.add(name)
    assert set(archive.namelist()) == listed | {"SHA256SUMS.txt"}


def check_review_package(media):
    with ZipFile(media / "export-clinic-review-package.zip") as package:
        check_archive(package)
        assert set(package.namelist()) == {
            "README.md", "SHA256SUMS.txt", "video/ExportClinic_2026-11-03_12-50-40.mkv",
            "video/export-clinic-2min.mp4", "data/export-clinic-paired-files.zip",
            "description/article-en.md", "verification/original-metadata-audit.json",
            "verification/original-metadata-notes.md", "verification/publication-review.json",
            "verification/recording-manifest.json",
        }
        assert package.read("data/export-clinic-paired-files.zip") == (media / "export-clinic-paired-files.zip").read_bytes()
        with ZipFile(BytesIO(package.read("data/export-clinic-paired-files.zip"))) as pairs:
            check_archive(pairs)
            assert len(pairs.namelist()) == 684


def check_video_downloads(page, context, local_media, media_dir, output):
    page.locator("video").evaluate("v=>{v.preload='metadata';v.load()}")
    page.wait_for_function("document.querySelector('video').readyState >= 1")
    durations = {"short": page.locator("video").evaluate("v=>v.duration")}
    assert 119 < durations["short"] < 121
    for mode, low, high in (("full", 368, 370), ("short", 119, 121)):
        page.locator(f'[data-version="{mode}"]').click()
        page.wait_for_function("document.querySelector('video').readyState >= 1")
        durations[mode] = page.locator("video").evaluate("v=>v.duration")
        assert low < durations[mode] < high
        chapter = page.locator('[data-chapter]').nth(3)
        target = float(chapter.get_attribute(f"data-{mode}"))
        chapter.click()
        page.wait_for_function("target=>{const v=document.querySelector('video');return !v.seeking&&Math.abs(v.currentTime-target)<3}", arg=target)
        page.locator("video").evaluate("v=>v.pause()")
    response = context.request.get(local_media + "export-clinic-2min.mp4", headers={"Range": "bytes=0-15"})
    assert response.status == 206 and len(response.body()) == 16
    downloads = Path(tempfile.mkdtemp(prefix="downloads-", dir=output))
    session = context.new_cdp_session(page)
    context_id = session.send("Target.getTargetInfo")["targetInfo"]["browserContextId"]
    session.send("Browser.setDownloadBehavior", {"behavior": "allow", "browserContextId": context_id,
                 "downloadPath": str(downloads.resolve()), "eventsEnabled": True})
    for name in ("export-clinic-paired-files.zip", "export-clinic-review-package.zip"):
        with page.expect_download() as event:
            page.locator(f'a[download="{name}"]').click()
        download = event.value
        assert download.suggested_filename == name
        download.path()
        saved = downloads / name
        assert saved.is_file(), saved
        assert digest(saved.read_bytes()) == digest((media_dir / name).read_bytes())
    return durations


def main(media_dir=None):
    site = ROOT / "dist/site"
    media = site / "assets/export-clinic"
    output = ROOT / "test-results/export-clinic"
    output.mkdir(parents=True, exist_ok=True)
    assert {p.relative_to(media).as_posix() for p in media.rglob("*") if p.is_file()} == set(FILES)
    downloads_manifest = json.loads((media / "download-manifest.json").read_text())
    remote = {item["file"]: item for item in downloads_manifest["files"]}
    assert set(remote) == set(DOWNLOADS)
    assert downloads_manifest["base_url"] == DOWNLOAD_BASE
    source = (site / PATH / "index.html").read_text(encoding="utf-8")
    for name, item in remote.items():
        assert item["url"] == DOWNLOAD_BASE + name
        assert f'href="{item["url"]}"' in source, name
        assert not (media / name).exists(), name
    for row in (media / "SHA256SUMS.txt").read_text().splitlines():
        expected, name = row.split("  ", 1)
        if name in remote:
            assert remote[name]["sha256"] == expected, name
            if media_dir:
                assert (media_dir / name).stat().st_size == remote[name]["bytes"]
                assert digest((media_dir / name).read_bytes()) == expected, name
        else:
            assert digest((media / name).read_bytes()) == expected, name
    if media_dir:
        check_review_package(media_dir)
    data = json.loads((media / "comparison-data.json").read_text(encoding="utf-8"))
    errors, failures = [], []
    with ExitStack() as stack, sync_playwright() as p:
        local_media = stack.enter_context(media_server(media_dir)) if media_dir else None
        base = stack.enter_context(site_server(site, html_replacements={DOWNLOAD_BASE: local_media} if local_media else None))
        browser = p.chromium.launch()
        context = browser.new_context(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
        context.grant_permissions(["clipboard-read", "clipboard-write"])
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("response", lambda response: failures.append(response.url) if response.status >= 400 else None)
        page.goto(base + PATH, wait_until="networkidle")
        expect(page.locator(".docs-header .brand")).to_contain_text("TgWitness")
        expect(page.locator('.sidebar [aria-current="page"]')).to_have_text("Export Clinic")
        assert page.locator('link[rel=stylesheet][href$="docs.css"]').count() == 1
        assert page.locator('link[rel=stylesheet][href$="site.css"]').count() == 0
        assert page.locator(".toc a").count() == 5
        for item in data["cases"]:
            page.locator(f'[data-case="{item["id"]}"]').click()
            for index, message in enumerate(item["differences"]):
                if index:
                    page.locator("#sample-next").click()
                assert page.locator("#before-message").text_content() == message["before_text"]
                assert page.locator("#modified-message").text_content() == message["modified_text"]
            expect(page.locator("#sample-next")).to_be_disabled()
            if len(item["differences"]) > 1:
                page.locator("#sample-previous").click()
                assert page.locator("#before-message").text_content() == item["differences"][-2]["before_text"]
            if item["image_pair"]:
                page.locator("#image-comparison summary").click()
                page.wait_for_function("['before-image','modified-image'].every(id=>{const im=document.getElementById(id);return im.complete&&im.naturalWidth>0})")
                page.locator("#image-comparison summary").click()
        page.locator('[data-case="bot"]').click()
        page.locator("#before-copy").click()
        assert page.evaluate("navigator.clipboard.readText()") == next(i for i in data["cases"] if i["id"] == "bot")["json_before_sha256"]
        durations = check_video_downloads(page, context, local_media, media_dir, output) if local_media else {}
        for link in page.locator('.export-clinic a[href]').all():
            href = link.get_attribute("href")
            if not href.startswith(("http", "#")) or (local_media and href.startswith(local_media)):
                assert context.request.head(urljoin(page.url, href)).status == 200, href
        page.locator('.archive-contents summary').click()
        expect(page.locator('.archive-contents')).to_contain_text("Ten files")
        for scheme in ("light", "dark"):
            page.evaluate("scheme=>{localStorage.setItem('tgw-theme',scheme);document.documentElement.dataset.theme=scheme}", scheme)
            for width in (1440, 1024, 768, 390, 320):
                page.set_viewport_size({"width": width, "height": 1000})
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (scheme, width)
            page.set_viewport_size({"width": 390 if scheme == "light" else 1440, "height": 1000})
            page.screenshot(path=str(output / f"page-{scheme}.png"), full_page=True)
        page.set_viewport_size({"width": 1440, "height": 1000})
        old_theme = page.locator("html").get_attribute("data-theme")
        page.locator(".theme-toggle").click()
        assert page.locator("html").get_attribute("data-theme") != old_theme
        page.goto(base + "docs/start/", wait_until="networkidle")
        page.locator("#guide-search").fill("Export Clinic")
        result = page.locator('#search-results a[href$="export-clinic/"]')
        expect(result).to_be_visible()
        result.click()
        assert page.url == base + PATH
        nojs = browser.new_context(java_script_enabled=False, viewport={"width": 390, "height": 844})
        fallback = nojs.new_page()
        fallback.goto(base + PATH, wait_until="networkidle")
        expect(fallback.locator("#before-message")).to_contain_text("RESULT: FAIL")
        expect(fallback.locator('a[download="export-clinic-paired-files.zip"]')).to_be_visible()
        assert fallback.evaluate("document.documentElement.scrollWidth <= innerWidth")
        assert not errors and not failures, (errors, failures)
        browser.close()
    receipt = {"result": "passed", "conversations": 7, "changed_messages": 17,
               "checked_local_files": len(FILES), "external_downloads": len(DOWNLOADS),
               "media_content": "verified using separate local media origin" if media_dir else "not loaded; supply --media-dir for playback and archive checks",
               "durations": durations, "download_filenames": "normal" if media_dir else "not exercised", "themes": ["light", "dark"],
               "widths": [1440, 1024, 768, 390, 320], "page_errors": errors}
    (output / ("check-with-media.json" if media_dir else "check.json")).write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--media-dir", type=Path, help="Optional directory containing the five separately hosted downloads")
    main(parser.parse_args().media_dir)
