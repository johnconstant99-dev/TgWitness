import sqlite3
import tempfile
import time
from pathlib import Path

from .format import canonical, digest, utcnow


class BrowserCapture:
    def __init__(self, endpoint, prefix):
        self.endpoint = endpoint
        self.prefix = prefix
        self.target_id = None
        self.runtime = None
        self.browser = None
        self.last_state = None
        self.last_capture = 0

    async def connect(self):
        if self.browser is not None and self.browser.is_connected():
            return
        await self.close()
        from playwright.async_api import async_playwright
        self.runtime = await async_playwright().start()
        self.browser = await self.runtime.chromium.connect_over_cdp(self.endpoint, timeout=10000)

    async def targets(self):
        await self.connect()
        result = []
        for context in self.browser.contexts:
            for page in context.pages:
                if not page.url.startswith(("http://", "https://")):
                    continue
                session = await context.new_cdp_session(page)
                try:
                    target = (await session.send("Target.getTargetInfo"))["targetInfo"]
                    result.append((page, target["targetId"], page.url))
                finally:
                    await session.detach()
        return result

    async def rendered_text(self, page):
        return await page.locator("body").inner_text(timeout=10000)

    async def capture(self, journal, settings, max_interval, force=False):
        candidates = [(page, target, url) for page, target, url in await self.targets()
                      if (self.target_id == target if self.target_id else self.prefix and url.startswith(self.prefix))]
        if len(candidates) != 1:
            raise ValueError("Select exactly one browser tab before starting capture")
        page, target, url = candidates[0]
        page.set_default_timeout(10000)
        observed = utcnow()
        text = await self.rendered_text(page)
        state = digest(canonical({"target": target, "url": url, "text": text}))
        if not force and state == self.last_state and time.monotonic() - self.last_capture < max_interval:
            return None
        metadata = {"source": "browser", "url": url[:8192], "target_id": target,
                    "title": (await page.title())[:4096], "browser_version": self.browser.version,
                    "method": "chromium-cdp", "scope": "selected tab; viewport PNG; rendered MHTML",
                    "detection": "polled rendered text and URL; periodic snapshots; not all DOM or network events",
                    "snapshot_started_at": observed, "text_sha256": digest(text.encode()),
                    "forced": force, "errors": []}
        artifacts = []
        session = await page.context.new_cdp_session(page)
        try:
            if settings["screenshots"]:
                try:
                    png = await page.screenshot(type="png", full_page=False, timeout=10000)
                    artifacts.append(journal.artifact(png, "viewport", "image/png"))
                except Exception as exc:
                    metadata["errors"].append({"component": "png", "error": type(exc).__name__})
            if settings["pages"]:
                try:
                    snapshot = await session.send("Page.captureSnapshot", {"format": "mhtml"})
                    artifacts.append(journal.artifact(snapshot["data"].encode(), "rendered_page", "multipart/related"))
                    artifacts.append(journal.artifact(text.encode(), "derived_rendered_text", "text/plain"))
                except Exception as exc:
                    metadata["errors"].append({"component": "mhtml", "error": type(exc).__name__})
        finally:
            await session.detach()
        metadata["snapshot_finished_at"] = utcnow()
        metadata["navigation_changed_during_capture"] = page.url != url
        metadata["representations_are_atomic"] = False
        if not artifacts:
            raise ValueError("No browser material could be captured")
        self.last_state, self.last_capture = state, time.monotonic()
        return metadata, artifacts, observed

    async def close(self):
        # Stopping our CDP transport leaves the independently owned browser running.
        if self.runtime is not None:
            await self.runtime.stop()
        self.runtime = self.browser = None


def sqlite_snapshot(journal, source_path, client_version, limit=512 * 1024 * 1024):
    source_path = Path(source_path).resolve(strict=True)
    if not source_path.is_file():
        raise ValueError("Database source is not a file")
    started = utcnow()
    deadline = time.monotonic() + 15
    with tempfile.TemporaryDirectory(dir=journal.pending) as temporary:
        snapshot = Path(temporary) / "snapshot.sqlite3"
        source = sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True, timeout=3)
        target = sqlite3.connect(snapshot)
        try:
            source.execute("PRAGMA query_only=ON")

            def progress(status, remaining, total):
                if time.monotonic() > deadline:
                    raise TimeoutError("SQLite backup deadline exceeded")
                if snapshot.exists() and snapshot.stat().st_size > limit:
                    raise ValueError("SQLite snapshot exceeds size limit")

            source.backup(target, pages=256, progress=progress, sleep=0.05)
            target.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
            check = target.execute("PRAGMA quick_check").fetchall()
            if check != [("ok",)]:
                raise ValueError("SQLite integrity check failed")
            schema = target.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name").fetchall()
            user_version = target.execute("PRAGMA user_version").fetchone()[0]
            target.commit()
        finally:
            source.close()
            target.close()
        with snapshot.open("rb") as stream:
            artifact = journal.artifact_stream(stream, "ayugram_database", "application/vnd.sqlite3", limit)
    return {"source": "ayugram", "method": "sqlite-online-backup", "client_version": client_version,
            "source_filename": source_path.name, "schema_sha256": digest(canonical(schema)),
            "user_version": user_version, "quick_check": "ok", "snapshot_started_at": started,
            "snapshot_finished_at": utcnow(), "scope": "configured SQLite database only; not account history or media",
            "message_schema_interpreted": False}, [artifact], started
