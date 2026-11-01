"""Display-zone boundaries, relative titles and persistence. Synthetic journal only."""
from pathlib import Path
import re
import sys
import tempfile

from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_browser import RunningApp, launch_browser, unlock


def main():
    with tempfile.TemporaryDirectory(prefix="panel-time-") as scratch, RunningApp(Path(scratch)) as app:
        store = app.app.state.store
        store.set_target(-1001, "Date boundary review", "supergroup", True)
        event = store.append("message.new", {"text": "Synthetic time-zone example", "sender_id": 42},
                             chat_id=-1001, message_id=1)
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            context = browser.new_context(viewport={"width": 1440, "height": 1000},
                                          timezone_id="America/Los_Angeles", reduced_motion="reduce")
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            unlock(page, app)
            expiry_cases = [
                ("2026-10-31T16:30:00Z", "2026-10-31T09:30"),
                ("2026-11-01T16:30:00Z", "2026-11-01T08:30"),
                ("2026-03-08T15:30:00Z", "2026-03-08T08:30"),
            ]
            for instant, expected in expiry_cases:
                expiry = page.evaluate("""instant=>{const value=localInput(Date.parse(instant)/1000);
                  return {value,roundTrip:new Date(value).toISOString()};}""", instant)
                assert expiry == {"value": expected, "roundTrip": instant.replace("Z", ".000Z")}, (instant, expiry)
            head = store.stats()["head"]
            expect(page.locator("#time-zone")).to_have_value("UTC")
            result = page.evaluate("""async () => {
                const {createTimeFormatter} = await import('/core/time.js');
                const t = createTimeFormatter({now: () => Date.parse('2026-10-31T15:19:22Z')});
                const utc = t.fmtTime('2026-10-31T15:19:22Z');
                const previous = t.fmtTime('2026-10-31T15:17:22Z', {mode:'relative'});
                const future = t.fmtTime('2026-10-31T15:21:22Z', {mode:'relative'});
                const utcDay = t.dayKey('2026-10-31T00:01:00Z');
                t.setZone('local');
                const local = t.fmtTime('2026-10-31T15:19:22Z');
                const localDay = t.dayKey('2026-10-31T00:01:00Z');
                const dst = [t.fmtTime('2026-11-01T08:30:00Z'), t.fmtTime('2026-11-01T09:30:00Z')];
                return {utc, previous, future, utcDay, local, localDay, dst,
                    invalid:t.fmtTime('not a date'), zero:t.fmtTime(0), empty:t.fmtTime(null)};
            }""")
            assert result["utc"] == "31 Oct 2026, 15:19:22 UTC"
            assert result["previous"] == "2 minutes ago" and result["future"] == "in 2 minutes"
            assert result["utcDay"] == "2026-10-31" and result["localDay"] == "2026-10-30"
            assert "08:19:22" in result["local"]
            assert result["dst"][0] != result["dst"][1] and all("01:30:00" in item for item in result["dst"])
            assert result["invalid"] == result["empty"] == "Not supplied"
            assert result["zero"] != "Not supplied"
            page.locator('.sidebar [data-view="observations"]').click()
            page.evaluate("async()=>{state.filter='message.new';await refreshEvents();}")
            expect(page.locator('#events-body .event-time').first).to_be_visible()
            timestamp = page.locator('#events-body .event-time').first
            expect(timestamp).to_have_attribute("title", page.evaluate("value=>fmtTime(value)", event["observed_at"]))
            page.locator("#time-zone").select_option("local")
            expect(timestamp).not_to_have_attribute("title", re.compile(r"UTC$"))
            assert store.stats()["head"] == head, "Display settings must not append journal events"
            page.reload()
            expect(page.locator("#time-zone")).to_have_value("local")
            assert page.evaluate("localStorage.getItem('tgwitness-time-zone')") == "local"
            output = Path("build/ux-review/after/04-time")
            output.mkdir(parents=True, exist_ok=True)
            for width in (1440, 390):
                page.set_viewport_size({"width": width, "height": 1000 if width == 1440 else 844})
                for theme in ("light", "dark"):
                    page.evaluate("theme=>document.documentElement.dataset.theme=theme", theme)
                    page.screenshot(path=str(output / f"journal-{width}-{theme}.png"))
            assert not errors, errors
            browser.close()
    print("Panel time checks passed: zones, DST, relative titles, persistence and unchanged journal.")


if __name__ == "__main__":
    main()
