"""Check the optional evidence-mode records: drand rounds and Telegram's device list.

Builds a real signed journal, writes both records the way the anchor loop does, exports the
evidence ZIP and verifies it with verify.py, including forged and unreachable drand answers.
Then switches both options on in the panel in a browser. With --live it also asks the real
drand relays and compares the recorded round with them.
"""
import argparse
import asyncio
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from telethon.tl import types

from tgwitness import anchoring
from tgwitness.collector import Collector
from tgwitness.evidence import export_file
from tgwitness.netclient import request
from tgwitness.network import NetworkConfig
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import (DRAND_CHAIN, DRAND_GENESIS, DRAND_PERIOD, DRAND_RELAYS, confirm_drand,
                              outside_lines, verify_bundle)


def fake_round(number=None):
    number = number or int((time.time() - DRAND_GENESIS) // DRAND_PERIOD) + 1
    signature = secrets.token_hex(48)
    return {"round": number, "randomness": hashlib.sha256(bytes.fromhex(signature)).hexdigest(),
            "signature": signature}


def journal(directory):
    directory.mkdir(parents=True)
    vault, store = Vault(directory), Store(directory)
    store.bind(vault)
    store.append("process.started", {"version": "check"})
    return vault, store


def authorization(hash, model, app, country, current=False, active=None):
    moment = datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc)
    return types.Authorization(hash=hash, device_model=model, platform="", system_version="", api_id=4,
                               app_name=app, app_version="1.0", date_created=moment,
                               date_active=active or moment, ip="198.51.100.7", country=country,
                               region="", current=current, official_app=not current)


class TelegramClient:
    def __init__(self):
        self.sessions = []

    def is_connected(self):
        return True

    async def __call__(self, request):
        assert type(request).__name__ == "GetAuthorizationsRequest"
        return types.account.Authorizations(authorization_ttl_days=180, authorizations=list(self.sessions))


async def check_records(directory):
    vault, store = journal(directory)
    collector = Collector(store, vault)
    telegram = TelegramClient()
    collector.client = telegram
    try:
        await collector.signed_in_devices()
        raise AssertionError("the device list must need running observation")
    except ValueError as exc:
        assert "not connected" in str(exc)
    collector.running = True
    beacon, asked = fake_round(), []

    async def relays(method, url, network, headers=None, **_):
        asked.append(url)
        if url.startswith(DRAND_RELAYS[0]):
            raise OSError("connection refused")
        return 200, {}, json.dumps(beacon).encode()
    anchoring.request = relays
    settings = {"drand": True, "devices": True}
    collector_session = authorization(0, "TgWitness", "TgWitness", "Germany", current=True)
    phone = authorization(1111, "iPhone 15", "Telegram iOS", "Netherlands")
    telegram.sessions = [collector_session, phone]
    saved = await anchoring.record_extras(store, NetworkConfig(kind="direct"), settings, collector.signed_in_devices)
    assert saved["drand"]["ok"] and saved["drand"]["round"] == beacon["round"], saved
    assert saved["drand"]["relay"] == DRAND_RELAYS[1] and len(asked) == 2, asked
    assert saved["devices"] == {**saved["devices"], "ok": True, "count": 2, "others": 1, "changed": True}, saved
    # The collector's own session is active all the time: that alone is not a change.
    telegram.sessions = [authorization(0, "TgWitness", "TgWitness", "Germany", current=True,
                                       active=datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)), phone]
    assert not (await anchoring.record_devices(store, collector.signed_in_devices))["changed"]
    stranger = authorization(2222, "SM-S918B", "Telegram Android", "Russia")
    telegram.sessions = [collector_session, phone, stranger]
    assert (await anchoring.record_devices(store, collector.signed_in_devices))["changed"]
    telegram.sessions = [collector_session, stranger]
    assert (await anchoring.record_devices(store, collector.signed_in_devices))["changed"]

    async def silent(*args, **kwargs):
        raise OSError("unreachable")
    anchoring.request = silent
    collector.running = False
    failed = await anchoring.record_extras(store, NetworkConfig(kind="direct"), settings, collector.signed_in_devices)
    assert not failed["drand"]["ok"] and "No drand relay answered" in failed["drand"]["error"], failed
    assert failed["drand"]["last_ok_at"] == saved["drand"]["at"], failed
    assert not failed["devices"]["ok"] and "not connected" in failed["devices"]["error"], failed
    assert store.get_setting("evidence_witnesses") == failed
    off = await anchoring.record_extras(store, NetworkConfig(kind="direct"), {"drand": False, "devices": False}, None)
    assert off == {}, off
    payloads = [json.loads(row["payload"]) for row in store.db.execute(
        "SELECT payload FROM events WHERE kind='account.devices' ORDER BY seq")]
    assert [p["changed"] for p in payloads] == [True, False, True, True], payloads
    assert "devices" not in payloads[1] and payloads[2]["added"] == ["2222"] and payloads[3]["removed"] == ["1111"]
    assert all("ip" not in d for p in payloads for d in p.get("devices", [])), "IP addresses must not be recorded"

    archive = export_file(store, vault, "zip")
    result = verify_bundle(archive)
    outside = result["outside"]
    assert outside["drand"]["rounds"] == 1 and outside["drand"]["last"]["round"] == beacon["round"], outside
    assert outside["devices"]["checks"] == 4 and outside["devices"]["changes_total"] == 3, outside
    lines = outside_lines(outside)
    assert any("1 drand round(s) recorded" in line for line in lines), lines
    assert any("Rounds not compared with drand relays" in line for line in lines), lines
    assert any("new session: SM-S918B, Telegram Android 1.0, Russia" in line for line in lines), lines
    assert any("session ended: iPhone 15, Telegram iOS 1.0, Netherlands" in line for line in lines), lines
    assert any("this collector" in line for line in lines), lines

    recorded = [{"seq": 2, "round": beacon["round"], "randomness": beacon["randomness"]}]
    same = confirm_drand(recorded, fetch=lambda relay, number: beacon)
    assert same == {"asked": 1, "confirmed": 1, "relays": [DRAND_RELAYS[0], DRAND_RELAYS[1]]}, same
    try:
        confirm_drand(recorded, fetch=lambda relay, number: fake_round(number))
        raise AssertionError("a forged round must fail")
    except ValueError as exc:
        assert "is not drand's" in str(exc)

    def down(relay, number):
        raise OSError("down")
    assert confirm_drand(recorded, fetch=down) == {"asked": 1, "confirmed": 0, "relays": []}
    # A long journal: a random sample that always holds the first and the last round.
    rounds = {n: fake_round(n) for n in range(1, 501)}
    seen = []

    def network(relay, number):
        seen.append((relay, number))
        return rounds[number]
    sample = confirm_drand([{"seq": n, **rounds[n]} for n in rounds], fetch=network)
    asked = [number for relay, number in seen if relay == DRAND_RELAYS[0]]
    assert sample["asked"] == sample["confirmed"] == 100 == len(set(asked)) and {1, 500} <= set(asked), sample

    plain = subprocess.run([sys.executable, "-m", "tgwitness.verify", str(archive), "--plain"], cwd=ROOT,
                           capture_output=True, text=True, encoding="utf-8", timeout=120,
                           env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    assert plain.returncode == 0, plain.stderr
    assert "drand round(s) recorded" in plain.stdout and "Telegram device list recorded 4 time(s)" in plain.stdout
    archive.unlink()

    # A key holder who writes a made-up value is caught offline when it is malformed.
    forged_vault, forged = journal(directory / "forged")
    bad = fake_round()
    forged.append("beacon.drand", {"chain": DRAND_CHAIN, **bad, "randomness": "0" * 64,
                                   "round_time": anchoring.drand_time(bad["round"]), "relay": DRAND_RELAYS[0]})
    forged_archive = export_file(forged, forged_vault, "zip")
    try:
        verify_bundle(forged_archive)
        raise AssertionError("a malformed drand value must fail verification")
    except ValueError as exc:
        assert "not the hash of its signature" in str(exc)
    forged_archive.unlink()
    forged.close()
    store.close()
    print("ok  records: drand round and device list in the signed journal; relay fallback, failures kept apart,"
          " no IP addresses; verify.py reports both, rejects forged and malformed rounds")


async def check_live(directory):
    vault, store = journal(directory)
    anchoring.request = request
    saved = await anchoring.record_drand(store, NetworkConfig(kind="direct"))
    archive = export_file(store, vault, "zip")
    result = verify_bundle(archive, check_drand=True)
    checked = result["outside"]["drand"]["checked"]
    assert checked["confirmed"] == 1 and checked["relays"][0] == DRAND_RELAYS[0] and len(checked["relays"]) == 2, checked
    archive.unlink()
    store.close()
    print("ok  live: round", saved["round"], "from", saved["relay"], "confirmed by", ", ".join(checked["relays"]))


def check_browser(directory, output):
    sys.path.insert(0, str(ROOT / "tools"))
    from check_browser import RunningApp, check_layout, launch_browser, navigate_panel, reload_panel, unlock
    from playwright.sync_api import expect, sync_playwright
    from tgwitness import i18n

    async def untouched(store, network, settings, devices):
        return store.get_setting("evidence_witnesses", None) or {}
    anchoring.record_extras = untouched  # the anchor loop must not reach the internet in this check
    errors = []
    with RunningApp(directory / "panel") as server, sync_playwright() as p:
        store = server.app.state.store
        browser = launch_browser(p)
        context = browser.new_context(viewport={"width": 1280, "height": 1000}, reduced_motion="reduce")
        page = context.new_page()
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        unlock(page, server)
        navigate_panel(page, "witness")
        page.locator("#extras-open-evidence").click()
        expect(page.locator("#evidence-form")).to_be_visible()
        expect(page.locator("#evidence-more")).not_to_have_attribute("open", "")
        expect(page.locator("#evidence-drand")).to_be_hidden()
        page.locator("#evidence-more summary").click()
        expect(page.locator("#evidence-drand")).not_to_be_checked()
        page.locator("#evidence-drand").check()
        page.locator("#evidence-devices").check()
        page.locator("#evidence-form button[type=submit]").click()
        deadline = time.monotonic() + 15
        while not (store.get_setting("evidence") or {}).get("devices") and time.monotonic() < deadline:
            time.sleep(.1)
        saved = store.get_setting("evidence")
        assert saved["drand"] is True and saved["devices"] is True and saved["enabled"] is False, saved
        changed = store.db.execute("SELECT payload FROM events WHERE kind='evidence.changed' ORDER BY seq DESC").fetchone()
        assert json.loads(changed["payload"])["devices"] is True
        store.set_setting("evidence", {**saved, "enabled": True, "tsa_urls": [], "ots_calendars": []})
        store.set_setting("evidence_witnesses", {
            "drand": {"at": "2026-11-01T10:00:00.000+00:00", "ok": True, "round": 33585778,
                      "round_time": "2026-11-01T09:59:58.000+00:00", "relay": DRAND_RELAYS[0], "seq": 9},
            "devices": {"at": "2026-11-01T10:00:01.000+00:00", "ok": False,
                        "error": "Telegram is not connected: observation is paused or reconnecting."}})
        reload_panel(page)
        expect(page.locator("#view-witness")).to_be_visible()
        navigate_panel(page, "witness")
        page.locator("#extras-open-evidence").click()
        expect(page.locator("#evidence-more")).to_have_attribute("open", "")
        expect(page.locator("#evidence-drand")).to_be_checked()
        expect(page.locator("#evidence-status")).to_contain_text("drand round 33585778 written to the journal")
        expect(page.locator("#evidence-status")).to_contain_text("Telegram's device list could not be read")
        page.screenshot(path=str(output / "evidence-witnesses-en.png"), full_page=True)
        for width in (390, 1440):
            page.set_viewport_size({"width": width, "height": 1000})
            check_layout(page)
        page.set_viewport_size({"width": 1280, "height": 1000})
        context.add_cookies([{"name": i18n.COOKIE, "value": "ru", "url": server.url}])
        reload_panel(page)
        expect(page.locator("#view-witness")).to_be_visible()
        navigate_panel(page, "witness")
        page.locator("#extras-open-evidence").click()
        words = i18n.words("ru")
        expect(page.locator("#evidence-more summary")).to_have_text(words["More witnesses · optional"])
        expect(page.locator("#evidence-status")).to_contain_text(
            words["Telegram is not connected: observation is paused or reconnecting."])
        page.locator("#evidence-form").screenshot(path=str(output / "evidence-witnesses-ru.png"))
        browser.close()
    assert not errors, errors
    print("ok  browser: options folded away by default, saved, shown with their latest result; English and Russian")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Also ask the real drand relays")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "test-results" / "evidence-witnesses")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="evidence-witnesses-") as scratch:
        scratch = Path(scratch)
        asyncio.run(check_records(scratch / "records"))
        if args.live:
            asyncio.run(check_live(scratch / "live"))
        if not args.no_browser:
            check_browser(scratch, args.output)


if __name__ == "__main__":
    main()
