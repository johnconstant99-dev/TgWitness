"""The 24/7 server wizard against a simulated Hetzner, Cloudflare, ntfy.sh and GitHub"""
import argparse
import asyncio
import json
import re
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import requests
import uvicorn
from tgwitness import __version__, assurance, cloud, cloud_wizard
from tgwitness.app import create_app
from tgwitness.providers import base, hetzner
from tgwitness.provenance import SOURCE_POLICY, source_files, source_tree_sha256
from tgwitness.security import Vault
from tgwitness.verify import fingerprint

ACCOUNT, OTHER, COMMIT, TUNNEL = "0" * 32, "1" * 32, "a" * 40, "6ff42ae2-765d-4adf-8112-31c55c1551ef"
HZ_TOKEN, CF_TOKEN = "H" * 64, "c" * 40
HETZNER_API = "https://api.hetzner.cloud/v1"


class Response:
    def __init__(self, status, data=None, text=""):
        self.status_code, self.data, self.content, self.text = status, data, b"", text

    def json(self):
        if self.data is None:
            raise ValueError("no JSON")
        return self.data


def server_type(name, memory, prices, architecture="x86", locations=None, deprecated=False):
    return {"name": name, "cores": 2, "memory": memory, "disk": 40, "architecture": architecture,
            "deprecated": deprecated, "deprecation": None,
            "prices": [{"location": place, "price_monthly": {"net": str(p / 1.19), "gross": str(p)}}
                       for place, p in prices.items()],
            "locations": [{"name": place, "available": available, "deprecation": None}
                          for place, available in (locations or {p: True for p in prices}).items()]}


TYPES = [server_type("cx22", 4, {"nbg1": 4.15}, locations={"nbg1": True}),
         server_type("cpx22", 4, {"nbg1": 7.13, "ash": 8.09}, locations={"nbg1": True, "ash": False}),
         server_type("cpx21", 4, {"ash": 9.99}),
         server_type("cpx11", 2, {"ash": 5.59}),
         server_type("cax11", 4, {"nbg1": 3.79}, architecture="arm"),
         server_type("cx11", 1, {"nbg1": 3.29}),
         server_type("cx21", 4, {"nbg1": 2.00}, deprecated=True)]
LOCATIONS = [{"name": "fsn1", "city": "Falkenstein", "country": "DE", "network_zone": "eu-central"},
             {"name": "nbg1", "city": "Nuremberg", "country": "DE", "network_zone": "eu-central"},
             {"name": "ash", "city": "Ashburn, VA", "country": "US", "network_zone": "us-east"}]


class World:
    def __init__(self, read_only=False, tunnels_allowed=True):
        self.read_only, self.tunnels_allowed = read_only, tunnels_allowed
        self.calls, self.dns, self.tunnels, self.servers, self.firewalls = [], [], {}, {}, {}
        self.user_data, self.server_id, self.ipv4, self.ids = None, 42, "192.0.2.10", 100
        self.posts, self.clock = {}, 1_800_000_000
        self.guard = threading.Lock()

    def get(self, url, params=None, timeout=None):
        assert timeout and url.startswith(cloud.BEACON_SERVER) and url.endswith("/json") and params["poll"] == "1"
        with self.guard:
            self.calls.append(("GET", url, params))
            posts = self.posts.get(url[:-len("/json")], [])
            return Response(200, None, "".join(json.dumps({"event": "message", **post}) + "\n" for post in posts))

    def post(self, topic, message):
        # ntfy.sh stamps each message with its own receive time.
        self.clock += 60
        self.posts.setdefault(topic, []).append({"time": self.clock, "message": message})

    def post_address(self, host, signed=True):
        topic = re.search(r"TGWITNESS_BEACON=(\S+)", self.user_data).group(1)
        key = re.search(r"^ *TGWITNESS_TUNNEL_TOKEN=(\S+)$", self.user_data, re.M).group(1)
        text = cloud.ADDRESS_FORMAT + " " + host + " " + str(self.clock + 60)
        self.post(topic, text + " " + (cloud.address_signature(key, text) if signed else "0" * 64))

    def request(self, method, url, timeout=None, json=None, params=None, headers=None, data=None):
        assert timeout
        with self.guard:
            self.calls.append((method, url, params))
            auth = (headers or {}).get("Authorization", "")
            if url.startswith(cloud_wizard.GITHUB):
                ref = url[len(cloud_wizard.GITHUB):]
                return Response(200, {"sha": COMMIT}) if ref == "v" + __version__ else Response(404, {})
            if url.startswith(cloud.CLOUDFLARE_API):
                assert auth == "Bearer " + CF_TOKEN, auth
                status, result = self.cloudflare(method, url[len(cloud.CLOUDFLARE_API):], json, params or {})
                errors = [] if status < 400 else [{"code": 10000, "message": "Authentication error"}]
                return Response(status, {"success": status < 400, "errors": errors, "result": result})
            assert url.startswith(HETZNER_API) and auth == "Bearer " + HZ_TOKEN, url
            return self.hetzner(method, url[len(HETZNER_API):], json, params or {})

    def next_id(self):
        self.ids += 1
        return self.ids

    def cloudflare(self, method, path, body, params):
        tunnel = "/accounts/" + ACCOUNT + "/cfd_tunnel"
        if path == "/accounts":
            return 200, [{"id": ACCOUNT, "name": "Mine"}, {"id": OTHER, "name": "Shared"}]
        if path == "/zones" and "name" in params:
            return 200, [{"id": "zone1", "name": "example.org", "account": {"id": ACCOUNT}}] \
                if params["name"] == "example.org" else []
        if path == "/zones":
            return 200, [{"id": "zone1", "name": "example.org", "account": {"id": ACCOUNT}},
                         {"id": "zone2", "name": "other.net", "account": {"id": OTHER}}]
        if path == "/accounts/" + OTHER + "/cfd_tunnel":
            return 403, None
        if path == tunnel and method == "GET":
            if not self.tunnels_allowed:
                return 403, None
            return 200, [t for t in self.tunnels.values() if t["name"] == params.get("name") and not t["deleted"]] \
                if "name" in params else []
        if path == tunnel and method == "POST":
            self.tunnels[TUNNEL] = {"id": TUNNEL, "name": body["name"], "created_at": "2026-11-01T10:00:00Z",
                                    "token": "eyJhIjoi" + "t" * 60, "deleted": False}
            return 200, self.tunnels[TUNNEL]
        if path == tunnel + "/" + TUNNEL + "/configurations":
            return 200, {"config": body["config"], "version": 1}
        if path == tunnel + "/" + TUNNEL + "/connections" and method == "DELETE":
            return 200, None
        if path == tunnel + "/" + TUNNEL and method == "DELETE":
            self.tunnels[TUNNEL]["deleted"] = True
            return 200, {"id": TUNNEL}
        if path == "/zones/zone1/dns_records" and method == "GET":
            return 200, [r for r in self.dns if r["name"] == params["name"]]
        if path == "/zones/zone1/dns_records":
            self.dns.append({"id": "dns" + str(self.next_id()), **body})
            return 200, self.dns[-1]
        if path.startswith("/zones/zone1/dns_records/") and method == "DELETE":
            self.dns = [r for r in self.dns if r["id"] != path.rsplit("/", 1)[1]]
            return 200, {"id": path.rsplit("/", 1)[1]}
        raise AssertionError("Cloudflare " + method + " " + path)

    def action(self, command):
        return {"id": self.next_id(), "command": command, "status": "success", "started": "2026-11-01T10:00:00Z",
                "finished": "2026-11-01T10:00:01Z", "progress": 100, "error": None, "resources": []}

    def labelled(self, items, params):
        wanted = params.get("label_selector", "")
        key, _, value = wanted.partition("=")
        return [item for item in items.values() if not wanted or item["labels"].get(key) == value]

    def hetzner(self, method, path, body, params):
        page = {"meta": {"pagination": {"next_page": None}}}
        if path == "/locations":
            return Response(200, {"locations": LOCATIONS})
        if path == "/server_types":
            return Response(200, {"server_types": TYPES, **page})
        if path == "/pricing":
            return Response(200, {"pricing": {"currency": "EUR"}})
        if path == "/firewalls" and method == "POST":
            if self.read_only:
                return Response(403, {"error": {"code": "forbidden", "message": "insufficient permissions"}})
            number = self.next_id()
            self.firewalls[number] = {"id": number, "name": body["name"], "labels": body["labels"], "rules": body["rules"]}
            return Response(201, {"firewall": self.firewalls[number], "actions": [self.action("set_firewall_rules")]})
        if path == "/firewalls":
            return Response(200, {"firewalls": self.labelled(self.firewalls, params), **page})
        if path == "/servers" and method == "POST":
            self.user_data = body["user_data"]
            if "TGWITNESS_BEACON=" in self.user_data:
                self.post_address("bright-words-here.trycloudflare.com")
                self.post_address("forged-address-here.trycloudflare.com", signed=False)
            self.servers[self.server_id] = {
                "id": self.server_id, "name": body["name"], "created": "2026-11-01T10:00:00Z", "labels": body["labels"],
                "public_net": {"ipv4": {"ip": self.ipv4}, "ipv6": {"ip": "2001:db8:1::/64"}}, "image": {"name": body["image"]},
                "server_type": {"name": body["server_type"]}, "location": {"name": body["location"]}}
            return Response(201, {"server": self.servers[self.server_id], "action": self.action("create_server"),
                                  "next_actions": [self.action("start_server")], "root_password": "provider-root-password"})
        if path == "/servers":
            return Response(200, {"servers": self.labelled(self.servers, params), **page})
        if path.startswith("/servers/") and method == "DELETE":
            self.servers.pop(int(path.rsplit("/", 1)[1]))
            return Response(200, {"action": self.action("delete_server")})
        if path.startswith("/firewalls/") and method == "DELETE":
            self.firewalls.pop(int(path.rsplit("/", 1)[1]), None)
            return Response(204)
        raise AssertionError("Hetzner " + method + " " + path)


class Host:
    def __init__(self, world, directory):
        self.world, self.vault, self.root = world, Vault(directory / "collector"), directory / "host"
        for folder in ("proc/net", "proc/sys/kernel/random", "run", "var/log", "etc/tgwitness"):
            (self.root / folder).mkdir(parents=True, exist_ok=True)
        (self.root / "proc/sys/kernel/random/boot_id").write_text("boot-1\n")
        (self.root / "proc/net/tcp").write_text("  sl  local_address rem_address   st\n")
        (self.root / "run/utmp").write_bytes(b"")
        (self.root / "var/log/wtmp").write_bytes(b"")
        self.receipt = {"run_id": "run-1", "version": __version__, "source_policy": SOURCE_POLICY,
                        "source_tree_sha256": source_tree_sha256(source_files())}
        self.hosts = []

    def get(self, url, timeout):
        data = self.world.user_data
        description = re.search(r"^ *(\{.*\"format\": \"tgwitness-deployment-v1\".*\})$", data, re.M).group(1)
        (self.root / "etc/tgwitness/assurance.json").write_text(description + "\n")
        provider = {"provider": "hetzner", "instance_id": self.world.server_id, "public_ipv4": self.world.ipv4,
                    **assurance.user_data_hashes(data), "user_data_redacted": assurance.redact_user_data(data)}
        challenge = parse_qs(urlsplit(url).query).get("challenge", [None])[0]
        return Response(200, assurance.statement(self.vault, self.receipt, 1, "hetzner", provider, challenge, self.root))

    def fetch(self, host, challenge):
        self.hosts.append(host)
        return cloud.collector_statement(host, challenge, session=self)


def quiet():
    base.pause = hetzner.pause = lambda seconds: None


def tokens_absent(directory, *secrets):
    for path in Path(directory).rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            for secret in secrets:
                assert secret.encode() not in data, (path, "holds a token")


def check_selection():
    eu = cloud_wizard.location("eu", LOCATIONS)
    us = cloud_wizard.location("us", LOCATIONS)
    assert eu["name"] == "nbg1" and us["name"] == "ash"
    assert cloud_wizard.location("eu", [LOCATIONS[0], LOCATIONS[2]])["name"] == "fsn1"
    picked = cloud_wizard.server_type(TYPES, "nbg1")
    assert picked["name"] == "cpx22" and picked["monthly"] == "7.13", picked
    assert cloud_wizard.server_type(TYPES, "ash")["name"] == "cpx11"
    try:
        cloud_wizard.server_type(TYPES, "hil")
        raise AssertionError("no offer expected")
    except cloud_wizard.WizardError:
        pass
    problem = cloud_wizard.explain(base.DeployError('Hetzner POST /firewalls: HTTP 403 forbidden: insufficient'))
    assert "Read & Write" in str(problem) and "HTTP 403" in problem.technical
    assert "permission" in str(cloud_wizard.explain(base.DeployError("Cloudflare GET /accounts: HTTP 403 10000: x")))
    assert "already used" in str(cloud_wizard.explain(base.DeployError("a.example.org already has DNS records; x")))
    print("ok  location, server type and error messages")


def check_boundaries(directory):
    jobs = cloud_wizard.Jobs(directory / "boundaries")
    inside = jobs.folder("case-1", "deployment.json")
    assert (inside.name, inside.parent.name, inside.parent.parent.name) == ("deployment.json", "case-1", "deployments")
    for parts in (("..",), ("..", "panel-token.txt"), ("../panel", "panel-token.txt"), ("/etc", "passwd")):
        assert jobs.folder(*parts) is None, parts
    for name, filename in (("..", "panel-token.txt"), ("case-1", "signing.enc"), ("Case-1", "deployment.json"),
                           ("case-1", "../deployment.json")):
        try:
            jobs.file(name, filename)
        except cloud_wizard.WizardError:
            continue
        raise AssertionError((name, filename))
    for good in ("example.org", "a-b.example.co.uk", "xn--80ak6aa92e.com"):
        assert cloud_wizard.domain(good), good
    for bad in ("example", "-a.org", "a-.org", "a..org", "Example.org", "a.o", "a.org1", "a_b.org", "a." * 130 + "org",
                "a" * 64 + ".org", "a" * 5000):
        assert not cloud_wizard.domain(bad), bad
    print("ok  boundaries: deployment paths stay in their directory; domains checked label by label")


def deploy_args(directory, name="case-1"):
    return argparse.Namespace(provider="hetzner", name=name, server_type="cpx22", location="nbg1", image=None,
                              ref=COMMIT, repository=cloud.DEFAULT_REPOSITORY, zone="example.org",
                              cloudflare_account=ACCOUNT, panel_host=name + ".example.org", witness_host=None,
                              debug_ssh_key=None, debug_ssh_from=None, out=directory / name, wait=1)


def quick_args(directory, name="quick-1"):
    return argparse.Namespace(**{**vars(deploy_args(directory, name)), "zone": None, "cloudflare_account": None,
                                 "panel_host": None, "quick_tunnel": True})


def services(world):
    return hetzner.Hetzner(HZ_TOKEN, session=world), cloud.Cloudflare(CF_TOKEN, world)


def check_command_line(directory):
    world = World()
    host, stages = Host(world, directory), []
    record, out = cloud.deploy(deploy_args(directory), *services(world), host.fetch,
                               resolve=lambda repository, ref: ref, progress=lambda stage, text: stages.append(stage))
    assert record["state"] == "running" and stages == ["tunnel", "server", "running", "waiting"], stages
    assert world.servers and world.firewalls and world.dns and not world.tunnels[TUNNEL]["deleted"]
    refused = argparse.Namespace(record=out / "deployment.json", confirm="other", provider_token_file=None,
                                 cloudflare_token_file=None)
    try:
        cloud.destroy(refused, *services(world))
        raise AssertionError("destroy without the right confirmation")
    except base.DeployError as exc:
        assert "Confirm with the server name case-1" in str(exc) and world.servers
    args = argparse.Namespace(**{**vars(refused), "confirm": "case-1"})
    record, removed = cloud.destroy(args, *services(world), progress=lambda stage, text: None)
    assert [r["resource"] for r in removed] == ["server", "firewall", "dns", "tunnel"], removed
    assert not world.servers and not world.firewalls and not world.dns and world.tunnels[TUNNEL]["deleted"]
    saved = json.loads((out / "deployment.json").read_text(encoding="utf-8"))
    assert saved["state"] == "removed" and saved["removals"][0]["removed"] == removed
    assert all("DELETE" in call["method"] or call["method"] == "GET" for call in saved["removals"][0]["api_calls"])
    print("ok  command line: deploy, refused and confirmed destroy")

    world = World(read_only=True)
    try:
        cloud.deploy(deploy_args(directory, "case-2"), *services(world), Host(world, directory).fetch,
                     resolve=lambda repository, ref: ref, progress=lambda stage, text: None)
        raise AssertionError("a read-only Hetzner token must stop the deployment")
    except base.DeployError as exc:
        assert "Read & Write" in str(cloud_wizard.explain(exc))
    assert world.dns and not world.servers
    args = argparse.Namespace(record=directory / "case-2" / "deployment.json", confirm="case-2",
                              provider_token_file=None, cloudflare_token_file=None)
    record, removed = cloud.destroy(args, *services(world), progress=lambda stage, text: None)
    assert [r["resource"] for r in removed] == ["dns", "tunnel"] and not world.dns and record["state"] == "removed"
    print("ok  a failed deployment is removed from Cloudflare")

    for wrong in ({"zone": "example.org"}, {"quick_tunnel": False}):
        try:
            cloud.specification(argparse.Namespace(**{**vars(quick_args(directory)), **wrong}), lambda r, ref: ref)
            raise AssertionError("a quick tunnel takes no domain, and a domain needs its options")
        except base.DeployError:
            pass
    world = World()
    host, stages, hz = Host(world, directory), [], hetzner.Hetzner(HZ_TOKEN, session=world)
    record, out = cloud.deploy(quick_args(directory), hz, None, host.fetch, resolve=lambda repository, ref: ref,
                               progress=lambda stage, text: stages.append(stage),
                               beacon=lambda topic, key=None, public_key=None:
                               cloud.read_beacon(topic, key, world, public_key))
    assert record["state"] == "running" and stages == ["tunnel", "server", "running", "waiting"], stages
    assert record["address"]["host"] == "bright-words-here.trycloudflare.com" == host.hosts[-1], host.hosts
    assert cloud.read_beacon(record["beacon"], session=world)["host"] == "forged-address-here.trycloudflare.com"
    assert not any(url.startswith(cloud.CLOUDFLARE_API) for _, url, _ in world.calls)
    key = (out / "address-key.txt").read_text(encoding="utf-8")
    published = (out / "cloud-init.redacted.yaml").read_text(encoding="utf-8")
    assert key not in published and "tgwitness-tunnel.service" in published and record["beacon"] in published
    assert cloud.reference_installer(record, ROOT) == published
    # A verifier has no address key. The collector signs its address with the collector key, so forged posts
    # claiming a later time, signed by another key or carrying a fake address-key signature do not mislead it.
    beacon = lambda topic, key=None, public_key=None: cloud.read_beacon(topic, key, world, public_key)  # noqa: E731
    assert record["collector"]["public_key"] == host.vault.public_key
    world.post(record["beacon"], assurance.address_post(host.vault, "collector-signed-here.trycloudflare.com",
                                                        world.clock))
    world.post(record["beacon"], assurance.address_post(Vault(directory / "forger"), "forged-v2-here.trycloudflare.com",
                                                        4_000_000_000))
    world.post(record["beacon"], cloud.ADDRESS_FORMAT + " forged-future-here.trycloudflare.com 4000000000 " + "0" * 64)
    found = cloud.posted_address(record, beacon)
    assert found["host"] == "collector-signed-here.trycloudflare.com" and found["signer"] == "collector", found
    assert cloud.read_beacon(record["beacon"], key, world)["host"] == "bright-words-here.trycloudflare.com"
    assert cloud.read_beacon(record["beacon"], session=world)["host"] == "forged-future-here.trycloudflare.com"
    unsigned = {**record, "collector": {**record["collector"], "public_key": Vault(directory / "older").public_key}}
    assert cloud.posted_address(unsigned, beacon)["signer"] is None
    sent, names = [], iter(["one-host-here.trycloudflare.com"] * 2 + ["two-host-here.trycloudflare.com"])

    async def posting():
        task = asyncio.create_task(assurance.address_loop(host.vault, record["beacon"], interval=0,
                                                          host=lambda: next(names, None),
                                                          post=lambda topic, body: sent.append((topic, body))))
        while len(sent) < 2:
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.05)
        task.cancel()
    asyncio.run(asyncio.wait_for(posting(), 10))
    assert [body.split(" ")[1] for topic, body in sent] == ["one-host-here.trycloudflare.com",
                                                            "two-host-here.trycloudflare.com"], sent
    assert all(topic == record["beacon"] and cloud.signed_by_collector(
        host.vault.public_key, body.rsplit(" ", 1)[0], body.rsplit(" ", 1)[1]) for topic, body in sent)
    assert asyncio.run(asyncio.wait_for(assurance.address_loop(host.vault, "https://example.net/tgw-x"), 1)) is None
    assert "Quick tunnel" in cloud.plan(cloud.specification(quick_args(directory, "quick-2"), lambda r, ref: ref))
    args = argparse.Namespace(record=out / "deployment.json", confirm="quick-1", provider_token_file=None,
                              cloudflare_token_file=None)
    record, removed = cloud.destroy(args, hz, None, progress=lambda stage, text: None)
    assert [r["resource"] for r in removed] == ["server", "firewall"] and not world.servers and not world.firewalls
    tokens_absent(out, HZ_TOKEN)
    print("ok  command line: quick tunnel, signed address, rebuilt installer, destroy without Cloudflare")


class RunningApp:
    def __init__(self, path):
        self.app = create_app(path)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.url = "http://127.0.0.1:" + str(self.sock.getsockname()[1])
        self.server = uvicorn.Server(uvicorn.Config(self.app, log_level="error", access_log=False,
                                                   timeout_graceful_shutdown=5))
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self.sock]}, daemon=True)

    def __enter__(self):
        self.thread.start()
        deadline = time.monotonic() + 45
        while not self.server.started:
            if not self.thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError("Local test server failed to start")
            time.sleep(.05)
        return self

    def __exit__(self, *args):
        self.server.should_exit = True
        self.thread.join(timeout=30)
        self.sock.close()


def wait_job(call, kind):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        job = call("GET", "cloud").json()["job"]
        if job and job["kind"] == kind and job["state"] != "running":
            return job
        time.sleep(.1)
    raise AssertionError(kind + " did not finish")


def check_panel(directory):
    world = World()
    host = Host(world, directory)
    data = directory / "panel"
    with RunningApp(data) as server:
        jobs = server.app.state.cloud_jobs
        jobs.session, jobs.fetch = world, host.fetch
        token = server.app.state.vault.token

        def call(method, path, body=None, headers=None):
            return requests.request(method, server.url + "/api/" + path, json=body, timeout=30,
                                    headers={"Authorization": "Bearer " + token, **(headers or {})})

        status = call("GET", "cloud").json()
        assert status["local"] is True and status["job"] is None and status["deployments"] == []
        keys = {"hetzner_token": HZ_TOKEN, "cloudflare_token": CF_TOKEN}
        proxied = call("POST", "cloud/check", {**keys, "region": "eu"}, {"X-Forwarded-For": "203.0.113.9"})
        assert proxied.status_code == 403 and "127.0.0.1" in proxied.json()["detail"]
        assert call("GET", "cloud", headers={"CF-Connecting-IP": "203.0.113.9"}).json()["local"] is False
        assert call("POST", "cloud/check", {**keys, "hetzner_token": "short"}).status_code == 422
        assert requests.get(server.url + "/api/cloud", timeout=30).status_code == 401
        offer = call("POST", "cloud/check", {**keys, "region": "eu"}).json()
        assert offer["server"]["name"] == "cpx22" and offer["currency"] == "EUR" and offer["location"]["name"] == "nbg1"
        assert offer["domains"] == [{"name": "example.org", "account": ACCOUNT}], offer["domains"]
        assert offer["version"] == {"ref": "v" + __version__, "commit": COMMIT}
        world.tunnels_allowed = False
        refused = call("POST", "cloud/check", {**keys, "region": "eu"}).json()
        assert "Cloudflare Tunnel" in refused["error"]["message"], refused
        world.tunnels_allowed = True

        order = {**keys, "region": "eu", "zone": "example.org", "account": ACCOUNT, "location": "nbg1",
                 "server_type": "cpx22", "name": "case-3"}
        started = call("POST", "cloud/deploy", order).json()
        assert started["job"]["kind"] == "deploy"
        job = wait_job(call, "deploy")
        assert job["state"] == "done", job
        assert job["result"]["panel"] == "https://case-3.example.org" and job["result"]["commit"] == COMMIT
        assert job["result"]["fingerprint"] == fingerprint(host.vault.public_key)
        assert [line["text"] for line in job["lines"]][0].startswith("Looking up")
        again = call("POST", "cloud/deploy", order).json()
        assert "already exists" in again["error"]["message"]
        listed = call("GET", "cloud").json()["deployments"]
        assert [(d["name"], d["state"], d["server_type"]) for d in listed] == [("case-3", "running", "cpx22")]
        panel_token = call("GET", "cloud/deployments/case-3/panel-token.txt")
        assert panel_token.status_code == 200 and len(panel_token.text.strip()) >= 32
        assert call("GET", "cloud/deployments/case-3/signing.enc").status_code == 404
        assert call("GET", "cloud/deployments/..%2Fpanel/panel-token.txt").status_code == 404

        wrong = call("POST", "cloud/destroy", {**keys, "name": "case-3", "confirm": "case"}).json()
        assert "Type the server name" in wrong["error"]["message"] and world.servers
        alone = call("POST", "cloud/destroy", {"hetzner_token": HZ_TOKEN, "name": "case-3", "confirm": "case-3"}).json()
        assert "Cloudflare token as well" in alone["error"]["message"] and world.servers
        call("POST", "cloud/destroy", {**keys, "name": "case-3", "confirm": "case-3"})
        job = wait_job(call, "destroy")
        assert job["state"] == "done" and not world.servers and not world.dns, job
        assert call("GET", "cloud").json()["deployments"][0]["state"] == "removed"

        alone = {"hetzner_token": HZ_TOKEN}
        offer = call("POST", "cloud/check", {**alone, "region": "eu"}).json()
        assert offer["domains"] == [] and offer["server"]["name"] == "cpx22", offer
        global_key = {**alone, "cloudflare_token": "cfk_" + "a" * 37, "region": "eu"}
        assert call("POST", "cloud/check", global_key).status_code == 422
        call("POST", "cloud/deploy", {**alone, "region": "eu", "location": "nbg1", "server_type": "cpx22", "name": "case-4"})
        job = wait_job(call, "deploy")
        assert job["state"] == "done" and job["result"]["quick"], job
        assert job["result"]["panel"] == "https://bright-words-here.trycloudflare.com", job["result"]
        listed = {d["name"]: d for d in call("GET", "cloud").json()["deployments"]}
        assert listed["case-4"]["quick"] and listed["case-4"]["address"] == "bright-words-here.trycloudflare.com"
        world.post_address("after-restart-here.trycloudflare.com")
        found = call("POST", "cloud/address", {"name": "case-4"}).json()
        assert found["address"] == "after-restart-here.trycloudflare.com", found
        assert "fixed address" in call("POST", "cloud/address", {"name": "case-3"}).json()["error"]["message"]
        assert call("POST", "cloud/address", {"name": "case-4"}, {"X-Forwarded-For": "203.0.113.9"}).status_code == 403
        call("POST", "cloud/destroy", {**alone, "name": "case-4", "confirm": "case-4"})
        job = wait_job(call, "destroy")
        assert job["state"] == "done" and not world.servers and not world.firewalls, job
    tokens_absent(data, HZ_TOKEN, CF_TOKEN)
    print("ok  panel: local only, check, deploy, files, confirmed destroy, quick tunnel address; no token on disk")


def check_browser(directory, output):
    sys.path.insert(0, str(ROOT / "tools"))
    from check_browser import RunningApp as PanelApp, answer_panel_dialog, check_layout, launch_browser, lock_panel, navigate_panel, reload_panel, unlock
    from playwright.sync_api import expect, sync_playwright
    from tgwitness import i18n
    world = World()
    host = Host(world, directory / "browser")
    errors, external = [], []
    with PanelApp(directory / "browser-panel") as server, sync_playwright() as p:
        jobs = server.app.state.cloud_jobs
        jobs.session, jobs.fetch = world, host.fetch
        browser = launch_browser(p)
        context = browser.new_context(viewport={"width": 1280, "height": 1000}, reduced_motion="reduce")
        page = context.new_page()
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.on("request", lambda req: external.append(req.url) if urlsplit(req.url).hostname != "127.0.0.1" else None)
        unlock(page, server)
        navigate_panel(page, "witness")
        page.locator("#extras-open-cloud").click()
        expect(page.locator("#cloud-wizard")).to_be_visible()
        expect(page.locator("#cloud-remote")).to_be_hidden()
        expect(page.locator("#cloud-cli")).not_to_have_attribute("open", "")
        expect(page.locator("#cloud-own-domain")).not_to_have_attribute("open", "")
        page.locator("#cloud-hetzner-token").fill(HZ_TOKEN)
        page.locator("#cloud-check").click()
        expect(page.locator("#cloud-offer")).to_be_visible()
        expect(page.locator("#cloud-domain-field")).to_be_hidden()
        expect(page.locator("#cloud-address")).to_contain_text("trycloudflare.com")
        expect(page.locator("#cloud-summary")).to_contain_text("quick tunnel")
        page.screenshot(path=str(output / "1-offer-quick.png"), full_page=True)
        for width in (390, 1440):
            page.set_viewport_size({"width": width, "height": 1000})
            for theme in ("light", "dark"):
                page.emulate_media(color_scheme=theme)
                check_layout(page)
                page.locator("#cloud-offer").screenshot(path=str(output / f"offer-quick-{theme}-{width}.png"))
        page.emulate_media(color_scheme="light")
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.locator("#cloud-consent").check()
        page.locator("#cloud-create").click()
        expect(page.locator("#cloud-job-title")).to_have_text("The server is ready", timeout=30000)
        expect(page.locator("#cloud-outcome a.text-link")).to_have_attribute(
            "href", "https://bright-words-here.trycloudflare.com")
        expect(page.locator("#cloud-outcome")).to_contain_text("changes whenever the server restarts")
        quick = world.servers[world.server_id]["name"]
        page.locator("#cloud-servers").evaluate("details => details.open = true")
        row = page.locator(".cloud-server", has_text=quick)
        expect(row.locator("a.cloud-address")).to_have_attribute("href", "https://bright-words-here.trycloudflare.com")
        world.post_address("after-restart-here.trycloudflare.com")
        row.get_by_role("button", name="Find the current address").click()
        expect(row.locator("a.cloud-address")).to_have_attribute("href", "https://after-restart-here.trycloudflare.com")
        page.screenshot(path=str(output / "2-ready-quick.png"), full_page=True)
        row.get_by_role("button", name="Delete the server").click()
        answer_panel_dialog(page, text=quick)
        expect(page.locator("#cloud-job-title")).to_have_text("The server is deleted", timeout=30000)
        expect(row).to_contain_text(quick + " · Server deleted")
        assert not world.servers and not world.firewalls

        page.locator("#cloud-own-domain summary").click()
        page.locator("#cloud-cloudflare-token").fill(CF_TOKEN)
        page.locator("#cloud-check").click()
        expect(page.locator("#cloud-offer")).to_be_visible()
        expect(page.locator("#cloud-summary")).to_contain_text("cpx22")
        expect(page.locator("#cloud-summary")).to_contain_text("7.13 EUR")
        expect(page.locator("#cloud-domain-field")).to_be_visible()
        expect(page.locator("#cloud-address")).to_contain_text(".example.org")
        expect(page.locator("#cloud-domain option")).to_have_count(2)
        page.screenshot(path=str(output / "1-offer.png"), full_page=True)
        for width in (390, 1440):
            page.set_viewport_size({"width": width, "height": 1000})
            for theme in ("light", "dark"):
                page.emulate_media(color_scheme=theme)
                check_layout(page)
                page.locator("#cloud-offer").screenshot(path=str(output / f"offer-{theme}-{width}.png"))
        page.emulate_media(color_scheme="light")
        page.set_viewport_size({"width": 1280, "height": 1000})
        name = page.locator("#cloud-address").inner_text().split("//", 1)[1].split(".", 1)[0]
        last = jobs.status()["job"]["id"]
        page.locator("#cloud-create").click()
        time.sleep(.5)
        assert not world.servers and jobs.status()["job"]["id"] == last
        page.locator("#cloud-consent").check()
        page.locator("#cloud-create").click()
        expect(page.locator("#cloud-job-title")).to_have_text("The server is ready", timeout=30000)
        expect(page.locator("#cloud-stages li.done")).to_have_count(5)
        assert world.servers and world.servers[world.server_id]["name"] == name
        page.locator("#cloud-outcome").get_by_role("button", name="Show the panel token").click()
        expect(page.locator("#cloud-outcome code")).to_have_text(re.compile(r"^\S{32,}$"))
        expect(page.locator("#cloud-server-list")).to_contain_text(name + " · Up and running")
        page.screenshot(path=str(output / "2-ready.png"), full_page=True)
        page.locator("#cloud-servers").evaluate("details => details.open = true")
        page.locator("#cloud-server-list").get_by_role("button", name="Delete the server").click()
        answer_panel_dialog(page, text="wrong")
        expect(page.locator("#toast")).to_contain_text("Type the server name")
        assert world.servers
        page.locator("#cloud-server-list").get_by_role("button", name="Delete the server").click()
        answer_panel_dialog(page, text=name)
        expect(page.locator("#cloud-job-title")).to_have_text("The server is deleted", timeout=30000)
        expect(page.locator("#cloud-server-list")).to_contain_text(name + " · Server deleted")
        assert not world.servers and not world.firewalls and not world.dns
        lock_panel(page)
        unlock(page, server)
        navigate_panel(page, "witness")
        page.locator("#extras-open-cloud").click()
        expect(page.locator("#cloud-hetzner-token")).to_have_value("")
        expect(page.locator("#cloud-offer")).to_be_hidden()
        context.add_cookies([{"name": i18n.COOKIE, "value": "ru", "url": server.url}])
        reload_panel(page)
        expect(page.locator("#view-witness")).to_be_visible()
        navigate_panel(page, "witness")
        page.locator("#extras-open-cloud").click()
        expect(page.locator("#cloud-check")).to_have_text(i18n.words("ru")["Check and show the price"])
        expect(page.locator("#cloud-own-domain summary")).to_have_text(
            i18n.words("ru")["Optional · your own domain instead of a trycloudflare.com address"])
        page.screenshot(path=str(output / "3-ru.png"), full_page=True)
        browser.close()
    assert not errors, errors
    assert not external, external
    tokens_absent(directory / "browser-panel", HZ_TOKEN, CF_TOKEN)
    print("ok  browser: quick tunnel and own domain: check, consent, create, address, panel token, delete; lock "
          "clears tokens")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--browser", action="store_true", help="Also run the panel flow in Chromium")
    args = parser.parse_args()
    quiet()
    with tempfile.TemporaryDirectory(prefix="cloud-wizard-") as folder:
        directory = Path(folder)
        check_selection()
        check_boundaries(directory)
        check_command_line(directory)
        check_panel(directory)
        if args.browser:
            output = ROOT / "test-results/cloud-wizard"
            output.mkdir(parents=True, exist_ok=True)
            check_browser(directory, output)
    print("cloud wizard checks passed")


if __name__ == "__main__":
    main()
