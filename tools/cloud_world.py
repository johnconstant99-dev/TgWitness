"""Simulated Cloudflare API and collector host for the Phala check (tools/check_phala.py).

Every request is recorded and every resource is kept in memory; no network, no real accounts.
"""
import re
import sys
from pathlib import Path
from types import SimpleNamespace as NS
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import assurance, cloud  # noqa: E402
from tgwitness.provenance import SOURCE_POLICY, source_files, source_tree_sha256  # noqa: E402
from tgwitness.security import Vault  # noqa: E402

ACCOUNT, COMMIT, TUNNEL = "0" * 32, "a" * 40, "6ff42ae2-765d-4adf-8112-31c55c1551ef"
CREATED, LATE = "2026-10-30T10:00:00+00:00", "2026-10-31T10:00:00+00:00"


class Response:
    def __init__(self, status, data=None, content=b""):
        self.status_code, self.data, self.content = status, data, content

    def json(self):
        if self.data is None:
            raise ValueError("no JSON")
        return self.data


class World:
    """Cloudflare plus one provider: every request is recorded, every resource is in memory."""
    key = ""

    def __init__(self):
        self.calls, self.dns, self.audit = [], [], []
        self.tunnel = self.config = self.user_data = None
        self.version, self.connector_ips, self.deleted = 0, None, False

    def request(self, method, url, timeout=None, json=None, params=None, headers=None, data=None):
        assert timeout
        self.calls.append((method, url, json if json is not None else data, params, headers))
        if url.startswith(cloud.CLOUDFLARE_API):
            assert headers["Authorization"].startswith("Bearer ")
            status, result = self.cloudflare(method, url[len(cloud.CLOUDFLARE_API):], json, params or {})
            return Response(status, {"success": status < 400, "errors": [], "result": result})
        return self.provider(method, url, json, params or {}, headers or {}, data)

    def cloudflare(self, method, path, body, params):
        tunnel = "/accounts/" + ACCOUNT + "/cfd_tunnel"
        if path == "/zones":
            return 200, [{"id": "zone1"}] if params["name"] == "example.org" else []
        if path == "/zones/zone1/dns_records" and method == "GET":
            return 200, [r for r in self.dns if r["name"] == params["name"]]
        if path == "/zones/zone1/dns_records":
            self.dns.append({"id": "dns" + str(len(self.dns)), **body})
            return 200, self.dns[-1]
        if path == tunnel and method == "POST":
            assert body["config_src"] == "cloudflare"
            self.tunnel = {"id": TUNNEL, "name": body["name"], "created_at": CREATED, "token": "eyJhIjoi" + "c" * 60}
            return 200, self.tunnel
        if path == tunnel + "/" + TUNNEL:
            return 200, {k: v for k, v in self.tunnel.items() if k != "token"}
        if path == tunnel + "/" + TUNNEL + "/configurations":
            if method == "PUT":
                self.version, self.config = self.version + 1, body["config"]
            return 200, {"config": self.config, "version": self.version}
        if path == tunnel + "/" + TUNNEL + "/connections":
            ips = self.connector_ips or [self.ipv4]
            return 200, [{"id": "connector", "conns": [{"origin_ip": ip, "colo_name": "fra"} for ip in ips]}]
        if path == "/accounts/" + ACCOUNT + "/audit_logs":
            return 200, self.audit
        raise AssertionError(method + " " + path)

    def json_body(self, body):
        return body




class Host:
    """The collector on the simulated server: a real vault signing real assurance statements."""
    def __init__(self, world, tmp_path, user_data=None):
        self.world, self.vault, self.root = world, Vault(tmp_path / "collector"), tmp_path / "host"
        self.user_data = user_data or (lambda: world.user_data)
        for directory in ("proc/net", "proc/sys/kernel/random", "run", "var/log", "etc/tgwitness"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / "proc/sys/kernel/random/boot_id").write_text("boot-1\n")
        (self.root / "proc/net/tcp").write_text("  sl  local_address rem_address   st\n")
        (self.root / "run/utmp").write_bytes(b"")
        (self.root / "var/log/wtmp").write_bytes(b"")
        self.receipt = {"run_id": "run-1", "version": "0.6.1", "source_policy": SOURCE_POLICY,
                        "source_tree_sha256": source_tree_sha256(source_files())}
        self.override = {}

    def provider(self):
        return {"provider": self.world.key or "generic", "instance_id": getattr(self.world, "server_id", "machine-1"),
                "public_ipv4": getattr(self.world, "ipv4", None), **assurance.user_data_hashes(self.user_data()),
                "user_data_redacted": assurance.redact_user_data(self.user_data()), **self.override}

    def get(self, url, timeout):
        description = re.search(r"^ *(\{\"commit\".*\})$", self.user_data(), re.M).group(1)
        (self.root / "etc/tgwitness/assurance.json").write_text(description + "\n")
        challenge = parse_qs(urlsplit(url).query).get("challenge", [None])[0]
        return Response(200, assurance.statement(self.vault, self.receipt, 1, self.world.key or "generic",
                                                 self.provider(), challenge, self.root))

    def fetch(self, host, challenge):
        return cloud.collector_statement(host, challenge, session=self)


def arguments(tmp_path, provider="hetzner", **changes):
    values = dict(provider=provider, name="case-1", server_type=None, location=None, image=None, ref=COMMIT,
                  repository=cloud.DEFAULT_REPOSITORY, zone="example.org", cloudflare_account=ACCOUNT,
                  panel_host="case1.example.org", witness_host="case1-w.example.org", debug_ssh_key=None,
                  debug_ssh_from=None, provider_token_file=None, cloudflare_token_file=None,
                  out=tmp_path / "deployment", wait=1)
    values.update(changes)
    return NS(**values)



def checks(report):
    return {c["check"]: c["status"] for c in report["checks"]}


def detail(report, check):
    return next(c["detail"] for c in report["checks"] if c["check"] == check)

