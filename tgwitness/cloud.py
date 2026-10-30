"""High-assurance deployment of a collector on a cloud server behind a Cloudflare Tunnel.

    python -m tgwitness.cloud plan   --provider P ...  the cloud-init and API calls; nothing is created
    python -m tgwitness.cloud deploy --provider P ...  tunnel, DNS, firewall and server; waits for the key
    python -m tgwitness.cloud lock   --record ...      removes every inbound firewall rule (debug deployments)
    python -m tgwitness.cloud verify --record ...      a report from the provider, Cloudflare and the collector

Providers (tgwitness/providers): hetzner, digitalocean, linode, vultr, aws. The server is created
through the provider's API without an SSH key, behind a provider firewall with no inbound rules,
and SSH is masked from the first boot. TgWitness is installed from one commit and creates its
signing key on that server; the panel is reached only through the tunnel. A verifier with
read-only credentials compares the provider's own log and firewall, the tunnel connector's
address and the collector's signed statement. "generic" installs on any server by hand with
install.sh and is never more than self-attested. Nothing here shows what a provider can do on
its own hypervisor.
"""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import __version__
from .assurance import redact_user_data, user_data_hashes
from .provenance import source_files, source_tree_sha256
from .providers import NAMES, get
from .providers import base
from .providers.base import Api, DeployError, parse_time
from .security import private_write
from .store import utcnow
from .verify import bounded_lines, canonical, fingerprint, open_archive, verify_bundle

DEFAULT_REPOSITORY = "https://github.com/phishdestroy/TgWitness.git"
CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"
PANEL_SERVICE = "http://127.0.0.1:8787"
WITNESS_PATHS = r"^/(profiles/[^/]+/)?api/(witness/head|assurance)$"
CF, COLLECTOR, JOURNAL, RECORD = ("Cloudflare API", "collector statement (self-reported)", "evidence journal",
                                  "deployment record")
NAME = re.compile(r"[a-z0-9]([a-z0-9-]{0,48}[a-z0-9])?")
SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,99}")
HOST = re.compile(r"(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
COMMIT = re.compile(r"[0-9a-f]{40}")
TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,99}")
REPOSITORY = re.compile(r"https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~-]+)+")
ACCOUNT = re.compile(r"[0-9a-f]{32}")
KEY_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@:-]{0,127}")
TUNNEL_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{16,4096}")
ESTABLISHES = (
    "The provider reports this server, its creation time, image and its own log of actions; the access "
    "paths the provider offers (console credentials, rescue, password reset, rebuild, images, backups) appear there.",
    "The provider firewall in front of the server admits no inbound connections, so SSH and every other "
    "port are closed at the network edge while that firewall is applied.",
    "Cloudflare reports which machine runs the tunnel connector; the panel is reachable only through it, "
    "and the tunnel's ingress forwards to the panel alone.",
    "The collector signs, with a key that answers from that server, the server ID, the hash of the "
    "cloud-init it was created with, the deployed commit and its own source tree.",
)
SELF_ESTABLISHES = (
    "Self-attested only. The collector signs the hash of the installer it ran, the deployed commit, its own "
    "source tree, the host inventory taken before installation and the host's SSH and login state.",
    "Cloudflare reports from which address the tunnel connector runs; the panel is reachable only through it.",
)
LIMITS = (
    "The collector's host measurements (SSH listeners, logins, boot) are self-reported: root on the server "
    "could falsify them. They support, not replace, the provider and Cloudflare records.",
    "The provider and its staff control the hypervisor, disks and network; nothing here excludes them.",
    "Provider and Cloudflare logs are kept for limited periods; produce this report early and keep it "
    "with the evidence.",
    "Panel actions through the tunnel are not SSH sessions; they are recorded in the signed journal.",
    "Message authenticity still rests on Telegram and on what the account could see; see EVIDENCE.md.",
)


class Cloudflare(Api):
    name, base = "Cloudflare", CLOUDFLARE_API

    def ok(self, data):
        return isinstance(data, dict) and data.get("success") is True

    def reason(self, data):
        errors = data.get("errors") if isinstance(data, dict) else None
        return "; ".join(str(e.get("code")) + ": " + str(e.get("message")) for e in errors or [] if isinstance(e, dict))

    def result(self, method, path, body=None, params=None, allow=()):
        data = self.call(method, path, body, params, allow)
        return None if data is None else data["result"]


def read_secret(path, variable, option, required=True):
    """Tokens come from a file or the environment, never from the command line."""
    value = Path(path).read_text(encoding="utf-8-sig").strip() if path else os.environ.get(variable, "").strip()
    if not value and required:
        raise DeployError("Provide " + option + " or set " + variable)
    return value or None


def resolve_commit(repository, ref, run=subprocess.run):
    """A tag (release) is resolved once, here; the server only ever receives the commit."""
    if COMMIT.fullmatch(ref):
        return ref
    if not TAG.fullmatch(ref) or ".." in ref:
        raise DeployError("--ref must be a 40-character commit or a release tag")
    git = shutil.which("git")
    if not git:
        raise DeployError("Resolving a tag needs git; pass the 40-character commit instead")
    names = ["refs/tags/" + ref, "refs/tags/" + ref + "^{}"]
    output = run([git, "ls-remote", repository, *names], capture_output=True, text=True,
                 timeout=120, check=True).stdout
    found = {name: sha for sha, name in (line.split("\t", 1) for line in output.splitlines() if "\t" in line)}
    commit = found.get(names[1]) or found.get(names[0])
    if not commit or not COMMIT.fullmatch(commit):
        raise DeployError("Tag " + ref + " was not found in " + repository)
    return commit


def specification(args, resolve=resolve_commit):
    kind = get(args.provider)
    generic = args.provider == "generic"
    if not NAME.fullmatch(args.name):
        raise DeployError("--name: lowercase letters, digits and hyphens, up to 50 characters")
    choices = {"location": None, "image": None, "server_type": None}
    if not generic:
        choices = {"location": args.location or kind.defaults["location"], "image": args.image or kind.defaults["image"],
                   "server_type": args.server_type}
        if not args.server_type:
            raise DeployError("--server-type is required for " + kind.title + ", e.g. " + kind.example_type)
        for option, value in choices.items():
            if not SLUG.fullmatch(value):
                raise DeployError("--" + option.replace("_", "-") + " has an unexpected value")
    if not REPOSITORY.fullmatch(args.repository):
        raise DeployError("--repository must be an https:// Git URL without credentials")
    if not ACCOUNT.fullmatch(args.cloudflare_account):
        raise DeployError("--cloudflare-account must be the 32-character account ID")
    zone = args.zone.lower().rstrip(".")
    hosts = [h.lower().rstrip(".") for h in (args.panel_host, args.witness_host) if h]
    for host in hosts:
        if not HOST.fullmatch(host) or not host.endswith("." + zone):
            raise DeployError(host + " must be a hostname inside the zone " + zone)
    if len(set(hosts)) != len(hosts):
        raise DeployError("Use different hostnames for the panel and the witness endpoint")
    ssh = "disabled"
    if args.debug_ssh_key or args.debug_ssh_from:
        if generic:
            raise DeployError("--debug-ssh-* apply to provider deployments; install.sh closes SSH itself")
        if not (args.debug_ssh_key and args.debug_ssh_from):
            raise DeployError("--debug-ssh-key and --debug-ssh-from go together")
        if not KEY_NAME.fullmatch(args.debug_ssh_key):
            raise DeployError("--debug-ssh-key must be the " + kind.ssh_key_help)
        try:
            network = ipaddress.ip_network(args.debug_ssh_from, strict=False)
        except ValueError:
            raise DeployError("--debug-ssh-from must be an IP address or network") from None
        if network.prefixlen < (24 if network.version == 4 else 48):
            raise DeployError("--debug-ssh-from must be one address or a small network (/24 or /48 at most)")
        ssh = {"debug_key": args.debug_ssh_key, "allowed_from": str(network)}
    return {"format": "tgwitness-deployment-v1", "deployment_id": secrets.token_hex(8), "name": args.name,
            "mode": "self-attested" if generic else "high-assurance" if ssh == "disabled" else "debug",
            "provider": args.provider, **choices, "repository": args.repository, "requested_ref": args.ref,
            "commit": resolve(args.repository, args.ref), "zone": zone, "cloudflare_account": args.cloudflare_account,
            "panel_host": hosts[0], "witness_host": hosts[1] if len(hosts) > 1 else None, "ssh": ssh}


def ingress(spec):
    rules = [{"hostname": spec["panel_host"], "service": PANEL_SERVICE}]
    if spec.get("witness_host"):
        rules.append({"hostname": spec["witness_host"], "path": WITNESS_PATHS, "service": PANEL_SERVICE})
    return rules + [{"service": "http_status:404"}]


def inbound_rules(spec):
    """Provider-neutral inbound rules: none, or the debug SSH rule."""
    if spec["ssh"] == "disabled":
        return []
    return [{"protocol": "tcp", "port": "22", "source": spec["ssh"]["allowed_from"]}]


UNIT = """\
[Unit]
Description=TgWitness observation journal (high-assurance deployment)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=tgwitness
Group=tgwitness
WorkingDirectory=/var/lib/tgwitness
StateDirectory=tgwitness
StateDirectoryMode=0700
UMask=0077
Environment=TGWITNESS_DATA=/var/lib/tgwitness
Environment=TGWITNESS_ASSURANCE=@PROVIDER@
Environment=TGWITNESS_NO_BROWSER=1
Environment=PYTHONDONTWRITEBYTECODE=1
EnvironmentFile=/etc/tgwitness/panel.env
ExecStart=/opt/tgwitness/.venv/bin/python -m tgwitness --host 127.0.0.1 --port 8787
Restart=on-failure
RestartSec=10
TimeoutStopSec=180
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictSUIDSGID=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/tgwitness

[Install]
WantedBy=multi-user.target
"""

SSH_OFF = """\
systemctl disable --now ssh.socket ssh.service || true
systemctl mask ssh.socket ssh.service
passwd -l root
rm -f /root/.ssh/authorized_keys
"""

END_SESSIONS = """\
pkill -x sshd-session || true
pkill -x sshd || true
"""

LOCK = """\
#!/bin/bash
# Run as the last command of the last SSH session, then: python -m tgwitness.cloud lock
set -euo pipefail
""" + SSH_OFF + """\
echo "SSH disabled $(date -u +%FT%TZ)" >> /var/log/tgwitness-bootstrap.log
""" + END_SESSIONS

INSTALL = """\
export DEBIAN_FRONTEND=noninteractive
APT="apt-get -o DPkg::Lock::Timeout=600 -y"
REPOSITORY='@REPOSITORY@'
COMMIT='@COMMIT@'
$APT update
$APT install --no-install-recommends ca-certificates curl git python3-venv
install -d -m 0755 /usr/share/keyrings /opt/tgwitness
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' \\
    > /etc/apt/sources.list.d/cloudflared.list
$APT update
$APT install cloudflared
id tgwitness >/dev/null 2>&1 || useradd --system --home-dir /var/lib/tgwitness --no-create-home \\
    --shell /usr/sbin/nologin tgwitness
git init -q /opt/tgwitness/source
git -C /opt/tgwitness/source fetch -q --depth 1 "$REPOSITORY" "$COMMIT"
git -C /opt/tgwitness/source checkout -q --detach FETCH_HEAD
test "$(git -C /opt/tgwitness/source rev-parse HEAD)" = "$COMMIT"
python3 -m venv /opt/tgwitness/.venv
/opt/tgwitness/.venv/bin/pip install --no-cache-dir -c /opt/tgwitness/source/deploy/constraints.txt /opt/tgwitness/source
"""

START = """\
set -a
. /etc/tgwitness/secrets.env
set +a
(umask 077 && printf 'TGWITNESS_TOKEN=%s\\n' "$TGWITNESS_TOKEN" > /etc/tgwitness/panel.env)
systemctl daemon-reload
systemctl enable --now tgwitness.service
cloudflared service install "$TGWITNESS_TUNNEL_TOKEN"
rm -f /etc/tgwitness/secrets.env
"""

PREINSTALL = """\
{
  echo "# TgWitness pre-installation inventory, $(date -u +%FT%TZ)"
  echo "## system"; uname -a; cat /etc/os-release; echo "booted $(uptime -s)"
  echo "## logins"; last -F -w -x 2>/dev/null | head -n 200 || true
  echo "## accounts with a login shell"
  getent passwd | awk -F: '$7 !~ /(nologin|false|sync)$/ {print $1 ":" $3 ":" $6 ":" $7}'
  echo "## authorized_keys"; find /root /home /etc -name 'authorized_keys*' -type f -exec sha256sum {} + 2>/dev/null || true
  echo "## listening sockets"; ss -ltnup 2>/dev/null || true
  echo "## enabled services"; systemctl list-unit-files --state=enabled --no-legend 2>/dev/null || true
  echo "## scheduled jobs"; ls -la /etc/cron.d /var/spool/cron/crontabs 2>/dev/null || true
  echo "## packages"; dpkg-query -W 2>/dev/null | wc -l; dpkg-query -W 2>/dev/null | sha256sum
} > /etc/tgwitness/preinstall.txt 2>&1
"""


def fill(template, spec):
    return template.replace("@REPOSITORY@", spec["repository"]).replace("@COMMIT@", spec["commit"])


def files(spec, tunnel_id, panel_token, tunnel_token):
    """What every deployment writes before installing: its description, the two secrets, the unit."""
    if not TUNNEL_TOKEN.fullmatch(tunnel_token) or not re.fullmatch(r"[A-Za-z0-9_-]{24,256}", panel_token):
        raise DeployError("Unexpected token format; refusing to write it into the installer")
    description = {"format": "tgwitness-deployment-v1", "tunnel_id": tunnel_id,
                   **{k: spec[k] for k in ("deployment_id", "name", "mode", "provider", "repository", "commit",
                                           "panel_host", "witness_host", "ssh")}}
    return [("/etc/tgwitness/assurance.json", "0644", json.dumps(description, sort_keys=True) + "\n"),
            ("/etc/tgwitness/secrets.env", "0600",
             "TGWITNESS_TOKEN=" + panel_token + "\nTGWITNESS_TUNNEL_TOKEN=" + tunnel_token + "\n"),
            ("/etc/systemd/system/tgwitness.service", "0644", UNIT.replace("@PROVIDER@", spec["provider"]))]


def block(text, spaces=6):
    return "".join(" " * spaces + line if line.strip() else line for line in text.splitlines(True))


def cloud_init(spec, tunnel_id, panel_token, tunnel_token):
    """The complete user data. Its redacted form (two secret values replaced) is what gets published."""
    locked = spec["ssh"] == "disabled"
    bootstrap = ("#!/bin/bash\n# TgWitness high-assurance bootstrap: runs once from cloud-init and needs no "
                 "interactive access.\nset -euo pipefail\nexec >>/var/log/tgwitness-bootstrap.log 2>&1\n"
                 + (SSH_OFF if locked else "") + fill(INSTALL, spec) + START
                 + 'echo "TgWitness bootstrap finished $(date -u +%FT%TZ)"\n')
    written = files(spec, tunnel_id, panel_token, tunnel_token) + [("/usr/local/sbin/tgwitness-bootstrap", "0700", bootstrap)]
    if not locked:
        written.append(("/usr/local/sbin/tgwitness-lock", "0700", LOCK))
    lines = ["#cloud-config", "# TgWitness " + spec["mode"] + " deployment " + spec["deployment_id"],
             "ssh_pwauth: false"]
    if locked:
        lines += ["bootcmd:", "  - [systemctl, mask, --now, ssh.socket, ssh.service]"]
    lines.append("write_files:")
    for path, mode, content in written:
        lines += ["  - path: " + path, '    permissions: "' + mode + '"', "    content: |", block(content).rstrip("\n")]
    lines += ["runcmd:", "  - [/usr/local/sbin/tgwitness-bootstrap]"]
    return "\n".join(lines) + "\n"


def install_script(spec, tunnel_id, panel_token, tunnel_token):
    """install.sh for a hand-installed server. Its redacted form is what gets published."""
    lines = ["#!/bin/bash",
             "# TgWitness self-attested installation, deployment " + spec["deployment_id"] + ".",
             "# Run once, as a file, as root on a freshly installed Ubuntu 24.04 server: sudo bash install.sh",
             "# It records the host as it is now, installs commit " + spec["commit"] + ",",
             "# closes SSH and ends this session. Nobody independent checks any of it.",
             "set -euo pipefail",
             'SCRIPT="$(readlink -f "$0")"',
             '[ "$(id -u)" = 0 ] || { echo "Run as root: sudo bash $0"; exit 1; }',
             '[ -f "$SCRIPT" ] || { echo "Save this installer as a file and run that file"; exit 1; }',
             '. /etc/os-release && [ "$ID" = ubuntu ] || { echo "Ubuntu is required"; exit 1; }',
             "install -d -m 0755 /etc/tgwitness", PREINSTALL.rstrip("\n")]
    for path, mode, content in files(spec, tunnel_id, panel_token, tunnel_token):
        lines += ["(umask 077 && cat > " + path + " <<'TGWITNESS_FILE'", content.rstrip("\n"), "TGWITNESS_FILE", ")",
                  "chmod " + mode + " " + path]
    lines += ["exec > >(tee -a /var/log/tgwitness-bootstrap.log) 2>&1", fill(INSTALL, spec).rstrip("\n"),
              "/opt/tgwitness/.venv/bin/python -m tgwitness.assurance install-record \"$SCRIPT\" "
              "/etc/tgwitness/preinstall.txt /etc/tgwitness/install.json",
              START.rstrip("\n"),
              "if command -v ufw >/dev/null; then ufw default deny incoming; ufw default allow outgoing; "
              "ufw --force enable; fi",
              'rm -f "$SCRIPT"', 'echo "TgWitness installed. SSH closes now and this session ends."',
              SSH_OFF.rstrip("\n"), END_SESSIONS.rstrip("\n")]
    return "\n".join(lines) + "\n"


def collector_statement(host, challenge=None, session=None):
    """The collector's signed /api/assurance answer, checked: format, signature, fingerprint, challenge."""
    url = "https://" + host + "/api/assurance" + ("?challenge=" + challenge if challenge else "")
    response = (session or requests).get(url, timeout=30)
    if response.status_code != 200:
        raise DeployError(url + " answered HTTP " + str(response.status_code))
    answer = response.json()
    statement = answer["statement"]
    if statement.get("format") != "tgwitness-assurance-v1":
        raise DeployError("Unexpected statement format from " + url)
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(statement["public_key"], validate=True)).verify(
            base64.b64decode(answer["signature"], validate=True), canonical(statement))
    except (InvalidSignature, ValueError):
        raise DeployError("The collector statement signature is invalid") from None
    if statement.get("fingerprint") != fingerprint(statement["public_key"]):
        raise DeployError("The statement's fingerprint does not belong to its key")
    if challenge and statement.get("challenge") != challenge:
        raise DeployError("The statement does not echo this request's challenge")
    return answer


def binding(statement, server_id, ipv4, cloud):
    """Problems tying the statement to the provider's server and to the cloud-init it was given."""
    provider, problems = (statement.get("host") or {}).get("provider") or {}, []
    if provider.get("error"):
        problems.append("the collector could not read the metadata service: " + provider["error"])
    if str(provider.get("instance_id")) != str(server_id):
        problems.append("instance ID " + str(provider.get("instance_id")) + " is not server " + str(server_id))
    if ipv4 and provider.get("public_ipv4") not in (None, ipv4):  # the public statement omits the address
        problems.append("public IPv4 " + str(provider.get("public_ipv4")) + " is not " + ipv4)
    for key in ("user_data_sha256", "user_data_redacted_sha256"):
        if provider.get(key) != cloud.get(key):
            problems.append(key + " differs from the deployment record")
    return problems


def write_record(path, record):
    path.write_bytes(json.dumps(record, indent=2, ensure_ascii=False).encode() + b"\n")


def wait_for_collector(host, minutes, fetch):
    deadline = time.monotonic() + minutes * 60
    while True:
        try:
            return fetch(host, secrets.token_hex(16))
        except (DeployError, requests.RequestException, ValueError, KeyError) as exc:
            if time.monotonic() > deadline:
                raise DeployError("The collector did not answer in time (" + str(exc) + "). Run verify "
                                  "later; without SSH a failed bootstrap means a new deployment.") from None
            base.pause(15)


def connect(kind, credentials, spec, log=None):
    provider = kind(credentials, log=log)
    provider.location, provider.mode = spec.get("location"), spec["mode"]
    return provider


def deploy(args, provider=None, cloudflare=None, fetch=collector_statement, resolve=resolve_commit):
    spec = specification(args, resolve)
    kind, generic = get(spec["provider"]), spec["provider"] == "generic"
    out = Path(args.out or Path("deployments") / spec["name"])
    if (out / "deployment.json").exists():
        raise DeployError(str(out) + " already holds a deployment; choose another --out or --name")
    log = []
    provider = provider or connect(kind, kind.credentials(args.provider_token_file), spec)
    provider.location, provider.mode, provider.log = spec["location"], spec["mode"], log
    cf = cloudflare or Cloudflare(read_secret(args.cloudflare_token_file, "CLOUDFLARE_API_TOKEN",
                                              "--cloudflare-token-file"))
    cf.log = log
    out.mkdir(parents=True, exist_ok=True)
    record = {**spec, "created_at": utcnow(), "deployed_by": "TgWitness " + __version__, "state": "starting",
              "api_calls": log}
    path = out / "deployment.json"
    account = spec["cloudflare_account"]
    hosts = [h for h in (spec["panel_host"], spec["witness_host"]) if h]
    try:
        zones = cf.result("GET", "/zones", params={"name": spec["zone"]})
        if len(zones) != 1:
            raise DeployError("Cloudflare zone " + spec["zone"] + " was not found for this token")
        record["zone_id"] = zones[0]["id"]
        for host in hosts:
            if cf.result("GET", "/zones/" + record["zone_id"] + "/dns_records", params={"name": host}):
                raise DeployError(host + " already has DNS records; choose an unused hostname")
        tunnel = cf.result("POST", "/accounts/" + account + "/cfd_tunnel",
                           {"name": "tgwitness-" + spec["name"] + "-" + spec["deployment_id"], "config_src": "cloudflare"})
        record["tunnel"] = {"id": tunnel["id"], "name": tunnel["name"], "created_at": tunnel.get("created_at")}
        write_record(path, record)
        print("Cloudflare tunnel", tunnel["id"], "created", flush=True)
        tunnel_token = tunnel.get("token") or cf.result(
            "GET", "/accounts/" + account + "/cfd_tunnel/" + tunnel["id"] + "/token")
        config = cf.result("PUT", "/accounts/" + account + "/cfd_tunnel/" + tunnel["id"] + "/configurations",
                           {"config": {"ingress": ingress(spec)}})
        record["tunnel"]["config_version"] = config.get("version")
        record["dns"] = []
        for host in hosts:
            created = cf.result("POST", "/zones/" + record["zone_id"] + "/dns_records", {
                "type": "CNAME", "name": host, "content": tunnel["id"] + ".cfargotunnel.com", "proxied": True,
                "comment": "TgWitness " + spec["mode"] + " deployment " + spec["deployment_id"]})
            record["dns"].append({"host": host, "id": created["id"]})
        write_record(path, record)
        panel_token = secrets.token_urlsafe(32)
        private_write(out / "panel-token.txt", panel_token.encode())
        if generic:
            script = install_script(spec, tunnel["id"], panel_token, tunnel_token)
            private_write(out / "install.sh", script.encode())
            (out / "install.redacted.sh").write_bytes(redact_user_data(script).encode())
            record["cloud_init"] = {**user_data_hashes(script), "published": "install.redacted.sh"}
            record["state"] = "waiting for install.sh on the server"
            write_record(path, record)
            print("Copy", out / "install.sh", "to a freshly installed Ubuntu 24.04 server and run it there as root:")
            print("    sudo bash install.sh")
            print("It installs commit", spec["commit"], "closes SSH and ends that session.", flush=True)
        else:
            user_data = cloud_init(spec, tunnel["id"], panel_token, tunnel_token)
            if len(user_data.encode()) > kind.user_data_limit:
                raise DeployError("cloud-init exceeds " + kind.title + "'s user data limit")
            (out / "cloud-init.redacted.yaml").write_bytes(redact_user_data(user_data).encode())
            record["cloud_init"] = {**user_data_hashes(user_data), "published": "cloud-init.redacted.yaml"}
            write_record(path, record)
            print(kind.title + ": creating the firewall and the server", flush=True)
            firewall, server = provider.create(spec, user_data, inbound_rules(spec))
            record["firewall"] = {**firewall, "inbound_rules": inbound_rules(spec)}
            record["server"] = server
            record["state"] = "server running; waiting for the collector"
            write_record(path, record)
            print(kind.title + " server", server["id"], "is running", flush=True)
        print("Waiting up to", args.wait, "minutes for the collector's signed statement", flush=True)
        answer = wait_for_collector(spec["panel_host"], args.wait, fetch)
        statement = answer["statement"]
        host = statement.get("host") or {}
        record["collector"] = {"fingerprint": statement["fingerprint"], "public_key": statement["public_key"],
                               "first_boot_id": host.get("boot_id"), "statement": answer}
        if generic:
            seen = host.get("provider") or {}
            record["server"] = {"id": seen.get("instance_id"), "name": spec["name"], "hostname": seen.get("hostname"),
                                "created": None, "ipv4": None, "ipv6": None, "machine_id": seen.get("instance_id")}
        problems = binding(statement, record["server"]["id"], record["server"].get("ipv4"), record["cloud_init"])
        if problems:
            raise DeployError("The collector answered but does not match this deployment: " + "; ".join(problems))
        record["state"] = "running"
    except Exception as exc:
        record["state"] = "failed: " + str(exc)
        raise DeployError(str(exc) + ". Resources created so far are listed in " + str(path)) from exc
    finally:
        write_record(path, record)
    return record, out


def lock(args, provider=None):
    path = Path(args.record)
    record = json.loads(path.read_text(encoding="utf-8"))
    if record["provider"] == "generic":
        raise DeployError("A hand-installed server has no provider firewall; install.sh closes SSH itself")
    kind = get(record["provider"])
    provider = provider or connect(kind, kind.credentials(args.provider_token_file), record)
    provider.location, provider.mode = record.get("location"), record["mode"]
    actions = provider.lock(record)
    record.setdefault("locks", []).append({"at": utcnow(), "actions": actions})
    record["firewall"]["inbound_rules"] = []
    write_record(path, record)
    return record


class Report:
    ORDER = ("pass", "unavailable", "review", "fail")

    def __init__(self, self_attested=False):
        self.checks, self.actions, self.cloudflare, self.collector = [], [], {}, None
        self.self_attested = self_attested

    def add(self, check, status, title, detail, source):
        self.checks.append({"check": check, "status": status, "title": title, "detail": detail, "source": source})

    def result(self):
        worst = max((c["status"] for c in self.checks), key=self.ORDER.index, default="unavailable")
        if self.self_attested:
            return "fail" if worst == "fail" else "self-attested"
        return {"unavailable": "incomplete"}.get(worst, worst)


def worst(statuses):
    return max(statuses, key=Report.ORDER.index)


def verify_provider(report, record, provider):
    source = provider.title + " API"
    server = provider.describe(record)
    if not server:
        report.add("server", "fail", "The server exists at the provider", "Server " + str(record["server"]["id"])
                   + " was not found: deleted, or the credentials belong to another account or project", source)
        return None
    created = parse_time(server["created"])
    recorded_image = record["server"].get("image")
    image_ok = recorded_image in (None, server["image"])
    report.add("server", "pass" if server["belongs"] and image_ok else "review" if server["belongs"] else "fail",
               "The server exists and belongs to this deployment",
               str(server["name"]) + " #" + str(server["id"]) + ", created " + str(server["created"]) + ", type "
               + str(server["type"]) + ", location " + str(server["location"]) + ", image " + str(server["image"])
               + ("" if image_ok else " (recorded " + str(recorded_image) + ")"), source)
    report.add("server_state", "fail" if server["flags"] else "pass",
               "No rescue system, console agent, ISO, disk images or provider backups",
               "; ".join(server["flags"]) or "none found", source)
    found = provider.firewall(record, server)
    problems = list(found["problems"])
    if found["inbound"]:
        problems.append(str(len(found["inbound"])) + " inbound rule(s): " + "; ".join(found["inbound"]))
    report.add("firewall", "fail" if problems else "review" if found.get("changed") else "pass",
               "The provider firewall admits no inbound connections",
               "; ".join(problems + ([found["changed"]] if found.get("changed") else []))
               or "firewall " + str(record["firewall"]["id"]) + " applied with no inbound rules", source)
    if record["mode"] == "debug":
        locks = record.get("locks") or []
        report.add("mode", "review" if locks and not found["inbound"] else "fail", "Deployed without SSH",
                   "debug deployment: SSH was permitted from " + record["ssh"]["allowed_from"] + " with key "
                   + record["ssh"]["debug_key"] + (", firewall closed at " + locks[0]["at"] if locks else
                                                   ", never closed with lock"), source)
    for action in provider.actions(record, server):
        status, meaning = provider.classify(action, created)
        report.actions.append({**{k: action.get(k) for k in ("resource", "id", "command", "started", "finished",
                                                              "status", "actor")},
                               "assessment": status, "meaning": meaning})
    flagged = [a for a in report.actions if a["assessment"] != "pass"]
    status = worst([a["assessment"] for a in report.actions] or ["review"])
    detail = str(len(report.actions)) + " action(s); " + (", ".join(
        str(a["command"]) + " #" + str(a["id"]) + " (" + a["assessment"] + ")" for a in flagged)
        or "none outside the deployment")
    if not any(a["meaning"] == "server created" for a in report.actions):
        status, detail = worst([status, "review"]), detail + "; the creation is no longer listed"
    report.add("provider_actions", status, "The provider's log shows no access to the server",
               detail + "; " + provider.log_retention, source)
    return server


def verify_tunnel(report, record, cf, server):
    base_path = "/accounts/" + record["cloudflare_account"] + "/cfd_tunnel/" + record["tunnel"]["id"]
    tunnel = cf.result("GET", base_path, allow=(404,))
    if not tunnel or tunnel.get("deleted_at"):
        report.add("tunnel", "fail", "The Cloudflare tunnel exists", "tunnel deleted or not visible to this token", CF)
        return
    report.add("tunnel", "pass", "The Cloudflare tunnel exists", tunnel["name"] + ", created " + str(tunnel.get("created_at")), CF)
    config = cf.result("GET", base_path + "/configurations") or {}
    current = [{k: r[k] for k in ("hostname", "path", "service") if r.get(k)}
               for r in (config.get("config") or {}).get("ingress") or []]
    expected = [{k: v for k, v in r.items() if v} for r in ingress(record)]
    foreign = [r["service"] for r in current if r.get("service") not in (PANEL_SERVICE, "http_status:404")]
    changed = config.get("version") != record["tunnel"].get("config_version")
    report.add("ingress", "fail" if foreign else "pass" if current == expected and not changed else "review",
               "The tunnel forwards only to the panel",
               ("services other than the panel: " + ", ".join(foreign) + "; " if foreign else "")
               + "configuration version " + str(config.get("version")) + " (recorded "
               + str(record["tunnel"].get("config_version")) + "); " + json.dumps(current), CF)
    report.cloudflare["ingress"] = current
    clients = cf.result("GET", base_path + "/connections") or []
    addresses = sorted({c.get("origin_ip") for client in clients for c in client.get("conns") or []} - {None})
    report.cloudflare["connector_addresses"] = addresses

    def ours(address):
        try:
            ip = ipaddress.ip_address(address)
            return address == (server or {}).get("ipv4") or bool(
                (server or {}).get("ipv6") and ip in ipaddress.ip_network(server["ipv6"], strict=False))
        except ValueError:
            return False
    if record["provider"] == "generic":
        report.add("connector", "review", "The tunnel connector runs on this server",
                   "connections from " + (", ".join(addresses) or "nowhere now")
                   + "; no provider record to compare the address with", CF)
    else:
        foreign = [a for a in addresses if not ours(a)]
        report.add("connector", "fail" if foreign or not server else "pass" if addresses else "review",
                   "The tunnel connector runs on this server",
                   ("connector from another machine: " + ", ".join(foreign)) if foreign else
                   ("connections from " + ", ".join(addresses)) if addresses else "no connector online now", CF)
    for entry in record.get("dns") or []:
        found = cf.result("GET", "/zones/" + record["zone_id"] + "/dns_records", params={"name": entry["host"]}) or []
        good = len(found) == 1 and found[0].get("type") == "CNAME" and found[0].get("proxied") \
            and found[0].get("content") == record["tunnel"]["id"] + ".cfargotunnel.com"
        report.add("dns:" + entry["host"], "pass" if good else "fail", entry["host"] + " points to this tunnel only",
                   json.dumps([{k: r.get(k) for k in ("type", "content", "proxied")} for r in found]), CF)
    logs = cf.call("GET", "/accounts/" + record["cloudflare_account"] + "/audit_logs",
                   params={"since": record["created_at"], "per_page": 1000, "direction": "asc"}, allow=(401, 403))
    if logs is None:
        report.add("audit_log", "unavailable", "Cloudflare audit log for the tunnel and DNS records",
                   "this token cannot read the account audit log (Account Settings Read)", CF)
        return
    ids = [record["tunnel"]["id"], *(e["id"] for e in record.get("dns") or [])]
    entries = [e for e in logs.get("result") or [] if any(i in json.dumps(e) for i in ids)]
    created = parse_time(record["created_at"]).timestamp()
    late = [e for e in entries if parse_time(e["when"]).timestamp() > created + 1800]
    report.cloudflare["audit_entries"] = [{k: e.get(k) for k in ("when", "action", "actor", "resource")} for e in entries]
    report.add("audit_log", "review" if late else "pass", "Cloudflare audit log for the tunnel and DNS records",
               str(len(entries)) + " entr(ies), " + str(len(late)) + " after the deployment (first 1000 log entries)", CF)


def verify_collector(report, record, server, args, fetch):
    try:
        answer = fetch(record["panel_host"], secrets.token_hex(16))
    except (DeployError, requests.RequestException, ValueError, KeyError) as exc:
        report.add("statement", "fail", "The collector answers with a fresh signed statement", str(exc), COLLECTOR)
        return None
    statement = answer["statement"]
    host = statement.get("host") or {}
    report.add("statement", "pass", "The collector answers with a fresh signed statement",
               "signature valid, challenge echoed; run " + statement["run_id"] + ", TgWitness " + statement["version"], COLLECTOR)
    recorded = (record.get("collector") or {}).get("fingerprint")
    if args.fingerprint:
        status, detail = ("pass" if statement["fingerprint"] == args.fingerprint.lower() else "fail"), \
            "compared with the fingerprint given independently"
    elif recorded:
        status, detail = ("pass" if statement["fingerprint"] == recorded else "fail"), \
            "compared with the deployment record only; pass --fingerprint from an independent channel"
    else:
        status, detail = "review", "no expected fingerprint"
    report.add("fingerprint", status, "The signing key is the one born at deployment",
               statement["fingerprint"] + "; " + detail, COLLECTOR)
    target = record["server"] if record["provider"] == "generic" else server
    if target:
        ipv4 = target.get("ipv4")
        problems = binding(statement, target["id"], ipv4, record.get("cloud_init") or {})
        report.add("binding", "fail" if problems else "pass",
                   "The key answers from the recorded server, set up with the recorded installer",
                   "; ".join(problems) or "instance " + str(target["id"]) + (", IPv4 " + ipv4 if ipv4 else "")
                   + ", installer hashes match", COLLECTOR)
    published = record.get("cloud_init", {}).get("published", "cloud-init.redacted.yaml")
    if args.cloud_init:
        data = Path(args.cloud_init).read_bytes()
        problems = []
        if hashlib.sha256(data).hexdigest() != (host.get("provider") or {}).get("user_data_redacted_sha256"):
            problems.append("its SHA-256 differs from the redacted installer the server reports")
        text = data.decode(errors="replace")
        if record["commit"] not in text:
            problems.append("it does not install commit " + record["commit"])
        if record["mode"] in ("high-assurance", "self-attested") and "systemctl mask ssh.socket ssh.service" not in text:
            problems.append("it does not mask SSH")
        report.add("cloud_init", "fail" if problems else "pass", "The published installer is what the server received",
                   "; ".join(problems) or "SHA-256 matches; installs " + record["commit"], COLLECTOR)
    else:
        report.add("cloud_init", "unavailable", "The published installer is what the server received",
                   "pass --cloud-init " + published, COLLECTOR)
    deployed = host.get("deployment") or {}
    same = deployed.get("commit") == record["commit"] and deployed.get("deployment_id") == record["deployment_id"]
    report.add("deployment", "pass" if same else "fail", "The server describes this deployment and commit",
               "commit " + str(deployed.get("commit")) + ", deployment " + str(deployed.get("deployment_id")), COLLECTOR)
    if args.source:
        expected = source_tree_sha256(source_files(Path(args.source) / "tgwitness"))
        same = expected == statement["source_tree_sha256"]
        report.add("source", "pass" if same else "fail", "The running code equals the checkout of the commit",
                   "running " + statement["source_tree_sha256"] + ", checkout " + expected
                   + ("" if same else "; on Windows clone with git -c core.autocrlf=false"), COLLECTOR)
    else:
        report.add("source", "unavailable", "The running code equals the checkout of the commit",
                   "pass --source with a checkout of " + record["commit"], COLLECTOR)
    flags = [(host.get("ssh_listening"), "something listens on port 22"),
             (host.get("ssh_processes"), "SSH server processes running"), (host.get("sessions"), "logged-in sessions now")]
    if record["provider"] != "generic":  # a hand-installed server keeps the installer's own login in wtmp
        flags.append((host.get("logins"), str(host.get("logins")) + " login(s) in wtmp"))
    problems = [text for flag, text in flags if flag]
    unknown = [k for k in ("sessions", "logins") if host.get(k) is None]
    notes = problems + (["unreadable: " + ", ".join(unknown)] if unknown else [])
    report.add("host_access", "fail" if problems else "review" if unknown else "pass", "No SSH and no logins on the host",
               "; ".join(notes) or "nothing on port 22, no SSH processes, no sessions, no logins recorded", COLLECTOR)
    first = (record.get("collector") or {}).get("first_boot_id")
    report.add("boot", "pass" if first and host.get("boot_id") == first else "review", "Running since the first boot",
               "boot " + str(host.get("boot_id")) + (" (same as at deployment)" if host.get("boot_id") == first
                                                     else ", deployment recorded " + str(first)), COLLECTOR)
    report.collector = answer
    return statement


def verify_journal(report, path, key, server_id, generic=False):
    try:
        result = verify_bundle(path, expected_fingerprint=key)
    except Exception as exc:
        report.add("journal", "fail", "The evidence journal is signed by this key", type(exc).__name__ + ": " + str(exc), JOURNAL)
        return
    starts, problems, boots, baseline = 0, [], [], None
    with open_archive(path) as archive, archive.open("events.jsonl") as stream:
        for line in bounded_lines(stream):
            event = json.loads(line)
            if event["kind"] == "process.started":
                starts += 1
                host = (event["payload"].get("run") or {}).get("host")
                if not host:
                    problems.append("record " + str(event["seq"]) + ": a start without host measurement")
                    continue
                instance = (host.get("provider") or {}).get("instance_id")
            elif event["kind"] == "host.state":
                host, instance = event["payload"], event["payload"].get("instance_id")
            else:
                continue
            if str(instance) != str(server_id):
                problems.append("record " + str(event["seq"]) + ": instance " + str(instance))
            for flag, text in (("ssh_listening", "port 22 open"), ("ssh_processes", "SSH processes"),
                               ("sessions", "sessions")):
                if host.get(flag):
                    problems.append("record " + str(event["seq"]) + ": " + text)
            # A hand-installed server keeps the installer's login: only logins after the first start count.
            logins = host.get("logins") or 0
            baseline = (logins if baseline is None else baseline) if generic else 0
            if logins > baseline:
                problems.append("record " + str(event["seq"]) + ": login(s) recorded")
            if host.get("boot_id") and host["boot_id"] not in boots:
                boots.append(host["boot_id"])
    report.add("journal", "fail" if problems else "pass", "The evidence journal is signed by this key and was kept on this server",
               "; ".join(problems[:20]) or str(result["events"]) + " records verified; " + str(starts)
               + " process start(s) on server " + str(server_id) + "; " + str(len(boots)) + " boot(s)", JOURNAL)


def verify(args, provider=None, cloudflare=None, fetch=collector_statement):
    record = json.loads(Path(args.record).read_text(encoding="utf-8"))
    if record.get("format") != "tgwitness-deployment-v1" or not record.get("server"):
        raise DeployError(str(args.record) + " is not a completed deployment record")
    kind = get(record["provider"])
    report = Report(self_attested=record["mode"] == "self-attested")
    server = None
    if record["provider"] == "generic":
        report.add("provider", "unavailable", "Provider records",
                   "self-attested: a hand-installed server; no provider record exists for a verifier", RECORD)
    else:
        provider = provider or connect(kind, kind.credentials(args.provider_token_file), record)
        provider.location, provider.mode = record.get("location"), record["mode"]
        server = verify_provider(report, record, provider)
    token = None if cloudflare else read_secret(args.cloudflare_token_file, "CLOUDFLARE_API_TOKEN",
                                                "--cloudflare-token-file", required=False)
    if cloudflare or token:
        verify_tunnel(report, record, cloudflare or Cloudflare(token), server)
    else:
        report.add("tunnel", "unavailable", "Cloudflare tunnel, ingress, connector and DNS",
                   "no Cloudflare token (Cloudflare Tunnel Read, DNS Read)", CF)
    statement = verify_collector(report, record, server, args, fetch)
    if args.evidence:
        key = args.fingerprint or (statement or {}).get("fingerprint") or (record.get("collector") or {}).get("fingerprint")
        verify_journal(report, args.evidence, key, record["server"]["id"], record["provider"] == "generic")
    files_seen = {}
    for path in (args.record, args.cloud_init, args.evidence):
        if path:
            digest = hashlib.sha256()
            with open(path, "rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            files_seen[Path(path).name] = digest.hexdigest()
    generic = record["provider"] == "generic"
    return {"format": "tgwitness-assurance-report-v1", "generated_at": utcnow(),
            "verifier": {"software": "TgWitness", "version": __version__}, "result": report.result(),
            "deployment": {k: record.get(k) for k in ("deployment_id", "name", "mode", "provider", "location",
                                                      "repository", "commit", "panel_host", "witness_host", "created_at")},
            "provider_title": kind.title, "server": record["server"], "firewall": (record.get("firewall") or {}).get("id"),
            "tunnel": record.get("tunnel", {}).get("id"), "cloudflare_account": record.get("cloudflare_account"),
            "fingerprint": (statement or {}).get("fingerprint"), "checks": report.checks,
            "provider_actions": report.actions, "cloudflare": report.cloudflare,
            "collector_statement": report.collector, "files": files_seen,
            "establishes": SELF_ESTABLISHES if generic else ESTABLISHES,
            "does_not_establish": tuple(kind.limits) + LIMITS}


def cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def render(report):
    """The report as Markdown, ready to attach to an evidence package."""
    deployment, server = report["deployment"], report["server"]
    account, tunnel = report["cloudflare_account"], report["tunnel"]
    lines = ["# TgWitness " + ("self-attested" if deployment["mode"] == "self-attested" else "high-assurance")
             + " deployment report", "",
             "Generated " + report["generated_at"] + " with TgWitness " + report["verifier"]["version"]
             + " (`python -m tgwitness.cloud verify`). Every provider and Cloudflare value below was "
             "requested by the verifier at that time; the deployment record supplied only the IDs to ask about.", "",
             "| | |", "| --- | --- |",
             "| **Result** | **" + report["result"].upper() + "** |",
             "| Collector key fingerprint | `" + str(report["fingerprint"]) + "` |",
             "| Deployment | " + cell(deployment["deployment_id"]) + " (" + cell(deployment["mode"]) + "), "
             + cell(deployment["created_at"]) + " |",
             "| Provider | " + cell(report["provider_title"]) + (", " + cell(deployment["location"]) if deployment["location"] else "") + " |",
             "| Software | " + cell(deployment["repository"]) + " at `" + cell(deployment["commit"]) + "` |",
             "| Server | " + cell(server.get("name")) + " #" + cell(server.get("id")) + ", " + cell(server.get("ipv4")) + " |",
             "| Provider firewall | " + cell(report["firewall"]) + " |",
             "| Cloudflare tunnel | " + cell(tunnel) + " |",
             "| Panel | https://" + cell(deployment["panel_host"]) + " |", ""]
    if deployment["mode"] == "self-attested":
        lines += ["> **Self-attested.** This server was installed by hand. Whoever ran the installer had root before it, "
                  "and no provider record is available, so every host value below comes from the host itself.", ""]
    lines += ["## Checks", "", "| Status | Check | Source | Detail |", "| --- | --- | --- | --- |"]
    lines += ["| " + c["status"].upper() + " | " + cell(c["title"]) + " | " + cell(c["source"]) + " | "
              + cell(c["detail"]) + " |" for c in report["checks"]]
    if report["provider_actions"]:
        lines += ["", "## Provider log", "",
                  "| ID | Resource | Action | Started | Status | Actor | Assessment |",
                  "| --- | --- | --- | --- | --- | --- | --- |"]
        lines += ["| " + " | ".join(cell(a[k]) for k in ("id", "resource", "command", "started", "status", "actor"))
                  + " | " + a["assessment"].upper() + ": " + cell(a["meaning"]) + " |" for a in report["provider_actions"]]
    if tunnel:
        lines += ["", "## Records kept by Cloudflare", "",
                  "- `GET " + CLOUDFLARE_API + "/accounts/" + str(account) + "/cfd_tunnel/" + tunnel + "/connections`",
                  "- `GET " + CLOUDFLARE_API + "/accounts/" + str(account) + "/cfd_tunnel/" + tunnel + "/configurations`",
                  "- `GET " + CLOUDFLARE_API + "/accounts/" + str(account) + "/audit_logs`"]
    if report["collector_statement"]:
        lines += ["", "## Signed collector statement", "", "```json",
                  json.dumps(report["collector_statement"], indent=2, ensure_ascii=False), "```"]
    lines += ["", "## What this report establishes", ""] + ["- " + t for t in report["establishes"]]
    lines += ["", "## What it does not establish", ""] + ["- " + t for t in report["does_not_establish"]]
    lines += ["", "## Reproduce", "", "```sh",
              "python -m tgwitness.cloud verify --record deployment.json --provider-token-file READ_ONLY_CREDENTIALS \\",
              "    --cloudflare-token-file READ_ONLY_TOKEN --fingerprint " + str(report["fingerprint"]) + " \\",
              "    --cloud-init PUBLISHED_INSTALLER --source CHECKOUT_OF_COMMIT --evidence tgwitness-evidence.zip",
              "python verify.py tgwitness-evidence.zip --fingerprint " + str(report["fingerprint"]), "```", "",
              "## Handover", "", "| File | SHA-256 |", "| --- | --- |"]
    lines += ["| " + cell(name) + " | `" + digest + "` |" for name, digest in report["files"].items()]
    return "\n".join(lines) + "\n"


def add_target(parser):
    parser.add_argument("--provider", required=True, choices=NAMES, help="Where the server runs")
    parser.add_argument("--name", required=True, help="Server name; also the deployment directory name")
    parser.add_argument("--server-type", help="Provider server type, e.g. cpx22, s-1vcpu-2gb, g6-standard-1, "
                        "vc2-1c-2gb, t3.small")
    parser.add_argument("--location", help="Provider location or region (default per provider)")
    parser.add_argument("--image", help="Image (default Ubuntu 24.04 of the provider)")
    parser.add_argument("--ref", required=True, help="40-character commit, or a release tag resolved once with git")
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY, help="Git repository (https)")
    parser.add_argument("--zone", required=True, help="Cloudflare zone, e.g. example.org")
    parser.add_argument("--cloudflare-account", required=True, help="Cloudflare account ID")
    parser.add_argument("--panel-host", required=True, help="Panel hostname in the zone")
    parser.add_argument("--witness-host", help="Optional hostname exposing only the witness and assurance endpoints")
    parser.add_argument("--debug-ssh-key", help="NOT high-assurance: provider SSH key for a debugging deployment")
    parser.add_argument("--debug-ssh-from", help="NOT high-assurance: the only address or network allowed to SSH")


def plan(spec):
    kind = get(spec["provider"])
    placeholder = ("TUNNEL-ID-AFTER-CREATION", "x" * 43, "x" * 32)
    if spec["provider"] == "generic":
        text = install_script(spec, *placeholder)
        calls = ["Cloudflare: tunnel, its ingress and DNS records as below",
                 "No provider API: you run install.sh on the server yourself (self-attested)"]
    else:
        text = cloud_init(spec, *placeholder)
        calls = [kind.title + ": firewall with inbound rules " + json.dumps(inbound_rules(spec)),
                 kind.title + ": server " + spec["server_type"] + ", " + spec["image"] + " in " + spec["location"]
                 + ", SSH keys " + json.dumps([spec["ssh"]["debug_key"]] if spec["ssh"] != "disabled" else []),
                 "user data " + str(len(text.encode())) + " of " + str(kind.user_data_limit) + " bytes"]
    lines = ["# Provider: " + kind.title + "; mode " + spec["mode"] + "; commit " + spec["commit"],
             "# Cloudflare: tunnel ingress " + json.dumps(ingress(spec)),
             *("# Cloudflare: CNAME " + h + " -> TUNNEL.cfargotunnel.com" for h in (spec["panel_host"], spec["witness_host"]) if h),
             *("# " + c for c in calls), "# Published installer (secrets replaced):"]
    return "\n".join(lines) + "\n" + redact_user_data(text)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m tgwitness.cloud",
                                     description="High-assurance collector on a cloud server behind a Cloudflare Tunnel")
    commands = parser.add_subparsers(dest="command", required=True)
    preview = commands.add_parser("plan", help="Print the published installer and API calls; nothing is created")
    add_target(preview)
    run = commands.add_parser("deploy", help="Create tunnel, DNS, firewall and server; wait for the collector key")
    add_target(run)
    run.add_argument("--provider-token-file", help="Provider credentials (or the provider's environment variable)")
    run.add_argument("--cloudflare-token-file",
                     help="Token with Cloudflare Tunnel Edit, Zone Read and DNS Edit (or CLOUDFLARE_API_TOKEN)")
    run.add_argument("--out", type=Path, help="Deployment directory (default deployments/NAME)")
    run.add_argument("--wait", type=int, help="Minutes to wait for the collector (default 20; 60 for generic)")
    close = commands.add_parser("lock", help="Remove every inbound rule from the deployment firewall")
    close.add_argument("--record", type=Path, required=True, help="deployment.json")
    close.add_argument("--provider-token-file", help="Provider credentials with write access")
    check = commands.add_parser("verify", help="Report what the provider, Cloudflare and the collector show")
    check.add_argument("--record", type=Path, required=True, help="deployment.json from the operator")
    check.add_argument("--provider-token-file", help="Read-only provider credentials (or the provider's variable)")
    check.add_argument("--cloudflare-token-file", help="Optional: Cloudflare Tunnel Read, DNS Read and Account "
                       "Settings Read (or CLOUDFLARE_API_TOKEN)")
    check.add_argument("--fingerprint", help="Collector key fingerprint received through an independent channel")
    check.add_argument("--cloud-init", type=Path, help="The published installer: cloud-init.redacted.yaml or install.redacted.sh")
    check.add_argument("--source", type=Path, help="A checkout of the deployed commit")
    check.add_argument("--evidence", type=Path, help="An evidence ZIP exported from this collector")
    check.add_argument("--report", type=Path, help="Write the Markdown report here and its JSON beside it")
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            sys.stdout.write(plan(specification(args)))
        elif args.command == "deploy":
            args.wait = args.wait or (60 if args.provider == "generic" else 20)
            if not 1 <= args.wait <= 240:
                parser.error("--wait must be 1-240 minutes")
            record, out = deploy(args)
            server, account = record["server"], record["cloudflare_account"]
            print("Deployment", record["deployment_id"], "is running (" + record["mode"] + ").")
            print("Collector key fingerprint:", record["collector"]["fingerprint"])
            print("Panel: https://" + record["panel_host"], "- token in", out / "panel-token.txt")
            print("Server", server["id"], server.get("ipv4") or "", "- tunnel", record["tunnel"]["id"])
            print("Cloudflare records:", CLOUDFLARE_API + "/accounts/" + account + "/cfd_tunnel/"
                  + record["tunnel"]["id"] + "/connections")
            print("Publish the fingerprint through a separate channel. Give a verifier", out / "deployment.json",
                  "and", out / record["cloud_init"]["published"], "with read-only credentials.")
        elif args.command == "lock":
            record = lock(args)
            print("Firewall", record["firewall"]["id"], "now admits no inbound connections.")
            if record["mode"] == "debug":
                print("Run sudo tgwitness-lock in the last SSH session first, or SSH keeps listening on the host.")
        else:
            report = verify(args)
            text = render(report)
            if args.report:
                args.report.write_bytes(text.encode())
                args.report.with_suffix(".json").write_bytes(json.dumps(report, indent=2, ensure_ascii=False).encode())
                for c in report["checks"]:
                    print("[" + c["status"].upper() + "] " + c["title"] + ": " + c["detail"])
                print("Result:", report["result"].upper(), "- report", args.report)
            else:
                sys.stdout.write(text)
            raise SystemExit({"pass": 0, "fail": 1}.get(report["result"], 2))
    except (DeployError, OSError, ValueError, KeyError, subprocess.SubprocessError, requests.RequestException) as exc:
        parser.exit(1, "Error: " + str(exc) + "\n")


if __name__ == "__main__":
    main()
