import argparse
import base64
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import time
import uuid
from pathlib import Path

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import __version__, attestation_report, dstack_image, tdx
from .assurance import (ADDRESS_SIGNED, BEACON, BEACON_SERVER, QUICK_HOST, redact_user_data, start_binding,
                        user_data_hashes)
from .provenance import LEGACY_SOURCE_POLICY, source_files, source_tree_sha256
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
TDX_SOURCE = "Intel TDX quote (checked to Intel's root)"
NAME = re.compile(r"[a-z0-9]([a-z0-9-]{0,48}[a-z0-9])?")
SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,99}")
HOST = re.compile(r"(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
COMMIT = re.compile(r"[0-9a-f]{40}")
TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,99}")
REPOSITORY = re.compile(r"https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~-]+)+")
ACCOUNT = re.compile(r"[0-9a-f]{32}")
KEY_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@:-]{0,127}")
TUNNEL_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{16,4096}")
DEPLOYMENT_ID = re.compile(r"[0-9a-f]{16}")
TUNNEL_ID = re.compile(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
ADDRESS_FORMAT = "tgwitness-address-v1"
INSTALLER_FIELDS = ("deployment_id", "name", "mode", "provider", "repository", "commit", "panel_host",
                    "witness_host", "ssh", "beacon", "gateway")
GATEWAY_RESOLVERS = ("172.64.36.1", "172.64.36.2")
GATEWAY_HOST = ".cloudflare-gateway.com"
DOH_SUBDOMAIN = re.compile(r"[a-z0-9]{6,32}")
LOCATION_ID = re.compile(r"[0-9a-f]{32}")
DNS_PORTS = (53, 853)
GATEWAY_WINDOW_SECONDS = 3 * 3600
GATEWAY_RULE_ACTIONS = ("override", "block", "safesearch", "ytrestricted", "resolve")

REFERENCE_BUILDER = """\
import json, sys
from pathlib import Path
source = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(source))
from tgwitness import cloud
from tgwitness.assurance import redact_user_data
if Path(cloud.__file__).resolve().parent != source / "tgwitness":
    sys.exit("the checkout's own tgwitness package was not the one imported")
spec, tunnel = json.load(sys.stdin)
if spec["provider"] == "phala":
    text = cloud.phala_compose(spec, tunnel, cloud.source_manifest(cloud.tree_files(source)))
else:
    build = cloud.install_script if spec["provider"] == "generic" else cloud.cloud_init
    text = redact_user_data(build(spec, tunnel, "x" * 43, "x" * 32))
sys.stdout.buffer.write(text.encode())
"""
REFERENCES = {}
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
GATEWAY_ESTABLISHES = (
    "With --gateway-dns the provider firewall lets DNS (ports 53 and 853) leave the server only to Cloudflare "
    "Gateway, over TLS, and Gateway answers it from the deployment's own location: Cloudflare logs every name the "
    "server looked up, and the report shows whether a Gateway policy could change those answers.",
)
GATEWAY_LIMITS = (
    "Gateway DNS covers lookups through the system resolver. A program that sends DNS over HTTPS on port 443 "
    "to another resolver, or connects to an address without looking it up (Telegram's servers, for one), is "
    "not in the Gateway log. Cloudflare keeps that log 24 hours on the free plan; the collector's journal "
    "keeps a copy only when evidence mode copies it.",
)
PHALA_ESTABLISHES = (
    "Intel signs, through a chain to its SGX Root CA that this verifier checks itself against Intel's revocation "
    "lists and TCB Info, that the collector's signed statement (its key, this request's challenge, the commit and "
    "its source tree) was produced inside an Intel TDX confidential VM that does not run in debug mode and cannot "
    "be migrated, on a platform at the TCB level shown.",
    "That VM's RTMR3, replayed from dstack's event log, measures the compose the collector reports. The compose "
    "pins the deployed commit's source files by hash and both container images by digest, and installs nothing "
    "else; its bytes equal the compose the commit's own code builds.",
    "When tdx_os passes, MRTD and RTMR0-2 equal the values this verifier computes from the dstack OS image "
    "Dstack-TEE publishes under the hash the CVM reports and from the ACPI tables QEMU builds for the VM's shape: "
    "the firmware, kernel, initrd and command line, with its root file system hash, are that production image's, "
    "which has no SSH.",
    "Every collector start in the journal carries such a quote over its run, its key and its host measurement.",
    "Cloudflare reports the tunnel and its ingress; the panel is reachable only through it.",
)
PHALA_QUICK = ("With a quick tunnel no Cloudflare account keeps records of the tunnel; the panel's address is "
               "whatever the CVM last posted, and the quote, not the address, identifies the collector.")


def phala_establishes(record):
    return PHALA_ESTABLISHES[:-1] if record.get("beacon") else PHALA_ESTABLISHES
COMMON_LIMITS = (
    "Provider and Cloudflare logs are kept for limited periods; produce this report early and keep it "
    "with the evidence.",
    "Panel actions through the tunnel are not SSH sessions; they are recorded in the signed journal.",
    "Message authenticity still rests on Telegram and on what the account could see; see EVIDENCE.md.",
)
LIMITS = (
    "The initial installer is a trust boundary. A malicious bootstrap could copy the signing key and falsify "
    "the collector's measurements without a later SSH login. Matching installer/source hashes reported by "
    "that collector are not independent runtime attestation or proof that the key was never copied.",
    "The collector's host measurements (SSH listeners, logins, boot) are self-reported: root on the server "
    "could falsify them. They support, not replace, the provider and Cloudflare records.",
    "The provider and its staff control the hypervisor, disks and network; nothing here excludes them.",
    *COMMON_LIMITS,
    "Without hardware attestation (AMD SEV-SNP or Intel TDX) a substitution during the first boot is not "
    "detected: root on the server, or whoever controls its image or hypervisor, could hand the collector forged "
    "metadata answers, user data and hashes before it signs them. The byte comparison with the reference "
    "installer shows what the collector was given, not what the provider delivered.",
)
PHALA_IMAGES = {"python": "python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159",
                "cloudflared": "cloudflare/cloudflared:2026.10.7"
                               "@sha256:4955524aeaa379e154023d5a027c250f7b35041a2e7e950cf13f144bc9b9c5ba"}
SOURCE_NEEDED = ("pyproject.toml", "README.md", "LICENSE", "NOTICE", "deploy/build.lock", "deploy/requirements.lock")
SOURCE_PACKAGES = ("tgwitness", "tgwitness_capture")
GITHUB = re.compile(r"https://github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100}?)(\.git)?")
PHALA_ENV = ("TGWITNESS_TOKEN", "TGWITNESS_TUNNEL_TOKEN")
PHALA_SETTINGS = {"kms_enabled": True, "gateway_enabled": False, "public_logs": False, "public_sysinfo": False,
                  "public_tcbinfo": True, "no_instance_id": False, "secure_time": True}
EXECUTABLE_SETTINGS = ("pre_launch_script", "bash_script", "init_script", "init_scripts")
TDX_OK = ("UpToDate",)


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

    def graphql(self, query, variables):
        response = self.send("POST", self.base + "/graphql", "/graphql", json={"query": query, "variables": variables},
                             headers=self.headers)
        try:
            data = response.json()
        except ValueError:
            data = None
        if response.status_code >= 400 or not isinstance(data, dict) or data.get("errors") or not data.get("data"):
            errors = (data or {}).get("errors") if isinstance(data, dict) else None
            raise DeployError("Cloudflare POST /graphql: HTTP " + str(response.status_code) + " "
                              + "; ".join(str(e.get("message")) for e in errors or [] if isinstance(e, dict)))
        return data["data"]


def read_secret(path, variable, option, required=True):
    value = Path(path).read_text(encoding="utf-8-sig").strip() if path else os.environ.get(variable, "").strip()
    if not value and required:
        raise DeployError("Provide " + option + " or set " + variable)
    return value or None


def resolve_commit(repository, ref, run=subprocess.run):
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
    if args.provider == "phala" and not GITHUB.fullmatch(args.repository):
        raise DeployError("--repository must be a GitHub repository for phala: the CVM downloads the commit's "
                          "archive from GitHub and checks every file against the hashes in its measured compose")
    if args.provider == "phala" and (args.debug_ssh_key or args.debug_ssh_from):
        raise DeployError("--debug-ssh-* do not apply to phala: a production dstack image has no SSH")
    quick = bool(getattr(args, "quick_tunnel", False))
    gateway = bool(getattr(args, "gateway_dns", False))
    if gateway:
        if args.provider != "hetzner":
            raise DeployError("--gateway-dns needs outbound firewall rules, implemented for Hetzner only so far")
        if not (args.cloudflare_account and ACCOUNT.fullmatch(args.cloudflare_account)):
            raise DeployError("--gateway-dns needs --cloudflare-account, the 32-character account ID")
    reused = getattr(args, "gateway_location", None)
    if reused and (not gateway or not LOCATION_ID.fullmatch(reused)):
        raise DeployError("--gateway-location takes the 32-character ID of a Gateway DNS location, with --gateway-dns")
    if quick:
        if args.zone or (args.cloudflare_account and not gateway) or args.panel_host or args.witness_host:
            raise DeployError("--quick-tunnel takes no --zone, --panel-host or --witness-host, and "
                              "--cloudflare-account only with --gateway-dns")
        zone, hosts = None, []
    else:
        if not (args.zone and args.cloudflare_account and args.panel_host):
            raise DeployError("Give --zone, --cloudflare-account and --panel-host, or --quick-tunnel without a domain")
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
            "panel_host": hosts[0] if hosts else None, "witness_host": hosts[1] if len(hosts) > 1 else None,
            "ssh": ssh, "beacon": BEACON_SERVER + "tgw-" + secrets.token_hex(16) if quick else None,
            # Filled in by deploy once Cloudflare has created the location.
            "gateway": {"account": args.cloudflare_account, "location_id": reused, "doh_subdomain": None}
            if gateway else None}


def ingress(spec):
    rules = [{"hostname": spec["panel_host"], "service": PANEL_SERVICE}]
    if spec.get("witness_host"):
        rules.append({"hostname": spec["witness_host"], "path": WITNESS_PATHS, "service": PANEL_SERVICE})
    return rules + [{"service": "http_status:404"}]


def inbound_rules(spec):
    if spec["ssh"] == "disabled":
        return []
    return [{"protocol": "tcp", "port": "22", "source": spec["ssh"]["allowed_from"]}]


def outbound_rules(spec):
    if not spec.get("gateway"):
        return []
    anywhere = ["0.0.0.0/0", "::/0"]
    rules = [{"protocol": protocol, "port": port, "destination": anywhere}
             for protocol in ("tcp", "udp") for port in ("1-52", "54-852", "854-65535")]
    return rules + [{"protocol": "tcp", "port": "853", "destination": [ip + "/32" for ip in GATEWAY_RESOLVERS]},
                    {"protocol": "icmp", "port": None, "destination": anywhere}]


def dns_leaks(outbound):
    if not outbound:
        return ["no outbound rules: every destination is reachable, DNS included"]
    gateway = [ipaddress.ip_network(ip) for ip in GATEWAY_RESOLVERS]
    leaks = []
    for rule in outbound:
        if rule["protocol"] not in ("tcp", "udp"):
            continue
        low, _, high = (rule.get("port") or "1-65535").partition("-")
        for port in DNS_PORTS:
            if int(low) <= port <= int(high or low):
                foreign = []
                for destination in rule["destination"]:
                    try:
                        network = ipaddress.ip_network(destination, strict=False)
                    except ValueError:
                        foreign.append(destination)
                        continue
                    if not any(network.version == g.version and network.subnet_of(g) for g in gateway):
                        foreign.append(destination)
                if foreign:
                    leaks.append(rule["protocol"] + " " + str(port) + " to " + ", ".join(foreign))
    return leaks


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
ProtectKernelLogs=true
ProtectClock=true
ProtectHostname=true
PrivateDevices=true
CapabilityBoundingSet=
AmbientCapabilities=
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
# The tunnel credentials stay with cloudflared, out of the collector's reach. /proc stays visible:
# the host measurement counts SSH processes there.
InaccessiblePaths=-/etc/cloudflared -/etc/systemd/system/cloudflared.service
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
# Every package must match a SHA-256 in the commit's locks; builds use the hashed setuptools only.
PIP="/opt/tgwitness/.venv/bin/pip install --no-cache-dir"
$PIP --require-hashes -r /opt/tgwitness/source/deploy/build.lock
$PIP --require-hashes --no-build-isolation -r /opt/tgwitness/source/deploy/requirements.lock
$PIP --no-deps --no-build-isolation /opt/tgwitness/source
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

QUICK_START = """\
set -a
. /etc/tgwitness/secrets.env
set +a
(umask 077 && printf 'TGWITNESS_TOKEN=%s\\n' "$TGWITNESS_TOKEN" > /etc/tgwitness/panel.env)
(umask 077 && printf 'TGWITNESS_TUNNEL_TOKEN=%s\\n' "$TGWITNESS_TUNNEL_TOKEN" > /etc/tgwitness/address.env)
systemctl daemon-reload
systemctl enable --now tgwitness.service tgwitness-tunnel.service tgwitness-address.service
rm -f /etc/tgwitness/secrets.env
"""

TUNNEL_UNIT = """\
[Unit]
Description=TgWitness quick tunnel: a random trycloudflare.com address for the panel
Wants=network-online.target
After=network-online.target tgwitness.service

[Service]
Type=simple
DynamicUser=yes
ExecStart=cloudflared tunnel --no-autoupdate --metrics 127.0.0.1:20241 --url http://127.0.0.1:8787
Restart=always
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
"""

ADDRESS_UNIT = """\
[Unit]
Description=TgWitness quick tunnel address, signed and posted to the deployment's ntfy.sh topic
After=tgwitness-tunnel.service

[Service]
Type=simple
DynamicUser=yes
Environment=TGWITNESS_BEACON=@BEACON@
EnvironmentFile=/etc/tgwitness/address.env
ExecStart=/usr/bin/python3 /usr/local/sbin/tgwitness-address
Restart=always
RestartSec=30
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
"""

ADDRESS_SCRIPT = """\
# Posts the quick tunnel's address when it changes, and every three hours (ntfy.sh keeps 12).
import hashlib, hmac, json, os, time, urllib.request
KEY, TOPIC = os.environ["TGWITNESS_TUNNEL_TOKEN"].encode(), os.environ["TGWITNESS_BEACON"]
last, sent = None, 0
while True:
    try:
        with urllib.request.urlopen("http://127.0.0.1:20241/quicktunnel", timeout=5) as answer:
            host = json.load(answer).get("hostname")
        now = int(time.time())
        if host and (host != last or now - sent >= 10800):
            text = "@FORMAT@ " + host + " " + str(now)
            body = text + " " + hmac.new(KEY, text.encode(), hashlib.sha256).hexdigest()
            urllib.request.urlopen(urllib.request.Request(TOPIC, body.encode(), method="POST"), timeout=20).close()
            last, sent = host, now
    except (OSError, ValueError):
        pass
    time.sleep(30)
"""

RESOLVED = """\
[Resolve]
DNS=@SERVERS@
DNSOverTLS=yes
Domains=~.
FallbackDNS=
"""

GATEWAY_START = """\
systemctl restart systemd-resolved
for attempt in $(seq 60); do getent hosts pkg.cloudflare.com >/dev/null && break; sleep 5; done
echo "DNS through Cloudflare Gateway @HOST@ $(date -u +%FT%TZ)"
"""


def gateway_host(spec):
    return (spec["gateway"]["doh_subdomain"] or "LOCATION-AFTER-CREATION") + GATEWAY_HOST


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
    if not TUNNEL_TOKEN.fullmatch(tunnel_token) or not re.fullmatch(r"[A-Za-z0-9_-]{24,256}", panel_token):
        raise DeployError("Unexpected token format; refusing to write it into the installer")
    description = deployment_description(spec, tunnel_id)
    extra = []
    if spec.get("beacon"):
        if not BEACON.fullmatch(spec["beacon"]):
            raise DeployError("Unexpected address topic; refusing to write it into the installer")
        description["beacon"] = spec["beacon"]
        extra = [("/etc/systemd/system/tgwitness-tunnel.service", "0644", TUNNEL_UNIT),
                 ("/etc/systemd/system/tgwitness-address.service", "0644", ADDRESS_UNIT.replace("@BEACON@", spec["beacon"])),
                 ("/usr/local/sbin/tgwitness-address", "0755", ADDRESS_SCRIPT.replace("@FORMAT@", ADDRESS_FORMAT))]
    if spec.get("gateway"):
        description["gateway"] = spec["gateway"]
        servers = " ".join(ip + "#" + gateway_host(spec) for ip in GATEWAY_RESOLVERS)
        extra.append(("/etc/systemd/resolved.conf.d/tgwitness-gateway.conf", "0644",
                      RESOLVED.replace("@SERVERS@", servers)))
    return [("/etc/tgwitness/assurance.json", "0644", json.dumps(description, sort_keys=True) + "\n"),
            ("/etc/tgwitness/secrets.env", "0600",
             "TGWITNESS_TOKEN=" + panel_token + "\nTGWITNESS_TUNNEL_TOKEN=" + tunnel_token + "\n"),
            ("/etc/systemd/system/tgwitness.service", "0644", UNIT.replace("@PROVIDER@", spec["provider"]))] + extra


def start_script(spec):
    return QUICK_START if spec.get("beacon") else START


def block(text, spaces=6):
    return "".join(" " * spaces + line if line.strip() else line for line in text.splitlines(True))


def cloud_init(spec, tunnel_id, panel_token, tunnel_token):
    locked = spec["ssh"] == "disabled"
    bootstrap = ("#!/bin/bash\n# TgWitness high-assurance bootstrap: runs once from cloud-init and needs no "
                 "interactive access.\nset -euo pipefail\nexec >>/var/log/tgwitness-bootstrap.log 2>&1\n"
                 + (SSH_OFF if locked else "")
                 + (GATEWAY_START.replace("@HOST@", gateway_host(spec)) if spec.get("gateway") else "")
                 + fill(INSTALL, spec) + start_script(spec)
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
              start_script(spec).rstrip("\n"),
              "if command -v ufw >/dev/null; then ufw default deny incoming; ufw default allow outgoing; "
              "ufw --force enable; fi",
              'rm -f "$SCRIPT"', 'echo "TgWitness installed. SSH closes now and this session ends."',
              SSH_OFF.rstrip("\n"), END_SESSIONS.rstrip("\n")]
    return "\n".join(lines) + "\n"


PHALA_INSTALLER = """\
import hashlib, io, json, os, subprocess, sys, tarfile, urllib.request
from pathlib import Path
ARCHIVE = "@ARCHIVE@"
MANIFEST = "@MANIFEST@"
NEEDED = @NEEDED@
PACKAGES = @PACKAGES@
DESCRIPTION = json.loads(@DESCRIPTION@)
SOURCE, VENV = Path("/opt/tgwitness/source"), Path("/opt/tgwitness/.venv")


def wanted(path):
    return path in NEEDED or (path.startswith(tuple(name + "/" for name in PACKAGES)) and "__pycache__" not in path.split("/")
                              and not path.endswith(".pyc"))


def install():
    # Only files whose hashes give MANIFEST are installed; anything else in the archive is ignored.
    with urllib.request.urlopen(ARCHIVE, timeout=300) as response:
        data = response.read(128 * 1024 * 1024)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive.getmembers():
            path = member.name.partition("/")[2]
            if member.isfile() and wanted(path):
                files[path] = archive.extractfile(member).read()
    digests = {path: hashlib.sha256(body).hexdigest() for path, body in files.items()}
    found = hashlib.sha256(json.dumps(digests, ensure_ascii=False, sort_keys=True,
                                      separators=(",", ":")).encode()).hexdigest()
    if found != MANIFEST:
        sys.exit("TgWitness: the downloaded source is not the deployed commit's (" + found + ")")
    for path, body in files.items():
        (SOURCE / path).parent.mkdir(parents=True, exist_ok=True)
        (SOURCE / path).write_bytes(body)
    pip = [str(VENV / "bin" / "pip"), "install", "--no-cache-dir"]
    subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True)
    subprocess.run(pip + ["--require-hashes", "-r", str(SOURCE / "deploy/build.lock")], check=True)
    subprocess.run(pip + ["--require-hashes", "--no-build-isolation", "-r",
                          str(SOURCE / "deploy/requirements.lock")], check=True)
    subprocess.run(pip + ["--no-deps", "--no-build-isolation", str(SOURCE)], check=True)
    (VENV / "tgwitness-source").write_text(MANIFEST)


marker = VENV / "tgwitness-source"
if not marker.exists() or marker.read_text() != MANIFEST:
    install()
Path("/etc/tgwitness").mkdir(parents=True, exist_ok=True)
Path("/etc/tgwitness/assurance.json").write_text(json.dumps(DESCRIPTION, sort_keys=True) + "\\n")
python = str(VENV / "bin" / "python")
os.execv(python, [python, "-m", "tgwitness", "--host", "127.0.0.1", "--port", "8787"])
"""

PHALA_COMPOSE = """\
# TgWitness high-assurance deployment @DEPLOYMENT@ on Phala Cloud (Intel TDX), commit @COMMIT@.
# The collector installs only the commit's files whose hashes give source manifest @MANIFEST@;
# both images are pinned by digest. Secrets arrive encrypted to this application and are not measured.
services:
  collector:
    image: @PYTHON@
    restart: unless-stopped
    environment:
      TGWITNESS_TOKEN: ${TGWITNESS_TOKEN}
      TGWITNESS_DATA: /data
      TGWITNESS_ASSURANCE: phala
      TGWITNESS_NO_BROWSER: "1"
      PYTHONDONTWRITEBYTECODE: "1"
      PIP_DISABLE_PIP_VERSION_CHECK: "1"
    volumes:
      - tgwitness-data:/data
      - /var/run/dstack.sock:/var/run/dstack.sock
    command:
      - python
      - -c
      - |
@INSTALLER@
@TUNNEL@
volumes:
  tgwitness-data:
"""

PHALA_TUNNEL = """\
  tunnel:
    image: @CLOUDFLARED@
    restart: unless-stopped
    network_mode: service:collector
    environment:
      TUNNEL_TOKEN: ${TGWITNESS_TUNNEL_TOKEN}
    command: [tunnel, --no-autoupdate, run]
"""

PHALA_QUICK_TUNNEL = """\
  tunnel:
    image: @CLOUDFLARED@
    restart: unless-stopped
    network_mode: service:collector
    command: [tunnel, --no-autoupdate, --metrics, 127.0.0.1:20241, --url, http://127.0.0.1:8787]
  address:
    image: @PYTHON@
    restart: unless-stopped
    network_mode: service:collector
    environment:
      TGWITNESS_TUNNEL_TOKEN: ${TGWITNESS_TUNNEL_TOKEN}
      TGWITNESS_BEACON: "@BEACON@"
    command:
      - python
      - -c
      - |
@ADDRESS@
"""


def wanted_source(path):
    return path in SOURCE_NEEDED or (path.startswith(tuple(name + "/" for name in SOURCE_PACKAGES)) and "__pycache__" not in path.split("/")
                                     and not path.endswith(".pyc"))


def source_manifest(files):
    digests = {path: hashlib.sha256(body).hexdigest() for path, body in files.items() if wanted_source(path)}
    missing = [path for path in SOURCE_NEEDED if path not in digests]
    if missing or not any(path.startswith("tgwitness/") for path in digests):
        raise DeployError("the source is missing " + (", ".join(missing) or "the tgwitness package"))
    return hashlib.sha256(canonical(digests)).hexdigest()


def tarball_files(data):
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive.getmembers():
            path = member.name.partition("/")[2]
            if member.isfile() and wanted_source(path):
                files[path] = archive.extractfile(member).read()
    return files


def tree_files(folder):
    folder = Path(folder)
    found = {path: (folder / path).read_bytes() for path in SOURCE_NEEDED if (folder / path).is_file()}
    for package in SOURCE_PACKAGES:
        for item in sorted((folder / package).rglob("*")):
            path = item.relative_to(folder).as_posix()
            if item.is_file() and wanted_source(path):
                found[path] = item.read_bytes()
    return found


def archive_url(spec):
    owner, name = GITHUB.fullmatch(spec["repository"]).group(1, 2)
    return "https://codeload.github.com/" + owner + "/" + name + "/tar.gz/" + spec["commit"]


def fetch_archive(spec, session=None):
    response = (session or requests).get(archive_url(spec), timeout=300)
    if response.status_code != 200:
        raise DeployError(archive_url(spec) + " answered HTTP " + str(response.status_code))
    return response.content


def deployment_description(spec, tunnel_id):
    description = {"format": "tgwitness-deployment-v1", "tunnel_id": tunnel_id,
                   **{k: spec[k] for k in ("deployment_id", "name", "mode", "provider", "repository", "commit",
                                           "panel_host", "witness_host", "ssh")}}
    if spec.get("beacon"):
        if not BEACON.fullmatch(spec["beacon"]):
            raise DeployError("Unexpected address topic; refusing to write it into the installer")
        description["beacon"] = spec["beacon"]
    return description


def phala_compose(spec, tunnel_id, manifest):
    if not re.fullmatch(r"[0-9a-f]{64}", manifest):
        raise DeployError("Unexpected source manifest")
    installer = PHALA_INSTALLER.replace("@ARCHIVE@", archive_url(spec)).replace("@MANIFEST@", manifest) \
        .replace("@NEEDED@", repr(SOURCE_NEEDED)) \
        .replace("@PACKAGES@", repr(SOURCE_PACKAGES)) \
        .replace("@DESCRIPTION@", json.dumps(json.dumps(deployment_description(spec, tunnel_id), sort_keys=True)))
    address = ADDRESS_SCRIPT.replace("@FORMAT@", ADDRESS_FORMAT)
    if "$" in installer or "$" in address:
        raise DeployError("The installer may not contain '$': docker compose would substitute it")
    tunnel = PHALA_QUICK_TUNNEL.replace("@BEACON@", spec["beacon"]) if spec.get("beacon") else PHALA_TUNNEL
    return PHALA_COMPOSE.replace("@TUNNEL@", tunnel.rstrip("\n")).replace("@ADDRESS@", block(address, 8).rstrip("\n")) \
        .replace("@DEPLOYMENT@", spec["deployment_id"]).replace("@COMMIT@", spec["commit"]) \
        .replace("@MANIFEST@", manifest).replace("@PYTHON@", PHALA_IMAGES["python"]) \
        .replace("@CLOUDFLARED@", PHALA_IMAGES["cloudflared"]).replace("@INSTALLER@", block(installer, 8).rstrip("\n"))


def app_compose(compose):
    # Without an empty pre_launch_script Phala Cloud measures its own pre-launch script into the app-compose.
    return {"docker_compose_file": compose, "allowed_envs": list(PHALA_ENV), "pre_launch_script": "", **PHALA_SETTINGS}


def compose_check(text, reference=None, published=None):
    try:
        found = json.loads(text)
    except (TypeError, ValueError):
        return "fail", "the measured app-compose is not JSON"
    if not isinstance(found, dict):
        return "fail", "the measured app-compose is not an object"
    problems, notes = [], []
    compose = found.get("docker_compose_file")
    expected = reference if reference is not None else published
    if not isinstance(compose, str):
        problems.append("it holds no docker-compose file")
    elif expected is not None and compose != expected:
        problems.append("its compose differs from " + ("the one the commit builds" if reference is not None
                        else "the published compose") + ", " + first_difference(expected, compose))
    if found.get("runner", "docker-compose") != "docker-compose":
        problems.append("runner " + str(found.get("runner")))
    for name in EXECUTABLE_SETTINGS:
        if found.get(name):
            problems.append(name + " runs code the compose does not show")
    if sorted(found.get("allowed_envs") or []) != sorted(PHALA_ENV):
        problems.append("environment variables allowed: " + json.dumps(found.get("allowed_envs")))
    for name, value in PHALA_SETTINGS.items():
        if name in found and found[name] != value:
            (problems if name in ("kms_enabled", "gateway_enabled", "no_instance_id") else notes).append(
                name + " is " + json.dumps(found[name]))
    if found.get("key_provider") not in (None, "kms") or found.get("local_key_provider_enabled"):
        problems.append("its keys do not come from the KMS")
    known = {"docker_compose_file", "allowed_envs", "runner", "manifest_version", "name", "features",
             "tproxy_enabled", "key_provider", "key_provider_id", "local_key_provider_enabled", "docker_config",
             "storage_fs", "swap_size", *PHALA_SETTINGS, *EXECUTABLE_SETTINGS}
    if found.get("tproxy_enabled"):
        problems.append("the gateway proxy is enabled")
    notes += ["setting " + name + " = " + json.dumps(found[name])[:80] for name in sorted(set(found) - known)]
    if problems:
        return "fail", "; ".join(problems)
    if expected is None:
        return "unavailable", "pass --source with a checkout of the commit: its code builds the reference compose"
    if notes:
        return "review", "the compose is the reference; " + "; ".join(notes)
    return "pass", "byte for byte the compose the " + ("commit's code builds" if reference is not None
                                                     else "deployment published") + "; no other code, KMS keys, no gateway"


def collector_statement(host, challenge=None, session=None):
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
    provider, problems = (statement.get("host") or {}).get("provider") or {}, []
    if provider.get("error"):
        problems.append("the collector could not read the metadata service: " + provider["error"])
    if str(provider.get("instance_id")) != str(server_id):
        problems.append("instance ID " + str(provider.get("instance_id")) + " is not server " + str(server_id))
    if ipv4 and provider.get("public_ipv4") not in (None, ipv4):
        problems.append("public IPv4 " + str(provider.get("public_ipv4")) + " is not " + ipv4)
    for key in ("user_data_sha256", "user_data_redacted_sha256"):
        if provider.get(key) != cloud.get(key):
            problems.append(key + " differs from the deployment record")
    received = provider.get("user_data_redacted")
    if received is not None and (not isinstance(received, str) or hashlib.sha256(received.encode()).hexdigest()
                                 != provider.get("user_data_redacted_sha256")):
        problems.append("the user data in the statement does not match its own SHA-256")
    return problems


def installer_spec(record):
    spec, tunnel = {k: record.get(k) for k in INSTALLER_FIELDS}, (record.get("tunnel") or {}).get("id")
    patterns = [(spec["deployment_id"], DEPLOYMENT_ID), (spec["name"], NAME), (spec["repository"], REPOSITORY),
                (spec["commit"], COMMIT)]
    if spec["beacon"] is None:
        patterns += [(spec["panel_host"], HOST), (tunnel, TUNNEL_ID)]
    else:
        patterns.append((spec["beacon"], BEACON))
    if spec["witness_host"] is not None:
        patterns.append((spec["witness_host"], HOST))
    valid = spec["provider"] in NAMES and all(isinstance(v, str) and p.fullmatch(v) for v, p in patterns)
    gateway = spec["gateway"]
    if gateway is not None:
        valid = (valid and spec["provider"] == "hetzner" and isinstance(gateway, dict)
                 and set(gateway) == {"account", "location_id", "doh_subdomain"}
                 and all(isinstance(gateway[k], str) for k in gateway) and bool(ACCOUNT.fullmatch(gateway["account"]))
                 and bool(LOCATION_ID.fullmatch(gateway["location_id"]))
                 and bool(DOH_SUBDOMAIN.fullmatch(gateway["doh_subdomain"])))
    if spec["beacon"] is not None:
        valid = valid and spec["panel_host"] is None and spec["witness_host"] is None and tunnel is None
    if spec["provider"] == "phala":
        valid = valid and bool(GITHUB.fullmatch(spec["repository"])) and spec["ssh"] == "disabled"
    generic, ssh = spec["provider"] == "generic", spec["ssh"]
    if ssh == "disabled":
        valid = valid and spec["mode"] == ("self-attested" if generic else "high-assurance")
    else:
        try:
            valid = (valid and not generic and spec["mode"] == "debug" and isinstance(ssh, dict)
                     and set(ssh) == {"debug_key", "allowed_from"} and isinstance(ssh["debug_key"], str)
                     and bool(KEY_NAME.fullmatch(ssh["debug_key"])) and isinstance(ssh["allowed_from"], str)
                     and str(ipaddress.ip_network(ssh["allowed_from"], strict=False)) == ssh["allowed_from"])
        except ValueError:
            valid = False
    if not valid:
        raise DeployError("the deployment record holds values deploy never writes; no reference installer is built from it")
    return spec, tunnel


def reference_installer(record, source, run=subprocess.run):
    spec, tunnel = installer_spec(record)
    folder = str(Path(source).resolve())
    key = (folder, json.dumps([spec, tunnel], sort_keys=True))
    if key not in REFERENCES:
        try:
            done = run([sys.executable, "-c", REFERENCE_BUILDER, folder], input=json.dumps([spec, tunnel]).encode(),
                       capture_output=True, timeout=120, cwd=folder)
        except (OSError, subprocess.SubprocessError) as exc:
            raise DeployError("the checkout could not build the reference installer: " + str(exc)) from None
        if done.returncode:
            raise DeployError("the checkout could not build the reference installer: "
                              + done.stderr.decode(errors="replace").strip()[-300:])
        REFERENCES[key] = done.stdout.decode()
    return REFERENCES[key]


def first_difference(expected, found):
    a, b = expected.splitlines(keepends=True), found.splitlines(keepends=True)
    for number, (x, y) in enumerate(zip(a, b), 1):
        if x != y:
            return "line " + str(number) + ": expected " + json.dumps(x[:120]) + ", found " + json.dumps(y[:120])
    number = min(len(a), len(b)) + 1
    if len(a) > len(b):
        return "line " + str(number) + ": expected " + json.dumps(a[number - 1][:120]) + ", found the end"
    return "line " + str(number) + ": unexpected " + json.dumps(b[number - 1][:120])


def installer_check(seen, commit, reference=None, published=None):
    received = seen.get("user_data_redacted") if isinstance(seen.get("user_data_redacted"), str) else None
    reported = seen.get("user_data_redacted_sha256")
    problems, compared = [], []
    if reference is not None:
        compared.append("the installer commit " + commit + " builds")
    if received is not None:
        compared.append("the user data the server read from its metadata service")
        if hashlib.sha256(received.encode()).hexdigest() != reported:
            problems.append("the user data in the statement does not match its own SHA-256")
        if reference is not None and received != reference:
            problems.append("the server received different user data, " + first_difference(reference, received))
    elif reference is not None:
        compared.append("the SHA-256 of the user data the server reported (not the user data itself)")
        if hashlib.sha256(reference.encode()).hexdigest() != reported:
            problems.append("the SHA-256 of the server's user data differs from the reference installer")
    expected = reference if reference is not None else received
    if published is not None:
        compared.append("the published installer")
        if expected is not None and published != expected.encode():
            problems.append("the published installer differs from " + ("the reference" if reference is not None
                            else "the server's user data") + ", "
                            + first_difference(expected, published.decode(errors="replace")))
        if expected is None:
            compared.append("the SHA-256 the server reported")
            if hashlib.sha256(published).hexdigest() != reported:
                problems.append("the published installer's SHA-256 differs from the one the server reports")
    if problems:
        return "fail", "; ".join(problems)
    if reference is None:
        return "unavailable", ("pass --source with a checkout of " + commit + ": the reference installer is built "
                               "by that commit's code" + ("; " + " and ".join(compared) + " agree"
                                                          if len(compared) > 1 else ""))
    return "pass", "byte for byte equal: " + ", ".join(compared)


def hex_id(value):
    return str(value or "").lower().removeprefix("0x")


def intel_collateral(path=None, session=None):
    if path:
        fixed = json.loads(Path(path).read_text(encoding="utf-8"))
        return lambda raw: fixed
    memo = {}

    def collateral(raw):
        fmspc = tdx.pck_extension(tdx.pem_chain(tdx.parse_quote(raw)["pck_chain"])[0])["fmspc"]
        if fmspc not in memo:
            memo[fmspc] = tdx.fetch_collateral(raw, session or requests.Session())
        return memo[fmspc]
    return collateral


def intel_check(raw, collateral, now=None):
    try:
        found = tdx.verify_quote(raw, collateral(raw), now)
    except tdx.QuoteError as exc:
        return "fail", str(exc), None
    except (requests.RequestException, OSError, ValueError, KeyError) as exc:
        return "unavailable", "Intel's collateral could not be read (" + type(exc).__name__ + "); pass " \
               "--tdx-collateral with collateral fetched from Intel's PCS", None
    advisories = (" with " + ", ".join(found["advisory_ids"][:12])) if found["advisory_ids"] else ""
    return ("pass" if found["status"] in TDX_OK else "review"), (
        "Intel TCB status " + found["status"] + advisories + "; quote v" + str(found["quote_version"]) + ", FMSPC "
        + found["fmspc"] + ", TCB level of " + found["tcb_date"] + ", Intel collateral issued "
        + found["collateral_issued"] + "; not in debug mode, not migratable"), found


def image_loader(option, folder, session=None):
    """The published dstack OS images, kept in folder/dstack-images ("auto"), in a given folder, or none."""
    if option in (None, "none"):
        return None
    cache = Path(folder) / "dstack-images" if option == "auto" else Path(option)

    def load(name, digest):
        if (cache / "metadata.json").is_file():
            image = dstack_image.load(cache)
            if image["digest"] != digest:
                raise dstack_image.ImageMismatch(str(cache) + " has OS image hash " + image["digest"] + ", not the "
                                                 "CVM's " + str(digest))
            return image
        return dstack_image.fetch(name, digest, cache, session)
    return load


def os_image_check(report, event_log, vm, identity, image):
    digest = hex_id(identity["os_image_hash"] or vm.get("os_image_hash"))
    try:
        found = image(vm.get("image"), digest)
    except dstack_image.ImageMismatch as exc:
        return "fail", str(exc), {}
    except (dstack_image.ImageError, OSError, tarfile.TarError) as exc:
        return "unavailable", "the published OS image could not be compared: " + str(exc), {}
    return dstack_image.check(report, event_log, vm, found)


def attestation_checks(answer, record, reference=None, published=None, collateral=None, expected=None, now=None,
                       image=None, details=None):
    statement = answer["statement"]
    seen = (statement.get("host") or {}).get("provider") or {}
    evidence = answer.get("tdx") or {}
    title = "The collector answers with an Intel TDX quote whose RTMR3 replays from its event log"
    if evidence.get("error") or not evidence.get("quote"):
        return [("tdx_quote", "fail", title, evidence.get("error") or "the answer carries no quote")]
    try:
        raw, log = tdx.evidence(evidence)
        quote, identity = tdx.measured(raw, log)
    except (tdx.QuoteError, ValueError, KeyError, TypeError) as exc:
        return [("tdx_quote", "fail", title, type(exc).__name__ + ": " + str(exc))]
    checks = []
    bound = quote["report"]["report_data"] == tdx.report_data(statement)
    checks.append(("tdx_binding", "pass" if bound else "fail", "The quote covers this signed statement and its challenge",
                   "report data is SHA-512 of the statement" if bound else
                   "the quote's report data is not SHA-512 of this statement: it vouches for something else"))
    status, detail, intel = intel_check(raw, collateral or intel_collateral(), now)
    checks.append(("tdx_quote", status, "Intel vouches for the quote: a genuine TDX platform at a current TCB level",
                   detail))
    text = seen.get("app_compose")
    same = isinstance(text, str) and hashlib.sha256(text.encode()).hexdigest() == identity["compose_hash"]
    after = identity["after_ready"]
    checks.append(("tdx_compose_hash", "fail" if not same else "review" if after else "pass",
                   "RTMR3 measures the app-compose the collector reports",
                   ("compose hash " + identity["compose_hash"] if same else "the reported app-compose is not the one "
                    "RTMR3 measured (" + identity["compose_hash"] + ")")
                   + ("; extended after boot: " + ", ".join(after[:10]) if after else "")))
    status, detail = compose_check(text, reference, published) if same else \
        ("fail", "not compared: the reported app-compose is not the measured one")
    checks.append(("tdx_compose", status, "The measured compose is the deployed commit's and runs nothing else", detail))
    server, problems, notes = record.get("server") or {}, [], []
    if hex_id(identity["app_id"]) != hex_id(server.get("app_id")):
        problems.append("app ID " + identity["app_id"] + " is not the deployed " + str(server.get("app_id")))
    if identity["instance_id"] is None:
        problems.append("no instance-id event")
    elif hex_id(identity["instance_id"]) != hex_id(seen.get("instance_id")) or (
            server.get("instance_id") and hex_id(identity["instance_id"]) != hex_id(server["instance_id"])):
        problems.append("instance " + identity["instance_id"] + " is not the deployed or reported instance")
    provider = identity["key_provider"]
    name = provider.get("name") if isinstance(provider, dict) else provider
    if name != "kms":
        (notes if str(name).startswith("local") else problems).append("key provider " + json.dumps(provider)[:120])
    if identity["storage_encrypted"] == "0":
        problems.append("the data disk is not encrypted")
    checks.append(("tdx_identity", "fail" if problems else "review" if notes else "pass",
                   "The quote comes from the deployed CVM, with KMS keys and an encrypted disk",
                   "; ".join(problems + notes) or "app " + identity["app_id"] + ", instance " + identity["instance_id"]
                   + ", key provider kms" + (", disk encrypted" if identity["storage_encrypted"] == "1" else "")))
    report = {k: v.hex() for k, v in quote["report"].items()}
    try:
        vm = json.loads(evidence.get("vm_config") or "{}")
    except ValueError:
        vm = {}
    vm = vm if isinstance(vm, dict) else {}
    os_image = {}
    if expected or not image:
        status, detail = tdx.compare_measurements(report, expected)
    else:
        status, detail, os_image = os_image_check(quote["report"], log, vm, identity, image)
    images = {hex_id(h) for h in (vm.get("os_image_hash"), identity["os_image_hash"], server.get("os_image_hash")) if h}
    if len(images) > 1:
        status, detail = "fail", "the OS image hashes disagree: " + ", ".join(sorted(images)) + "; " + detail
    checks.append(("tdx_os", status, "Firmware, kernel and command line are the dstack OS image's",
                   detail + ("; OS image " + next(iter(images)) if len(images) == 1 else "")
                   + (", " + str(vm.get("cpu_count")) + " vCPU, " + str(vm.get("memory_size")) + " bytes" if vm else "")))
    if details is not None:
        try:
            certificates = tdx.chain_summary(raw)
        except tdx.QuoteError:
            certificates = []
        details.update({"certificates": certificates, "quote": {"version": quote.get("version"), "tee": "Intel TDX",
                                  **{k: report[k] for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3", "report_data",
                                                            "td_attributes", "xfam") if k in report}},
                        "intel": intel, "identity": {k: identity.get(k) for k in (
                            "app_id", "compose_hash", "instance_id", "os_image_hash", "key_provider")},
                        "vm": vm, "os_image": os_image})
    return checks


def write_record(path, record):
    private_write(path, json.dumps(record, indent=2, ensure_ascii=False).encode() + b"\n")
    if os.name != "nt":
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def address_signature(key, text):
    return hmac.new(key.encode(), text.encode(), hashlib.sha256).hexdigest()


def signed_by_collector(public_key, text, signature):
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True)).verify(
            base64.b64decode(signature, validate=True), text.encode())
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def read_beacon(topic, key=None, session=None, public_key=None):
    # key: the operator's address key; public_key: the collector key, which a verifier holds.
    # With neither, the newest post is returned, and anyone can post to the topic.
    if not BEACON.fullmatch(topic or ""):
        raise DeployError("The deployment has no address topic")
    response = (session or requests).get(topic + "/json", params={"poll": "1", "since": "all"}, timeout=30)
    if response.status_code != 200:
        raise DeployError("ntfy.sh answered HTTP " + str(response.status_code) + " for the address topic")
    found, required = None, key is not None or public_key is not None
    for line in response.text.splitlines():
        try:
            item = json.loads(line)
            parts = (item.get("message") or "").split(" ")
        except (ValueError, AttributeError):
            continue
        if len(parts) != 4 or parts[0] not in (ADDRESS_FORMAT, ADDRESS_SIGNED) or not QUICK_HOST.fullmatch(parts[1]) \
                or not parts[2].isdigit():
            continue
        text = " ".join(parts[:3])
        if parts[0] == ADDRESS_SIGNED:
            signer = "collector" if public_key is not None and signed_by_collector(public_key, text, parts[3]) else None
        else:
            signer = "address key" if key is not None and hmac.compare_digest(
                parts[3], address_signature(key, text)) else None
        if required and not signer:
            continue
        # A signed post retains its original ordering when it is delivered again.
        # Unsigned timestamps are untrusted, so use the relay's receive time instead.
        posted, received = int(parts[2]), item.get("time")
        received = received if isinstance(received, int) else posted
        order = (posted, received) if signer else (received, posted)
        if found is None or order >= found["order"]:
            found = {"host": parts[1], "posted": posted, "signed": bool(signer), "signer": signer, "order": order}
    if not found:
        raise DeployError("The server has not posted its quick tunnel address yet" + (
            ", signed with " + ("the collector key" if public_key is not None else "the address key") if required
            else ""))
    del found["order"]
    return found


def wait_for_collector(host, minutes, fetch):
    deadline = time.monotonic() + minutes * 60
    while True:
        try:
            return fetch(host() if callable(host) else host, secrets.token_hex(16))
        except (DeployError, requests.RequestException, ValueError, KeyError) as exc:
            if time.monotonic() > deadline:
                raise DeployError("The collector did not answer in time (" + str(exc) + "). Run verify "
                                  "later; without SSH a failed bootstrap means a new deployment.") from None
            base.pause(15)


def connect(kind, credentials, spec, log=None):
    provider = kind(credentials, log=log)
    provider.location, provider.mode = spec.get("location"), spec["mode"]
    return provider


def printed(stage, text):
    print(text, flush=True)


def deploy(args, provider=None, cloudflare=None, fetch=collector_statement, resolve=resolve_commit, progress=printed,
           beacon=read_beacon, archive=None, collateral=None, image=None):
    spec = specification(args, resolve)
    kind, generic, quick = get(spec["provider"]), spec["provider"] == "generic", bool(spec["beacon"])
    phala = spec["provider"] == "phala"
    out = Path(args.out or Path("deployments") / spec["name"])
    if (out / "deployment.json").exists():
        raise DeployError(str(out) + " already holds a deployment; choose another --out or --name")
    log = []
    provider = provider or connect(kind, kind.credentials(args.provider_token_file), spec)
    provider.location, provider.mode, provider.log = spec["location"], spec["mode"], log
    cf = None
    if not quick or spec["gateway"]:
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
        if quick:
            tunnel_id, tunnel_token = None, secrets.token_urlsafe(32)
            private_write(out / "address-key.txt", tunnel_token.encode())
            progress("tunnel", "Quick tunnel: the server posts its trycloudflare.com address, signed, to "
                     + spec["beacon"])
        else:
            zones = cf.result("GET", "/zones", params={"name": spec["zone"]})
            if len(zones) != 1:
                raise DeployError("Cloudflare zone " + spec["zone"] + " was not found for this token")
            record["zone_id"] = zones[0]["id"]
            for host in hosts:
                if cf.result("GET", "/zones/" + record["zone_id"] + "/dns_records", params={"name": host}):
                    raise DeployError(host + " already has DNS records; choose an unused hostname")
            tunnel = cf.result("POST", "/accounts/" + account + "/cfd_tunnel",
                               {"name": "tgwitness-" + spec["name"] + "-" + spec["deployment_id"], "config_src": "cloudflare"})
            tunnel_id = tunnel["id"]
            record["tunnel"] = {"id": tunnel_id, "name": tunnel["name"], "created_at": tunnel.get("created_at")}
            write_record(path, record)
            progress("tunnel", "Cloudflare tunnel " + tunnel_id + " created")
            tunnel_token = tunnel.get("token") or cf.result(
                "GET", "/accounts/" + account + "/cfd_tunnel/" + tunnel_id + "/token")
            config = cf.result("PUT", "/accounts/" + account + "/cfd_tunnel/" + tunnel_id + "/configurations",
                               {"config": {"ingress": ingress(spec)}})
            record["tunnel"]["config_version"] = config.get("version")
            record["dns"] = []
            for host in hosts:
                created = cf.result("POST", "/zones/" + record["zone_id"] + "/dns_records", {
                    "type": "CNAME", "name": host, "content": tunnel_id + ".cfargotunnel.com", "proxied": True,
                    "comment": "TgWitness " + spec["mode"] + " deployment " + spec["deployment_id"]})
                record["dns"].append({"host": host, "id": created["id"]})
            write_record(path, record)
        if spec["gateway"]:
            progress("gateway", "Cloudflare Gateway: preparing the DNS location")
            spec["gateway"], record["gateway_shared"] = create_gateway(cf, spec)
            record["gateway"] = spec["gateway"]
            write_record(path, record)
            progress("gateway", "Cloudflare Gateway location " + spec["gateway"]["location_id"]
                     + (" (shared; this server's queries are told apart by its address)" if record["gateway_shared"]
                        else "") + ": the server resolves only through " + gateway_host(spec) + ", over TLS")
        panel_token = secrets.token_urlsafe(32)
        private_write(out / "panel-token.txt", panel_token.encode())
        if phala:
            compose = phala_compose(spec, tunnel_id, source_manifest(tarball_files((archive or fetch_archive)(spec))))
            fields = app_compose(compose)
            if len(compose.encode()) > kind.user_data_limit:
                raise DeployError("the compose exceeds " + kind.title + "'s limit")
            (out / "docker-compose.yaml").write_bytes(compose.encode())
            record["compose"] = {"sha256": hashlib.sha256(compose.encode()).hexdigest(), "settings": PHALA_SETTINGS,
                                 "published": "docker-compose.yaml"}
            write_record(path, record)
            progress("server", kind.title + ": creating the confidential VM")
            firewall, server = provider.create(spec, fields, {"TGWITNESS_TOKEN": panel_token,
                                                              "TGWITNESS_TUNNEL_TOKEN": tunnel_token})
            record["firewall"], record["server"] = firewall, server
            record["state"] = "CVM running; waiting for the collector"
            write_record(path, record)
            progress("running", kind.title + " CVM " + str(server["id"]) + " (app "
                     + str(server["app_id"]) + ") is running")
        elif generic:
            script = install_script(spec, tunnel_id, panel_token, tunnel_token)
            private_write(out / "install.sh", script.encode())
            (out / "install.redacted.sh").write_bytes(redact_user_data(script).encode())
            record["cloud_init"] = {**user_data_hashes(script), "published": "install.redacted.sh"}
            record["state"] = "waiting for install.sh on the server"
            write_record(path, record)
            progress("install", "Copy " + str(out / "install.sh") + " to a freshly installed Ubuntu 24.04 server and "
                     "run it there as root:\n    sudo bash install.sh\nIt installs commit " + spec["commit"]
                     + " closes SSH and ends that session.")
        else:
            user_data = cloud_init(spec, tunnel_id, panel_token, tunnel_token)
            if len(user_data.encode()) > kind.user_data_limit:
                raise DeployError("cloud-init exceeds " + kind.title + "'s user data limit")
            (out / "cloud-init.redacted.yaml").write_bytes(redact_user_data(user_data).encode())
            record["cloud_init"] = {**user_data_hashes(user_data), "published": "cloud-init.redacted.yaml"}
            write_record(path, record)
            progress("server", kind.title + ": creating the firewall and the server")
            outbound = outbound_rules(spec)
            firewall, server = provider.create(spec, user_data, inbound_rules(spec), outbound)
            record["firewall"] = {**firewall, "inbound_rules": inbound_rules(spec),
                                  **({"outbound_rules": outbound} if outbound else {})}
            record["server"] = server
            record["state"] = "server running; waiting for the collector"
            write_record(path, record)
            progress("running", kind.title + " server " + str(server["id"]) + " is running")
        progress("waiting", "Waiting up to " + str(args.wait) + " minutes for the collector's signed statement")
        located = {}

        def current():
            located.update(beacon(spec["beacon"], tunnel_token))
            return located["host"]
        answer = wait_for_collector(current if quick else spec["panel_host"], args.wait, fetch)
        if quick:
            record["address"] = {"host": located["host"], "posted": located["posted"], "seen_at": utcnow()}
        statement = answer["statement"]
        host = statement.get("host") or {}
        record["collector"] = {"fingerprint": statement["fingerprint"], "public_key": statement["public_key"],
                               "first_boot_id": host.get("boot_id"), "statement": answer}
        if generic:
            seen = host.get("provider") or {}
            record["server"] = {"id": seen.get("instance_id"), "name": spec["name"], "hostname": seen.get("hostname"),
                                "created": None, "ipv4": None, "ipv6": None, "machine_id": seen.get("instance_id")}
        if phala:
            loader = image_loader(image, out) if isinstance(image, str) else image
            if loader:
                progress("attestation", "Comparing the CVM's firmware, kernel and command line with the published "
                         "dstack OS image" + (" (downloaded once into " + str(out / "dstack-images") + ")"
                                              if image == "auto" else ""))
            checks = attestation_checks(answer, record, compose, None, collateral, image=loader)
            for check, status, title, detail in checks:
                progress("attestation", "[" + status.upper() + "] " + title + ": " + detail)
            problems = [title + ": " + detail for check, status, title, detail in checks if status == "fail"]
            record["collector"]["attestation"] = [{"check": c, "status": st} for c, st, _, _ in checks]
        else:
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


def remove_tunnel(cf, record):
    account, removed = record["cloudflare_account"], []
    tunnels = {record["tunnel"]["id"]} if record.get("tunnel") else set()
    name = "tgwitness-" + record["name"] + "-" + record["deployment_id"]
    tunnels |= {t["id"] for t in cf.result("GET", "/accounts/" + account + "/cfd_tunnel",
                                           params={"name": name, "is_deleted": "false"}) or []}
    zone = record.get("zone_id")
    for host in (record["panel_host"], record.get("witness_host")) if zone else ():
        for item in (cf.result("GET", "/zones/" + zone + "/dns_records", params={"name": host}) if host else None) or []:
            target = (item.get("content") or "").removesuffix(".cfargotunnel.com")
            if target in tunnels or record["deployment_id"] in (item.get("comment") or ""):
                cf.result("DELETE", "/zones/" + zone + "/dns_records/" + item["id"], allow=(404,))
                removed.append({"resource": "dns", "id": item["id"], "name": host})
    for tunnel in sorted(tunnels):
        path = "/accounts/" + account + "/cfd_tunnel/" + tunnel
        for attempt in range(6):
            try:
                cf.call("DELETE", path + "/connections", allow=(404,))
                cf.result("DELETE", path, allow=(404,))
                break
            except DeployError:
                if attempt == 5:
                    raise
                base.pause(10)
        removed.append({"resource": "tunnel", "id": tunnel, "name": name})
    return removed


def gateway_name(record):
    return "tgwitness-" + record["name"] + "-" + record["deployment_id"]


def create_gateway(cf, spec):
    account, wanted = spec["gateway"]["account"], spec["gateway"]["location_id"]
    path = "/accounts/" + account + "/gateway"
    try:
        cf.result("GET", path)
    except DeployError as exc:
        if "1001" not in str(exc):
            raise
        cf.result("POST", path)
    shared = bool(wanted)
    if wanted:
        location = cf.result("GET", path + "/locations/" + wanted)
    else:
        try:
            location = cf.result("POST", path + "/locations", {
                "name": gateway_name(spec), "client_default": False, "ecs_support": False,
                "endpoints": {"doh": {"enabled": True}, "dot": {"enabled": True}, "ipv4": {"enabled": False},
                              "ipv6": {"enabled": False}}})
        except DeployError as exc:
            if "1002" not in str(exc):
                raise
            existing = cf.result("GET", path + "/locations") or []
            if len(existing) != 1:
                raise DeployError("Cloudflare allows no further DNS location in this account; choose one of its "
                                  "locations with --gateway-location: " + ", ".join(
                                      str(item.get("id")) + " (" + str(item.get("name")) + ")"
                                      for item in existing)) from None
            location, shared = existing[0], True
    if not (LOCATION_ID.fullmatch(str(location.get("id")))
            and DOH_SUBDOMAIN.fullmatch(str(location.get("doh_subdomain")))):
        raise DeployError("Cloudflare returned an unexpected Gateway location")
    if not ((location.get("endpoints") or {}).get("dot") or {}).get("enabled"):
        raise DeployError("Gateway location " + location["id"] + " does not accept DNS over TLS; turn on its DoT "
                          "endpoint in Cloudflare Zero Trust, or let the deployment create its own location")
    return {"account": account, "location_id": location["id"], "doh_subdomain": location["doh_subdomain"]}, shared


def remove_gateway(cf, record):
    path = "/accounts/" + record["gateway"]["account"] + "/gateway/locations"
    ids = set() if record.get("gateway_shared") else {record["gateway"]["location_id"]} - {None}
    ids |= {item["id"] for item in cf.result("GET", path) or [] if item.get("name") == gateway_name(record)}
    removed = []
    for location in sorted(ids):
        cf.result("DELETE", path + "/" + location, allow=(404,))
        removed.append({"resource": "gateway location", "id": location, "name": gateway_name(record)})
    return removed


def destroy(args, provider=None, cloudflare=None, progress=printed):
    path = Path(args.record)
    record = json.loads(path.read_text(encoding="utf-8"))
    if args.confirm != record["name"]:
        raise DeployError("Confirm with the server name " + record["name"] + ": its journal and signing key are "
                          "deleted with it")
    generic, quick, log, removed = record["provider"] == "generic", bool(record.get("beacon")), [], []
    if not generic:
        kind = get(record["provider"])
        provider = provider or connect(kind, kind.credentials(args.provider_token_file), record)
        provider.location, provider.mode, provider.log = record.get("location"), record["mode"], log
    cf = None
    if not quick or record.get("gateway"):
        cf = cloudflare or Cloudflare(read_secret(args.cloudflare_token_file, "CLOUDFLARE_API_TOKEN",
                                                  "--cloudflare-token-file"))
        cf.log = log
    try:
        if not generic:
            progress("server", kind.title + (": deleting the confidential VM" if record["provider"] == "phala"
                                             else ": deleting the server and its firewall"))
            removed += provider.destroy(record)
        if not quick:
            progress("tunnel", "Cloudflare: deleting the DNS records and the tunnel")
            removed += remove_tunnel(cf, record)
        if record.get("gateway"):
            progress("gateway", "Cloudflare Gateway: the shared DNS location stays; only a leftover of this "
                     "deployment is removed" if record.get("gateway_shared") else
                     "Cloudflare Gateway: deleting the DNS location; its logs stay with Cloudflare for their "
                     "retention period")
            removed += remove_gateway(cf, record)
        record["state"] = "removed"
    except Exception as exc:
        record["state"] = "removal failed: " + str(exc)
        raise DeployError(str(exc) + ". What was removed so far is listed in " + str(path)) from exc
    finally:
        record.setdefault("removals", []).append({"at": utcnow(), "removed": removed, "api_calls": log})
        write_record(path, record)
    if generic:
        progress("note", "The server itself was installed by hand: wipe or delete it at its provider")
    return record, removed


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
               or found.get("detail") or "firewall " + str(record["firewall"]["id"]) + " applied with no inbound rules", source)
    if record.get("gateway"):
        leaks = dns_leaks(found.get("outbound"))
        report.add("dns_firewall", "fail" if leaks else "pass", "DNS leaves the server only to Cloudflare Gateway",
                   "; ".join(leaks) or "outbound rules let ports 53 and 853 reach only " + ", ".join(GATEWAY_RESOLVERS)
                   + "; DNS over HTTPS on port 443 is not covered", source)
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
    report.add("provider_actions", status, "No flagged access operations appear in the available provider log",
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
    if record["provider"] == "phala":
        report.add("connector", "pass" if addresses else "review", "The tunnel connector is online",
                   "connections from " + (", ".join(addresses) or "nowhere now") + "; a Phala CVM has no address of "
                   "its own to compare: its quote, not its address, identifies it", CF)
    elif record["provider"] == "generic":
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


def gateway_queries(by_source):
    return ("query($account: String!, $location: String!, $since: Time!, $until: Time!"
            + (", $source: String!" if by_source else "") + ") { viewer { accounts(filter: {accountTag: $account}) { "
            "cf1GatewayDnsRawGroups(limit: 1000, filter: {location: $location" + (", sourceIP: $source" if by_source
                                                                               else "")
            + ", datetime_geq: $since, datetime_lt: $until}, orderBy: [datetime_DESC]) { dimensions { datetime "
            "destination } } } } }")


def gateway_day(cf, by_source, asked):
    rows, end = [], time.time()
    start = end - 86400
    while end > start and len(rows) < 5000:
        begin = max(start, end - GATEWAY_WINDOW_SECONDS)
        window = {**asked, "since": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(begin)),
                  "until": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end))}
        rows += cf.graphql(gateway_queries(by_source), window)["viewer"]["accounts"][0]["cf1GatewayDnsRawGroups"]
        end = begin
    return rows


def verify_gateway(report, record, cf, server=None):
    gateway, path = record["gateway"], "/accounts/" + record["gateway"]["account"] + "/gateway"
    if not gateway.get("location_id"):
        report.add("gateway_location", "fail", "The server's Gateway location exists and takes DNS over TLS",
                   "the deployment never recorded a Gateway location", RECORD)
        return
    title = "The server's Gateway location exists and takes DNS over TLS"
    try:
        location = cf.result("GET", path + "/locations/" + gateway["location_id"], allow=(404,))
    except DeployError as exc:
        report.add("gateway_location", "unavailable", title, "this token cannot read Gateway (Zero Trust Read): "
                   + str(exc), CF)
        return
    dot = ((location or {}).get("endpoints") or {}).get("dot") or {}
    good = bool(location) and location.get("doh_subdomain") == gateway["doh_subdomain"] and dot.get("enabled")
    report.add("gateway_location", "pass" if good else "fail", title,
               (str(location.get("name")) + ", " + str(location.get("doh_subdomain")) + GATEWAY_HOST + ", DNS over TLS "
                + ("on" if dot.get("enabled") else "off")
                + ("; shared with whatever else uses this location" if record.get("gateway_shared") else ""))
               if location else "location deleted or not visible to this token", CF)
    logging = cf.result("GET", path + "/logging") or {}
    dns = (logging.get("settings_by_rule_type") or {}).get("dns") or {}
    report.add("gateway_logging", "pass" if dns.get("log_all") else "review", "Gateway logs every DNS query",
               "log every DNS query: " + ("yes" if dns.get("log_all") else "no") + "; Cloudflare keeps the log 24 hours "
               "on the free plan" + ("; personal data redacted in logs" if logging.get("redact_pii") else ""), CF)
    rules = cf.result("GET", path + "/rules") or []
    acting = [r for r in rules if r.get("enabled") and "dns" in (r.get("filters") or [])
              and r.get("action") in GATEWAY_RULE_ACTIONS]
    report.add("gateway_rules", "review" if acting else "pass", "No Gateway DNS policy changes, blocks or redirects answers",
               "; ".join(str(r.get("name")) + " (" + str(r.get("action")) + "): " + str(r.get("traffic") or "all DNS")
                         for r in acting)[:900] or "none of " + str(len(rules)) + " polic(ies) acts on DNS answers", CF)
    report.cloudflare["gateway_rules"] = [{k: r.get(k) for k in ("name", "action", "enabled", "traffic", "updated_at")}
                                          for r in acting]
    title = "The server resolves through its Gateway location"
    source = (server or {}).get("ipv4") or record["server"].get("ipv4")
    asked = {"account": gateway["account"], "location": str(uuid.UUID(gateway["location_id"]))}
    try:
        try:
            if not source:
                raise DeployError("the server's IPv4 address is unknown")
            rows = gateway_day(cf, True, {**asked, "source": source})
        except DeployError as exc:
            if record.get("gateway_shared") or "sourceIP" not in str(exc):
                raise
            # A location of the server's own: every query in it is the server's.
            rows, source = gateway_day(cf, False, asked), None
    except (DeployError, KeyError, IndexError, TypeError) as exc:
        needs = "Account Analytics Read" + (" and, for a shared location, Zero Trust PII Read"
                                            if record.get("gateway_shared") else "")
        report.add("gateway_queries", "unavailable", title, "this token cannot read the server's Gateway log ("
                   + needs + "): " + str(exc), CF)
    else:
        names = sorted({r["dimensions"]["destination"] for r in rows})
        report.cloudflare["gateway_names_24h"] = names[:300]
        report.add("gateway_queries", "pass" if rows else "review", title,
                   str(len(rows)) + ("+" if len(rows) >= 5000 else "") + " DNS queries"
                   + (" from " + source if source else " in the server's own location")
                   + " in the last 24 hours, "
                   + str(len(names)) + " names, latest " + rows[0]["dimensions"]["datetime"] if rows else
                   "no DNS query in the last 24 hours: the server is stopped or resolves elsewhere", CF)
    logs = cf.call("GET", "/accounts/" + gateway["account"] + "/audit_logs",
                   params={"since": record["created_at"], "per_page": 1000, "direction": "asc"}, allow=(401, 403))
    if logs is None:
        report.add("gateway_audit", "unavailable", "Cloudflare audit log for Gateway",
                   "this token cannot read the account audit log (Audit Logs Read)", CF)
        return
    entries = [e for e in logs.get("result") or [] if str((e.get("resource") or {}).get("type") or "").startswith("gateway")
               or gateway["location_id"] in json.dumps(e)]
    created = parse_time(record["created_at"]).timestamp()
    late = [e for e in entries if parse_time(e["when"]).timestamp() > created + 1800]
    report.cloudflare["gateway_audit"] = [{k: e.get(k) for k in ("when", "action", "actor", "resource")} for e in entries]
    report.add("gateway_audit", "review" if late else "pass", "Cloudflare audit log for Gateway",
               str(len(entries)) + " Gateway entr(ies), " + str(len(late)) + " after the deployment"
               + (": " + "; ".join(str(e["when"]) + " " + str((e.get("action") or {}).get("type")) + " "
                                   + str((e.get("resource") or {}).get("type")) for e in late[:10]) if late else "")
               + " (first 1000 log entries)", CF)


def posted_address(record, beacon):
    collector = (record.get("collector") or {}).get("public_key")
    if collector:
        try:
            return beacon(record["beacon"], public_key=collector)
        except DeployError:
            pass
    return beacon(record["beacon"])


def verify_collector(report, record, server, args, fetch, reference=None, reference_error=None, beacon=read_beacon):
    located = None
    try:
        if record["panel_host"]:
            host = record["panel_host"]
        else:
            located = posted_address(record, beacon)
            host = located["host"]
        answer = fetch(host, secrets.token_hex(16))
    except (DeployError, requests.RequestException, ValueError, KeyError) as exc:
        report.add("statement", "fail", "The collector answers with a fresh signed statement", str(exc), COLLECTOR)
        return None
    statement = answer["statement"]
    host = statement.get("host") or {}
    report.add("statement", "pass", "The collector answers with a fresh signed statement",
               "signature valid, challenge echoed; run " + statement["run_id"] + ", TgWitness " + statement["version"]
               + ("" if located is None else "; address " + located["host"] + (
                   " posted signed with the collector key" if located.get("signer") == "collector" else
                   " taken from an unsigned post: this collector does not sign its address")), COLLECTOR)
    recorded = (record.get("collector") or {}).get("fingerprint")
    if args.fingerprint:
        status, detail = ("pass" if statement["fingerprint"] == args.fingerprint.lower() else "fail"), \
            "compared with the fingerprint given independently"
    elif recorded:
        status, detail = ("pass" if statement["fingerprint"] == recorded else "fail"), \
            "compared with the deployment record only; pass --fingerprint from an independent channel"
    else:
        status, detail = "review", "no expected fingerprint"
    report.add("fingerprint", status, "The collector key matches the expected fingerprint",
               statement["fingerprint"] + "; " + detail, COLLECTOR)
    phala = record["provider"] == "phala"
    target = record["server"] if record["provider"] == "generic" else server
    if target and not phala:
        ipv4 = target.get("ipv4")
        problems = binding(statement, target["id"], ipv4, record.get("cloud_init") or {})
        report.add("binding", "fail" if problems else "pass",
                   "The collector reports the recorded server and installer hashes",
                   "; ".join(problems) or "instance " + str(target["id"]) + (", IPv4 " + ipv4 if ipv4 else "")
                   + ", installer hashes match", COLLECTOR)

    title = "The collector-reported user data equals the installer the deployed commit builds"
    if phala:
        pass
    elif reference_error:
        report.add("cloud_init", "fail", title, reference_error, COLLECTOR)
    else:
        published = Path(args.cloud_init).read_bytes() if args.cloud_init else None
        status, detail = installer_check(host.get("provider") or {}, record["commit"], reference, published)
        report.add("cloud_init", status, title, detail, COLLECTOR)
    deployed = host.get("deployment") or {}
    same = deployed.get("commit") == record["commit"] and deployed.get("deployment_id") == record["deployment_id"]
    report.add("deployment", "pass" if same else "fail", "The server describes this deployment and commit",
               "commit " + str(deployed.get("commit")) + ", deployment " + str(deployed.get("deployment_id")), COLLECTOR)
    if args.source:
        try:
            expected = source_tree_sha256(source_files(Path(args.source) / "tgwitness",
                policy=statement.get("source_policy", LEGACY_SOURCE_POLICY)))
        except ValueError as exc:
            report.add("source", "fail", "The collector-reported source hash matches the checkout", str(exc), COLLECTOR)
        else:
            same = expected == statement["source_tree_sha256"]
            report.add("source", "pass" if same else "fail", "The collector-reported source hash matches the checkout",
                       "running " + statement["source_tree_sha256"] + ", checkout " + expected
                       + ("" if same else "; on Windows clone with git -c core.autocrlf=false"), COLLECTOR)
    else:
        report.add("source", "unavailable", "The collector-reported source hash matches the checkout",
                   "pass --source with a checkout of " + record["commit"], COLLECTOR)
    flags = [(host.get("ssh_listening"), "something listens on port 22"),
             (host.get("ssh_processes"), "SSH server processes running"), (host.get("sessions"), "logged-in sessions now")]
    if record["provider"] != "generic":
        flags.append((host.get("logins"), str(host.get("logins")) + " login(s) in wtmp"))
    problems = [text for flag, text in flags if flag]
    unknown = [k for k in ("sessions", "logins") if host.get(k) is None]
    notes = problems + (["unreadable: " + ", ".join(unknown)] if unknown else [])
    if not phala:
        report.add("host_access", "fail" if problems else "review" if unknown else "pass",
                   "No SSH and no logins on the host",
                   "; ".join(notes) or "nothing on port 22, no SSH processes, no sessions, no logins recorded", COLLECTOR)
    first = (record.get("collector") or {}).get("first_boot_id")
    report.add("boot", "pass" if first and host.get("boot_id") == first else "review", "Running since the first boot",
               "boot " + str(host.get("boot_id")) + (" (same as at deployment)" if host.get("boot_id") == first
                                                     else ", deployment recorded " + str(first)), COLLECTOR)
    report.collector = answer
    return statement


def verify_journal(report, path, key, server_id, generic=False, reference=None):
    if not key:
        report.add("journal", "fail", "The evidence journal matches the expected collector key",
                   "no expected collector key is available for this deployment", JOURNAL)
        return
    try:
        result = verify_bundle(path, expected_fingerprint=key)
    except Exception as exc:
        report.add("journal", "fail", "The evidence journal is signed by this key", type(exc).__name__ + ": " + str(exc), JOURNAL)
        return
    starts, problems, boots, baseline, unknown, keys = 0, [], [], None, [], []
    expected = hashlib.sha256(reference.encode()).hexdigest() if reference is not None else None
    with open_archive(path) as archive, archive.open("events.jsonl") as stream:
        for line in bounded_lines(stream):
            event = json.loads(line)
            if event["kind"] == "account.authorized":
                keys.append((event["seq"], event["payload"].get("key_origin")))
                continue
            if event["kind"] == "process.started":
                starts += 1
                host = (event["payload"].get("run") or {}).get("host")
                if not host:
                    problems.append("record " + str(event["seq"]) + ": a start without host measurement")
                    continue
                instance = (host.get("provider") or {}).get("instance_id")
                if expected and (host.get("provider") or {}).get("user_data_redacted_sha256") != expected:
                    problems.append("record " + str(event["seq"]) + ": started from user data other than the reference installer")
            elif event["kind"] == "host.state":
                host, instance = event["payload"], event["payload"].get("instance_id")
            else:
                continue
            if str(instance) != str(server_id):
                problems.append("record " + str(event["seq"]) + ": instance " + str(instance))
            missing = [name for name in ("boot_id", "ssh_listening", "ssh_processes", "sessions", "logins")
                       if host.get(name) is None]
            if missing:
                unknown.append("record " + str(event["seq"]) + ": unavailable host measurements: " + ", ".join(missing))
            for flag, text in (("ssh_listening", "port 22 open"), ("ssh_processes", "SSH processes"),
                               ("sessions", "sessions")):
                if host.get(flag):
                    problems.append("record " + str(event["seq"]) + ": " + text)

            logins = host.get("logins") or 0
            baseline = (logins if baseline is None else baseline) if generic else 0
            if logins > baseline:
                problems.append("record " + str(event["seq"]) + ": login(s) recorded")
            if host.get("boot_id") and host["boot_id"] not in boots:
                boots.append(host["boot_id"])
    account_key_check(report, keys)
    if not starts:
        problems.append("no process.started record binds this journal to the reported server")
    report.add("journal", "fail" if problems else "unavailable" if unknown else "pass",
               "The journal signatures and recorded host measurements match",
               "; ".join((problems + unknown)[:20]) or str(result["events"]) + " records verified; " + str(starts)
               + " process start(s) on server " + str(server_id) + "; " + str(len(boots)) + " boot(s)", JOURNAL)


def account_key_check(report, keys):
    notes = ["record " + str(seq) + ": " + (
        "authorized with an imported session; its key also exists outside this server, and whoever holds it "
        "could stand in for Telegram on the network path, so observations also rest on the key's holders"
        if origin == "imported" else "the journal does not say where the account's key was created")
        for seq, origin in keys if origin != "created"]
    imported = any(origin == "imported" for _, origin in keys)
    report.add("account_key", "review" if imported else "unavailable" if notes or not keys else "pass",
               "The Telegram authorization key was created on this server",
               "; ".join(notes[:20]) or ("created by signing in on this server (record " + ", ".join(
                   str(seq) for seq, _ in keys) + ")" if keys else "no account authorization in this journal"), JOURNAL)


def verify_tdx_journal(report, path, key, record, reference=None, collateral=None, now=None, image=None):
    if not key:
        report.add("journal", "fail", "The evidence journal matches the expected collector key",
                   "no expected collector key is available for this deployment", JOURNAL)
        return
    try:
        result = verify_bundle(path, expected_fingerprint=key)
    except Exception as exc:
        report.add("journal", "fail", "The evidence journal is signed by this key", type(exc).__name__ + ": " + str(exc), JOURNAL)
        return
    server, collateral = record["server"], collateral or intel_collateral()
    starts, problems, reviews, keys, composes, statuses, systems = 0, [], [], [], set(), set(), set()
    with open_archive(path) as archive, archive.open("events.jsonl") as stream:
        for line in bounded_lines(stream):
            event = json.loads(line)
            where = "record " + str(event["seq"]) + ": "
            if event["kind"] == "account.authorized":
                keys.append((event["seq"], event["payload"].get("key_origin")))
            elif event["kind"] == "host.state":
                if hex_id(event["payload"].get("instance_id")) != hex_id(server.get("instance_id")):
                    problems.append(where + "instance " + str(event["payload"].get("instance_id")))
            elif event["kind"] == "process.started":
                starts += 1
                run = event["payload"].get("run") or {}
                quote = run.get("tdx_start") or {}
                if quote.get("error") or not quote.get("quote"):
                    problems.append(where + "a start without an Intel TDX quote (" + str(quote.get("error")) + ")")
                    continue
                try:
                    raw, log = tdx.evidence(quote)
                    measured, identity = tdx.measured(raw, log)
                except (tdx.QuoteError, ValueError, KeyError, TypeError) as exc:
                    problems.append(where + str(exc))
                    continue
                if run.get("public_key") and fingerprint(run["public_key"]) != key.lower():
                    problems.append(where + "started with another key")
                if measured["report"]["report_data"] != tdx.report_data(start_binding(run)):
                    problems.append(where + "the quote does not cover this start")
                seen = (run.get("host") or {}).get("provider") or {}
                text = seen.get("app_compose")
                if not isinstance(text, str) or hashlib.sha256(text.encode()).hexdigest() != identity["compose_hash"]:
                    problems.append(where + "the recorded app-compose is not the measured one")
                else:
                    status, detail = compose_check(text, reference)
                    if status == "fail":
                        problems.append(where + "started from another compose: " + detail)
                composes.add(identity["compose_hash"])
                if hex_id(identity["app_id"]) != hex_id(server.get("app_id")):
                    problems.append(where + "app " + identity["app_id"])
                if hex_id(identity["instance_id"]) != hex_id(server.get("instance_id")):
                    problems.append(where + "instance " + str(identity["instance_id"]))
                status, detail, found = intel_check(raw, collateral, now)
                if status == "fail":
                    problems.append(where + detail)
                elif status != "pass":
                    reviews.append(where + detail)
                if found:
                    statuses.add(found["status"])
                if image:
                    try:
                        vm = json.loads(quote.get("vm_config") or "{}")
                    except ValueError:
                        vm = {}
                    status, detail, values = os_image_check(measured["report"], log, vm if isinstance(vm, dict) else {},
                                                            identity, image)
                    if status == "fail":
                        problems.append(where + detail)
                    elif status != "pass":
                        reviews.append(where + detail)
                    else:
                        systems.add(values["image"])
    account_key_check(report, keys)
    if not starts:
        problems.append("no process.started record binds this journal to the deployed CVM")
    if len(composes) > 1:
        reviews.append("the collector started from " + str(len(composes)) + " different composes")
    report.add("journal", "fail" if problems else "review" if reviews else "pass",
               "The journal signatures and every start's Intel TDX quote match the deployed CVM",
               "; ".join((problems + reviews)[:20]) or str(result["events"]) + " records verified; " + str(starts)
               + " start(s), each quoted inside CVM " + str(server.get("instance_id")) + " (Intel TCB "
               + ", ".join(sorted(statuses)) + ")" + (", booted from the published " + ", ".join(sorted(systems))
                                                       if systems else ""), JOURNAL)


def verify(args, provider=None, cloudflare=None, fetch=collector_statement, beacon=read_beacon):
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
    if record.get("beacon"):
        report.add("tunnel", "unavailable", "Cloudflare tunnel, ingress, connector and DNS",
                   "quick tunnel: no Cloudflare account keeps records of it, so the machine running its connector "
                   "is not confirmed; the collector statement found at the posted address is checked below", CF)
    elif cloudflare or token:
        verify_tunnel(report, record, cloudflare or Cloudflare(token), server)
    else:
        report.add("tunnel", "unavailable", "Cloudflare tunnel, ingress, connector and DNS",
                   "no Cloudflare token (Cloudflare Tunnel Read, DNS Read)", CF)
    if record.get("gateway") and (cloudflare or token):
        verify_gateway(report, record, cloudflare or Cloudflare(token), server)
    elif record.get("gateway"):
        report.add("gateway_location", "unavailable", "Cloudflare Gateway location, logging, policies and queries",
                   "no Cloudflare token (Zero Trust Read, Account Analytics Read, Audit Logs Read)", CF)
    reference = reference_error = None
    if args.source:
        try:
            reference = reference_installer(record, args.source)
        except DeployError as exc:
            reference_error = str(exc)
    statement = verify_collector(report, record, server, args, fetch, reference, reference_error, beacon)
    phala = record["provider"] == "phala"
    collateral = intel_collateral(getattr(args, "tdx_collateral", None)) if phala else None
    expected = json.loads(Path(args.tdx_measurements).read_text(encoding="utf-8")) \
        if phala and getattr(args, "tdx_measurements", None) else None
    image = image_loader(getattr(args, "tdx_image", None), Path(args.record).parent) if phala else None
    attestation = {}
    if phala and report.collector:
        published = Path(args.cloud_init).read_text(encoding="utf-8") if args.cloud_init else None
        for check, status, title, detail in attestation_checks(report.collector, record, reference, published,
                                                               collateral, expected, image=image, details=attestation):
            if reference_error and check == "tdx_compose":
                status, detail = "fail", reference_error
            report.add(check, status, title, detail, TDX_SOURCE)
        attested = any(c["check"] == "tdx_compose" and c["status"] == "pass" for c in report.checks)
        for c in report.checks:
            if c["check"] == "tunnel" and record.get("beacon") and attested:
                c.update(status="pass", source=TDX_SOURCE, title="The quick tunnel's connector runs inside the attested CVM",
                         detail="cloudflared, pinned by digest in the measured compose, serves the panel from inside "
                                "the CVM; no Cloudflare account keeps records of a quick tunnel, and the quote, not the "
                                "address, identifies the collector")
    if args.evidence:
        key = args.fingerprint or (statement or {}).get("fingerprint") or (record.get("collector") or {}).get("fingerprint")
        if phala:
            verify_tdx_journal(report, args.evidence, key, record, reference, collateral, image=image)
        else:
            verify_journal(report, args.evidence, key, record["server"]["id"], record["provider"] == "generic", reference)
    files_seen = {}
    for path in (args.record, args.cloud_init, args.evidence):
        if path:
            digest = hashlib.sha256()
            with open(path, "rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            files_seen[Path(path).name] = digest.hexdigest()
    generic = record["provider"] == "generic"
    assurance = {"runtime_measurements": "collector-self-report", "independent_runtime_attestation": "not-performed",
                 "key_nonexportability": "not-established", "source_authenticity": "not-established"}
    if phala:
        found = {c["check"]: c["status"] for c in report.checks if c["source"] == TDX_SOURCE}
        attested = all(found.get(c) in ("pass", "review")
                       for c in ("tdx_binding", "tdx_quote", "tdx_compose_hash", "tdx_compose", "tdx_identity"))
        assurance = {"runtime_measurements": "intel-tdx-quote",
                     "independent_runtime_attestation": "intel-tdx" if attested else "failed",
                     "key_nonexportability": ("established-by-measured-code" if found.get("tdx_os") == "pass"
                                              else "conditional-on-os-image") if attested else "not-established",
                     "source_authenticity": "commit-pinned-in-measured-compose" if attested else "not-established"}
    return {"format": "tgwitness-assurance-report-v1", "generated_at": utcnow(),
            "verifier": {"software": "TgWitness", "version": __version__}, "result": report.result(),
            "verification_scope": "hardware-attestation" if phala else "deployment-consistency",
            "assurance": assurance,
            "deployment": {k: record.get(k) for k in ("deployment_id", "name", "mode", "provider", "location",
                                                      "repository", "commit", "panel_host", "witness_host", "beacon",
                                                      "gateway", "created_at")},
            "provider_title": kind.title, "server": record["server"], "firewall": (record.get("firewall") or {}).get("id"),
            "tunnel": (record.get("tunnel") or {}).get("id"), "cloudflare_account": record.get("cloudflare_account"),
            "fingerprint": (statement or {}).get("fingerprint"), "checks": report.checks,
            "provider_actions": report.actions, "cloudflare": report.cloudflare,
            "collector_statement": report.collector, "attestation": attestation or None, "files": files_seen,
            "establishes": (SELF_ESTABLISHES if generic else phala_establishes(record) if phala else ESTABLISHES)
            + (GATEWAY_ESTABLISHES if record.get("gateway") else ()),
            "does_not_establish": tuple(kind.limits) + (COMMON_LIMITS if phala else LIMITS)
            + ((PHALA_QUICK,) if phala and record.get("beacon") else ())
            + (GATEWAY_LIMITS if record.get("gateway") else ())}


RUNTIME = {"not-performed": "Self-reported by the collector; no independent runtime attestation",
           "intel-tdx": "Intel TDX quote over the collector's statement, checked by this verifier to Intel's root",
           "failed": "**An Intel TDX quote was expected and did not verify**"}
CUSTODY = {"not-established": "This report does not establish that the key was never copied",
           "established-by-measured-code": "Created and kept inside the attested CVM by the measured commit; "
                                           "the OS image measurements match",
           "conditional-on-os-image": "Created inside the attested CVM by the measured commit; the OS image "
                                      "measurements were not compared with the published image"}


def cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def render(report):
    deployment, server = report["deployment"], report["server"]
    account, tunnel = report["cloudflare_account"], report["tunnel"]
    lines = ["# TgWitness " + ("self-attested" if deployment["mode"] == "self-attested" else "high-assurance")
             + " deployment report", "",
             "Generated " + report["generated_at"] + " with TgWitness " + report["verifier"]["version"]
             + " (`python -m tgwitness.cloud verify`). Every provider and Cloudflare value below was "
             "requested by the verifier at that time; the deployment record supplied only the IDs to ask about.", "",
             "| | |", "| --- | --- |",
             "| **Deployment checks** | **" + report["result"].upper() + "** |",
             "| Runtime measurements | " + RUNTIME.get(report["assurance"]["independent_runtime_attestation"],
                                                   RUNTIME["not-performed"]) + " |",
             "| Private-key custody | " + CUSTODY.get(report["assurance"]["key_nonexportability"],
                                                  CUSTODY["not-established"]) + " |",
             "| Collector key fingerprint | `" + str(report["fingerprint"]) + "` |",
             "| Deployment | " + cell(deployment["deployment_id"]) + " (" + cell(deployment["mode"]) + "), "
             + cell(deployment["created_at"]) + " |",
             "| Provider | " + cell(report["provider_title"]) + (", " + cell(deployment["location"]) if deployment["location"] else "") + " |",
             "| Software | " + cell(deployment["repository"]) + " at `" + cell(deployment["commit"]) + "` |",
             "| Server | " + cell(server.get("name")) + " #" + cell(server.get("id")) + ", " + cell(server.get("ipv4")) + " |",
             "| Provider firewall | " + cell(report["firewall"]) + " |",
             "| Cloudflare tunnel | " + cell(tunnel) + " |",
             *(["| Cloudflare Gateway DNS | location " + cell(deployment["gateway"].get("location_id")) + ", "
                + cell(deployment["gateway"].get("doh_subdomain")) + GATEWAY_HOST + " |"] if deployment.get("gateway") else []),
             "| Panel | " + ("https://" + cell(deployment["panel_host"]) if deployment["panel_host"] else
                            "quick tunnel, address posted to " + cell(deployment.get("beacon"))) + " |", ""]
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
    gateway = deployment.get("gateway")
    if gateway and gateway.get("location_id"):
        path = CLOUDFLARE_API + "/accounts/" + str(gateway["account"]) + "/gateway"
        lines += ["", "## Records kept by Cloudflare Gateway", "",
                  "- `GET " + path + "/locations/" + gateway["location_id"] + "`",
                  "- `GET " + path + "/logging` and `GET " + path + "/rules`",
                  "- DNS queries of the location: GraphQL `cf1GatewayDnsRawGroups`, filter `location: "
                  + str(uuid.UUID(gateway["location_id"])) + "` (24 hours on the free plan)"]
        names = report["cloudflare"].get("gateway_names_24h")
        if names:
            lines += ["", "Names the server looked up in the last 24 hours: " + ", ".join("`" + cell(n) + "`" for n in names)]
    if report["collector_statement"]:
        lines += ["", "## Signed collector statement", "", "```json",
                  json.dumps(report["collector_statement"], indent=2, ensure_ascii=False), "```"]
    lines += ["", "## What this report establishes", ""] + ["- " + t for t in report["establishes"]]
    lines += ["", "## What it does not establish", ""] + ["- " + t for t in report["does_not_establish"]]
    phala = deployment["provider"] == "phala"
    lines += ["", "## Reproduce", "", "```sh",
              "python -m tgwitness.cloud verify --record deployment.json --provider-token-file READ_ONLY_CREDENTIALS \\",
              "    --cloudflare-token-file READ_ONLY_TOKEN --fingerprint " + str(report["fingerprint"]) + " \\",
              "    --cloud-init " + ("docker-compose.yaml" if phala else "PUBLISHED_INSTALLER")
              + " --source CHECKOUT_OF_COMMIT --evidence tgwitness-evidence.zip",
              "python verify.py tgwitness-evidence.zip --fingerprint " + str(report["fingerprint"]), "```", "",
              "## Handover", "", "| File | SHA-256 |", "| --- | --- |"]
    lines += ["| " + cell(name) + " | `" + digest + "` |" for name, digest in report["files"].items()]
    return "\n".join(lines) + "\n"


def add_target(parser):
    parser.add_argument("--provider", required=True, choices=NAMES, help="Where the server runs")
    parser.add_argument("--name", required=True, help="Server name; also the deployment directory name")
    parser.add_argument("--server-type", help="Provider server type, e.g. cpx22, s-1vcpu-2gb, g6-standard-1, "
                        "vc2-1c-2gb, t3.small, tdx.small (phala)")
    parser.add_argument("--location", help="Provider location or region (default per provider)")
    parser.add_argument("--image", help="Image (default Ubuntu 24.04 of the provider)")
    parser.add_argument("--ref", required=True, help="40-character commit, or a release tag resolved once with git")
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY, help="Git repository (https)")
    parser.add_argument("--zone", help="Cloudflare zone, e.g. example.org")
    parser.add_argument("--cloudflare-account", help="Cloudflare account ID")
    parser.add_argument("--panel-host", help="Panel hostname in the zone")
    parser.add_argument("--quick-tunnel", action="store_true",
                        help="No domain and no Cloudflare account: a random https://*.trycloudflare.com address that "
                        "changes when the server restarts; verify cannot check its connector")
    parser.add_argument("--gateway-dns", action="store_true",
                        help="DNS only through a Cloudflare Gateway location of this server, over TLS; the provider "
                        "firewall blocks DNS to any other resolver (Hetzner; needs --cloudflare-account)")
    parser.add_argument("--gateway-location", help="With --gateway-dns: an existing Gateway DNS location ID to use "
                        "instead of creating one; destroy leaves it")
    parser.add_argument("--witness-host", help="Optional hostname exposing only the witness and assurance endpoints")
    parser.add_argument("--debug-ssh-key", help="NOT high-assurance: provider SSH key for a debugging deployment")
    parser.add_argument("--debug-ssh-from", help="NOT high-assurance: the only address or network allowed to SSH")


def plan(spec, archive=None):
    kind = get(spec["provider"])
    placeholder = (None, "x" * 43, "x" * 43) if spec["beacon"] else ("TUNNEL-ID-AFTER-CREATION", "x" * 43, "x" * 32)
    if spec["provider"] == "phala":
        compose = phala_compose(spec, placeholder[0], source_manifest(tarball_files((archive or fetch_archive)(spec))))
        settings = {k: v for k, v in app_compose(compose).items() if k != "docker_compose_file"}
        lines = ["# Provider: " + kind.title + "; mode " + spec["mode"] + "; commit " + spec["commit"],
                 *(["# Quick tunnel without a Cloudflare account; the address is posted, signed, to "
                    + spec["beacon"]] if spec["beacon"] else
                   ["# Cloudflare: tunnel ingress " + json.dumps(ingress(spec)),
                    *("# Cloudflare: CNAME " + h + " -> TUNNEL.cfargotunnel.com"
                      for h in (spec["panel_host"], spec["witness_host"]) if h)]),
                 "# " + kind.title + ": CVM " + spec["server_type"] + " in " + spec["location"] + ", OS image "
                 + spec["image"] + ", app-compose settings " + json.dumps(settings),
                 "# " + kind.title + ": " + ", ".join(PHALA_ENV) + " encrypted to the application's KMS key",
                 "# compose " + str(len(compose.encode())) + " of " + str(kind.user_data_limit) + " bytes",
                 "# Published compose (measured into RTMR3; no secrets):"]
        return "\n".join(lines) + "\n" + compose
    if spec["provider"] == "generic":
        text = install_script(spec, *placeholder)
        calls = ["Cloudflare: tunnel, its ingress and DNS records as below" if not spec["beacon"] else
                 "Cloudflare: nothing; cloudflared opens the quick tunnel on the server",
                 "No provider API: you run install.sh on the server yourself (self-attested)"]
    else:
        text = cloud_init(spec, *placeholder)
        calls = [kind.title + ": firewall with inbound rules " + json.dumps(inbound_rules(spec))
                 + (" and outbound rules " + json.dumps(outbound_rules(spec)) if spec.get("gateway") else ""),
                 kind.title + ": server " + spec["server_type"] + ", " + spec["image"] + " in " + spec["location"]
                 + ", SSH keys " + json.dumps([spec["ssh"]["debug_key"]] if spec["ssh"] != "disabled" else []),
                 "user data " + str(len(text.encode())) + " of " + str(kind.user_data_limit) + " bytes"]
    if spec["beacon"]:
        tunnel = ["# Quick tunnel without a Cloudflare account; the address is posted, signed, to " + spec["beacon"]]
    else:
        tunnel = ["# Cloudflare: tunnel ingress " + json.dumps(ingress(spec)),
                  *("# Cloudflare: CNAME " + h + " -> TUNNEL.cfargotunnel.com"
                    for h in (spec["panel_host"], spec["witness_host"]) if h)]
    if spec.get("gateway"):
        tunnel.append("# Cloudflare Gateway: a DNS location " + gateway_name(spec) + " in account "
                      + spec["gateway"]["account"] + "; its DNS-over-TLS name replaces LOCATION-AFTER-CREATION below")
    lines = ["# Provider: " + kind.title + "; mode " + spec["mode"] + "; commit " + spec["commit"], *tunnel,
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
                     help="Token with Cloudflare Tunnel Edit, Zone Read and DNS Edit, and Zero Trust Edit for "
                     "--gateway-dns (or CLOUDFLARE_API_TOKEN)")
    run.add_argument("--out", type=Path, help="Deployment directory (default deployments/NAME)")
    run.add_argument("--wait", type=int, help="Minutes to wait for the collector (default 20; 40 for phala; "
                     "60 for generic)")
    run.add_argument("--tdx-image", default="auto", help="phala: the published dstack OS image the CVM's firmware, "
                     "kernel and command line are compared with: auto (downloaded from Dstack-TEE once, into "
                     "dstack-images in the deployment directory), a folder, or none")
    close = commands.add_parser("lock", help="Remove every inbound rule from the deployment firewall")
    close.add_argument("--record", type=Path, required=True, help="deployment.json")
    close.add_argument("--provider-token-file", help="Provider credentials with write access")
    check = commands.add_parser("verify", help="Report what the provider, Cloudflare and the collector show")
    check.add_argument("--record", type=Path, required=True, help="deployment.json from the operator")
    check.add_argument("--provider-token-file", help="Read-only provider credentials (or the provider's variable)")
    check.add_argument("--cloudflare-token-file", help="Optional: Cloudflare Tunnel Read, DNS Read and Account "
                       "Settings Read; with Gateway DNS also Zero Trust Read, Account Analytics Read, Audit Logs "
                       "Read and, for a shared location, Zero Trust PII Read (or CLOUDFLARE_API_TOKEN)")
    check.add_argument("--fingerprint", help="Collector key fingerprint received through an independent channel")
    check.add_argument("--cloud-init", type=Path, help="The published installer: cloud-init.redacted.yaml, "
                       "install.redacted.sh or, for phala, docker-compose.yaml")
    check.add_argument("--source", type=Path, help="A checkout of the deployed commit; its own code builds the reference "
                       "installer the server's user data must equal byte for byte")
    check.add_argument("--evidence", type=Path, help="An evidence ZIP exported from this collector")
    check.add_argument("--tdx-image", default="auto", help="phala: the published dstack OS image the CVM's firmware, "
                       "kernel and command line are compared with: auto (downloaded from Dstack-TEE once, into "
                       "dstack-images beside the record), a folder, or none")
    check.add_argument("--tdx-measurements", type=Path, help="phala: JSON with mrtd, rtmr0, rtmr1 and rtmr2 to "
                       "compare instead, all four computed by other means")
    check.add_argument("--tdx-collateral", type=Path, help="phala: Intel collateral in dcap-qvl's JSON layout, "
                       "instead of fetching it from Intel's PCS")
    check.add_argument("--report", type=Path, help="Write the Markdown report here and its JSON beside it; for phala "
                       "also the attestation certificate (HTML, PDF) and its seal")
    check.add_argument("--sign-with", default="~/.tgwitness/verifier", help="phala: the verifier's own key folder "
                       "that signs the seal and the PDF (created on first use), or none")
    check.add_argument("--timestamp", action="append", help="phala: an RFC 3161 time-stamping authority for the seal; "
                       "repeat for several, or none (default: the Belgian government's qualified TSA and FreeTSA)")
    seal_check = commands.add_parser("check-report", help="Check an attestation certificate against its seal and "
                                     "time stamps")
    seal_check.add_argument("--report", type=Path, required=True, help="The report's JSON, Markdown, HTML or PDF")
    seal_check.add_argument("--verifier-fingerprint", help="The verifier key fingerprint received independently")
    remove = commands.add_parser("destroy", help="Delete the server, its firewall, DNS records and tunnel; "
                                 "the record stays")
    remove.add_argument("--record", type=Path, required=True, help="deployment.json")
    remove.add_argument("--confirm", required=True,
                        help="The server name again: the journal and signing key on the server are deleted with it")
    remove.add_argument("--provider-token-file", help="Provider credentials with write access")
    remove.add_argument("--cloudflare-token-file",
                        help="Token with Cloudflare Tunnel Edit, Zone Read and DNS Edit, and Zero Trust Edit for "
                     "--gateway-dns (or CLOUDFLARE_API_TOKEN)")
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            sys.stdout.write(plan(specification(args)))
        elif args.command == "deploy":
            args.wait = args.wait or {"generic": 60, "phala": 40}.get(args.provider, 20)
            if not 1 <= args.wait <= 240:
                parser.error("--wait must be 1-240 minutes")
            record, out = deploy(args, image=args.tdx_image)
            server, account = record["server"], record["cloudflare_account"]
            print("Deployment", record["deployment_id"], "is running (" + record["mode"] + ").")
            print("Collector key fingerprint:", record["collector"]["fingerprint"])
            rate = server.get("hourly_rate") or {}
            if rate.get("total"):
                print("Billed by " + get(record["provider"]).name + ":", rate["total"], "USD an hour (compute",
                      str(rate.get("compute")) + ", disk", str(rate.get("disk")) + ")")
            if record["beacon"]:
                print("Panel now: https://" + record["address"]["host"], "- token in", out / "panel-token.txt")
                print("The address changes when the server restarts; the current one is posted, signed with",
                      out / "address-key.txt", "to", record["beacon"])
                print("Server", server["id"], server.get("ipv4") or "", "- quick tunnel, no Cloudflare records")
            else:
                print("Panel: https://" + record["panel_host"], "- token in", out / "panel-token.txt")
                print("Server", server["id"], server.get("ipv4") or "", "- tunnel", record["tunnel"]["id"])
                print("Cloudflare records:", CLOUDFLARE_API + "/accounts/" + account + "/cfd_tunnel/"
                      + record["tunnel"]["id"] + "/connections")
            published = (record.get("cloud_init") or record.get("compose"))["published"]
            print("Publish the fingerprint through a separate channel. Give a verifier", out / "deployment.json",
                  "and", out / published, "with read-only credentials.")
        elif args.command == "lock":
            record = lock(args)
            print("Firewall", record["firewall"]["id"], "now admits no inbound connections.")
            if record["mode"] == "debug":
                print("Run sudo tgwitness-lock in the last SSH session first, or SSH keeps listening on the host.")
        elif args.command == "destroy":
            record, removed = destroy(args)
            for item in removed:
                print("Removed", item["resource"], item["id"], item.get("name") or "")
            print("Deployment", record["deployment_id"], "removed; its record stays in", args.record)
        elif args.command == "check-report":
            base = Path(args.report)
            base = base.with_suffix("") if base.suffix in (".json", ".md", ".html", ".pdf") else base
            for label, text in attestation_report.check(base, args.verifier_fingerprint):
                print("[PASS] " + label + ": " + text)
            print("The seal holds: " + str(base.with_suffix(".json")) + " is the report that was sealed.")
        else:
            report = verify(args)
            text = render(report)
            if args.report and report["verification_scope"] == "hardware-attestation":
                from .security import Vault
                vault = Vault(Path(args.sign_with).expanduser()) if args.sign_with != "none" else None
                tsas = () if args.timestamp == ["none"] else tuple(args.timestamp or attestation_report.TIME_STAMPS)
                sealed = attestation_report.write(report, text, args.report.with_suffix(""), vault, tsas)
                for c in report["checks"]:
                    print("[" + c["status"].upper() + "] " + c["title"] + ": " + c["detail"])
                for stamp in sealed["statement"]["time_stamps"]:
                    print("Time stamp", attestation_report.readable(stamp["time"]), "by",
                          attestation_report.common_name(stamp["signer"])
                          + (" - qualified eIDAS time stamp" if stamp.get("qualified") else ""))
                for stamp in sealed["failed_time_stamps"]:
                    print("No time stamp from", stamp["tsa"] + ":", stamp["error"])
                if sealed.get("fingerprint"):
                    print("Signed with verifier key", sealed["fingerprint"])
                print("Result:", report["result"].upper(), "- certificate", args.report.with_suffix(".html"), "and",
                      args.report.with_suffix(".pdf"))
            elif args.report:
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
