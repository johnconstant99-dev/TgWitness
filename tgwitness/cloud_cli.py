import argparse
import json
from pathlib import Path
import subprocess
import sys

import requests

from . import attestation_report
from .providers import NAMES, get
from .providers.base import DeployError


def add_target(parser, repository):
    parser.add_argument("--provider", required=True, choices=NAMES, help="Where the server runs")
    parser.add_argument("--name", required=True, help="Server name; also the deployment directory name")
    parser.add_argument("--server-type", help="Provider server type, e.g. cpx22, s-1vcpu-2gb, g6-standard-1, "
                        "vc2-1c-2gb, t3.small, tdx.small (phala)")
    parser.add_argument("--location", help="Provider location or region (default per provider)")
    parser.add_argument("--image", help="Image (default Ubuntu 24.04 of the provider)")
    parser.add_argument("--ref", required=True, help="40-character commit, or a release tag resolved once with git")
    parser.add_argument("--repository", default=repository, help="Git repository (https)")
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


def build_parser(cloud):
    parser = argparse.ArgumentParser(prog="python -m tgwitness.cloud",
                                     description="High-assurance collector on a cloud server behind a Cloudflare Tunnel")
    commands = parser.add_subparsers(dest="command", required=True)
    preview = commands.add_parser("plan", help="Print the published installer and API calls; nothing is created")
    cloud.add_target(preview)
    run = commands.add_parser("deploy", help="Create tunnel, DNS, firewall and server; wait for the collector key")
    cloud.add_target(run)
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
    check.add_argument("--trust-source", action="store_true",
                       help="Allow --source from a repository other than the official one; its code runs on this computer")
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
    return parser


def main(argv, cloud):
    parser = build_parser(cloud)
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            sys.stdout.write(cloud.plan(cloud.specification(args)))
        elif args.command == "deploy":
            args.wait = args.wait or {"generic": 60, "phala": 40}.get(args.provider, 20)
            if not 1 <= args.wait <= 240:
                parser.error("--wait must be 1-240 minutes")
            record, out = cloud.deploy(args, image=args.tdx_image)
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
                print("Cloudflare records:", cloud.CLOUDFLARE_API + "/accounts/" + account + "/cfd_tunnel/"
                      + record["tunnel"]["id"] + "/connections")
            published = (record.get("cloud_init") or record.get("compose"))["published"]
            print("Publish the fingerprint through a separate channel. Give a verifier", out / "deployment.json",
                  "and", out / published, "with read-only credentials.")
        elif args.command == "lock":
            record = cloud.lock(args)
            print("Firewall", record["firewall"]["id"], "now admits no inbound connections.")
            if record["mode"] == "debug":
                print("Run sudo tgwitness-lock in the last SSH session first, or SSH keeps listening on the host.")
        elif args.command == "destroy":
            record, removed = cloud.destroy(args)
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
            report = cloud.verify(args)
            text = cloud.render(report)
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
