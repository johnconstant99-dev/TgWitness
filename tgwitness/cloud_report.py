import json
import uuid

COVERAGE_TITLE = "What this report covers"
SCOPE_TITLE = "Outside this report's scope"


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


RUNTIME = {"not-performed": "Self-reported by the collector; no independent runtime attestation",
           "intel-tdx": "Intel TDX quote over the collector's statement, checked by this verifier to Intel's root",
           "failed": "**An Intel TDX quote was expected and did not verify**"}


CUSTODY = {"not-established": "Custody is recorded for the key's use inside this deployment",
           "established-by-measured-code": "Created and kept inside the attested CVM by the measured commit; "
                                           "the OS image measurements match",
           "conditional-on-os-image": "Created inside the attested CVM by the measured commit; the OS image "
                                      "measurements were not compared with the published image"}


def cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def render(report, *, cloudflare_api, gateway_host):
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
                + cell(deployment["gateway"].get("doh_subdomain")) + gateway_host + " |"] if deployment.get("gateway") else []),
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
                  "- `GET " + cloudflare_api + "/accounts/" + str(account) + "/cfd_tunnel/" + tunnel + "/connections`",
                  "- `GET " + cloudflare_api + "/accounts/" + str(account) + "/cfd_tunnel/" + tunnel + "/configurations`",
                  "- `GET " + cloudflare_api + "/accounts/" + str(account) + "/audit_logs`"]
    gateway = deployment.get("gateway")
    if gateway and gateway.get("location_id"):
        path = cloudflare_api + "/accounts/" + str(gateway["account"]) + "/gateway"
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
    lines += ["", "## " + COVERAGE_TITLE, ""] + ["- " + t for t in report["establishes"]]
    lines += ["", "## " + SCOPE_TITLE, ""] + ["- " + t for t in report["does_not_establish"]]
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
