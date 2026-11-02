"""Hetzner Cloud: servers, firewalls and the per-server action log (api.hetzner.cloud)."""
import json
import time

from .base import DeployError, Provider, labels, network, pause, resource_name

METADATA = "http://169.254.169.254/hetzner/v1/"


def describe_rule(rule):
    return (rule.get("protocol") or "") + " " + (rule.get("port") or "") + " from " + ", ".join(rule.get("source_ips") or [])


def outbound_rule(rule):
    """A provider-neutral outbound rule (cloud.outbound_rules) as Hetzner writes it."""
    made = {"direction": "out", "protocol": rule["protocol"], "destination_ips": list(rule["destination"]),
            "description": "TgWitness: DNS only to Cloudflare Gateway"}
    if rule.get("port"):
        made["port"] = rule["port"]
    return made


def neutral_rule(rule):
    return {"protocol": rule.get("protocol"), "port": rule.get("port"), "destination": rule.get("destination_ips") or []}


class Hetzner(Provider):
    key, title, name, base = "hetzner", "Hetzner Cloud", "Hetzner", "https://api.hetzner.cloud/v1"
    variables = ("HCLOUD_TOKEN",)
    defaults = {"location": "nbg1", "image": "ubuntu-24.04"}
    example_type = "cpx22"
    ssh_key_help = "name or ID of an SSH key in the Hetzner project"
    write_access = "API token with Read & Write permission of a dedicated project"
    read_access = "API token with Read permission of the same project"
    log_retention = "server and firewall actions are listed while the resources exist"
    limits = ("Opening the web console needs a request_console action, which the log shows; the hypervisor "
              "and Hetzner staff remain outside any record here.",
              "Earlier firewall rule contents are not in the action log; set_firewall_rules only shows a change.")
    CREATION = ("create_server",)
    DEPLOYMENT = ("start_server", "apply_firewall")
    INTERRUPTIONS = ("start_server", "stop_server", "shutdown_server", "reboot_server", "reset_server")
    ACCESS = {
        "request_console": "web console (VNC) credentials requested",
        "enable_rescue": "rescue system enabled: another OS with access to the disk",
        "reset_password": "root password reset",
        "rebuild_server": "disk rebuilt from an image",
        "attach_iso": "ISO attached: the server can boot another OS",
        "create_image": "image of the disk created: a copy of the signing key at rest",
        "enable_backup": "provider backups enabled: copies of the disk, including the signing key at rest",
    }
    FAIL = {"remove_firewall": "firewall removed from the server"}
    REVIEW = {"set_firewall_rules": "firewall rules replaced; earlier rule contents are not in the provider log"}

    def ok(self, data):
        return isinstance(data, dict) and not data.get("error")

    def reason(self, data):
        error = data.get("error") if isinstance(data, dict) else None
        return str(error.get("code")) + ": " + str(error.get("message")) if isinstance(error, dict) else ""

    def pages(self, path, key, allow=(), params=None):
        items, page = [], 1
        while page:
            data = self.call("GET", path, params={**(params or {}), "page": page, "per_page": 50, "sort": "id:asc"},
                             allow=allow)
            if data is None:
                return items
            items += data[key]
            page = ((data.get("meta") or {}).get("pagination") or {}).get("next_page")
        return items

    def wait(self, action, timeout=900):
        deadline = time.monotonic() + timeout
        while action["status"] == "running":
            if time.monotonic() > deadline:
                raise DeployError("Hetzner action " + action["command"] + " is still running")
            pause(3)
            action = self.call("GET", "/actions/" + str(action["id"]))["action"]
        if action["status"] != "success":
            raise DeployError("Hetzner action " + action["command"] + " failed: " + json.dumps(action.get("error")))
        return action

    def create(self, spec, user_data, rules, outbound=()):
        # With any outbound rule, Hetzner drops outbound traffic that no rule allows.
        made = self.call("POST", "/firewalls", {"name": resource_name(spec), "labels": labels(spec), "rules": [
            {"direction": "in", "protocol": r["protocol"], "port": r["port"], "source_ips": [r["source"]],
             "description": "TgWitness debug SSH; remove with python -m tgwitness.cloud lock"} for r in rules]
            + [outbound_rule(r) for r in outbound]})
        for action in made.get("actions") or []:
            self.wait(action)
        firewall = made["firewall"]
        created = self.call("POST", "/servers", {
            "name": spec["name"], "server_type": spec["server_type"], "image": spec["image"],
            "location": spec["location"], "start_after_create": True, "user_data": user_data,
            "ssh_keys": [spec["ssh"]["debug_key"]] if spec["ssh"] != "disabled" else [],
            "firewalls": [{"firewall": firewall["id"]}], "labels": labels(spec),
            "public_net": {"enable_ipv4": True, "enable_ipv6": True}})
        for action in [created["action"], *(created.get("next_actions") or [])]:
            self.wait(action)
        server, net = created["server"], created["server"].get("public_net") or {}
        return ({"id": firewall["id"], "name": firewall["name"]},
                {"id": server["id"], "name": server["name"], "created": server["created"],
                 "image": (server.get("image") or {}).get("name"),
                 "ipv4": (net.get("ipv4") or {}).get("ip"), "ipv6": network((net.get("ipv6") or {}).get("ip")),
                 "root_password": "returned by the provider and discarded" if created.get("root_password") else None})

    def lock(self, record):
        keep = [outbound_rule(r) for r in record["firewall"].get("outbound_rules") or []]
        actions = self.call("POST", "/firewalls/" + str(record["firewall"]["id"]) + "/actions/set_rules",
                            {"rules": keep})["actions"]
        for action in actions:
            self.wait(action)
        return [a["id"] for a in actions]

    def destroy(self, record):
        # By label, so a deployment that failed before its record listed the server is removed as well.
        selector = {"label_selector": "tgwitness-deployment=" + record["deployment_id"]}
        removed = []
        for server in self.pages("/servers", "servers", params=selector):
            self.wait(self.call("DELETE", "/servers/" + str(server["id"]))["action"])
            removed.append({"resource": "server", "id": server["id"], "name": server["name"]})
        for firewall in self.pages("/firewalls", "firewalls", params=selector):
            for attempt in range(12):
                try:
                    self.call("DELETE", "/firewalls/" + str(firewall["id"]), allow=(404,))
                    break
                except DeployError:
                    if attempt == 11:
                        raise
                    pause(5)  # still detaching from the deleted server
            removed.append({"resource": "firewall", "id": firewall["id"], "name": firewall["name"]})
        return removed

    def describe(self, record):
        data = self.call("GET", "/servers/" + str(record["server"]["id"]), allow=(404,))
        if not data:
            return None
        server, net = data["server"], data["server"].get("public_net") or {}
        flags = [text for flag, text in ((server.get("rescue_enabled"), "rescue system enabled"),
                                         (server.get("iso"), "ISO attached"),
                                         (server.get("backup_window"), "provider backups enabled")) if flag]
        return {"id": server["id"], "name": server["name"], "created": server["created"],
                "image": (server.get("image") or {}).get("name"), "type": (server.get("server_type") or {}).get("name"),
                "location": (server.get("location") or {}).get("name"), "ipv4": (net.get("ipv4") or {}).get("ip"),
                "ipv6": network((net.get("ipv6") or {}).get("ip")), "flags": flags,
                "belongs": server["name"] == record["name"]
                and (server.get("labels") or {}).get("tgwitness-deployment") == record["deployment_id"],
                "firewalls": net.get("firewalls") or []}

    def firewall(self, record, server):
        wanted, applied, problems, inbound = record["firewall"]["id"], server["firewalls"], [], []
        outbound = []
        if not any(f["id"] == wanted and f["status"] == "applied" for f in applied):
            problems.append("the deployment firewall " + str(wanted) + " is not applied")
        if not applied:
            problems.append("no provider firewall: every port is reachable from the internet")
        for item in applied:
            found = self.call("GET", "/firewalls/" + str(item["id"]), allow=(404,))
            if found:
                inbound += [describe_rule(r) for r in found["firewall"]["rules"] if r["direction"] == "in"]
                outbound += [neutral_rule(r) for r in found["firewall"]["rules"] if r["direction"] == "out"]
        # Hetzner merges the rules of every firewall applied to a server: any of them may let traffic out.
        return {"problems": problems, "inbound": inbound, "changed": None, "outbound": outbound}

    def actions(self, record, server):
        rows = []
        for resource, path in (("server", "/servers/" + str(server["id"])),
                               ("firewall", "/firewalls/" + str(record["firewall"]["id"]))):

            for action in self.pages(path + "/actions", "actions", allow=(404,) if resource == "firewall" else ()):
                rows.append({"resource": resource, "id": action["id"], "command": action["command"],
                             "started": action["started"], "finished": action.get("finished"),
                             "status": action["status"], "actor": None})
        return rows

    @staticmethod
    def metadata(request, root):
        return {"instance_id": int(request(METADATA + "metadata/instance-id").strip()),
                "hostname": request(METADATA + "metadata/hostname").strip(),
                "public_ipv4": request(METADATA + "metadata/public-ipv4").strip(),
                "region": request(METADATA + "metadata/region").strip(),
                "user_data": request(METADATA + "userdata")}


PROVIDER = Hetzner
