"""DigitalOcean: Droplets, Cloud Firewalls and Droplet actions (api.digitalocean.com)."""
import json

from .base import DeployError, Provider, network, resource_name

METADATA = "http://169.254.169.254/metadata/v1.json"
ANYWHERE = {"addresses": ["0.0.0.0/0", "::/0"]}
OUTBOUND = [{"protocol": "tcp", "ports": "0", "destinations": ANYWHERE},
            {"protocol": "udp", "ports": "0", "destinations": ANYWHERE},
            {"protocol": "icmp", "destinations": ANYWHERE}]


class DigitalOcean(Provider):
    key, title, name, base = "digitalocean", "DigitalOcean", "DigitalOcean", "https://api.digitalocean.com/v2"
    variables = ("DIGITALOCEAN_TOKEN",)
    defaults = {"location": "fra1", "image": "ubuntu-24-04-x64"}
    example_type = "s-1vcpu-2gb"
    ssh_key_help = "ID or fingerprint of an SSH key in the DigitalOcean team"
    user_data_limit = 64 * 1024
    write_access = "personal access token with write access of a dedicated team"
    read_access = "read-only personal access token of the same team"
    log_retention = "Droplet actions are listed while the Droplet exists"
    limits = ("The Recovery Console is not a Droplet action. The web console agent is not installed and root is "
              "locked at the first boot, so a console login needs a password reset, which is an action.",
              "Cloud Firewall changes have no history in the API; only the current rules can be checked.",
              "A tag-based firewall is applied by DigitalOcean moments after creation, not before the first packet.")
    CREATION = ("create",)
    INTERRUPTIONS = ("reboot", "power_cycle", "shutdown", "power_off", "power_on")
    ACCESS = {
        "password_reset": "root password reset",
        "rebuild": "disk rebuilt from an image",
        "restore": "disk restored from a backup or snapshot",
        "snapshot": "snapshot of the disk: a copy of the signing key at rest",
        "enable_backups": "provider backups enabled: copies of the disk, including the signing key at rest",
        "change_kernel": "boot kernel changed",
    }
    REVIEW = {"resize": "server resized", "rename": "server renamed", "enable_ipv6": "IPv6 enabled",
              "disable_backups": "backups disabled", "change_backup_policy": "backup policy changed"}

    def reason(self, data):
        return str(data.get("id")) + ": " + str(data.get("message")) if isinstance(data, dict) else ""

    def wait(self, action_id):
        def done():
            status = self.call("GET", "/actions/" + str(action_id))["action"]["status"]
            if status == "errored":
                raise DeployError("DigitalOcean action " + str(action_id) + " failed")
            return status == "completed"
        self.wait_until(done, "action " + str(action_id))

    def create(self, spec, user_data, rules, outbound=()):
        if outbound:
            raise DeployError(self.title + ": outbound firewall rules are not implemented here")
        tag = "tgwitness-" + spec["deployment_id"]
        firewall = self.call("POST", "/firewalls", {
            "name": resource_name(spec), "tags": [tag], "outbound_rules": OUTBOUND,
            "inbound_rules": [{"protocol": r["protocol"], "ports": r["port"], "sources": {"addresses": [r["source"]]}}
                              for r in rules]})["firewall"]
        key = spec["ssh"]["debug_key"] if spec["ssh"] != "disabled" else None
        created = self.call("POST", "/droplets", {
            "name": spec["name"], "region": spec["location"], "size": spec["server_type"], "image": spec["image"],
            "ssh_keys": [int(key) if key.isdigit() else key] if key else [], "backups": False, "ipv6": True,
            "monitoring": False, "with_droplet_agent": False, "tags": [tag], "user_data": user_data})
        for link in (created.get("links") or {}).get("actions") or []:
            self.wait(link["id"])
        droplet = self.droplet(created["droplet"]["id"])
        return ({"id": firewall["id"], "name": firewall["name"]},
                {"id": droplet["id"], "name": droplet["name"], "created": droplet["created_at"],
                 "image": (droplet.get("image") or {}).get("slug"), "ipv4": public(droplet)[0], "ipv6": public(droplet)[1],
                 "root_password": None if key else "emailed by the provider; root is locked at the first boot"})

    def droplet(self, droplet_id, allow=()):
        data = self.call("GET", "/droplets/" + str(droplet_id), allow=allow)
        return data["droplet"] if data else None

    def lock(self, record):
        firewall = self.call("GET", "/firewalls/" + str(record["firewall"]["id"]))["firewall"]
        if firewall.get("inbound_rules"):
            self.call("DELETE", "/firewalls/" + str(firewall["id"]) + "/rules",
                      {"inbound_rules": firewall["inbound_rules"]})
        return []

    def describe(self, record):
        droplet = self.droplet(record["server"]["id"], allow=(404,))
        if not droplet:
            return None
        features = droplet.get("features") or []
        flags = [text for flag, text in (("backups" in features or droplet.get("backup_ids"), "provider backups enabled"),
                                         (droplet.get("snapshot_ids"), "snapshots of the disk exist"),
                                         ("droplet_agent" in features, "web console agent installed")) if flag]
        ipv4, ipv6 = public(droplet)
        return {"id": droplet["id"], "name": droplet["name"], "created": droplet["created_at"],
                "image": (droplet.get("image") or {}).get("slug"), "type": droplet.get("size_slug"),
                "location": (droplet.get("region") or {}).get("slug"), "ipv4": ipv4, "ipv6": ipv6, "flags": flags,
                "belongs": droplet["name"] == record["name"]
                and "tgwitness-" + record["deployment_id"] in (droplet.get("tags") or [])}

    def firewall(self, record, server):
        applied = self.call("GET", "/droplets/" + str(server["id"]) + "/firewalls").get("firewalls") or []
        problems = [] if any(f["id"] == record["firewall"]["id"] for f in applied) else \
            ["the deployment firewall " + str(record["firewall"]["id"]) + " is not applied"]
        if not applied:
            problems.append("no Cloud Firewall: every port is reachable from the internet")
        problems += ["firewall " + f["name"] + " failed to apply" for f in applied if f.get("status") == "failed"]
        inbound = [f["name"] + ": " + r["protocol"] + " " + str(r.get("ports", "")) + " from "
                   + json.dumps(r.get("sources") or {}) for f in applied for r in f.get("inbound_rules") or []
                   if r.get("action", "allow") == "allow"]
        return {"problems": problems, "inbound": inbound, "changed": None}

    def actions(self, record, server):
        rows, page = [], 1
        while page:
            data = self.call("GET", "/droplets/" + str(server["id"]) + "/actions", params={"page": page, "per_page": 200})
            for action in data.get("actions") or []:
                rows.append({"resource": "droplet", "id": action["id"], "command": action["type"],
                             "started": action.get("started_at"), "finished": action.get("completed_at"),
                             "status": {"completed": "success", "errored": "error"}.get(action["status"], "running"),
                             "actor": None})
            page = page + 1 if ((data.get("links") or {}).get("pages") or {}).get("next") else None
        return rows

    @staticmethod
    def metadata(request, root):
        found = json.loads(request(METADATA))
        interface = (((found.get("interfaces") or {}).get("public")) or [{}])[0]
        return {"instance_id": found["droplet_id"], "hostname": found.get("hostname"),
                "public_ipv4": (interface.get("ipv4") or {}).get("ip_address"), "region": found.get("region"),
                "user_data": found.get("user_data") or ""}


def public(droplet):
    networks = droplet.get("networks") or {}
    ipv4 = [n["ip_address"] for n in networks.get("v4") or [] if n.get("type") == "public"]
    ipv6 = [n for n in networks.get("v6") or [] if n.get("type") == "public"]
    return (ipv4[0] if ipv4 else None,
            network(ipv6[0]["ip_address"] + "/" + str(ipv6[0].get("netmask", 128))) if ipv6 else None)


PROVIDER = DigitalOcean
