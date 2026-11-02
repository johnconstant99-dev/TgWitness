"""Akamai Cloud (Linode): instances, Cloud Firewalls with rule versions and account events."""
import base64
import ipaddress
import json
import secrets

from .base import DeployError, Provider, network

METADATA = "http://169.254.169.254/v1/"


class Linode(Provider):
    key, title, name, base = "linode", "Akamai Cloud (Linode)", "Linode", "https://api.linode.com/v4"
    variables = ("LINODE_TOKEN",)
    defaults = {"location": "eu-central", "image": "linode/ubuntu24.04"}
    example_type = "g6-standard-1"
    ssh_key_help = "Linode username whose profile SSH keys are added to root (authorized_users)"
    user_data_limit = 65535
    write_access = "personal access token with linodes, firewall and events read/write scopes"
    read_access = "personal access token with linodes:read_only, firewall:read_only and events:read_only"
    log_retention = "account events cover the last 90 days"
    limits = ("Lish and Glish console sessions are not account events. Root is locked at the first boot, so a "
              "console login needs a password reset or a boot configuration change, which are events.",
              "Cloud-init user data needs a region with the Metadata service.",
              "Account events cover 90 days: produce the report within that period.")
    CREATION = ("linode_create",)
    DEPLOYMENT = ("linode_boot", "linode_config_create", "disk_create", "firewall_create", "firewall_device_add",
                  "firewall_apply")
    INTERRUPTIONS = ("linode_boot", "linode_reboot", "linode_shutdown", "host_reboot", "lassie_reboot",
                     "linode_poweroff_on")
    ACCESS = {
        "password_reset": "root password reset",
        "linode_rebuild": "disk rebuilt from an image",
        "lish_boot": "booted from the Lish console",
        "linode_snapshot": "snapshot of the disks: a copy of the signing key at rest",
        "backups_enable": "provider backups enabled: copies of the disk, including the signing key at rest",
        "backups_restore": "disk restored from a backup",
        "disk_imagize": "image of a disk created: a copy of the signing key at rest",
        "disk_duplicate": "disk duplicated",
        "linode_clone": "server cloned, including its disks",
        "linode_config_create": "boot configuration created: can boot another kernel or a rescue system",
        "linode_config_update": "boot configuration changed: can boot another kernel or a rescue system",
    }
    FAIL = {"firewall_disable": "firewall disabled", "firewall_device_remove": "firewall removed from the server",
            "firewall_delete": "firewall deleted", "disk_create": "disk created", "disk_update": "disk changed"}
    REVIEW = {"firewall_rules_update": "firewall rules changed; compare the rule version",
              "firewall_update": "firewall label or tags changed", "linode_update": "server settings changed",
              "disk_resize": "disk resized", "linode_resize": "server resized", "linode_migrate": "moved to another host",
              "linode_mutate": "server upgraded", "linode_addip": "address added", "linode_deleteip": "address removed"}

    def reason(self, data):
        errors = data.get("errors") if isinstance(data, dict) else None
        return "; ".join(str(e.get("field") or "") + " " + str(e.get("reason")) for e in errors or [] if isinstance(e, dict))

    def instance(self, linode_id, allow=()):
        return self.call("GET", "/linode/instances/" + str(linode_id), allow=allow)

    def create(self, spec, user_data, rules, outbound=()):
        if outbound:
            raise DeployError(self.title + ": outbound firewall rules are not implemented here")
        if not 3 <= len(spec["name"]) <= 64:
            raise DeployError("Linode labels need 3 to 64 characters; choose another --name")
        tag = "tgwitness-" + spec["deployment_id"]
        firewall = self.call("POST", "/networking/firewalls", {"label": tag, "tags": [tag], "rules": {
            "inbound_policy": "DROP", "outbound_policy": "ACCEPT", "outbound": [], "inbound": [
                {"action": "ACCEPT", "protocol": r["protocol"].upper(), "ports": r["port"], "label": "tgwitness-debug-ssh",
                 "addresses": {"ipv" + str(ipaddress.ip_network(r["source"]).version): [r["source"]]}} for r in rules]}})
        body = {"label": spec["name"], "region": spec["location"], "type": spec["server_type"],
                "image": spec["image"], "root_pass": "aA1!" + secrets.token_urlsafe(32), "booted": False,
                "backups_enabled": False, "firewall_id": firewall["id"], "tags": [tag],
                "metadata": {"user_data": base64.b64encode(user_data.encode()).decode()}}
        if spec["ssh"] != "disabled":
            body["authorized_users"] = [spec["ssh"]["debug_key"]]
        linode = self.call("POST", "/linode/instances", body)
        attached = self.call("GET", "/linode/instances/" + str(linode["id"]) + "/firewalls").get("data") or []
        if not any(f["id"] == firewall["id"] for f in attached):
            self.call("POST", "/networking/firewalls/" + str(firewall["id"]) + "/devices",
                      {"type": "linode", "id": linode["id"]})

        self.wait_until(lambda: self.instance(linode["id"])["status"] == "offline", "provisioning")
        self.call("POST", "/linode/instances/" + str(linode["id"]) + "/boot", {})
        linode = self.wait_until(lambda: (lambda found: found if found["status"] == "running" else None)(
            self.instance(linode["id"])), "boot")
        return ({"id": firewall["id"], "name": firewall["label"]},
                {"id": linode["id"], "name": linode["label"], "created": linode["created"], "image": linode.get("image"),
                 "ipv4": public_ipv4(linode), "ipv6": network(linode.get("ipv6")),
                 "root_password": "random, never stored; root is locked at the first boot"})

    def lock(self, record):
        self.call("PUT", "/networking/firewalls/" + str(record["firewall"]["id"]) + "/rules",
                  {"inbound_policy": "DROP", "outbound_policy": "ACCEPT", "inbound": [], "outbound": []})
        return []

    def describe(self, record):
        linode = self.instance(record["server"]["id"], allow=(404,))
        if not linode:
            return None
        flags = ["provider backups enabled"] if (linode.get("backups") or {}).get("enabled") else []
        return {"id": linode["id"], "name": linode["label"], "created": linode["created"], "image": linode.get("image"),
                "type": linode.get("type"), "location": linode.get("region"), "ipv4": public_ipv4(linode),
                "ipv6": network(linode.get("ipv6")), "flags": flags,
                "belongs": linode["label"] == record["name"]
                and "tgwitness-" + record["deployment_id"] in (linode.get("tags") or [])}

    def firewall(self, record, server):
        wanted = record["firewall"]["id"]
        applied = self.call("GET", "/linode/instances/" + str(server["id"]) + "/firewalls").get("data") or []
        enabled = [f for f in applied if f.get("status") == "enabled"]
        problems = [] if any(f["id"] == wanted for f in enabled) else \
            ["the deployment firewall " + str(wanted) + " is not applied and enabled"]
        if not enabled:
            problems.append("no enabled Cloud Firewall: every port is reachable from the internet")
        inbound = []
        for f in enabled:
            rules = f.get("rules") or {}
            if rules.get("inbound_policy") != "DROP":
                problems.append("firewall " + f["label"] + " accepts inbound traffic by default")
            inbound += [f["label"] + ": " + str(r.get("protocol")) + " " + str(r.get("ports", "")) + " from "
                        + json.dumps(r.get("addresses") or {}) for r in rules.get("inbound") or []
                        if r.get("action") == "ACCEPT"]
        version = (self.call("GET", "/networking/firewalls/" + str(wanted) + "/rules", allow=(404,)) or {}).get("version")
        changed = "rules version " + str(version) + ": changed since creation" if version and version > 1 else None
        return {"problems": problems, "inbound": inbound, "changed": changed}

    def events(self, query):
        rows, page = [], 1
        while True:
            data = self.call("GET", "/account/events", params={"page": page, "page_size": 100},
                             headers={"X-Filter": json.dumps(query)})
            rows += data.get("data") or []
            if page >= (data.get("pages") or 1):
                return rows
            page += 1

    def actions(self, record, server):

        found = {e["id"]: e for query in ({"entity.id": server["id"]},
                                          {"entity.id": record["firewall"]["id"], "entity.type": "firewall"})
                 for e in self.events(query)}
        return [{"resource": (e.get("entity") or {}).get("type"), "id": e["id"], "command": e["action"],
                 "started": e["created"], "finished": None, "actor": e.get("username"),
                 "status": "error" if e.get("status") == "failed" else
                 "running" if e.get("status") in ("started", "scheduled", "in_progress") else "success"}
                for e in sorted(found.values(), key=lambda e: e["id"])]

    @staticmethod
    def metadata(request, root):
        token = request(METADATA + "token", "PUT", {"Metadata-Token-Expiry-Seconds": "300"}).strip()
        headers = {"Metadata-Token": token, "Accept": "application/json"}
        instance = json.loads(request(METADATA + "instance", "GET", headers))
        addresses = ((json.loads(request(METADATA + "network", "GET", headers)).get("ipv4") or {}).get("public") or [])
        return {"instance_id": instance["id"], "hostname": instance.get("label"), "region": instance.get("region"),
                "public_ipv4": addresses[0].split("/")[0] if addresses else None,
                "user_data": base64.b64decode(request(METADATA + "user-data", "GET", {"Metadata-Token": token})).decode()}


PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def public_ipv4(linode):

    found = [a for a in linode.get("ipv4") or [] if not any(ipaddress.ip_address(a) in n for n in PRIVATE)]
    return found[0] if found else None


PROVIDER = Linode
