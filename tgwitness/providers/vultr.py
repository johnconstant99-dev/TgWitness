"""Vultr: instances, firewall groups and the account activity log (api.vultr.com).

The activity log records each API and portal request with its method, path and body. Only the
names of body fields are kept: an instance's creation request carries its user data.
"""
import base64
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone

from .base import DeployError, Provider, network, parse_time, resource_name

METADATA = "http://169.254.169.254/v1.json"
ACCESS_PATHS = {"reinstall": "disk reinstalled", "restore": "disk restored from a backup or snapshot",
                "iso": "ISO attached: the server can boot another OS",
                "backup-schedule": "provider backups scheduled: copies of the disk, including the signing key at rest"}
ACCESS_FIELDS = {"backups", "os_id", "app_id", "image_id", "snapshot_id", "iso_id", "user_data", "firewall_group_id"}


class Vultr(Provider):
    key, title, name, base = "vultr", "Vultr", "Vultr", "https://api.vultr.com/v2"
    variables = ("VULTR_API_KEY",)
    defaults = {"location": "fra", "image": "ubuntu-24.04"}
    example_type = "vc2-1c-2gb"
    ssh_key_help = "ID of an SSH key in the Vultr account"
    write_access = "API key of a dedicated account or sub-account"
    read_access = "API key of a user with read access and the activity_logs permission"
    log_retention = "the activity log keeps 30 days unless an audit-log subscription preserves it"
    limits = ("Any API key that can read the instance also receives its console (KVM) address and its user data, "
              "which holds the panel and tunnel tokens. Root is locked at the first boot, and neither the record nor "
              "this report stores either.",
              "The activity log keeps 30 days unless an audit-log subscription preserves it.",
              "Opening the web console is not identified as such in the activity log.")

    def reason(self, data):
        return str(data.get("error")) if isinstance(data, dict) else ""

    def instance(self, instance_id, allow=()):
        data = self.call("GET", "/instances/" + str(instance_id), allow=allow)
        return data["instance"] if data else None

    def os_id(self, image):
        if image.isdigit():
            return int(image)
        wanted, cursor, found = image.lower().replace("-", " "), None, []
        while True:
            data = self.call("GET", "/os", params={"per_page": 500, **({"cursor": cursor} if cursor else {})})
            found += [o for o in data.get("os") or [] if o.get("name", "").lower().startswith(wanted)
                      and o.get("arch") == "x64"]
            cursor = ((data.get("meta") or {}).get("links") or {}).get("next")
            if not cursor:
                break
        if not found:
            raise DeployError("Vultr has no x64 operating system named like " + image + "; pass its numeric os_id")
        return found[0]["id"]

    def create(self, spec, user_data, rules, outbound=()):
        if outbound:
            raise DeployError(self.title + ": outbound firewall rules are not implemented here")
        tag = "tgwitness-" + spec["deployment_id"]
        firewall = self.call("POST", "/firewalls", {"description": resource_name(spec)})["firewall_group"]
        for rule in rules:
            net = ipaddress.ip_network(rule["source"])
            self.call("POST", "/firewalls/" + firewall["id"] + "/rules", {
                "ip_type": "v" + str(net.version), "protocol": rule["protocol"], "port": rule["port"],
                "subnet": str(net.network_address), "subnet_size": net.prefixlen, "notes": "TgWitness debug SSH"})
        body = {"region": spec["location"], "plan": spec["server_type"], "os_id": self.os_id(spec["image"]),
                "label": spec["name"], "hostname": spec["name"], "tags": [tag],
                "user_data": base64.b64encode(user_data.encode()).decode(), "firewall_group_id": firewall["id"],
                "enable_ipv6": True, "backups": "disabled", "activation_email": False}
        if spec["ssh"] != "disabled":
            body["sshkey_id"] = [spec["ssh"]["debug_key"]]
        created = self.call("POST", "/instances", body)["instance"]
        instance = self.wait_until(lambda: (lambda i: i if i["status"] == "active" and i.get("main_ip") not in
                                            (None, "", "0.0.0.0") else None)(self.instance(created["id"])), "installation")
        return ({"id": firewall["id"], "name": resource_name(spec)},
                {"id": instance["id"], "name": instance["label"], "created": instance["date_created"],
                 "image": instance.get("os"), "ipv4": instance["main_ip"], "ipv6": ipv6(instance),
                 "root_password": "returned by the provider and discarded" if created.get("default_password") else None})

    def rules(self, firewall_id):
        rules, cursor = [], None
        while True:
            data = self.call("GET", "/firewalls/" + firewall_id + "/rules",
                             params={"per_page": 500, **({"cursor": cursor} if cursor else {})})
            rules += data.get("firewall_rules") or []
            cursor = ((data.get("meta") or {}).get("links") or {}).get("next")
            if not cursor:
                return rules

    def lock(self, record):
        for rule in self.rules(record["firewall"]["id"]):
            self.call("DELETE", "/firewalls/" + record["firewall"]["id"] + "/rules/" + str(rule["id"]))
        return []

    def describe(self, record):
        instance = self.instance(record["server"]["id"], allow=(404,))
        if not instance:
            return None
        iso = (self.call("GET", "/instances/" + instance["id"] + "/iso", allow=(404,)) or {}).get("iso_status") or {}
        flags = [text for flag, text in (("auto_backups" in (instance.get("features") or []), "provider backups enabled"),
                                         (iso.get("state") in ("isomounted", "ismounting"), "ISO attached")) if flag]

        return {"id": instance["id"], "name": instance["label"], "created": instance["date_created"],
                "image": instance.get("os"), "type": instance.get("plan"), "location": instance.get("region"),
                "ipv4": instance.get("main_ip"), "ipv6": ipv6(instance), "flags": flags,
                "firewall_group": instance.get("firewall_group_id") or None,
                "belongs": instance["label"] == record["name"]
                and "tgwitness-" + record["deployment_id"] in (instance.get("tags") or [])}

    def firewall(self, record, server):
        current, problems = server["firewall_group"], []
        if not current:
            problems.append("no firewall group: every port is reachable from the internet")
        elif current != record["firewall"]["id"]:
            problems.append("another firewall group " + current + " is applied")
        inbound = [str(r.get("protocol")) + " " + str(r.get("port") or "") + " from "
                   + (r.get("source") or str(r.get("subnet")) + "/" + str(r.get("subnet_size")))
                   for r in (self.rules(current) if current else [])]
        return {"problems": problems, "inbound": inbound, "changed": None}

    def actions(self, record, server):
        ids = (str(server["id"]), str(record["firewall"]["id"]))
        start = (parse_time(server["created"]) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        window = {"start_time": start, "end_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        found, missing = {}, 0
        for query in ({"resource_type": "instances", "resource_id": ids[0]}, {}):
            data = self.call("GET", "/logs", params={**window, **query})
            missing = max(missing, ((data.get("meta") or {}).get("unreturned_count")) or 0)
            for entry in data.get("logs") or []:
                meta = entry.get("metadata") or {}
                text = " ".join(str(v) for v in (entry.get("resource_id"), meta.get("request_path"), meta.get("request_body")))
                if (meta.get("method") or "GET").upper() != "GET" and any(i in text for i in ids):
                    found[(entry.get("timestamp"), meta.get("method"), meta.get("request_path"))] = entry
        rows = [action(entry, ids) for _, entry in sorted(found.items(), key=lambda item: str(item[0][0]))]
        if missing:
            rows.append({"resource": "log", "id": "-", "command": "LOG incomplete", "started": None, "finished": None,
                         "status": "success", "actor": None, "unreturned": missing})
        return rows

    def classify(self, action, created):
        if action["command"] == "LOG incomplete":
            return "review", str(action["unreturned"]) + " log entries were not returned; narrow the period"
        method, path = action["command"].split(" ", 1)
        fields = set(action.get("fields") or ())
        early = (parse_time(action.get("started") or created.isoformat()) - created).total_seconds() <= self.window
        failed = action["status"] == "error"
        tail = path.rsplit("/", 1)[-1]

        def access(meaning):
            return ("review", meaning + " (the request failed)") if failed else ("fail", meaning)
        if method == "POST" and path.endswith("/instances"):
            return "pass", "server created"
        if early and method == "POST" and re.search(r"/firewalls(/\{firewall\}/rules)?$", path):
            return "pass", "part of the deployment"
        if method == "POST" and "/instances/{instance}/" in path and tail in ACCESS_PATHS:
            return access(ACCESS_PATHS[tail])
        if method == "POST" and path.endswith("/snapshots"):
            return access("snapshot of the disk: a copy of the signing key at rest")
        if method == "PATCH" and path.endswith("/instances/{instance}"):
            changed = sorted(fields & ACCESS_FIELDS)
            return access("instance changed: " + ", ".join(changed)) if changed else ("review", "instance settings changed")
        if method == "POST" and path.endswith("/firewalls/{firewall}/rules"):
            return access("firewall rule added")
        if method == "DELETE" and "/firewalls/{firewall}" in path:
            return "review", "firewall rule or group removed"
        if tail in ("halt", "reboot", "start", "stop"):
            return "review", "power or restart: collection was interrupted; compare with the journal"
        return "review", "not expected in this mode"

    @staticmethod
    def metadata(request, root):
        found = json.loads(request(METADATA))
        region = found.get("region")
        public = [i.get("ipv4", {}).get("address") for i in found.get("interfaces") or [] if i.get("network-type") == "public"]
        user_data = found.get("user-data") or ""
        try:
            decoded = base64.b64decode(user_data, validate=True).decode()
            user_data = decoded if decoded.startswith("#cloud-config") else user_data
        except ValueError:
            pass
        return {"instance_id": found.get("instance-v2-id"), "hostname": found.get("hostname"),
                "region": region.get("regioncode") if isinstance(region, dict) else region,
                "public_ipv4": public[0] if public else None, "user_data": user_data}


def ipv6(instance):
    return network(instance["v6_network"] + "/" + str(instance.get("v6_network_size") or 64)) \
        if instance.get("v6_network") else None


def action(entry, ids):
    meta = entry.get("metadata") or {}
    body = meta.get("request_body")
    try:
        body = json.loads(body) if isinstance(body, str) else body
    except ValueError:
        body = None
    path = str(meta.get("request_path") or "").split("?", 1)[0].replace(ids[0], "{instance}").replace(ids[1], "{firewall}")
    return {"resource": entry.get("resource_type"), "id": entry.get("timestamp"),
            "command": str(meta.get("method") or "").upper() + " " + path, "started": entry.get("timestamp"),
            "finished": None, "status": "error" if (meta.get("http_status_code") or 0) >= 400 else "success",
            "actor": " ".join(str(v) for v in (meta.get("username"), meta.get("ip_address")) if v) or None,
            "fields": sorted(body) if isinstance(body, dict) else []}


PROVIDER = Vultr
