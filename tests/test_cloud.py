"""Cloud deployment with fake provider and Cloudflare APIs."""
import base64
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace as NS
from urllib.parse import parse_qs, urlsplit

import pytest

from tgwitness import assurance, cloud
from tgwitness.evidence import export_file
from tgwitness.providers import base, get
from tgwitness.providers.aws import signed_headers
from tgwitness.provenance import source_files, source_tree_sha256
from tgwitness.security import Vault
from tgwitness.verify import fingerprint

ROOT = Path(__file__).resolve().parents[1]
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


class Hetzner(World):
    key, server_type = "hetzner", "cpx22"
    ipv4, server_id = "192.0.2.10", 42

    def __init__(self):
        super().__init__()
        self.firewall, self.actions_of = None, {"server": [], "firewall": []}

    def action(self, number, command, started=CREATED, status="success"):
        return {"id": number, "command": command, "status": status, "started": started, "finished": started,
                "progress": 100, "error": None, "resources": []}

    def provider(self, method, url, body, params, headers, data):
        assert headers["Authorization"].startswith("Bearer ")
        path = url[len("https://api.hetzner.cloud/v1"):]
        if path == "/firewalls" and method == "POST":
            self.firewall = {"id": 77, "name": body["name"], "labels": body["labels"], "rules": body["rules"]}
            self.rules_action = self.action(5, "set_firewall_rules", status="running")
            return Response(201, {"firewall": self.firewall, "actions": [self.rules_action]})
        if path == "/actions/5":
            self.rules_action["status"] = "success"
            return Response(200, {"action": self.rules_action})
        if path.startswith("/firewalls/77") and self.firewall is None:
            return Response(404, {"error": {"code": "not_found", "message": "firewall not found"}})
        if path == "/firewalls/77":
            return Response(200, {"firewall": self.firewall})
        if path == "/firewalls/77/actions/set_rules":
            self.firewall["rules"] = body["rules"]
            self.actions_of["firewall"].append(self.action(9, "set_firewall_rules", "2026-10-30T12:00:00+00:00"))
            return Response(201, {"actions": [self.actions_of["firewall"][-1]]})
        if path == "/servers" and method == "POST":
            assert self.rules_action["status"] == "success"
            self.user_data, self.body = body["user_data"], body
            self.server = {"id": 42, "name": body["name"], "created": CREATED, "labels": body["labels"],
                           "image": {"name": body["image"]}, "server_type": {"name": body["server_type"]},
                           "location": {"name": body["location"]}, "rescue_enabled": False, "iso": None,
                           "backup_window": None, "public_net": {
                               "ipv4": {"ip": self.ipv4}, "ipv6": {"ip": "2001:db8:1::/64"},
                               "firewalls": [{"id": f["firewall"], "status": "applied"} for f in body["firewalls"]]}}
            self.actions_of = {"server": [self.action(1, "create_server", status="running"), self.action(2, "start_server")],
                               "firewall": [self.action(3, "apply_firewall")]}
            return Response(201, {"server": self.server, "action": self.actions_of["server"][0],
                                  "next_actions": [self.actions_of["server"][1]], "root_password": "provider-root-password"})
        if path == "/actions/1":
            self.actions_of["server"][0]["status"] = "success"
            return Response(200, {"action": self.actions_of["server"][0]})
        if path == "/servers/42":
            return Response(404, {"error": {"code": "not_found"}}) if self.deleted else Response(200, {"server": self.server})
        if path in ("/servers/42/actions", "/firewalls/77/actions"):
            items = self.actions_of["server" if path.startswith("/servers") else "firewall"]
            page = params["page"]
            return Response(200, {"actions": items[page - 1:page],
                                  "meta": {"pagination": {"next_page": page + 1 if page < len(items) else None}}})
        raise AssertionError(method + " " + path)

    def sent(self):
        return self.body["ssh_keys"], self.firewall["rules"]

    def access(self):
        self.actions_of["server"].append(self.action(11, "request_console", LATE))

    def interrupt(self):
        self.actions_of["server"].append(self.action(10, "reboot_server", LATE))

    def open_inbound(self):
        self.firewall["rules"].append({"direction": "in", "protocol": "tcp", "port": "22", "source_ips": ["0.0.0.0/0"]})

    def inbound(self):
        return [r for r in self.firewall["rules"] if r["direction"] == "in"]


class DigitalOcean(World):
    key, server_type = "digitalocean", "s-1vcpu-2gb"
    ipv4, server_id = "192.0.2.20", 3164444

    def provider(self, method, url, body, params, headers, data):
        assert headers["Authorization"].startswith("Bearer ")
        path = url[len("https://api.digitalocean.com/v2"):]
        if path == "/firewalls" and method == "POST":
            assert body["outbound_rules"] and body["tags"] == ["tgwitness-" + body["name"].rsplit("-", 1)[1]]
            self.firewall = {"id": "fw-1", "status": "succeeded", **body}
            return Response(202, {"firewall": self.firewall})
        if path == "/firewalls/fw-1" and method == "GET":
            return Response(200, {"firewall": self.firewall})
        if path == "/firewalls/fw-1/rules" and method == "DELETE":
            self.firewall["inbound_rules"] = [r for r in self.firewall["inbound_rules"] if r not in body["inbound_rules"]]
            return Response(204)
        if path == "/droplets" and method == "POST":
            assert body["with_droplet_agent"] is False and body["backups"] is False and body["monitoring"] is False
            self.user_data, self.body = body["user_data"], body
            self.droplet = {"id": self.server_id, "name": body["name"], "created_at": CREATED, "status": "active",
                            "image": {"slug": body["image"]}, "size_slug": body["size"], "region": {"slug": body["region"]},
                            "tags": body["tags"], "features": ["ipv6"], "backup_ids": [], "snapshot_ids": [],
                            "networks": {"v4": [{"ip_address": self.ipv4, "type": "public"},
                                                {"ip_address": "10.0.0.5", "type": "private"}],
                                         "v6": [{"ip_address": "2001:db8:2::5", "netmask": 64, "type": "public"}]}}
            self.events = [{"id": 1, "type": "create", "status": "in-progress", "started_at": CREATED, "completed_at": None}]
            return Response(202, {"droplet": {"id": self.server_id, "name": body["name"]},
                                  "links": {"actions": [{"id": 1, "rel": "create"}]}})
        if path == "/actions/1":
            self.events[0]["status"] = "completed"
            return Response(200, {"action": self.events[0]})
        if path == "/droplets/3164444":
            return Response(404, {"id": "not_found", "message": "gone"}) if self.deleted else Response(200, {"droplet": self.droplet})
        if path == "/droplets/3164444/firewalls":
            tagged = set(self.firewall["tags"]) & set(self.droplet["tags"])
            return Response(200, {"firewalls": [self.firewall] if tagged else []})
        if path == "/droplets/3164444/actions":
            return Response(200, {"actions": self.events, "links": {"pages": {}}, "meta": {"total": len(self.events)}})
        raise AssertionError(method + " " + path)

    def sent(self):
        return self.body["ssh_keys"], self.firewall["inbound_rules"]

    def access(self):
        self.events.append({"id": 11, "type": "password_reset", "status": "completed", "started_at": LATE})

    def interrupt(self):
        self.events.append({"id": 10, "type": "reboot", "status": "completed", "started_at": LATE})

    def open_inbound(self):
        self.firewall["inbound_rules"].append({"protocol": "tcp", "ports": "22", "sources": {"addresses": ["0.0.0.0/0"]}})

    def inbound(self):
        return self.firewall["inbound_rules"]


class Linode(World):
    key, server_type = "linode", "g6-standard-1"
    ipv4, server_id = "192.0.2.30", 6001

    def __init__(self):
        super().__init__()
        self.events, self.attached = [], False

    def event(self, number, action, entity_type, entity_id, created=CREATED, username="operator"):
        self.events.append({"id": number, "action": action, "created": created.replace("+00:00", ""),
                            "status": "finished", "username": username, "entity": {"type": entity_type, "id": entity_id}})

    def provider(self, method, url, body, params, headers, data):
        assert headers["Authorization"].startswith("Bearer ")
        path = url[len("https://api.linode.com/v4"):]
        if path == "/networking/firewalls" and method == "POST":
            assert body["rules"]["inbound_policy"] == "DROP"
            self.firewall = {"id": 501, "label": body["label"], "status": "enabled", "rules": dict(body["rules"]), "version": 1}
            self.event(1, "firewall_create", "firewall", 501)
            return Response(200, self.firewall)
        if path == "/linode/instances" and method == "POST":
            assert body["booted"] is False and len(body["root_pass"]) > 30 and body["backups_enabled"] is False
            self.user_data, self.body = base64.b64decode(body["metadata"]["user_data"]).decode(), body
            self.linode = {"id": self.server_id, "label": body["label"], "status": "provisioning", "created": "2026-10-30T10:00:00",
                           "image": body["image"], "type": body["type"], "region": body["region"], "tags": body["tags"],
                           "ipv4": [self.ipv4, "192.168.1.5"], "ipv6": "2001:db8:3::5/128", "backups": {"enabled": False}}
            self.event(2, "linode_create", "linode", self.server_id)
            self.event(3, "linode_config_create", "linode", self.server_id)
            return Response(200, dict(self.linode))
        if path == "/linode/instances/6001/firewalls":
            return Response(200, {"data": [self.firewall] if self.attached else [], "page": 1, "pages": 1})
        if path == "/networking/firewalls/501/devices":
            self.attached = True
            self.event(4, "firewall_device_add", "firewall", 501)
            return Response(200, {"id": 1, "entity": body})
        if path == "/linode/instances/6001" and method == "GET":
            if self.deleted:
                return Response(404, {"errors": [{"reason": "Not found"}]})
            if self.linode["status"] == "provisioning":
                self.linode["status"] = "offline"
            return Response(200, dict(self.linode))
        if path == "/linode/instances/6001/boot":
            assert self.attached, "booted before the firewall was attached"
            self.linode["status"] = "running"
            self.event(5, "linode_boot", "linode", self.server_id)
            return Response(200, {})
        if path == "/networking/firewalls/501/rules":
            if method == "PUT":
                self.firewall["rules"], self.firewall["version"] = dict(body), self.firewall["version"] + 1
                self.event(9, "firewall_rules_update", "firewall", 501, "2026-10-30T12:00:00+00:00")
            return Response(200, {**self.firewall["rules"], "version": self.firewall["version"]})
        if path == "/account/events":
            query = json.loads(headers["X-Filter"])
            rows = [e for e in self.events if e["entity"]["id"] == query["entity.id"]
                    and query.get("entity.type", e["entity"]["type"]) == e["entity"]["type"]]
            size = params["page_size"]
            return Response(200, {"data": rows[(params["page"] - 1) * size:params["page"] * size], "page": params["page"],
                                  "pages": max(1, -(-len(rows) // size)), "results": len(rows)})
        raise AssertionError(method + " " + path)

    def sent(self):
        return self.body.get("authorized_users", []), self.firewall["rules"]["inbound"]

    def access(self):
        self.event(11, "password_reset", "linode", self.server_id, LATE, "intruder")

    def interrupt(self):
        self.event(10, "linode_reboot", "linode", self.server_id, LATE)

    def open_inbound(self):
        self.firewall["rules"]["inbound"].append({"action": "ACCEPT", "protocol": "TCP", "ports": "22",
                                                  "addresses": {"ipv4": ["0.0.0.0/0"]}})

    def inbound(self):
        return self.firewall["rules"]["inbound"]


class Vultr(World):
    key, server_type = "vultr", "vc2-1c-2gb"
    ipv4, server_id = "192.0.2.40", "cb676a46-66fd-4dfb-b839-443f2e6c0b60"
    console = "https://my.vultr.com/subs/vps/novnc/api.php?data=CONSOLE-SECRET"

    def __init__(self):
        super().__init__()
        self.logs, self.rules = [], []

    def log(self, method, path, body=None, timestamp=CREATED, resource=None, status=202):
        self.logs.append({"resource_id": resource or "", "resource_type": "instances", "log_level": "info",
                          "message": "request", "timestamp": timestamp,
                          "metadata": {"username": "operator", "ip_address": "198.51.100.9", "method": method,
                                       "request_path": path, "request_body": json.dumps(body) if body else "",
                                       "http_status_code": status}})

    def provider(self, method, url, body, params, headers, data):
        assert headers["Authorization"].startswith("Bearer ")
        path = url[len("https://api.vultr.com/v2"):]
        if path == "/firewalls" and method == "POST":
            self.firewall = {"id": "fwg-1", "description": body["description"]}
            self.log("POST", "/v2/firewalls", body, resource="fwg-1")
            return Response(201, {"firewall_group": self.firewall})
        if path == "/firewalls/fwg-1/rules" and method == "POST":
            self.rules.append({"id": len(self.rules) + 1, **body})
            self.log("POST", "/v2/firewalls/fwg-1/rules", body, resource="fwg-1")
            return Response(201, {"firewall_rule": self.rules[-1]})
        if path == "/firewalls/fwg-1/rules" and method == "GET":
            return Response(200, {"firewall_rules": self.rules, "meta": {"links": {"next": ""}}})
        if path.startswith("/firewalls/fwg-1/rules/") and method == "DELETE":
            self.rules = [r for r in self.rules if str(r["id"]) != path.rsplit("/", 1)[1]]
            self.log("DELETE", "/v2" + path, None, "2026-10-30T12:00:00+00:00", "fwg-1", 204)
            return Response(204)
        if path == "/os":
            return Response(200, {"os": [{"id": 1743, "name": "Ubuntu 22.04 LTS x64", "arch": "x64"},
                                         {"id": 2284, "name": "Ubuntu 24.04 LTS x64", "arch": "x64"},
                                         {"id": 2285, "name": "Ubuntu 24.04 LTS arm", "arch": "arm64"}],
                                  "meta": {"links": {"next": ""}}})
        if path == "/instances" and method == "POST":
            assert body["os_id"] == 2284 and body["backups"] == "disabled" and body["firewall_group_id"] == "fwg-1"
            self.user_data, self.body = base64.b64decode(body["user_data"]).decode(), body
            self.instance = {"id": self.server_id, "label": body["label"], "status": "pending", "main_ip": "0.0.0.0",
                             "date_created": CREATED, "os": "Ubuntu 24.04 LTS x64", "plan": body["plan"],
                             "region": body["region"], "tags": body["tags"], "features": ["ipv6"],
                             "firewall_group_id": "fwg-1", "v6_network": "2001:db8:4::", "v6_network_size": 64,
                             "kvm": self.console, "default_password": "vultr-root-password"}
            self.log("POST", "/v2/instances", body, resource=self.server_id)
            return Response(202, {"instance": dict(self.instance)})
        if path == "/instances/" + self.server_id:
            if self.deleted:
                return Response(404, {"error": "Invalid instance-id."})
            self.instance.update(status="active", main_ip=self.ipv4)
            return Response(200, {"instance": dict(self.instance)})
        if path == "/instances/" + self.server_id + "/iso":
            return Response(200, {"iso_status": {"state": "ready"}})
        if path == "/logs":
            rows = [e for e in self.logs if not params.get("resource_id") or e["resource_id"] == params["resource_id"]]
            return Response(200, {"logs": rows, "meta": {"returned_count": len(rows), "unreturned_count": 0}})
        raise AssertionError(method + " " + path)

    def sent(self):
        return self.body.get("sshkey_id", []), self.rules

    def access(self):
        self.log("POST", "/v2/instances/" + self.server_id + "/reinstall", {"hostname": "x"}, LATE, self.server_id)

    def interrupt(self):
        self.log("POST", "/v2/instances/" + self.server_id + "/reboot", None, LATE, self.server_id)

    def open_inbound(self):
        self.rules.append({"id": 99, "protocol": "tcp", "port": "22", "subnet": "0.0.0.0", "subnet_size": 0})

    def inbound(self):
        return self.rules


def xml(action, inner):
    return Response(200, content=("<" + action + 'Response xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">'
                                  + inner + "</" + action + "Response>").encode())


class Aws(World):
    key, server_type = "aws", "t3.small"
    ipv4, server_id = "192.0.2.50", "i-0abc"

    def __init__(self):
        super().__init__()
        self.rules, self.trail, self.form = [], [], {}

    def event(self, name, resource, when=CREATED, detail=None, read_only=False):
        self.trail.append({"EventId": "ev-" + str(len(self.trail)), "EventName": name, "ReadOnly": str(read_only).lower(),
                           "EventTime": datetime.fromisoformat(when).timestamp(), "Username": "operator",
                           "Resources": [{"ResourceName": resource}] if resource else [],
                           "CloudTrailEvent": json.dumps(detail or {})})

    def provider(self, method, url, body, params, headers, data):
        assert headers["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIDTEST/")
        if url.startswith("https://cloudtrail.eu-central-1.amazonaws.com/"):
            query = json.loads(data)
            attribute = query["LookupAttributes"][0]
            key = {"ResourceName": lambda e: [r["ResourceName"] for r in e["Resources"]],
                   "EventName": lambda e: [e["EventName"]]}[attribute["AttributeKey"]]
            return Response(200, {"Events": [e for e in self.trail if attribute["AttributeValue"] in key(e)]})
        assert url == "https://ec2.eu-central-1.amazonaws.com/"
        form = {k: v[0] for k, v in parse_qs(data.decode()).items()}
        action = form["Action"]
        if action == "DescribeVpcs":
            return xml(action, "<vpcSet><item><vpcId>vpc-1</vpcId></item></vpcSet>")
        if action == "CreateSecurityGroup":
            self.event("CreateSecurityGroup", "sg-1")
            return xml(action, "<return>true</return><groupId>sg-1</groupId>")
        if action == "AuthorizeSecurityGroupIngress":
            self.rules.append({"id": "sgr-" + str(len(self.rules)), "protocol": form["IpPermissions.1.IpProtocol"],
                               "port": form["IpPermissions.1.FromPort"], "cidr": form.get("IpPermissions.1.IpRanges.1.CidrIp")})
            self.event("AuthorizeSecurityGroupIngress", "sg-1")
            return xml(action, "<return>true</return>")
        if action == "DescribeImages":
            assert form["Owner.1"] == "099720109477" and "ubuntu-noble-24.04-amd64" in form["Filter.1.Value.1"]
            return xml(action, "<imagesSet><item><imageId>ami-old</imageId><creationDate>2025-01-01</creationDate></item>"
                               "<item><imageId>ami-new</imageId><creationDate>2026-10-01</creationDate></item></imagesSet>")
        if action == "RunInstances":
            assert form["ImageId"] == "ami-new" and form["MetadataOptions.HttpTokens"] == "required"
            assert "IamInstanceProfile.Name" not in form and form["SecurityGroupId.1"] == "sg-1"
            self.form, self.user_data = form, base64.b64decode(form["UserData"]).decode()
            self.event("RunInstances", self.server_id)
            return xml(action, "<instancesSet><item><instanceId>i-0abc</instanceId></item></instancesSet>")
        if action == "DescribeInstances":
            if self.deleted:
                return Response(400, content=b"<Response><Errors><Error><Code>InvalidInstanceID.NotFound</Code>"
                                             b"<Message>gone</Message></Error></Errors></Response>")
            tags = "".join("<item><key>" + k + "</key><value>" + v + "</value></item>" for k, v in self.tags().items())
            return xml(action, "<reservationSet><item><instancesSet><item><instanceId>i-0abc</instanceId>"
                               "<imageId>ami-new</imageId><instanceState><name>running</name></instanceState>"
                               "<instanceType>t3.small</instanceType><placement><availabilityZone>eu-central-1a"
                               "</availabilityZone></placement><launchTime>2026-10-30T10:00:00.000Z</launchTime>"
                               "<ipAddress>" + self.ipv4 + "</ipAddress><groupSet><item><groupId>sg-1</groupId></item>"
                               "</groupSet><blockDeviceMapping><item><deviceName>/dev/sda1</deviceName><ebs>"
                               "<volumeId>vol-1</volumeId><attachTime>2026-10-30T10:00:00.000Z</attachTime></ebs>"
                               "</item></blockDeviceMapping><networkInterfaceSet><item><networkInterfaceId>eni-1"
                               "</networkInterfaceId><groupSet><item><groupId>sg-1</groupId></item></groupSet>"
                               "</item></networkInterfaceSet>" + ("<keyName>ops</keyName>" if "KeyName" in self.form else "")
                               + "<tagSet>" + tags + "</tagSet></item></instancesSet></item></reservationSet>")
        if action == "DescribeSecurityGroups":
            permissions = "".join("<item><ipProtocol>" + r["protocol"] + "</ipProtocol><fromPort>" + r["port"]
                                  + "</fromPort><toPort>" + r["port"] + "</toPort><ipRanges><item><cidrIp>" + r["cidr"]
                                  + "</cidrIp></item></ipRanges></item>" for r in self.rules)
            return xml(action, "<securityGroupInfo><item><groupId>sg-1</groupId><ipPermissions>" + permissions
                               + "</ipPermissions></item></securityGroupInfo>")
        if action == "DescribeSecurityGroupRules":
            rules = "".join("<item><securityGroupRuleId>" + r["id"] + "</securityGroupRuleId><isEgress>false</isEgress>"
                            "</item>" for r in self.rules)
            return xml(action, "<securityGroupRuleSet>" + rules + "<item><securityGroupRuleId>sgr-egress"
                               "</securityGroupRuleId><isEgress>true</isEgress></item></securityGroupRuleSet>")
        if action == "RevokeSecurityGroupIngress":
            gone = {v for k, v in form.items() if k.startswith("SecurityGroupRuleId.")}
            assert "sgr-egress" not in gone
            self.rules = [r for r in self.rules if r["id"] not in gone]
            self.event("RevokeSecurityGroupIngress", "sg-1", "2026-10-30T12:00:00+00:00")
            return xml(action, "<return>true</return>")
        raise AssertionError(action)

    def tags(self):
        found = {k: v for k, v in self.form.items() if k.startswith("TagSpecification.1.Tag.")}
        return {found[k]: found[k.replace(".Key", ".Value")] for k in found if k.endswith(".Key")}

    def sent(self):
        return [self.form["KeyName"]] if "KeyName" in self.form else [], self.rules

    def access(self):
        self.event("StartSession", None, LATE, {"requestParameters": {"target": self.server_id}})

    def interrupt(self):
        self.event("RebootInstances", self.server_id, LATE)

    def open_inbound(self):
        self.rules.append({"id": "sgr-open", "protocol": "tcp", "port": "22", "cidr": "0.0.0.0/0"})

    def inbound(self):
        return self.rules


WORLDS = (Hetzner, DigitalOcean, Linode, Vultr, Aws)


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
        self.receipt = {"run_id": "run-1", "version": "0.6.1", "source_tree_sha256": source_tree_sha256(source_files())}
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


def connect(world, credentials="token"):
    provider = get(world.key)("AKIDTEST SECRET" if world.key == "aws" else credentials, session=world)
    return provider


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "pause", lambda seconds: None)

    def build(world_class, **changes):
        world = world_class()
        host = Host(world, tmp_path)
        args = arguments(tmp_path, world.key, server_type=world.server_type, **changes)
        record, out = cloud.deploy(args, connect(world), cloud.Cloudflare("cf-write", world), host.fetch,
                                   resolve=lambda repository, ref: ref)
        return world, host, record, out
    return build


def verify_args(out, **changes):
    values = dict(record=out / "deployment.json", provider_token_file=None, cloudflare_token_file=None,
                  fingerprint=None, cloud_init=out / "cloud-init.redacted.yaml", source=ROOT, evidence=None)
    values.update(changes)
    return NS(**values)


def run_verify(world, host, out, **changes):
    return cloud.verify(verify_args(out, **changes), connect(world, "read-only"), cloud.Cloudflare("cf-read", world), host.fetch)


def checks(report):
    return {c["check"]: c["status"] for c in report["checks"]}


def detail(report, check):
    return next(c["detail"] for c in report["checks"] if c["check"] == check)


def build_here(command, input, **options):
    """Build the reference installer in-process."""
    spec, tunnel = json.loads(input)
    build = cloud.install_script if spec["provider"] == "generic" else cloud.cloud_init
    return NS(returncode=0, stdout=assurance.redact_user_data(build(spec, tunnel, "x" * 43, "x" * 32)).encode(), stderr=b"")


@pytest.fixture
def real_reference():
    """Opt into the real subprocess builder."""


@pytest.fixture(autouse=True)
def reference_in_process(request, monkeypatch):

    if "real_reference" not in request.fixturenames:
        original = cloud.reference_installer
        monkeypatch.setattr(cloud, "reference_installer", lambda record, source: original(record, source, run=build_here))


def test_cloud_init_installs_one_commit_masks_ssh_and_publishes_without_secrets(tmp_path):
    spec = cloud.specification(arguments(tmp_path, server_type="cpx22"), resolve=lambda repository, ref: ref)
    text = cloud.cloud_init(spec, TUNNEL, "p" * 43, "eyJhIjoi" + "c" * 60)
    published = assurance.redact_user_data(text)
    assert text.startswith("#cloud-config\n") and len(text.encode()) < 16 * 1024
    assert "p" * 43 not in published and "c" * 60 not in published and published.count("=REDACTED") == 2
    assert "COMMIT='" + COMMIT + "'" in text and 'test "$(git -C /opt/tgwitness/source rev-parse HEAD)" = "$COMMIT"' in text
    assert "[systemctl, mask, --now, ssh.socket, ssh.service]" in text and "passwd -l root" in text
    assert "Environment=TGWITNESS_ASSURANCE=hetzner" in text and "tgwitness-lock" not in text
    debug = cloud.specification(arguments(tmp_path, server_type="cpx22", debug_ssh_key="ops",
                                          debug_ssh_from="198.51.100.4"), resolve=lambda repository, ref: ref)
    text = cloud.cloud_init(debug, TUNNEL, "p" * 43, "eyJhIjoi" + "c" * 60)
    assert debug["mode"] == "debug" and "bootcmd" not in text and "/usr/local/sbin/tgwitness-lock" in text
    assert cloud.inbound_rules(debug) == [{"protocol": "tcp", "port": "22", "source": "198.51.100.4/32"}]
    with pytest.raises(cloud.DeployError, match="token format"):
        cloud.cloud_init(spec, TUNNEL, "p" * 43, "bad'token\nTGWITNESS_TOKEN=x")


def test_install_script_for_any_server_records_closes_ssh_and_removes_itself(tmp_path):
    spec = cloud.specification(arguments(tmp_path, "generic"), resolve=lambda repository, ref: ref)
    text = cloud.install_script(spec, TUNNEL, "p" * 43, "eyJhIjoi" + "c" * 60)
    published = assurance.redact_user_data(text)
    assert spec["mode"] == "self-attested" and published.count("=REDACTED") == 2 and "p" * 43 not in published
    order = [text.index(s) for s in ("preinstall.txt 2>&1", "pip install", "install-record", "enable --now tgwitness",
                                     'rm -f "$SCRIPT"', "systemctl mask ssh.socket ssh.service", "pkill -x sshd")]
    assert order == sorted(order) and "Environment=TGWITNESS_ASSURANCE=generic" in text
    with pytest.raises(cloud.DeployError, match="install.sh closes SSH"):
        cloud.specification(arguments(tmp_path, "generic", debug_ssh_key="ops", debug_ssh_from="198.51.100.4"),
                            resolve=lambda repository, ref: ref)


def test_install_record_hashes_the_installer_as_it_ran(tmp_path):
    script, inventory = tmp_path / "install.sh", tmp_path / "preinstall.txt"
    script.write_bytes(b"#!/bin/bash\nTGWITNESS_TOKEN=secret\n")
    inventory.write_bytes(b"# inventory\n")
    record = assurance.install_record(script, inventory, tmp_path / "install.json")
    assert record["redacted_sha256"] == assurance.user_data_hashes("#!/bin/bash\nTGWITNESS_TOKEN=REDACTED\n")["user_data_sha256"]
    (tmp_path / "etc/tgwitness").mkdir(parents=True)
    (tmp_path / "etc/tgwitness/install.json").write_text((tmp_path / "install.json").read_text())
    (tmp_path / "etc/machine-id").write_text("machine-1\n")
    found = assurance.provider_record("generic", None, tmp_path)
    assert found["instance_id"] == "machine-1" and found["user_data_sha256"] == record["sha256"]


@pytest.mark.parametrize("changes, message", [
    ({"debug_ssh_key": "ops", "debug_ssh_from": "0.0.0.0/0"}, "small network"),
    ({"debug_ssh_key": "ops"}, "go together"),
    ({"panel_host": "case1.example.net"}, "inside the zone"),
    ({"witness_host": "case1.example.org"}, "different hostnames"),
    ({"repository": "https://user:secret@github.com/x/y.git"}, "without credentials"),
    ({"name": "Case_1"}, "--name"),
    ({"cloudflare_account": "account"}, "account ID"),
    ({"server_type": None}, "--server-type is required"),
])
def test_specification_refuses_unsafe_input(tmp_path, changes, message):
    with pytest.raises(cloud.DeployError, match=message):
        cloud.specification(arguments(tmp_path, **{"server_type": "cpx22", **changes}), resolve=lambda repository, ref: ref)


def test_release_tag_resolves_to_the_peeled_commit_once(monkeypatch):
    monkeypatch.setattr(cloud.shutil, "which", lambda name: "git")
    output = "b" * 40 + "\trefs/tags/v0.6.1\n" + "c" * 40 + "\trefs/tags/v0.6.1^{}\n"
    seen = []

    def run(command, **options):
        seen.append(command)
        return NS(stdout=output)
    assert cloud.resolve_commit(cloud.DEFAULT_REPOSITORY, "v0.6.1", run) == "c" * 40
    assert seen[0][1:] == ["ls-remote", cloud.DEFAULT_REPOSITORY, "refs/tags/v0.6.1", "refs/tags/v0.6.1^{}"]
    assert cloud.resolve_commit(cloud.DEFAULT_REPOSITORY, COMMIT, run) == COMMIT and len(seen) == 1
    with pytest.raises(cloud.DeployError):
        cloud.resolve_commit(cloud.DEFAULT_REPOSITORY, "--upload-pack=x", run)


def test_sigv4_matches_the_published_aws_examples():
    when = datetime(2015, 8, 30, 12, 36, tzinfo=timezone.utc)
    secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    vanilla = signed_headers("GET", "https://example.amazonaws.com/", "us-east-1", "service", {}, b"",
                             "AKIDEXAMPLE", secret, now=when)
    assert vanilla["authorization"] == ("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
                                        "SignedHeaders=host;x-amz-date, Signature="
                                        "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")
    iam = signed_headers("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", "us-east-1", "iam",
                         {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}, b"", "AKIDEXAMPLE", secret,
                         now=when)
    assert iam["authorization"].endswith("Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7")


@pytest.mark.parametrize("world_class", WORLDS, ids=lambda w: w.key)
def test_deploy_creates_a_closed_server_and_records_no_secret(setup, world_class):
    world, host, record, out = setup(world_class)
    keys, inbound = world.sent()
    assert keys == [] and inbound == [] and record["state"] == "running" and record["mode"] == "high-assurance"
    assert record["collector"]["fingerprint"] == fingerprint(host.vault.public_key)
    assert record["collector"]["first_boot_id"] == "boot-1" and str(record["server"]["id"]) == str(world.server_id)
    assert world.config["ingress"] == cloud.ingress(record) and world.config["ingress"][1]["path"] == cloud.WITNESS_PATHS
    assert [r["content"] for r in world.dns] == [TUNNEL + ".cfargotunnel.com"] * 2 and all(r["proxied"] for r in world.dns)
    panel_token = (out / "panel-token.txt").read_text()
    saved = (out / "deployment.json").read_text() + (out / "cloud-init.redacted.yaml").read_text()
    for secret in (panel_token, world.tunnel["token"], "provider-root-password", "vultr-root-password",
                   "CONSOLE-SECRET", "token", "AKIDTEST", "SECRET", "cf-write"):
        assert secret not in saved.replace("tgwitness", "").replace("TOKEN=REDACTED", "")
    assert "user_data" not in json.dumps(record["api_calls"])
    assert assurance.user_data_hashes(world.user_data)["user_data_redacted_sha256"] == \
        assurance.user_data_hashes((out / "cloud-init.redacted.yaml").read_text())["user_data_sha256"]
    order = [c[1] for c in world.calls]
    assert max(i for i, u in enumerate(order) if "/configurations" in u) < min(
        i for i, (m, u, b, *_) in enumerate(world.calls) if not u.startswith(cloud.CLOUDFLARE_API))
    with pytest.raises(cloud.DeployError, match="already holds"):
        cloud.deploy(arguments(out.parent, world.key, server_type=world.server_type), connect(world),
                     cloud.Cloudflare("cf", world), host.fetch, resolve=lambda repository, ref: ref)


@pytest.mark.parametrize("world_class", WORLDS, ids=lambda w: w.key)
def test_clean_deployment_passes_and_each_access_path_is_reported(setup, world_class):
    world, host, _record, out = setup(world_class)
    report = run_verify(world, host, out, fingerprint=fingerprint(host.vault.public_key))
    assert report["result"] == "pass", [c for c in report["checks"] if c["status"] != "pass"]
    assert any(a["meaning"] == "server created" for a in report["provider_actions"])
    markdown = cloud.render(report)
    assert "**PASS**" in markdown and "What it does not establish" in markdown and "CONSOLE-SECRET" not in markdown
    assert world.tunnel["token"] not in markdown + json.dumps(report)

    world.interrupt()
    assert checks(run_verify(world, host, out))["provider_actions"] == "review"
    world.access()
    report = run_verify(world, host, out)
    assert report["result"] == "fail" and checks(report)["provider_actions"] == "fail"
    world.open_inbound()
    assert checks(run_verify(world, host, out))["firewall"] == "fail"
    world.connector_ips = [world.ipv4, "203.0.113.99"]
    assert checks(run_verify(world, host, out))["connector"] == "fail"
    world.deleted = True
    result = checks(run_verify(world, host, out))
    assert result["server"] == "fail" and result["connector"] == "fail" and "binding" not in result


def test_host_evidence_mismatches_fail(setup):
    world, host, _record, out = setup(Hetzner)
    (host.root / "proc/net/tcp").write_text("  sl  local_address\n  0: 00000000:0016 00000000:0000 0A x\n")
    (host.root / "proc/sys/kernel/random/boot_id").write_text("boot-2\n")
    result = checks(run_verify(world, host, out, source=None))
    assert result["host_access"] == "fail" and result["boot"] == "review" and result["source"] == "unavailable"
    tampered = out / "tampered.yaml"
    tampered.write_bytes((out / "cloud-init.redacted.yaml").read_bytes().replace(b"passwd -l root", b"true"))
    assert checks(run_verify(world, host, out, cloud_init=tampered))["cloud_init"] == "fail"
    assert checks(run_verify(world, host, out, fingerprint="0" * 64))["fingerprint"] == "fail"
    host.override = {"instance_id": 99}
    assert checks(run_verify(world, host, out))["binding"] == "fail"


def test_bootstrap_measurements_are_explicitly_self_reported(setup):
    world, host, _record, out = setup(Hetzner)
    original = world.user_data
    world.user_data += "\n# Synthetic unexpected bootstrap change\n"
    assert checks(run_verify(world, host, out))["binding"] == "fail"


    host.override = {**assurance.user_data_hashes(original), "user_data_redacted": assurance.redact_user_data(original)}
    report = run_verify(world, host, out)
    assert report["result"] == "pass", [c for c in report["checks"] if c["status"] != "pass"]
    assert report["verification_scope"] == "deployment-consistency"
    assert report["assurance"]["independent_runtime_attestation"] == "not-performed"
    assert report["assurance"]["key_nonexportability"] == "not-established"
    shown = cloud.render(report)
    assert "Deployment checks" in shown and "malicious bootstrap" in shown


def test_a_deleted_hetzner_firewall_fails_the_report_instead_of_stopping_it(setup):
    world, host, _record, out = setup(Hetzner)
    world.firewall, world.server["public_net"]["firewalls"] = None, []
    report = run_verify(world, host, out)
    assert checks(report)["firewall"] == "fail" and report["result"] == "fail"
    assert {a["resource"] for a in report["provider_actions"]} == {"server"}


def test_without_a_cloudflare_token_the_report_is_incomplete_not_passed(setup, monkeypatch):
    world, host, _record, out = setup(Hetzner)
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    report = cloud.verify(verify_args(out), connect(world), None, host.fetch)
    assert checks(report)["tunnel"] == "unavailable" and report["result"] == "incomplete"


@pytest.mark.parametrize("world_class", WORLDS, ids=lambda w: w.key)
def test_debug_deployment_is_never_high_assurance_and_lock_closes_the_firewall(setup, world_class):
    world, host, record, out = setup(world_class, debug_ssh_key="ops", debug_ssh_from="198.51.100.4")
    keys, inbound = world.sent()
    assert keys == ["ops"] and len(inbound) == 1 and record["mode"] == "debug"
    before = checks(run_verify(world, host, out))
    assert before["mode"] == "fail" and before["firewall"] == "fail"
    cloud.lock(NS(record=out / "deployment.json", provider_token_file=None), connect(world))
    assert world.inbound() == [] and json.loads((out / "deployment.json").read_text())["locks"]
    after = run_verify(world, host, out)
    assert checks(after)["mode"] == "review" and checks(after)["firewall"] in ("pass", "review")
    assert after["result"] == "review"


def test_deploy_stops_before_creating_anything_when_the_hostname_is_taken(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "pause", lambda seconds: None)
    world = Hetzner()
    world.dns.append({"id": "old", "name": "case1.example.org", "type": "A", "content": "203.0.113.1"})
    with pytest.raises(cloud.DeployError, match="already has DNS records"):
        cloud.deploy(arguments(tmp_path, server_type="cpx22"), connect(world), cloud.Cloudflare("cf", world),
                     Host(world, tmp_path).fetch, resolve=lambda repository, ref: ref)
    assert world.tunnel is None and not any(u.startswith("https://api.hetzner") for _, u, *_ in world.calls)


def test_any_server_is_self_attested_at_best(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "pause", lambda seconds: None)
    world = World()
    world.ipv4 = "198.51.100.77"
    out = tmp_path / "deployment"
    host = Host(world, tmp_path, user_data=lambda: (out / "install.sh").read_text())
    record, out = cloud.deploy(arguments(tmp_path, "generic"), None, cloud.Cloudflare("cf", world), host.fetch,
                               resolve=lambda repository, ref: ref)
    assert record["mode"] == "self-attested" and record["server"]["id"] == "machine-1"
    assert (out / "install.sh").read_text().count("REDACTED") == 0 and (out / "install.redacted.sh").read_text().count("REDACTED") == 2
    report = cloud.verify(verify_args(out, cloud_init=out / "install.redacted.sh"), None, cloud.Cloudflare("cf", world), host.fetch)
    assert report["result"] == "self-attested" and checks(report)["provider"] == "unavailable"
    assert checks(report)["binding"] == "pass" and checks(report)["cloud_init"] == "pass"
    assert "Self-attested" in cloud.render(report)
    host.override = {"user_data_sha256": "0" * 64}
    assert cloud.verify(verify_args(out, cloud_init=None), None, cloud.Cloudflare("cf", world), host.fetch)["result"] == "fail"
    with pytest.raises(cloud.DeployError, match="no provider firewall"):
        cloud.lock(NS(record=out / "deployment.json", provider_token_file=None))


def test_evidence_journal_must_carry_this_key_and_this_server(journal):
    store, vault = journal
    state = {"boot_id": "boot-1", "ssh_listening": False, "ssh_processes": 0, "sessions": 0, "logins": 0}
    store.append("process.started", {"run": {"host": {"provider": {"instance_id": 42}, **state}}})
    report = cloud.Report()
    cloud.verify_journal(report, export_file(store, vault, "zip"), fingerprint(vault.public_key), 42)
    assert report.checks[-1]["status"] == "pass" and "1 process start(s)" in report.checks[-1]["detail"]
    store.append("host.state", {"instance_id": 42, **state, "ssh_listening": True})
    cloud.verify_journal(report, export_file(store, vault, "zip"), fingerprint(vault.public_key), 42)
    assert report.checks[-1]["status"] == "fail" and "port 22 open" in report.checks[-1]["detail"]
    cloud.verify_journal(report, export_file(store, vault, "zip"), "0" * 64, 42)
    assert report.checks[-1]["status"] == "fail"


def test_hand_installed_journal_tolerates_the_installer_login_only(journal):
    store, vault = journal
    state = {"boot_id": "boot-1", "ssh_listening": False, "ssh_processes": 0, "sessions": 0, "logins": 1}
    store.append("process.started", {"run": {"host": {"provider": {"instance_id": "m"}, **state}}})
    report = cloud.Report()
    cloud.verify_journal(report, export_file(store, vault, "zip"), fingerprint(vault.public_key), "m", generic=True)
    assert report.checks[-1]["status"] == "pass"
    store.append("host.state", {"instance_id": "m", **state, "logins": 2, "before": {"logins": 1}})
    cloud.verify_journal(report, export_file(store, vault, "zip"), fingerprint(vault.public_key), "m", generic=True)
    assert report.checks[-1]["status"] == "fail"


def test_reference_installer_is_built_by_the_checkouts_own_code(tmp_path, monkeypatch, real_reference):
    monkeypatch.setattr(cloud, "REFERENCES", {})
    spec = cloud.specification(arguments(tmp_path, server_type="cpx22"), resolve=lambda repository, ref: ref)
    record = {**spec, "tunnel": {"id": TUNNEL}}
    built = cloud.reference_installer(record, ROOT)
    assert built == assurance.redact_user_data(cloud.cloud_init(spec, TUNNEL, "p" * 43, "eyJhIjoi" + "c" * 60))
    with pytest.raises(cloud.DeployError, match="reference installer"):
        cloud.reference_installer(record, tmp_path)


def test_installer_must_equal_the_reference_byte_for_byte(setup):
    world, host, record, out = setup(Hetzner)
    published = (out / "cloud-init.redacted.yaml").read_bytes()
    report = run_verify(world, host, out)
    assert checks(report)["cloud_init"] == "pass" and "byte for byte equal" in detail(report, "cloud_init")
    assert "the user data the server read from its metadata service" in detail(report, "cloud_init")

    added = out / "added.yaml"
    added.write_bytes(published.replace(b"runcmd:", b"runcmd:\n  - [curl, -o, /tmp/x, https://example.net/x]"))
    report = run_verify(world, host, out, cloud_init=added)
    assert checks(report)["cloud_init"] == "fail" and "published installer differs" in detail(report, "cloud_init")

    host.override = {"user_data_redacted": published.decode() + "# extra\n",
                     "user_data_redacted_sha256": assurance.user_data_hashes(published.decode() + "# extra\n")["user_data_sha256"]}
    report = run_verify(world, host, out, cloud_init=None)
    assert checks(report)["cloud_init"] == "fail" and 'unexpected "# extra\\n"' in detail(report, "cloud_init")
    host.override = {"user_data_redacted": published.decode() + "# extra\n"}
    assert "its own SHA-256" in detail(run_verify(world, host, out), "binding")
    host.override = {"user_data_redacted": None}
    report = run_verify(world, host, out)
    assert checks(report)["cloud_init"] == "pass" and "not the user data itself" in detail(report, "cloud_init")
    host.override = {}
    assert checks(run_verify(world, host, out, source=None))["cloud_init"] == "unavailable"

    forged = json.loads((out / "deployment.json").read_text())
    forged["deployment_id"] += "\nruncmd: [[sh, -c, id]]"
    (out / "deployment.json").write_text(json.dumps(forged))
    report = run_verify(world, host, out)
    assert checks(report)["cloud_init"] == "fail" and "never writes" in detail(report, "cloud_init")


def test_journal_starts_carry_the_reference_installer_and_imported_keys_are_marked(journal):
    store, vault = journal
    reference = "#cloud-config\n# reference\n"
    state = {"boot_id": "boot-1", "ssh_listening": False, "ssh_processes": 0, "sessions": 0, "logins": 0}
    provider = {"instance_id": 42, **assurance.user_data_hashes(reference)}
    store.append("process.started", {"run": {"host": {"provider": provider, **state}}})
    store.append("account.authorized", {"account_id": 44, "key_origin": "created"})

    def run():
        report = cloud.Report()
        cloud.verify_journal(report, export_file(store, vault, "zip"), fingerprint(vault.public_key), 42, reference=reference)
        return {c["check"]: c for c in report.checks}
    found = run()
    assert found["journal"]["status"] == "pass" and found["account_key"]["status"] == "pass"
    store.append("account.authorized", {"account_id": 44, "key_origin": "imported"})
    store.append("account.authorized", {"account_id": 44})
    found = run()
    assert found["account_key"]["status"] == "review" and "imported session" in found["account_key"]["detail"]
    assert "does not say where" in found["account_key"]["detail"]
    store.append("process.started", {"run": {"host": {"provider": {"instance_id": 42, **assurance.user_data_hashes("x")},
                                                      **state}}})
    assert "other than the reference installer" in run()["journal"]["detail"]


@pytest.mark.parametrize("key, answers, expected", [
    ("hetzner", {"metadata/instance-id": "42\n", "metadata/hostname": "case-1", "metadata/public-ipv4": "192.0.2.10",
                 "metadata/region": "eu-central", "userdata": "#cloud-config\n"}, {"instance_id": 42, "public_ipv4": "192.0.2.10"}),
    ("digitalocean", {"metadata/v1.json": json.dumps({"droplet_id": 7, "hostname": "case-1", "region": "fra1",
                                                       "interfaces": {"public": [{"ipv4": {"ip_address": "192.0.2.20"}}]},
                                                       "user_data": "#cloud-config\n"})}, {"instance_id": 7, "public_ipv4": "192.0.2.20"}),
    ("linode", {"v1/token": "tok", "v1/instance": json.dumps({"id": 6001, "label": "case-1", "region": "eu-central"}),
                "v1/network": json.dumps({"ipv4": {"public": ["192.0.2.30/32"]}}),
                "v1/user-data": base64.b64encode(b"#cloud-config\n").decode()}, {"instance_id": 6001, "public_ipv4": "192.0.2.30"}),
    ("vultr", {"v1.json": json.dumps({"instance-v2-id": "uuid-1", "hostname": "case-1", "region": {"regioncode": "FRA"},
                                       "interfaces": [{"network-type": "public", "ipv4": {"address": "192.0.2.40"}}],
                                       "user-data": base64.b64encode(b"#cloud-config\n").decode()})},
     {"instance_id": "uuid-1", "public_ipv4": "192.0.2.40", "region": "FRA"}),
    ("aws", {"latest/api/token": "tok", "latest/meta-data/instance-id": "i-0abc", "latest/meta-data/local-hostname": "ip-1",
             "latest/meta-data/placement/region": "eu-central-1", "latest/user-data": "#cloud-config\n"},
     {"instance_id": "i-0abc", "public_ipv4": None, "region": "eu-central-1"}),
])
def test_each_provider_metadata_service_is_read_without_keeping_user_data(key, answers, expected):
    seen = []

    def request(url, method="GET", headers=None):
        seen.append((url, method, headers))
        path = url.split("169.254.169.254/", 1)[1].replace("hetzner/v1/", "")
        if path not in answers:
            raise OSError("404 " + path)
        return answers[path]
    record = assurance.provider_record(key, request)
    assert "error" not in record and expected.items() <= record.items() and "user_data" not in record
    assert record["user_data_sha256"] == assurance.user_data_hashes("#cloud-config\n")["user_data_sha256"]
    if key in ("linode", "aws"):
        assert seen[0][1] == "PUT" and all(h and "tok" in h.values() for _, m, h in seen[1:])


def test_cli_plan_prints_calls_and_redacted_installer(capsys):
    for provider in ("hetzner", "digitalocean", "linode", "vultr", "aws", "generic"):
        cloud.main(["plan", "--provider", provider, "--name", "case-1", "--ref", COMMIT, "--zone", "example.org",
                    "--cloudflare-account", ACCOUNT, "--panel-host", "case1.example.org"]
                   + ([] if provider == "generic" else ["--server-type", "x1"]))
        output = capsys.readouterr().out
        assert "TGWITNESS_TOKEN=REDACTED" in output and output.isascii() and "mode " in output
