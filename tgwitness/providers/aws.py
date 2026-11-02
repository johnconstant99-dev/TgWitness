"""Amazon EC2: instances, security groups and CloudTrail event history, signed with SigV4.

Credentials: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and optionally AWS_SESSION_TOKEN, or a file
holding "ACCESS_KEY_ID SECRET_ACCESS_KEY [SESSION_TOKEN]". The region is the deployment location.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import requests

from .base import DeployError, Provider, labels, network, parse_time, pause, resource_name

EC2_VERSION = "2016-11-15"
CANONICAL = "099720109477"
IMAGES = {"ubuntu-24.04": "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-{arch}-server-*"}
METADATA = "http://169.254.169.254/latest/"
SESSIONS = ("StartSession", "SendSSHPublicKey", "SendSerialConsoleSSHPublicKey", "SendCommand")


def signed_headers(method, url, region, service, headers, body, key_id, secret, token=None, now=None):
    """AWS Signature Version 4: the headers to send with one request."""
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    parts = urllib.parse.urlsplit(url)
    headers = {**{k.lower(): v for k, v in headers.items()}, "host": parts.netloc, "x-amz-date": stamp}
    if token:
        headers["x-amz-security-token"] = token
    names = sorted(headers)
    query = "&".join(urllib.parse.quote(k, safe="-_.~") + "=" + urllib.parse.quote(v, safe="-_.~")
                     for k, v in sorted(urllib.parse.parse_qsl(parts.query, keep_blank_values=True)))
    request = "\n".join((method, urllib.parse.quote(parts.path or "/", safe="/-_.~"), query,
                         "".join(n + ":" + " ".join(str(headers[n]).split()) + "\n" for n in names),
                         ";".join(names), hashlib.sha256(body).hexdigest()))
    scope = "/".join((stamp[:8], region, service, "aws4_request"))
    text = "\n".join(("AWS4-HMAC-SHA256", stamp, scope, hashlib.sha256(request.encode()).hexdigest()))
    key = ("AWS4" + secret).encode()
    for part in (stamp[:8], region, service, "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    headers["authorization"] = ("AWS4-HMAC-SHA256 Credential=" + key_id + "/" + scope + ", SignedHeaders="
                                + ";".join(names) + ", Signature=" + hmac.new(key, text.encode(), hashlib.sha256).hexdigest())
    return headers


def text(node, path, default=None):
    found = node.find(path) if node is not None else None
    return found.text if found is not None and found.text is not None else default


def items(node, path):
    found = node.find(path) if node is not None else None
    return found.findall("item") if found is not None else []


def tags(number, kind, values):
    params = {"TagSpecification." + str(number) + ".ResourceType": kind}
    for index, (key, value) in enumerate(values.items(), 1):
        params["TagSpecification.%d.Tag.%d.Key" % (number, index)] = key
        params["TagSpecification.%d.Tag.%d.Value" % (number, index)] = value
    return params


class Aws(Provider):
    key, title, name = "aws", "Amazon EC2", "AWS"
    variables = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
    defaults = {"location": "eu-central-1", "image": "ubuntu-24.04"}
    example_type = "t3.small"
    ssh_key_help = "name of an EC2 key pair in the region"
    user_data_limit = 16 * 1024
    write_access = ("IAM credentials allowed ec2:DescribeVpcs, DescribeImages, CreateSecurityGroup, "
                    "AuthorizeSecurityGroupIngress, RunInstances, CreateTags, DescribeInstances, "
                    "DescribeSecurityGroupRules and RevokeSecurityGroupIngress")

    read_access = "IAM credentials allowed only ec2:DescribeInstances, ec2:DescribeSecurityGroups and cloudtrail:LookupEvents"
    log_retention = "CloudTrail event history keeps 90 days of management events per region"
    limits = ("CloudTrail event history keeps 90 days: produce the report within that period, or keep a trail.",
              "Actions by AWS staff and on the underlying host are outside CloudTrail.")
    CREATION = ("RunInstances",)
    DEPLOYMENT = ("CreateSecurityGroup", "CreateTags")
    INTERRUPTIONS = ("StartInstances", "StopInstances", "RebootInstances")
    ACCESS = {
        "SendSSHPublicKey": "EC2 Instance Connect pushed an SSH key",
        "SendSerialConsoleSSHPublicKey": "serial console key pushed",
        "StartSession": "Systems Manager session", "ResumeSession": "Systems Manager session resumed",
        "SendCommand": "Systems Manager command",
        "AssociateIamInstanceProfile": "instance profile attached: agents can be granted access",
        "ReplaceIamInstanceProfileAssociation": "instance profile replaced: agents can be granted access",
        "ModifyInstanceAttribute": "instance attribute changed (user data, type, kernel or security groups)",
        "CreateImage": "image of the disk created: a copy of the signing key at rest",
        "CreateSnapshot": "snapshot of a volume: a copy of the signing key at rest",
        "CreateSnapshots": "snapshot of the volumes: a copy of the signing key at rest",
        "CreateReplaceRootVolumeTask": "root volume replaced",
        "DetachVolume": "a volume detached", "AttachVolume": "a volume attached",
    }
    FAIL = {"AuthorizeSecurityGroupIngress": "inbound rule added", "ModifySecurityGroupRules": "security group rules changed",
            "ModifyNetworkInterfaceAttribute": "network interface changed (security groups)",
            "TerminateInstances": "server terminated"}
    REVIEW = {"RevokeSecurityGroupIngress": "inbound rules removed", "DisassociateIamInstanceProfile": "instance profile removed",
              "ModifyInstanceMetadataOptions": "metadata service options changed"}

    @classmethod
    def credentials(cls, path):
        parts = Path(path).read_text(encoding="utf-8-sig").split() if path else \
            [os.environ[v] for v in cls.variables if os.environ.get(v)]
        if len(parts) < 2:
            raise DeployError("Provide --provider-token-file with 'ACCESS_KEY_ID SECRET_ACCESS_KEY [SESSION_TOKEN]' "
                              "or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
        return " ".join(parts[:3])

    def __init__(self, credentials, session=None, log=None):
        parts = credentials.split()
        self.key_id, self.secret, self.token = parts[0], parts[1], parts[2] if len(parts) > 2 else None
        self.session = session or requests.Session()
        self.log = [] if log is None else log

    def signed(self, service, target, body, headers):
        url = "https://" + service + "." + self.location + ".amazonaws.com/"
        return self.send("POST", url, target, data=body, headers=signed_headers(
            "POST", url, self.location, service, headers, body, self.key_id, self.secret, self.token))

    def ec2(self, action, params=None, allow=()):
        body = urllib.parse.urlencode({"Action": action, "Version": EC2_VERSION, **(params or {})}).encode()
        response = self.signed("ec2", action, body, {"content-type": "application/x-www-form-urlencoded; charset=utf-8"})
        root = ET.fromstring(response.content)
        for node in root.iter():
            node.tag = node.tag.rsplit("}", 1)[-1]
        if response.status_code >= 400:
            code = text(root, ".//Code")
            if code in allow:
                return None
            raise DeployError("AWS " + action + ": HTTP " + str(response.status_code) + " " + str(code) + ": "
                              + str(text(root, ".//Message")))
        return root

    def lookup(self, attribute, value, start):
        events, token = [], None
        while True:
            params = {"LookupAttributes": [{"AttributeKey": attribute, "AttributeValue": value}],
                      "StartTime": start, "MaxResults": 50, **({"NextToken": token} if token else {})}
            body = json.dumps(params).encode()
            response = self.signed("cloudtrail", "LookupEvents", body, {
                "content-type": "application/x-amz-json-1.1",
                "x-amz-target": "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"})
            data = response.json()
            if response.status_code >= 400:
                raise DeployError("AWS LookupEvents: HTTP " + str(response.status_code) + " "
                                  + str(data.get("__type")) + ": " + str(data.get("message") or data.get("Message")))
            events += data.get("Events") or []
            token = data.get("NextToken")
            if not token:
                return events
            pause(0.6)

    def image(self, image, instance_type):
        if image.startswith("ami-"):
            return image
        if image not in IMAGES:
            raise DeployError("--image must be an AMI ID or one of: " + ", ".join(IMAGES))
        arch = "arm64" if re.match(r"[a-z]+\d+g", instance_type) else "amd64"
        found = items(self.ec2("DescribeImages", {
            "Owner.1": CANONICAL, "Filter.1.Name": "name", "Filter.1.Value.1": IMAGES[image].format(arch=arch),
            "Filter.2.Name": "state", "Filter.2.Value.1": "available"}), "imagesSet")
        if not found:
            raise DeployError("No official Ubuntu image found for " + image + " in " + self.location)
        return text(max(found, key=lambda i: text(i, "creationDate", "")), "imageId")

    def node(self, instance_id):
        root = self.ec2("DescribeInstances", {"InstanceId.1": str(instance_id)},
                        allow=("InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed"))
        return root.find("reservationSet/item/instancesSet/item") if root is not None else None

    def create(self, spec, user_data, rules, outbound=()):
        if outbound:
            raise DeployError(self.title + ": outbound firewall rules are not implemented here")
        values = {"Name": spec["name"], **labels(spec)}
        vpc = text(self.ec2("DescribeVpcs", {"Filter.1.Name": "isDefault", "Filter.1.Value.1": "true"}),
                   "vpcSet/item/vpcId")
        if not vpc:
            raise DeployError("This region has no default VPC; create one or choose another region")
        group = text(self.ec2("CreateSecurityGroup", {
            "GroupName": resource_name(spec), "VpcId": vpc, **tags(1, "security-group", values),
            "GroupDescription": "TgWitness " + spec["mode"] + " deployment " + spec["deployment_id"]}), "groupId")
        for rule in rules:
            family = "Ipv6Ranges.1.CidrIpv6" if ":" in rule["source"] else "IpRanges.1.CidrIp"
            self.ec2("AuthorizeSecurityGroupIngress", {
                "GroupId": group, "IpPermissions.1.IpProtocol": rule["protocol"], "IpPermissions.1.FromPort": rule["port"],
                "IpPermissions.1.ToPort": rule["port"], "IpPermissions.1." + family: rule["source"]})
        params = {"ImageId": self.image(spec["image"], spec["server_type"]), "InstanceType": spec["server_type"],
                  "MinCount": "1", "MaxCount": "1", "ClientToken": spec["deployment_id"],
                  "UserData": base64.b64encode(user_data.encode()).decode(), "SecurityGroupId.1": group,
                  "MetadataOptions.HttpTokens": "required", "MetadataOptions.HttpEndpoint": "enabled",
                  **tags(1, "instance", values), **tags(2, "volume", values)}
        if spec["ssh"] != "disabled":
            params["KeyName"] = spec["ssh"]["debug_key"]
        instance_id = text(self.ec2("RunInstances", params), "instancesSet/item/instanceId")
        node = self.wait_until(lambda: (lambda n: n if n is not None and text(n, "instanceState/name") == "running"
                                        and text(n, "ipAddress") else None)(self.node(instance_id)), "instance start")
        server = self.normalise(node, None)
        return ({"id": group, "name": resource_name(spec), "vpc": vpc},
                {"id": instance_id, "name": spec["name"], "created": server["created"], "ipv4": server["ipv4"],
                 "ipv6": server["ipv6"], "image": params["ImageId"], "root_password": None})

    def lock(self, record):
        rules = items(self.ec2("DescribeSecurityGroupRules", {
            "Filter.1.Name": "group-id", "Filter.1.Value.1": record["firewall"]["id"]}), "securityGroupRuleSet")
        ids = [text(r, "securityGroupRuleId") for r in rules if text(r, "isEgress") == "false"]
        if ids:
            self.ec2("RevokeSecurityGroupIngress", {"GroupId": record["firewall"]["id"],
                                                    **{"SecurityGroupRuleId." + str(n): i for n, i in enumerate(ids, 1)}})
        return []

    def normalise(self, node, record):
        values = {text(t, "key"): text(t, "value") for t in items(node, "tagSet")}
        interfaces = items(node, "networkInterfaceSet")
        groups = {text(g, "groupId") for g in items(node, "groupSet")}
        groups |= {text(g, "groupId") for i in interfaces for g in items(i, "groupSet")}
        addresses = [text(a, "ipv6Address") for i in interfaces for a in items(i, "ipv6AddressesSet")]
        volumes = items(node, "blockDeviceMapping")
        state = text(node, "instanceState/name")
        flags = [text for flag, text in (
            (node.find("iamInstanceProfile") is not None,
             "an instance profile is attached: Systems Manager or other agents can be granted access"),
            (record and record["mode"] == "high-assurance" and text(node, "keyName"), "an SSH key pair is attached"),
            (state in ("shutting-down", "terminated"), "the instance is " + str(state))) if flag]
        return {"id": text(node, "instanceId"), "name": values.get("Name"), "state": state,
                "created": text(volumes[0], "ebs/attachTime") if volumes else text(node, "launchTime"),
                "image": text(node, "imageId"), "type": text(node, "instanceType"),
                "location": text(node, "placement/availabilityZone"), "ipv4": text(node, "ipAddress"),
                "ipv6": network(addresses[0]) if addresses else None, "flags": flags, "groups": sorted(groups),
                "volumes": [text(v, "ebs/volumeId") for v in volumes],
                "interfaces": [text(i, "networkInterfaceId") for i in interfaces],
                "belongs": bool(record) and values.get("tgwitness-deployment") == record["deployment_id"]}

    def describe(self, record):
        node = self.node(record["server"]["id"])
        return self.normalise(node, record) if node is not None else None

    def firewall(self, record, server):
        wanted, problems, inbound = record["firewall"]["id"], [], []
        if wanted not in server["groups"]:
            problems.append("the deployment security group " + wanted + " is not attached")
        if not server["groups"]:
            problems.append("no security group")
        found = self.ec2("DescribeSecurityGroups", {"GroupId." + str(n): g for n, g in enumerate(server["groups"], 1)}) \
            if server["groups"] else None
        for group in items(found, "securityGroupInfo"):
            for permission in items(group, "ipPermissions"):
                sources = [text(r, key) for kind, key in (("ipRanges", "cidrIp"), ("ipv6Ranges", "cidrIpv6"),
                                                         ("groups", "groupId"), ("prefixListIds", "prefixListId"))
                           for r in items(permission, kind)]
                inbound.append(text(group, "groupId") + ": " + str(text(permission, "ipProtocol")) + " "
                               + str(text(permission, "fromPort", "")) + "-" + str(text(permission, "toPort", ""))
                               + " from " + ", ".join(s for s in sources if s))
        return {"problems": problems, "inbound": inbound, "changed": None}

    def actions(self, record, server):
        start = parse_time(server["created"]).timestamp() - 3600
        found = {}
        for value in [server["id"], record["firewall"]["id"], *server["volumes"], *server["interfaces"]]:
            for event in self.lookup("ResourceName", value, start):
                found[event["EventId"]] = event
        for name in SESSIONS:
            for event in self.lookup("EventName", name, start):
                if server["id"] in (event.get("CloudTrailEvent") or ""):
                    found[event["EventId"]] = event
        rows = []
        for event in sorted(found.values(), key=lambda e: e["EventTime"]):
            detail = json.loads(event.get("CloudTrailEvent") or "{}")
            rows.append({"resource": ", ".join(r.get("ResourceName", "") for r in event.get("Resources") or []) or None,
                         "id": event["EventId"], "command": event["EventName"],
                         "started": parse_time(event["EventTime"]).isoformat(), "finished": None,
                         "status": "error" if detail.get("errorCode") else "success", "actor": event.get("Username"),
                         "read_only": str(event.get("ReadOnly")).lower() == "true"})
        return rows

    def classify(self, action, created):
        early = (parse_time(action["started"]) - created).total_seconds() <= self.window
        if action["command"] == "AuthorizeSecurityGroupIngress" and self.mode == "debug" and early:
            return "pass", "debug SSH rule added at deployment"
        return super().classify(action, created)

    @staticmethod
    def metadata(request, root):
        token = request(METADATA + "api/token", "PUT", {"X-aws-ec2-metadata-token-ttl-seconds": "300"}).strip()
        headers = {"X-aws-ec2-metadata-token": token}
        try:
            public = request(METADATA + "meta-data/public-ipv4", "GET", headers).strip()
        except OSError:
            public = None
        return {"instance_id": request(METADATA + "meta-data/instance-id", "GET", headers).strip(),
                "hostname": request(METADATA + "meta-data/local-hostname", "GET", headers).strip(),
                "region": request(METADATA + "meta-data/placement/region", "GET", headers).strip(),
                "public_ipv4": public, "user_data": request(METADATA + "user-data", "GET", headers)}


PROVIDER = Aws
