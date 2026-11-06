import http.client
import json
import secrets
import socket

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .. import __version__
from .base import DeployError, Provider, resource_name

SOCKET = "/var/run/dstack.sock"
API_VERSION = "2026-06-23"
COMPOSE_LIMIT = 200 * 1024


class GuestConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = path

    def connect(self):
        self.sock = socket.socket(getattr(socket, "AF_UNIX"), socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def guest(method, body=None, path=SOCKET, timeout=10):
    connection = GuestConnection(path, timeout)
    try:
        connection.request("POST", "/" + method, json.dumps(body or {}), {"Content-Type": "application/json"})
        response = connection.getresponse()
        data = response.read(8 * 1024 * 1024)
    finally:
        connection.close()
    if response.status != 200:
        raise OSError("dstack guest agent " + method + ": HTTP " + str(response.status))
    return json.loads(data)


def encrypt_environment(values, public_key_hex):
    secret = X25519PrivateKey.generate()
    shared = secret.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex.removeprefix("0x"))))
    nonce = secrets.token_bytes(12)
    body = json.dumps({"env": [{"key": k, "value": v} for k, v in values.items()]}).encode()
    public = secret.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return (public + nonce + AESGCM(shared).encrypt(nonce, body, None)).hex()


class Phala(Provider):
    key, title, name = "phala", "Phala Cloud (Intel TDX)", "Phala Cloud"
    base = "https://cloud-api.phala.com/api/v1"
    variables = ("PHALA_CLOUD_API_KEY",)
    defaults = {"location": "any", "image": "default"}
    example_type = "tdx.small"
    ssh_key_help = "not used: a Phala CVM has no SSH"
    user_data_limit = COMPOSE_LIMIT
    log_retention = ("Phala lists every revision of the application for as long as it exists; restarts, stops and "
                     "starts appear among the operations of the CVM")
    limits = (
        "Intel signs what the processor measured. A flaw in Intel's TDX module or microcode, or physical "
        "access to the memory bus of the machine (published attacks on DDR4/DDR5 interposers), is outside "
        "what a quote can exclude.",
        "Phala's KMS gives this application its disk and environment keys. Whoever controls the application in "
        "Phala's account can deploy another compose; it is a new revision with a new compose hash, and code it "
        "runs could read the keys. The revisions below and the compose hash of every start in the journal show it.",
        "Disk encryption gives confidentiality, not freshness: an earlier copy of the encrypted disk can be put "
        "back. The journal's hash chain, retained checkpoints and an external witness detect a rolled-back journal.",
        "The CVM has no trusted clock and its network belongs to the host, which can delay or block traffic. "
        "Timestamps still come from RFC 3161 and OpenTimestamps anchors.",
        "The key the environment secrets are encrypted to comes from Phala's API. Those secrets (panel and tunnel "
        "tokens) give access to the panel, not to the signing key, and every panel action is in the journal.",
    )
    CREATION = ("create",)
    REVIEW = {"update_env": "environment secrets replaced", "restart": "restart: collection was interrupted",
              "stop": "stopped: collection was interrupted", "start": "started again",
              "upgrade_os": "the OS image changed"}
    FAIL = {"update_compose": "the compose changed after the deployment: other code could have run with this "
                              "application's keys"}

    def __init__(self, credentials, session=None, log=None):
        super().__init__(credentials, session, log)
        self.headers = {"X-API-Key": credentials, "X-Phala-Version": API_VERSION, "User-Agent": "TgWitness/" + __version__}

    def create(self, spec, app_compose, environment):
        name = resource_name(spec)
        body = {"name": name, "instance_type": spec["server_type"], "compose_file": {**app_compose, "name": name},
                "listed": False, "kms": "PHALA"}
        if spec.get("location") not in (None, "any"):
            body["region"] = spec["location"]
        if spec.get("image") not in (None, "default"):
            body["image"] = spec["image"]
        prepared = self.call("POST", "/cvms", body)
        if "image" not in body:
            if not isinstance(prepared.get("os_image_version"), str) or not prepared["os_image_version"]:
                raise DeployError("Phala Cloud did not name its current OS image; choose one with --image")
            body["image"] = "dstack-" + prepared["os_image_version"]
            prepared = self.call("POST", "/cvms", body)
        for field in ("app_id", "app_env_encrypt_pubkey", "compose_hash"):
            if not isinstance(prepared.get(field), str) or not prepared[field]:
                raise DeployError("Phala Cloud did not prepare the CVM (no " + field + ")")
        token = {"token": prepared["token"]} if isinstance(prepared.get("token"), str) and prepared["token"] else {}
        committed = self.call("POST", "/cvms", {
            "app_id": prepared["app_id"], "compose_hash": prepared["compose_hash"], **token,
            "encrypted_env": encrypt_environment(environment, prepared["app_env_encrypt_pubkey"]),
            "env_keys": sorted(environment)})
        cvm = str(committed.get("id") or "")
        if not cvm:
            raise DeployError("Phala Cloud did not create the CVM")
        found = self.wait_until(lambda: self.running(cvm), "the CVM start", timeout=1800, every=10)
        return {"id": None, "inbound_rules": []}, {
            "id": cvm, "name": body["name"], "created": committed.get("created_at") or found.get("created_at"),
            "app_id": prepared["app_id"], "compose_hash": prepared["compose_hash"], "instance_id": found.get("instance_id"),
            "ipv4": None, "ipv6": None, "image": (found.get("os") or {}).get("version"),
            "os_image_hash": (found.get("os") or {}).get("os_image_hash"), "type": spec["server_type"],
            "location": (found.get("node_info") or {}).get("region"), "hourly_rate": found.get("hourly_rate")}

    def running(self, cvm):
        found = self.call("GET", "/cvms/" + cvm)
        if found.get("status") != "running":
            return None
        found["instance_id"] = found.get("instance_id") or self.call("GET", "/cvms/" + cvm + "/state").get("instance_id")
        return found if found["instance_id"] else None

    def lock(self, record):
        raise DeployError("A Phala CVM has no SSH and no provider firewall to close")

    def destroy(self, record):
        name, server = resource_name(record), record.get("server") or {}
        cvms, page = ([str(server["id"])] if server.get("id") else []), 1
        while not cvms:
            data = self.call("GET", "/cvms/paginated", params={"page": page, "page_size": 100})
            cvms += [str(item["id"]) for item in data.get("items") or [] if item.get("name") == name and item.get("id")]
            if page >= int(data.get("pages") or 1):
                break
            page += 1
        for cvm in cvms:
            self.call("DELETE", "/cvms/" + cvm, allow=(404,))
        return [{"resource": "cvm", "id": cvm, "name": name} for cvm in cvms]

    def describe(self, record):
        found = self.call("GET", "/cvms/" + str(record["server"]["id"]), allow=(404,))
        if not found:
            return None
        os_info, node, resource = found.get("os") or {}, found.get("node_info") or {}, found.get("resource") or {}
        flags = []
        if os_info.get("is_dev"):
            flags.append("a development OS image: SSH into the CVM and debugging are possible")
        if found.get("status") != "running":
            flags.append("the CVM is " + str(found.get("status")))
        return {"id": found.get("id"), "name": found.get("name"), "created": record["server"].get("created") or
                record["created_at"], "type": resource.get("instance_type"), "location": node.get("region"),
                "image": os_info.get("version") or os_info.get("os_image_hash"),
                "belongs": found.get("name") == record["server"]["name"] and found.get("app_id") == record["server"]["app_id"],
                "flags": flags, "ipv4": None, "ipv6": None, "app_id": found.get("app_id"),
                "instance_id": found.get("instance_id"), "compose_hash": found.get("compose_hash"),
                "os_image_hash": os_info.get("os_image_hash"), "node": node.get("name"),
                "gateway_enabled": found.get("gateway_enabled"), "endpoints": found.get("endpoints") or []}

    def firewall(self, record, server):
        inbound = []
        if server.get("gateway_enabled"):
            inbound.append("the dstack gateway forwards public connections into the CVM")
        inbound += ["public endpoint " + str(e.get("app") or e.get("url") or e) for e in server.get("endpoints") or []
                    if isinstance(e, dict)]
        return {"problems": [], "inbound": inbound, "changed": None,
                "detail": "no dstack gateway and no public endpoint: the CVM accepts no connections"}

    def actions(self, record, server):
        found, page = [], 1
        while True:
            data = self.call("GET", "/apps/" + str(record["server"]["app_id"]) + "/revisions",
                             params={"page": page, "page_size": 100})
            found += data.get("revisions") or []
            if page >= int(data.get("total_pages") or 1):
                break
            page += 1
        first = record["server"]["compose_hash"]
        actions = []
        for index, revision in enumerate(sorted(found, key=lambda r: r.get("created_at") or "")):
            command = revision.get("operation_type") or "revision"
            if revision.get("compose_hash") != first:
                command = "update_compose"
            elif index == 0:
                command = "create"
            actions.append({"resource": "app", "id": revision.get("revision_id"), "command": command,
                            "operation": revision.get("operation_type"), "started": revision.get("created_at"),
                            "finished": revision.get("created_at"), "status": "success",
                            "actor": (revision.get("triggered_by") or {}).get("username")})
        cursor = None
        while True:
            data = self.call("GET", "/cvms/" + str(record["server"]["id"]) + "/operations",
                             params={"limit": 50, **({"cursor": cursor} if cursor else {})})
            for item in data.get("items") or []:
                if item.get("operation_type") != "create":
                    actions.append({"resource": "cvm", "id": item.get("correlation_id"),
                                    "command": item.get("operation_type") or "operation",
                                    "operation": item.get("operation_type"), "started": item.get("started_at"),
                                    "finished": item.get("completed_at"), "status": item.get("status"),
                                    "actor": item.get("triggered_by_username")})
            cursor = data.get("next_cursor")
            if not cursor:
                break
        return actions

    @staticmethod
    def metadata(request, root):
        info = guest("Info")
        tcb = json.loads(info["tcb_info"]) if isinstance(info.get("tcb_info"), str) else info.get("tcb_info") or {}
        return {"instance_id": info.get("instance_id"), "app_id": info.get("app_id"), "hostname": socket.gethostname(),
                "public_ipv4": None, "region": None, "compose_hash": info.get("compose_hash") or tcb.get("compose_hash"),
                "app_compose": tcb.get("app_compose") or info.get("app_compose"),
                "os_image_hash": info.get("os_image_hash") or tcb.get("os_image_hash"),
                "key_provider_info": info.get("key_provider_info"), "vm_config": info.get("vm_config")}

    @staticmethod
    def attest(data):
        if len(data) != 64:
            raise ValueError("report data must be 64 bytes")
        answer = guest("GetQuote", {"report_data": data.hex()}, timeout=30)
        return {"quote": answer["quote"], "event_log": answer["event_log"], "vm_config": answer.get("vm_config")}


PROVIDER = Phala
