"""What every provider implements, and the HTTP client they share."""
import ipaddress
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

from .. import __version__
from ..store import utcnow


class DeployError(RuntimeError):
    pass


def pause(seconds):
    time.sleep(seconds)


def parse_time(value):
    """Provider timestamps: ISO 8601 with or without zone (naive means UTC), or epoch seconds."""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def network(address):
    """An address or a network as a CIDR string, or None."""
    try:
        return str(ipaddress.ip_network(address, strict=False)) if address else None
    except ValueError:
        return None


class Api:
    """JSON over HTTPS. The log keeps method, path and status: no bodies, no credentials."""
    name = base = ""

    def __init__(self, token, session=None, log=None):
        self.session = session or requests.Session()
        self.log = [] if log is None else log
        self.headers = {"Authorization": "Bearer " + token, "User-Agent": "TgWitness/" + __version__}

    def ok(self, data):
        return isinstance(data, (dict, list))

    def reason(self, data):
        return json.dumps(data)[:300] if data else ""

    def send(self, method, url, path, **options):
        response = self.session.request(method, url, timeout=60, **options)
        self.log.append({"at": utcnow(), "service": self.name, "method": method, "path": path,
                         "status": response.status_code})
        return response

    def call(self, method, path, body=None, params=None, allow=(), headers=None):
        response = self.send(method, self.base + path, path, json=body, params=params,
                             headers={**self.headers, **(headers or {})})
        if response.status_code in allow:
            return None
        if response.status_code == 204:
            return {}
        try:
            data = response.json()
        except ValueError:
            data = None
        if response.status_code >= 400 or not self.ok(data):
            raise DeployError(self.name + " " + method + " " + path + ": HTTP " + str(response.status_code)
                              + " " + self.reason(data))
        return data


class Provider(Api):
    """A cloud with an API that creates servers, firewalls and keeps a log of actions.

    Deploy: create(spec, user_data, rules, outbound) returns (firewall, server) records and waits until
    the server runs; lock(record) removes every inbound rule and keeps the outbound ones. Verify: describe() reads the server back,
    firewall() what filters its public interface, actions() the provider's own log, normalised to
    {resource, id, command, started, finished, status, actor}. metadata() runs on the server.
    """
    key = title = ""
    location = mode = None
    variables = ()
    defaults = {}
    example_type = ""
    ssh_key_help = "name or ID of an SSH key in the provider account"
    user_data_limit = 32 * 1024
    window = 1800
    log_retention = "see the provider's documentation"
    limits = ()
    write_access = read_access = ""
    CREATION, DEPLOYMENT, INTERRUPTIONS, READ_ONLY = (), (), (), ()
    ACCESS, FAIL, REVIEW = {}, {}, {}

    @classmethod
    def credentials(cls, path):
        """Credentials come from a file or the environment, never from the command line."""
        value = Path(path).read_text(encoding="utf-8-sig").strip() if path else \
            os.environ.get(cls.variables[0], "").strip()
        if not value:
            raise DeployError("Provide --provider-token-file or set " + cls.variables[0])
        return value

    def __init__(self, credentials, session=None, log=None):
        super().__init__(credentials, session, log)

    def create(self, spec, user_data, rules, outbound=()):
        raise NotImplementedError

    def lock(self, record):
        raise NotImplementedError

    def destroy(self, record):
        """Deletes the deployment's server and firewall, found by its label; returns what was removed."""
        raise DeployError(self.title + ": removal through the API is not available here; delete the resources "
                          "labelled tgwitness-deployment=" + record["deployment_id"] + " in the provider's console")

    def describe(self, record):
        raise NotImplementedError

    def firewall(self, record, server):
        raise NotImplementedError

    def actions(self, record, server):
        raise NotImplementedError

    @staticmethod
    def metadata(request, root):
        raise NotImplementedError

    def classify(self, action, created):
        """pass, review or fail for one logged action, with its meaning."""
        command, status = action["command"], action["status"]
        started = parse_time(action.get("started") or created.isoformat())
        early = (started - created).total_seconds() <= self.window
        if command in self.CREATION:
            return "pass", "server created"
        if command in self.DEPLOYMENT and early:
            return "pass", "part of the deployment"
        if command in self.ACCESS:
            meaning = self.ACCESS[command]
            return ("review", meaning + " (the attempt failed)") if status == "error" else ("fail", meaning)
        if command in self.FAIL:
            return "fail", self.FAIL[command]
        if command in self.READ_ONLY or action.get("read_only"):
            return "pass", "read-only"
        if command in self.INTERRUPTIONS:
            return "review", "power or restart: collection was interrupted; compare with the journal"
        if command in self.REVIEW:
            return "review", self.REVIEW[command]
        return "review", "not expected in this mode"

    def wait_until(self, check, what, timeout=900, every=5):
        deadline = time.monotonic() + timeout
        while True:
            value = check()
            if value is not None and value is not False:
                return value
            if time.monotonic() > deadline:
                raise DeployError(self.title + ": " + what + " did not finish in time")
            pause(every)


def labels(spec):
    """Tags marking every created resource; the deployment ID makes them unique."""
    return {"tgwitness": spec["mode"], "tgwitness-deployment": spec["deployment_id"]}


def resource_name(spec):
    return "tgwitness-" + spec["name"] + "-" + spec["deployment_id"]
