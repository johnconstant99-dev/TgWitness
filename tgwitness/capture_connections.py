import asyncio
import hashlib
import ipaddress
import secrets
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests
from cryptography.exceptions import InvalidSignature
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from tgwitness_capture.format import HEX, check_checkpoint, check_event, decode
from tgwitness_capture.verify import verify_zip

KINDS = ("browser", "ayugram", "trusted")
MAX_EXPORT = 512 * 1024 * 1024
MAX_OBJECT = 16 * 1024 * 1024
LOCAL_SERVICES = {"capture-browser", "capture-ayugram", "capture-trusted"}


def endpoint(value):
    value = value.strip().rstrip("/")
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host = parsed.hostname
        local = host == "localhost" or host in LOCAL_SERVICES
        try:
            local = local or ipaddress.ip_address(host).is_loopback
        except ValueError:
            pass
        if (parsed.scheme not in {"http", "https"} or not host or parsed.username is not None
                or parsed.password is not None or parsed.path or "?" in value or "#" in value
                or (parsed.scheme == "http" and not local) or (port is not None and port < 1)
                or any(c.isspace() or ord(c) < 32 or c == "\\" for c in value)):
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("Use an HTTPS origin, localhost, or the documented capture service name; no credentials or path.") from None
    return value


class Connection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool = False
    url: str = Field(default="", max_length=2048)
    fingerprint: str = Field(default="", max_length=64)
    token: str = Field(default="", max_length=512)
    screen_url: str = Field(default="", max_length=2048)

    @field_validator("url", "screen_url")
    @classmethod
    def valid_url(cls, value):
        return endpoint(value)

    @field_validator("fingerprint")
    @classmethod
    def valid_pin(cls, value):
        value = value.strip().lower()
        if value and (len(value) != 64 or any(c not in "0123456789abcdef" for c in value)):
            raise ValueError("Supply the recorder's 64-character SHA-256 key fingerprint.")
        return value

    @field_validator("token")
    @classmethod
    def valid_token(cls, value):
        if value and (len(value) < 32 or any(not 33 <= ord(c) <= 126 for c in value)):
            raise ValueError("Use the complete recorder control token (at least 32 printable ASCII characters).")
        return value


class CaptureConnections:
    def __init__(self, store, vault):
        self.store, self.vault = store, vault
        self.lock = asyncio.Lock()
        self.guard = threading.RLock()

    def public(self):
        with self.guard:
            saved = self.vault.read("capture_connections")
            return {"connections": {kind: {**Connection().model_dump(exclude={"token"}),
                                           **{key: value for key, value in saved.get(kind, {}).items()
                                              if key in {"enabled", "url", "fingerprint", "screen_url"}},
                                           "configured": bool(saved.get(kind, {}).get("token"))}
                                    for kind in KINDS}, "max_export_bytes": MAX_EXPORT}

    def save(self, kind, connection):
        with self.guard:
            saved = self.vault.read("capture_connections")
            old = saved.get(kind, {})
            new = connection.model_dump()
            same = old.get("url") == new["url"] and old.get("fingerprint") == new["fingerprint"]
            new["token"] = new["token"] or (old.get("token", "") if same else "")
            if new["enabled"] and not all(new[key] for key in ("url", "fingerprint", "token")):
                raise ValueError("Set the recorder URL, pinned key fingerprint and control token before enabling the connection.")
            if same and old.get("checkpoint"):
                new["checkpoint"] = old["checkpoint"]
            saved[kind] = new
            self.vault.save("capture_connections", saved)
            self.store.append("capture.connection_changed", {"kind": kind, "enabled": new["enabled"],
                                                           "fingerprint": new["fingerprint"]})
            return self.public()

    def _connection(self, kind):
        connection = self.vault.read("capture_connections").get(kind, {})
        if not connection.get("enabled"):
            raise ValueError("Enable this recorder connection first. This does not start capture.")
        return connection

    def _request(self, connection, method, path, body=None, *, destination=None, raw=False, timeout=30):
        with requests.Session() as client:
            client.trust_env = False
            deadline = time.monotonic() + 120
            with client.request(method, connection["url"] + "/api/" + path,
                                headers={"Authorization": "Bearer " + connection["token"]},
                                json=body, timeout=(5, timeout), allow_redirects=False, stream=True) as response:
                if response.status_code != 200:
                    raise ValueError("Recorder request refused (HTTP " + str(response.status_code)
                                     + "). Check its token, selected tab and capture state.")
                limit = MAX_EXPORT if destination else MAX_OBJECT if raw else 8 * 1024 * 1024
                result, size = bytearray(), 0
                for chunk in response.iter_content(65536):
                    size += len(chunk)
                    if size > limit or time.monotonic() > deadline:
                        raise ValueError("Recorder response exceeded the size or time limit. Export locally for larger archives.")
                    if destination:
                        destination.write(chunk)
                    else:
                        result.extend(chunk)
                if raw:
                    return bytes(result)
                if destination is None:
                    return decode(bytes(result))

    def _checkpoint(self, kind, connection):
        challenge = secrets.token_hex(32)
        checkpoint = self._request(connection, "GET", "checkpoint?challenge=" + challenge)
        try:
            body = checkpoint["body"]
            public_key = body["public_key"]
            if hashlib.sha256(bytes.fromhex(public_key)).hexdigest() != connection["fingerprint"]:
                raise ValueError
            check_checkpoint(checkpoint, public_key, body["observer_id"])
            if body["challenge"] != challenge:
                raise ValueError
            previous = connection.get("checkpoint", {}).get("body")
            if previous and (body["observer_id"] != previous["observer_id"] or body["seq"] < previous["seq"]
                             or (body["seq"] == previous["seq"] and body["head_hash"] != previous["head_hash"])):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise ValueError("Recorder identity or checkpoint verification failed. Check the pinned key and journal continuity.") from None
        return checkpoint

    def _remember(self, kind, checkpoint):
        saved = self.vault.read("capture_connections")
        saved[kind]["checkpoint"] = checkpoint
        self.vault.save("capture_connections", saved)

    def _identified(self, kind):
        connection = self._connection(kind)
        checkpoint = self._checkpoint(kind, connection)
        status = self._request(connection, "GET", "status")
        if (status.get("kind") != kind or status.get("fingerprint") != connection["fingerprint"]
                or status.get("observer_id") != checkpoint["body"]["observer_id"]):
            raise ValueError("This endpoint is not the configured recorder kind and identity.")
        self._remember(kind, checkpoint)
        return connection, checkpoint, status

    def open(self, kind, url, wait_seconds=5, purpose="", subject=None, chat_id=None):
        if kind != "browser":
            raise ValueError("Only the browser recorder opens addresses.")
        with self.guard:
            connection, checkpoint, _ = self._identified(kind)
            answer = self._request(connection, "POST", "open",
                                   {"url": url, "wait_seconds": wait_seconds, "purpose": purpose}, timeout=120)
            event = answer.get("event") if isinstance(answer, dict) else None
            try:
                check_event(event, checkpoint["body"]["public_key"], checkpoint["body"]["observer_id"])
                if event["kind"] != "capture.opened" or event["seq"] <= checkpoint["body"]["seq"]:
                    raise ValueError
            except (KeyError, TypeError, ValueError, InvalidSignature):
                raise ValueError("The recorder answer is not a valid signed capture from the pinned recorder.") from None
            payload = event["payload"]
            record = {"kind": kind, "fingerprint": connection["fingerprint"],
                      "observer_id": checkpoint["body"]["observer_id"], "recorder_seq": event["seq"],
                      "recorder_event_hash": event["hash"], "requested_url": url,
                      **{key: payload.get(key) for key in ("final_url", "title", "http_status", "server", "tls", "errors")},
                      "artifacts": event["artifacts"], "purpose": purpose, "subject": subject,
                      "meaning": "The pinned browser recorder signed this capture; this record links to its event"}
            main = self.store.append("capture.opened", record, chat_id)
            return {"event": main, "recorder_event": event}

    def object(self, kind, sha256):
        if not isinstance(sha256, str) or not HEX.fullmatch(sha256):
            raise ValueError("Use a SHA-256 object name.")
        with self.guard:
            data = self._request(self._connection(kind), "GET", "object/" + sha256, raw=True)
        if hashlib.sha256(data).hexdigest() != sha256:
            raise ValueError("The recorder returned bytes that differ from the requested hash.")
        return data

    def request(self, kind, path="status", body=None):
        with self.guard:
            connection, checkpoint, status = self._identified(kind)
            if path == "status":
                return {"status": status, "checkpoint": checkpoint}
            if path == "checkpoint":
                return checkpoint
            if path not in {"targets", "target", "settings", "snapshot", "events"}:
                raise ValueError("Unknown recorder action.")
            result = self._request(connection, "GET" if body is None else "POST", path, body)
            if body is not None:
                self.store.append("capture.command_sent", {"kind": kind, "action": path})
            return result

    def export(self, kind):
        with self.guard:
            connection = self._connection(kind)
            checkpoint = self._checkpoint(kind, connection)
            status = self._request(connection, "GET", "status")
            if status.get("kind") != kind or status.get("settings", {}).get("enabled"):
                raise ValueError("Pause the configured recorder before exporting a fixed boundary.")
            path = None
            try:
                with tempfile.NamedTemporaryFile(prefix="tgwitness-capture-", suffix=".zip", delete=False) as target:
                    path = Path(target.name)
                    self._request(connection, "POST", "export", {}, destination=target)
                result = verify_zip(path, expected_fingerprint=connection["fingerprint"], checkpoint=checkpoint)
                if connection.get("checkpoint"):
                    verify_zip(path, expected_fingerprint=connection["fingerprint"], checkpoint=connection["checkpoint"])
                self._remember(kind, checkpoint)
                self.store.append("capture.export_verified", {"kind": kind, "fingerprint": result["fingerprint"],
                                                             "events": result["events"], "head_hash": result["head_hash"]})
                return path
            except BaseException:
                if path:
                    path.unlink(missing_ok=True)
                raise
