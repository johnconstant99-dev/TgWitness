import secrets
import urllib.error
import urllib.parse
import urllib.request

from .format import FORMAT, canonical, check_checkpoint, decode, fingerprint, seal, utcnow
from .journal import durable_write


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Checkpoint redirects are not allowed")


def witness_once(journal, url, token, expected_fingerprint):
    parsed = urllib.parse.urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Use a service URL without credentials, query or fragment")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}):
        raise ValueError("A remote witness requires HTTPS")
    challenge = secrets.token_hex(32)
    request = urllib.request.Request(url.rstrip("/") + "/api/checkpoint?challenge=" + challenge,
                                     headers={"Authorization": "Bearer " + token})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=15) as response:
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError("Checkpoint response too large")
    checkpoint = decode(raw)
    body = checkpoint["body"]
    if fingerprint(body["public_key"]) != expected_fingerprint or body["public_key"] == journal.public_key:
        raise ValueError("Checkpoint key is not independently trusted")
    check_checkpoint(checkpoint, body["public_key"], body["observer_id"])
    if body["challenge"] != challenge:
        raise ValueError("Checkpoint challenge mismatch")
    previous = [event["payload"]["checkpoint"]["body"] for event in journal.events()
                if event["kind"] == "witness.observed" and event["payload"]["checkpoint"]["body"]["public_key"] == body["public_key"]]
    if previous:
        last = previous[-1]
        if body["observer_id"] != last["observer_id"] or body["seq"] < last["seq"] or (
                body["seq"] == last["seq"] and body["head_hash"] != last["head_hash"]):
            journal.append("witness.conflict", {"checkpoint": checkpoint, "previous": last})
            raise ValueError("Observer rollback or conflicting head detected")
    event = journal.append("witness.observed", {"checkpoint": checkpoint, "received_at": utcnow(),
                           "scope": "fresh signed head; the journal export covers intermediate events"})
    receipt_body = {"format": FORMAT, "kind": "witness.receipt", "public_key": journal.public_key,
                    "witness_observer_id": journal.observer_id, "witness_seq": event["seq"],
                    "witness_event_hash": event["hash"], "received_at": event["recorded_at"], "checkpoint": checkpoint}
    receipt = {"body": receipt_body, "signature": seal(journal.key, "receipt", receipt_body)}
    directory = journal.root / "receipts"
    directory.mkdir(exist_ok=True)
    destination = directory / (str(event["seq"]).zfill(12) + ".json")
    durable_write(destination, canonical(receipt), exclusive=True)
    return destination
