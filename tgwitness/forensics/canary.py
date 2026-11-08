import hmac
import hashlib
import time


def probe_token(secret, case_id, target_user_id, created_at):
    raw = (str(case_id) + ":" + str(target_user_id) + ":" + repr(created_at)).encode("utf-8")
    return hmac.new(secret, raw, hashlib.sha256).hexdigest()[:16]


def client_address(headers, fallback):
    return fallback


def http_observation_record(probe, headers, remote, now=None):
    return {"kind": "forensics.http_observed",
            "payload": {"case_id": probe["case_id"], "configured_subject_id": probe["target_user_id"],
                        "probe_token": probe["token"], "network_address": client_address(headers, remote),
                        "user_agent": headers.get("User-Agent", "unknown"),
                        "observed_at": time.time() if now is None else now, "identity_established": False,
                        "meaning": "Observed HTTP request metadata; a proxy, preview service or different person may request a link."}}


def correlation(read_at, hit_at, window_seconds=5.0):
    if read_at is None or hit_at is None:
        return {"within_window": None, "latency_seconds": None, "identity_established": False}
    latency = abs(hit_at - read_at)
    return {"within_window": latency <= window_seconds,
            "latency_seconds": latency, "identity_established": False}


class CanaryProbes:
    def __init__(self, journal, secret, clock=time.time):
        self.journal = journal
        self.secret = secret
        self.clock = clock
        self.active = {}

    def create(self, case_id, target_user_id, base_url):
        created_at = self.clock()
        token = probe_token(self.secret, case_id, target_user_id, created_at)
        self.active[token] = {"token": token, "case_id": case_id, "target_user_id": target_user_id,
                              "created_at": created_at, "triggered": False, "read_at": None}
        self.journal.append("forensics.canary_created",
                            {"case_id": case_id, "configured_subject_id": target_user_id, "probe_token": token,
                             "observed_at": created_at})
        return base_url.rstrip("/") + "/v1/verify/" + token

    def note_read(self, target_user_id):
        for probe in self.active.values():
            if probe["target_user_id"] == target_user_id:
                probe["read_at"] = self.clock()

    def hit(self, token, headers, remote):
        probe = self.active.get(token)
        if probe is None:
            return None
        now = self.clock()
        record = http_observation_record(probe, headers, remote, now)
        link = correlation(probe.get("read_at"), now)
        record["payload"].update(link)
        probe["triggered"] = True
        self.journal.append(record["kind"], record["payload"])
        return record
