import hashlib
import re

from .mtproto import MTProtoFrameError

MAX_SCAN_WINDOWS = 1_000_000
MAX_SCAN_BYTES = 64 * 1024 * 1024
LIMITATIONS = ("Frame matching checks supplied payload digests and optional message identifiers. "
               "Review capture origin, acquisition time and custody through the acquisition record. Generic PCAP import "
               "is not supported by this helper.")


class UnsupportedCapture(ValueError):
    pass


def decode_frames(decryptor, frames):
    for index, frame in enumerate(frames):
        for from_server in (True, False):
            try:
                yield decryptor.decrypt_frame(frame, from_server=from_server)
                break
            except MTProtoFrameError:
                continue
        else:
            raise MTProtoFrameError(f"Supplied frame {index} is invalid in both directions")


def index_frames(decryptor, frames):
    by_message, by_digest = {}, {}
    for record in decode_frames(decryptor, frames):
        by_message.setdefault(record["message_id"], []).append(record)
        by_digest.setdefault(record["payload_sha256"], []).append(record)
    return by_message, by_digest


def cross_verify(decryptor, frames, events):
    records = list(decode_frames(decryptor, frames))
    checked = matched = 0
    annotated = []
    for event in events:
        payload = event.get("payload") or {}
        mid = payload.get("mtproto_message_id")
        digest = payload.get("mtproto_payload_sha256")
        if digest is None:
            annotated.append({"event": event, "capture_match": None,
                              "basis": "identifier_only" if mid is not None else "none"})
            continue
        checked += 1
        match = bool(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
                     and (mid is None or type(mid) is int) and any(
            record["payload_sha256"] == digest and (mid is None or record["message_id"] == mid)
            for record in records))
        if match:
            matched += 1
        annotated.append({"event": event, "capture_match": match, "basis": "payload_sha256"})
    return {"status": "DIGESTS_MATCH" if checked and matched == checked else "PARTIAL" if checked else "NO_DIGEST_ANCHORS",
            "frames_decrypted": len(records), "events_total": len(annotated),
            "events_with_anchor": checked, "capture_matches": matched,
            "match_ratio": matched / checked if checked else 0.0, "events": annotated, "limitations": LIMITATIONS}


def _window_digests(payload, length, wanted):
    seen = set()
    for start in range(0, len(payload) - length + 1):
        digest = hashlib.sha256(payload[start:start + length]).hexdigest()
        if digest in wanted:
            seen.add(digest)
    return seen


def anchor_by_raw(decryptor, frames, anchors):
    anchors = list(anchors)
    wanted_by_length = {}
    for anchor in anchors:
        length, digest = anchor.get("length"), anchor.get("sha256")
        if type(length) is not int or length <= 0 or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Raw anchors require a positive byte length and a lowercase SHA-256 digest")
        wanted_by_length.setdefault(length, set()).add(digest)
    payloads = [record["payload"] for record in decode_frames(decryptor, frames)]
    by_length = {}
    windows = scan_bytes = 0
    for length, wanted in wanted_by_length.items():
        count = sum(max(0, len(payload) - length + 1) for payload in payloads)
        windows += count
        scan_bytes += count * length
        if windows > MAX_SCAN_WINDOWS or scan_bytes > MAX_SCAN_BYTES:
            raise ValueError("Raw anchor scan exceeds the offline work limit")
        by_length[length] = set()
        for payload in payloads:
            by_length[length].update(_window_digests(payload, length, wanted))
    found = []
    for anchor in anchors:
        length = anchor["length"]
        found.append({"anchor": anchor, "capture_match": anchor["sha256"] in by_length[length]})
    return {"frames_decrypted": len(payloads), "anchors": found, "limitations": LIMITATIONS,
            "matched": sum(1 for a in found if a["capture_match"])}


def frames_from_pcap(path, auth_key_id):
    raise UnsupportedCapture("Generic PCAP import is not qualified; supply complete MTProto frames explicitly")


def verify_capture(session_path, pcap_path, events):
    raise UnsupportedCapture("Generic PCAP import is not qualified; supply complete MTProto frames explicitly")
