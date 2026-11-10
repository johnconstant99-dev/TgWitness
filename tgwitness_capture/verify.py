import hashlib
import re
import zipfile

from .format import FORMAT, HEX, ZERO, check_checkpoint, check_events, check_seal, decode, fingerprint

MAX_TOTAL = 8 * 1024 ** 3
MAX_FILE = 512 * 1024 ** 2


def verify_zip(path, expected_fingerprint=None, checkpoint=None, receipt=None,
               witness_fingerprint=None, require_final_anchor=False, expected_settings=None, *, check_drand=False):
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        if len(names) != len(set(names)) or len(names) > 100000:
            raise ValueError("Duplicate or excessive archive entries")
        if any(item.file_size > MAX_FILE or item.flag_bits & 1 or item.is_dir()
               or (item.external_attr >> 16) & 0o170000 not in {0, 0o100000} for item in infos):
            raise ValueError("Unsupported archive member")
        if sum(item.file_size for item in infos) > MAX_TOTAL:
            raise ValueError("Archive exceeds verification limit")
        if not {"manifest.json", "manifest.sig", "events.jsonl", "report.html"} <= set(names):
            raise ValueError("Incomplete capture export")
        if archive.getinfo("manifest.json").file_size > 16 * 1024 ** 2 or archive.getinfo("manifest.sig").file_size != 128:
            raise ValueError("Invalid manifest size")
        manifest = decode(archive.read("manifest.json"))
        if (set(manifest) != {"format", "observer_id", "public_key", "created_at", "seq", "head_hash", "files"}
                or manifest["format"] != FORMAT or not isinstance(manifest["files"], dict)):
            raise ValueError("Unsupported manifest")
        public_key = manifest["public_key"]
        actual_fingerprint = fingerprint(public_key)
        if expected_fingerprint is not None and expected_fingerprint != actual_fingerprint:
            raise ValueError("Untrusted observer key")
        check_seal(public_key, "manifest", manifest, archive.read("manifest.sig").decode("ascii"))
        if set(names) != set(manifest["files"]) | {"manifest.json", "manifest.sig"}:
            raise ValueError("Archive inventory does not match manifest")
        for name, descriptor in manifest["files"].items():
            if name not in {"events.jsonl", "report.html"} and not re.fullmatch(r"objects/[0-9a-f]{64}", name):
                raise ValueError("Unsafe or unknown archive path")
            if (set(descriptor) != {"sha256", "size"} or not HEX.fullmatch(descriptor["sha256"])
                    or type(descriptor["size"]) is not int or descriptor["size"] != archive.getinfo(name).file_size):
                raise ValueError("Invalid file descriptor")
            with archive.open(name) as source:
                if hashlib.file_digest(source, "sha256").hexdigest() != descriptor["sha256"]:
                    raise ValueError("File hash mismatch: " + name)
        events = []
        with archive.open("events.jsonl") as source:
            while line := source.readline(2 * 1024 ** 2 + 1):
                if len(line) > 2 * 1024 ** 2 or not line.endswith(b"\n"):
                    raise ValueError("Invalid journal line")
                events.append(decode(line))
        head = check_events(events, public_key, manifest["observer_id"])
        if type(manifest["seq"]) is not int or manifest["seq"] != len(events) or manifest["head_hash"] != head:
            raise ValueError("Manifest boundary does not match journal")
        referenced = {"events.jsonl", "report.html"}
        for event in events:
            for artifact in event["artifacts"]:
                name = "objects/" + artifact["sha256"]
                if manifest["files"].get(name) != {"sha256": artifact["sha256"], "size": artifact["size"]}:
                    raise ValueError("Missing or altered event artifact")
                referenced.add(name)
        if referenced != set(manifest["files"]):
            raise ValueError("Unreferenced export files")
        from .trusted_verify import verify_analysis
        report_count = int(verify_analysis(events, archive.read))
    from .trusted_anchor import confirm
    drand = confirm(events, check_drand)
    anchored_seq = 0
    independently_witnessed = False
    checkpoints = [checkpoint] if checkpoint is not None else []
    if receipt is not None:
        if not witness_fingerprint:
            raise ValueError("A trusted witness fingerprint is required for a receipt")
        receipt_body = receipt["body"]
        if receipt_body.get("format") != FORMAT or receipt_body.get("kind") != "witness.receipt":
            raise ValueError("Invalid witness receipt")
        witness_key = receipt_body["public_key"]
        if fingerprint(witness_key) != witness_fingerprint or witness_key == public_key:
            raise ValueError("Untrusted or shared witness key")
        check_seal(witness_key, "receipt", receipt_body, receipt["signature"])
        checkpoints.append(receipt_body["checkpoint"])
        independently_witnessed = True
    for retained in checkpoints:
        body = check_checkpoint(retained, public_key, manifest["observer_id"])
        if body["seq"] > len(events):
            raise ValueError("Export is shorter than retained checkpoint")
        expected_head = events[body["seq"] - 1]["hash"] if body["seq"] else ZERO
        if expected_head != body["head_hash"]:
            raise ValueError("Export disagrees with retained checkpoint")
        anchored_seq = max(anchored_seq, body["seq"])
    if require_final_anchor and (not checkpoints or anchored_seq != len(events)):
        raise ValueError("Export has an unanchored tail")
    from .official_proof import official_report
    official = official_report(events, expected_settings)
    return {"valid": True, "format": FORMAT, "observer_id": manifest["observer_id"],
            "fingerprint": actual_fingerprint, "key_pinned": expected_fingerprint is not None,
            "events": len(events), "head_hash": head, "checkpoint_checked": bool(checkpoints),
            "independently_witnessed": independently_witnessed, "anchored_seq": anchored_seq,
            "unanchored_events": len(events) - anchored_seq,
            "trusted_reports_checked": report_count, "drand": drand,
            **({"official": official} if official is not None else {})}
