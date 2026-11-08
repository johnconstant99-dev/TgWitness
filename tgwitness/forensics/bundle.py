import hashlib
import json
import shutil
from pathlib import Path

from ..security import owner_only, owner_only_state, private_write
from .mtproto import MTProtoDecryptor, extract_auth_key
from .pcap import UnsupportedCapture, cross_verify


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_bundle(target_dir, *, session_path, events, pcap_path=None, frames=None, include_key=False):
    target = Path(target_dir)
    if target.is_symlink() or (target.exists() and (not target.is_dir() or any(target.iterdir()))):
        raise ValueError("The bundle destination must be an empty directory or a new path")
    if frames is None:
        raise UnsupportedCapture("Supply complete MTProto frames; PCAP files can only be retained as attachments")
    frames = list(frames)
    if pcap_path is not None and not Path(pcap_path).is_file():
        raise ValueError("The PCAP attachment does not exist")
    network = target / "network"
    auth_key = extract_auth_key(session_path)
    decryptor = MTProtoDecryptor(auth_key)
    report = cross_verify(decryptor, frames, events)
    if include_key:
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        owner_only(target)
        if not owner_only_state(target)[0]:
            raise PermissionError("The key bundle destination must be accessible only to its owner.")
    network.mkdir(parents=True, exist_ok=True)
    frame_dir = network / "frames"
    frame_dir.mkdir()
    frame_paths = []
    for index, frame in enumerate(frames):
        path = frame_dir / f"{index:08d}.bin"
        path.write_bytes(frame)
        frame_paths.append(path.relative_to(target).as_posix())
    (network / "verification_report.json").write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    keys = {"auth_key_id": decryptor.auth_key_id.hex(), "auth_key_sha256": hashlib.sha256(auth_key).hexdigest()}
    if include_key:
        keys["auth_key_hex"] = auth_key.hex()
        keys["sensitive"] = "Contains the account master key; keep this bundle private."
    private_write(network / "session_keys.json", json.dumps(keys, indent=2, sort_keys=True).encode("utf-8"))
    paths = [*frame_paths, "network/verification_report.json", "network/session_keys.json"]
    if pcap_path is not None:
        shutil.copy2(pcap_path, network / "traffic.pcap")
        paths.append("network/traffic.pcap")

    manifest = {"files": {}, "status": report["status"],
                "capture_matches": report["capture_matches"], "frame_order": frame_paths,
                "pcap_role": "unverified_attachment" if pcap_path is not None else None,
                "events_with_anchor": report["events_with_anchor"], "includes_key": bool(include_key)}
    for path in sorted(paths):
        manifest["files"][path] = _sha256(target / path)
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest
