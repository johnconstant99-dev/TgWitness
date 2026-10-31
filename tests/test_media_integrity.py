import asyncio
import hashlib
import io
import os
import zipfile

import pytest

from tgwitness import replica
from tgwitness.evidence import checkpoint
from tgwitness.store import canonical
from tgwitness.verify import fingerprint, verify_bundle


KINDS = ("media.saved", "actor.avatar_saved")
CONTENT = b"saved attachment"
DIGEST = hashlib.sha256(CONTENT).hexdigest()


def signed_bundle(path, store, vault, media):
    """An independently packaged signed journal, without optional report derivatives."""
    files = {"events.jsonl": b"".join(canonical(e) + b"\n" for e in store.all_events()), **media}
    head = store.stats()["head"]
    manifest = {"format": "tgwitness-evidence-v1", "public_key": vault.public_key,
                "event_count": head["seq"], "head_hash": head["hash"],
                "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        archive.writestr("manifest.json", canonical(manifest))
        archive.writestr("manifest.sig", vault.sign(canonical(manifest)))
    return path


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("fault", (None, "missing", "changed", "size", "invalid_hash"))
def test_evidence_files_match_the_signed_media_references(journal, tmp_path, kind, fault):
    store, vault = journal
    payload = {"media_sha256": DIGEST, "size": len(CONTENT)}
    if fault == "size":
        payload["size"] += 1
    elif fault == "invalid_hash":
        payload["media_sha256"] = "../untrusted"
    store.append(kind, payload, -100123, 7, 42)
    media = {} if fault == "missing" else {"media/" + DIGEST: b"changed bytes" if fault == "changed" else CONTENT}
    path = signed_bundle(tmp_path / "independent.zip", store, vault, media)
    if fault:
        with pytest.raises(ValueError, match="media|attachment"):
            verify_bundle(path, fingerprint(vault.public_key))
    else:
        assert verify_bundle(path, fingerprint(vault.public_key))["events"] == 1


@pytest.mark.parametrize("missing", (False, True))
def test_restore_requires_saved_avatar_bytes(journal, tmp_path, missing):
    store, vault = journal
    store.append("actor.avatar_saved", {"media_sha256": DIGEST, "size": len(CONTENT),
                                       "peer_id": 42, "photo_id": 7}, -100123, actor_id=42)
    base, key = "workspace", os.urandom(32)
    clear = {"journal/000000000001-000000000001.jsonl": canonical(store.all_events()[0]) + b"\n",
             "checkpoints/checkpoint-000000000001.json": canonical(checkpoint(store, vault))}
    if not missing:
        clear["media/opaque-object-name"] = CONTENT
    objects = {}
    for suffix, data in clear.items():
        name = base + "/" + suffix + ".tgwr"
        objects[name] = b"".join(replica.encrypt(key, name, io.BytesIO(data).read, os.urandom(8)))

    class MemoryS3:
        async def list(self, prefix):
            for name, data in objects.items():
                assert name.startswith(prefix)
                yield name, len(data)

        async def get(self, name, sink):
            await sink(objects[name])

    out = tmp_path / "restored"
    out.mkdir()
    result = replica.restore_objects(MemoryS3(), {"fingerprint": fingerprint(vault.public_key)}, key, base, out)
    if missing:
        with pytest.raises(ValueError, match="media is missing"):
            asyncio.run(result)
    else:
        assert asyncio.run(result)["media_verified"] == 1
        assert (out / "media" / DIGEST).read_bytes() == CONTENT
