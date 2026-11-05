"""Real encrypted split/assembly plus size fallback, corruption and provenance checks."""
import asyncio
import json
from pathlib import Path
import random
import sys
from types import SimpleNamespace
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import evidence, sealed
from tgwitness.sealed_crypto import keypair, decrypt_file
from tgwitness.sealed_package import package
from tgwitness.sealed_parts import EncryptedParts, MANIFEST, SEALED_RESULT, assemble, load_manifest
from tgwitness.sealed_verify import verify as verify_sealed
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import verify_bundle
from tools.browser_fixtures import CapsuleClient, config
from tools.test_export_capacity import collect


@pytest.fixture(scope="module")
def key():
    return keypair()


def test_streaming_encrypted_parts_reassemble_and_reject_tampering(tmp_path, key):
    vault, store = Vault(tmp_path / "data"), Store(tmp_path / "data")
    store.bind(vault)
    output = tmp_path / "out"
    output.mkdir()
    cfg = config(key)
    try:
        store.append("message.new", {"text": random.Random(27).randbytes(32768).hex()}, -42, 1)
        with EncryptedParts(output, vault, cfg, part_bytes=8192) as outgoing:
            evidence.export_file(store, vault, "zip", compact=True, output_stream=outgoing)
        manifest = load_manifest(output / MANIFEST, encrypted=True)
        assert len(manifest["parts"]) > 2
        assert all(p["bytes"] <= 8192 for p in manifest["parts"])
        assert not (output / "evidence.zip").exists()
        (output / "result.json").write_text(json.dumps(SEALED_RESULT))
        attestation = output / "attestation.jsonl"
        attestation.write_text("Synthetic attestation; not a GitHub proof.")
        package(cfg, output, attestation)
        decrypt_file(output / "delivery.tgwsealed", tmp_path / "delivery.zip", key)
        with zipfile.ZipFile(tmp_path / "delivery.zip") as z:
            assert set(z.namelist()) == {MANIFEST, "attestation.jsonl", "README.txt"}
            assert z.read(MANIFEST) == (output / MANIFEST).read_bytes()
        assembled = tmp_path / "evidence.zip"
        assemble(output / MANIFEST, assembled, key)
        assert verify_bundle(assembled)["events"] == 1
        before = assembled.read_bytes()
        with pytest.raises(FileExistsError):
            assemble(output / MANIFEST, assembled, key)
        assert assembled.read_bytes() == before
        part = output / manifest["parts"][1]["encrypted_file"]
        original = part.read_bytes()
        part.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with pytest.raises(ValueError, match="changed"):
            assemble(output / MANIFEST, tmp_path / "corrupted.zip", key)
        assert not (tmp_path / "corrupted.zip").exists()
        with pytest.raises(ValueError, match="changed"):
            load_manifest(output / MANIFEST, encrypted=True)
    finally:
        store.close()


def test_interrupted_stream_removes_all_uncommitted_parts(tmp_path, key):
    vault = Vault(tmp_path / "data")
    output = tmp_path / "out"
    output.mkdir()
    with pytest.raises(OSError, match="synthetic"):
        with EncryptedParts(output, vault, config(key), part_bytes=2048) as stream:
            stream.write(b"synthetic" * 1000)
            raise OSError("synthetic disk failure")
    assert list(output.iterdir()) == []


def test_core_exceeding_single_zip_cap_still_delivers_every_signed_event(tmp_path, monkeypatch, key):
    original_value = evidence.tuning.value
    monkeypatch.setattr(evidence.tuning, "value", lambda store, name:
        (4 * 1024**2 + 100) / 1024**3 if name == "export_max_gib" else original_value(store, name))

    async def run():
        cfg = config(key)
        output = tmp_path / "out"
        app = sealed.create_app(tmp_path / "data", output, cfg, CapsuleClient)
        async with app.router.lifespan_context(app):
            await collect(app)
            session = app.state.session
            assert session.phase == "sealed", session.reason
            assert session.revocation == "revoked"
            assert json.loads((output / "result.json").read_bytes()) == SEALED_RESULT
            assemble(output / MANIFEST, output / "evidence.zip", key)
            internal = verify_bundle(output / "evidence.zip")
            assert internal["events"] == session.store.db.execute("SELECT count(*) FROM events").fetchone()[0]
            policy = tmp_path / "policy.json"
            workflow = "phishdestroy/TgWitness/.github/workflows/sealed-collector.yml"
            policy.write_text(json.dumps({"format": "tgwitness-sealed-policy-v1", "workflow": workflow,
                "releases": [{"collector_sha": "a" * 40, "workflow_sha": "b" * 40}]}))
            attestation = output / "attestation.jsonl"
            attestation.write_text("Synthetic external verifier response; not real GitHub attestation.")
            calls = []
            def external(command, **kwargs):
                calls.append(command)
                return SimpleNamespace(returncode=0, stdout='[{"synthetic":true}]')
            verified = verify_sealed(output / MANIFEST, attestation, "user/fork", policy, run=external)
            assert verified["verified"] and str((output / MANIFEST).resolve()) in calls[0]
            with (output / "evidence.zip").open("ab") as stream:
                stream.write(b"changed")
            with pytest.raises(ValueError, match="differs"):
                verify_sealed(output / MANIFEST, attestation, "user/fork", policy, run=external)
    asyncio.run(run())
