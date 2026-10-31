"""Host measurements and signed change records."""
import asyncio
import base64
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient

from tgwitness import assurance
from tgwitness.app import create_app
from tgwitness.verify import canonical, fingerprint

LISTEN_22 = "  0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1\n"
HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def utmp_entry(kind, user=b"", line=b"", host=b"", seconds=0):
    return assurance.UTMP.pack(kind, 100, line, b"", user, host, 0, 0, 0, seconds, 0, b"", b"")


def host_root(tmp_path, listening=False, logins=0):
    root = tmp_path / "host"
    (root / "proc/net").mkdir(parents=True, exist_ok=True)
    (root / "proc/sys/kernel/random").mkdir(parents=True, exist_ok=True)
    (root / "proc/sys/kernel/random/boot_id").write_text("boot-1\n")
    (root / "proc/net/tcp").write_text(HEADER + (LISTEN_22 if listening else ""))
    (root / "run").mkdir(exist_ok=True)
    (root / "run/utmp").write_bytes(b"")
    (root / "var/log").mkdir(parents=True, exist_ok=True)
    (root / "var/log/wtmp").write_bytes(utmp_entry(2, b"reboot", b"~", b"6.8.0", 1)
                                        + b"".join(utmp_entry(7, b"root", b"pts/0", b"198.51.100.4", 5)
                                                   for _ in range(logins)))
    return root


def test_utmp_layout_is_the_glibc_64_bit_record():
    assert assurance.UTMP.size == 384
    assert struct.calcsize("<h2xi") == 8


def test_host_state_counts_logins_listeners_and_ssh_processes(tmp_path):
    root = host_root(tmp_path)
    clean = assurance.host_state(root)
    assert clean["boot_id"] == "boot-1" and clean["ssh_listening"] is False and clean["ssh_processes"] == 0
    assert clean["sessions"] == 0 and clean["logins"] == 0

    root = host_root(tmp_path, listening=True, logins=2)
    (root / "proc/123").mkdir()
    (root / "proc/123/comm").write_text("sshd\n")
    (root / "proc/124").mkdir()
    (root / "proc/124/comm").write_text("python3\n")
    state = assurance.host_state(root)
    assert state["ssh_listening"] is True and state["ssh_processes"] == 1 and state["logins"] == 2
    assert state["recent_logins"][0] == {"user": "root", "line": "pts/0", "host": "198.51.100.4", "at": 5}
    assert state["wtmp_sha256"] != clean["wtmp_sha256"]


def test_missing_host_files_are_reported_as_unknown_not_clean(tmp_path):
    state = assurance.host_state(tmp_path / "empty")
    assert state["boot_id"] is None and state["sessions"] is None and state["logins"] is None


def test_provider_record_hashes_user_data_and_keeps_errors_visible():
    base = "http://169.254.169.254/hetzner/v1/"
    answers = {base + "metadata/instance-id": "42\n", base + "metadata/hostname": "case-1",
               base + "metadata/public-ipv4": "192.0.2.10", base + "metadata/region": "eu-central",
               base + "userdata": "#cloud-config\n  TGWITNESS_TOKEN=secret\n"}
    record = assurance.provider_record("hetzner", lambda url, method="GET", headers=None: answers[url])
    assert record["instance_id"] == 42 and record["public_ipv4"] == "192.0.2.10"
    assert record["user_data_redacted_sha256"] == assurance.user_data_hashes(
        "#cloud-config\n  TGWITNESS_TOKEN=REDACTED\n")["user_data_sha256"]
    assert "secret" not in str(record)

    def offline(url, method="GET", headers=None):
        raise OSError("no metadata service")
    assert assurance.provider_record("hetzner", offline) == {"provider": "hetzner", "error": "OSError"}


def test_redaction_replaces_only_the_two_secret_values():
    text = "a: 1\n      TGWITNESS_TOKEN=abc\n      TGWITNESS_TUNNEL_TOKEN=eyJ==\nprintf 'TGWITNESS_TOKEN=%s'\n"
    assert assurance.redact_user_data(text) == ("a: 1\n      TGWITNESS_TOKEN=REDACTED\n"
                                                "      TGWITNESS_TUNNEL_TOKEN=REDACTED\nprintf 'TGWITNESS_TOKEN=%s'\n")


def test_assurance_loop_records_changes_only(journal, tmp_path):
    store, _vault = journal
    root = host_root(tmp_path)

    async def run():
        task = asyncio.create_task(assurance.assurance_loop(store, "hetzner", {"instance_id": 42}, 0.01, root))
        await asyncio.sleep(0.1)
        assert store.events(kind="host.state") == []
        host_root(tmp_path, listening=True, logins=1)
        await asyncio.sleep(0.1)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    asyncio.run(run())
    [event] = store.events(kind="host.state")
    assert event["payload"]["ssh_listening"] is True and event["payload"]["before"]["ssh_listening"] is False
    assert event["payload"]["instance_id"] == 42 and event["payload"]["logins"] == 1
    store.verify(_vault.public_key)


def test_ordinary_installation_has_no_assurance_endpoint_or_host_record(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_ASSURANCE", raising=False)
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    with TestClient(create_app(tmp_path)) as c:
        assert c.get("/api/assurance").status_code == 404
        c.headers["Authorization"] = "Bearer " + (tmp_path / "panel-token.txt").read_text()
        assert "host" not in c.get("/api/run-receipt").json()["statement"]["run"]


def test_assurance_mode_signs_the_host_into_the_start_record_and_a_public_statement(tmp_path, monkeypatch):
    monkeypatch.setenv("TGWITNESS_ASSURANCE", "hetzner")
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    provider = {"provider": "hetzner", "instance_id": 42, "public_ipv4": "192.0.2.10",
                **assurance.user_data_hashes("#cloud-config\n")}
    monkeypatch.setattr(assurance, "provider_record", lambda selected: provider)
    with TestClient(create_app(tmp_path / "data")) as c:
        assert c.get("/api/assurance?challenge=XYZ").status_code == 422
        answer = c.get("/api/assurance?challenge=" + "ab" * 16).json()
        statement = answer["statement"]
        Ed25519PublicKey.from_public_bytes(base64.b64decode(statement["public_key"])).verify(
            base64.b64decode(answer["signature"]), canonical(statement))
        assert statement["challenge"] == "ab" * 16 and statement["host"]["provider"]["instance_id"] == 42

        assert "public_ipv4" not in statement["host"]["provider"] and "recent_logins" not in statement["host"]
        assert statement["fingerprint"] == fingerprint(c.app.state.vault.public_key)
        [started] = c.app.state.store.events(kind="process.started")
        assert started["seq"] == statement["run_event_seq"]
        assert started["payload"]["run"]["host"]["provider"] == provider
        assert started["payload"]["run"]["source_tree_sha256"] == statement["source_tree_sha256"]
        for secret in ("panel-token.txt", "vault.key"):
            assert (tmp_path / "data" / secret).read_text() not in c.get("/api/assurance").text


def test_unknown_assurance_mode_refuses_to_start(tmp_path, monkeypatch):
    monkeypatch.setenv("TGWITNESS_ASSURANCE", "elsewhere")
    with pytest.raises(RuntimeError, match="TGWITNESS_ASSURANCE"):
        with TestClient(create_app(tmp_path)):
            pass
