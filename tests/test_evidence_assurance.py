from tgwitness import cloud
from tgwitness.evidence import export_file
from tgwitness.verify import fingerprint


def test_ordinary_signed_records_do_not_prove_cloud_host_binding(journal):
    store, vault = journal
    store.append("message.new", {"text": "no deployment measurement"}, 123, 1)
    evidence = export_file(store, vault, "zip")
    try:
        report = cloud.Report()
        cloud.verify_journal(report, evidence, fingerprint(vault.public_key), 42)
        assert report.result() == "fail"
        assert "no process.started" in report.checks[-1]["detail"]
    finally:
        evidence.unlink()


def test_cloud_journal_needs_an_expected_collector_key(journal):
    store, vault = journal
    store.append("process.started", {"run": {"host": {"provider": {"instance_id": 42}}}})
    evidence = export_file(store, vault, "zip")
    try:
        report = cloud.Report()
        cloud.verify_journal(report, evidence, None, 42)
        assert report.result() == "fail"
        assert "no expected collector key" in report.checks[-1]["detail"]
    finally:
        evidence.unlink()


def test_missing_host_measurements_are_not_treated_as_no_access(journal):
    store, vault = journal
    store.append("process.started", {"run": {"host": {"provider": {"instance_id": 42}}}})
    evidence = export_file(store, vault, "zip")
    try:
        report = cloud.Report()
        cloud.verify_journal(report, evidence, fingerprint(vault.public_key), 42)
        assert report.result() == "incomplete"
        assert "unavailable host measurements" in report.checks[-1]["detail"]
    finally:
        evidence.unlink()
