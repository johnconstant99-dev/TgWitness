"""Missing message numbers: per-chat and account-wide sequences, validity, exports, reports and scoped access."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import report, tuning  # noqa: E402
from tgwitness.access import Principal, Refused  # noqa: E402
from tgwitness.archive import ArchiveQuery, ArchiveReader  # noqa: E402
from tgwitness.evidence import export_file  # noqa: E402
from tgwitness.security import Vault  # noqa: E402
from tgwitness.store import Store  # noqa: E402
from tgwitness.verify import (GAP_DEFAULTS, MESSAGE_KINDS, Sequences, coverage_lines, fingerprint, summarize_gaps,  # noqa: E402
                              verify_bundle)

CHANNEL, OTHER_CHANNEL, PERSON, GROUP = -1001000000001, -1001000000002, 4242, -555
FIXTURE = ROOT / "tools" / "fixtures" / "evidence-before-fulltext.zip"
WIDE = {"mode": "account", "types": {"channels": True, "groups": True, "private": True, "bots": True},
        "exclude": [], "own_actions": True}


def event(kind, chat_id=None, message_id=None, payload=None, at="2026-10-01T10:00:00.000+00:00"):
    return {"kind": kind, "chat_id": chat_id, "message_id": message_id, "payload": payload or {}, "observed_at": at}


def times(*numbers):
    return {n: "2026-10-01T10:00:%02d.000+00:00" % (n % 60) for n in numbers}


def test_gaps_are_counted_and_anchored():
    settings = {**GAP_DEFAULTS, "gap_service_estimate": True}
    result = summarize_gaps(times(1, 2, 3, 6, 7, 10), settings, service=3, notices=[7])
    assert (result["missing"], result["span"], result["gap_ranges"], result["largest_gap"]) == (4, 10, 2, 2)
    assert result["density"] == 0.4 and result["observed_without_content"] == 1
    first = result["clusters"][0]
    assert (first["low"], first["high"], first["after"]["message_id"], first["before"]["message_id"]) == (4, 5, 3, 6)
    assert result["service_estimate"]["expected_service_in_missing"] == 2, "3 service of 6 observed: half of 4"
    assert result["missing"] == 4, "An estimate is never subtracted"
    narrow = summarize_gaps(times(1, 2, 3, 6, 7, 10), {**GAP_DEFAULTS, "gap_cluster_min": 3, "gap_clusters_listed": 1})
    assert narrow["clusters"] == [] and narrow["clusters_total"] == 0 and narrow["missing"] == 4
    assert summarize_gaps(times(5), GAP_DEFAULTS)["status"] == "not_applicable"


def feed(sequences, events):
    for item in events:
        sequences.add(item, MESSAGE_KINDS)
    return sequences.result()


def test_channel_numbering_is_valid_per_chat_but_not_per_sender():
    events = [event("message.new", CHANNEL, n) for n in (10, 11, 14)] + [event("message.deleted", CHANNEL, 12)]
    chosen = feed(Sequences(chats_selected=True), events)
    assert chosen["chats"][0]["status"] == "applicable" and chosen["chats"][0]["missing"] == 1
    assert chosen["chats"][0]["observed_without_content"] == 1, "A deletion notice proves the number existed"
    by_sender = feed(Sequences(senders_selected=True), events)
    assert by_sender["chats"][0]["status"] == "not_applicable"
    assert feed(Sequences({"gap_analysis": False}), events)["status"] == "off"


def account_events(scope):
    return ([event("message.new", PERSON, 90), event("message.new", PERSON, 95)]
            + [event("scope.changed", payload={"before": {}, "after": scope})]
            + [event("message.new", PERSON, 100), event("message.new", GROUP, 101),
               event("deletion.unscoped", payload={"message_ids": [102]}), event("message.new", PERSON, 104),
               event("chat.service", GROUP, 101)])


def test_account_sequence_needs_whole_account_collection():
    measured = feed(Sequences(), account_events(WIDE))["account"]
    assert measured["status"] == "applicable" and (measured["observed_from"], measured["observed_to"]) == (100, 104)
    assert measured["missing"] == 1 and measured["clusters"][0]["low"] == 103, "Numbers before the scope are outside"
    assert measured["observed_without_content"] == 1, "An account-level deletion closes its number"
    for scope in ({**WIDE, "own_actions": False}, {**WIDE, "exclude": [PERSON]},
                  {**WIDE, "types": {**WIDE["types"], "bots": False}}, {**WIDE, "mode": "selected"}):
        assert feed(Sequences(), account_events(scope))["account"]["status"] == "not_applicable", scope
    assert feed(Sequences(chats_selected=True), account_events(WIDE))["account"]["status"] == "not_applicable"
    assert feed(Sequences({"gap_account_sequence": False}), account_events(WIDE))["account"]["status"] == "not_applicable"
    assert feed(Sequences(), account_events(WIDE) + [event("scope.changed", payload={"after": {"mode": "selected"}}),
                                                    event("scope.changed", payload={"after": WIDE})])["account"]["note"]


@pytest.fixture
def journal(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    store.set_target(CHANNEL, "Synthetic channel", "channel", True)
    store.set_target(OTHER_CHANNEL, "Other channel", "channel", True)
    store.append("scope.changed", {"before": {}, "after": WIDE})
    for number in (1, 2, 5, 6, 9):
        store.append("message.new", {"text": "post " + str(number)}, CHANNEL, number)
    for number in (1, 2):
        store.append("message.new", {"text": "other"}, OTHER_CHANNEL, number)
    for number in (300, 301, 303):
        store.append("message.new", {"text": "private"}, PERSON, number)
    yield vault, store
    store.close()


def reader(store, chats):
    principal = (Principal(True, "Synthetic admin") if chats is None else
                 Principal(False, "Synthetic reviewer", {"id": "synthetic", "workspaces": {"default": chats},
                                                         "all_workspaces": False, "permissions": ["view"],
                                                         "expires_at": None}))
    state = type("State", (), {"store": store, "collector": type("Collector", (), {"running": False})()})()
    registry = type("Registry", (), {"entries": {"default": {"app": type("App", (), {"state": state})(),
                                                             "label": "Synthetic"}}})()
    return ArchiveReader(registry, principal)


def test_capture_status_reports_gaps_within_access(journal):
    _, store = journal
    status = reader(store, None).read(ArchiveQuery(tool="get_capture_status"))["gap_summary"]
    channel = next(c for c in status["chats"] if c["chat_id"] == CHANNEL)
    assert channel["missing"] == 4 and "clusters" not in channel, "Listed gaps come with a chosen chat"
    assert status["account"]["status"] == "applicable" and status["account"]["missing"] == 1
    chosen = reader(store, None).read(ArchiveQuery(tool="get_capture_status", chat_id=CHANNEL))["gap_summary"]
    assert [(c["low"], c["high"]) for c in chosen["chats"][0]["clusters"]] == [(3, 4), (7, 8)]
    assert chosen["account"]["status"] == "not_applicable"
    scoped = reader(store, [CHANNEL]).read(ArchiveQuery(tool="get_capture_status"))["gap_summary"]
    assert [c["chat_id"] for c in scoped["chats"]] == [CHANNEL]
    assert scoped["account"]["status"] == "not_applicable" and "whole workspace" in scoped["account"]["reason"]
    with pytest.raises(Refused):
        reader(store, [CHANNEL]).read(ArchiveQuery(tool="get_capture_status", chat_id=OTHER_CHANNEL))
    assert "gap_summary" not in reader(store, None).read(ArchiveQuery(tool="get_capture_status", gaps=False))
    store.set_setting("parameters", {"gap_analysis": False})
    assert reader(store, None).read(ArchiveQuery(tool="get_capture_status"))["gap_summary"]["status"] == "off"


def test_export_report_and_verifier_carry_the_measurement(journal, tmp_path):
    vault, store = journal
    store.set_setting("parameters", {"gap_cluster_min": 2})
    archive = export_file(store, vault, "zip")
    try:
        with zipfile.ZipFile(archive) as bundle:
            coverage = json.loads(bundle.read("coverage.json"))
            page = bundle.read("report.html").decode("utf-8")
        summary = coverage["gap_summary"]
        assert summary["parameters"]["gap_cluster_min"] == 2
        assert next(c for c in summary["chats"] if c["chat_id"] == CHANNEL)["clusters_total"] == 2
        assert summary["account"]["missing"] == 1 and coverage["unobserved_ids"], "Earlier fields stay"
        assert "Missing message numbers" in page and "Account-wide message numbering" in page
        checked = verify_bundle(archive, expected_fingerprint=fingerprint(vault.public_key))
        recomputed = checked["coverage"]["gap_summary"]
        assert recomputed == summary, "The verifier uses the signed measurement parameters"
        assert recomputed["account"]["missing"] == summary["account"]["missing"], "The verifier repeats it"
        assert any("Account-wide sequence" in line for line in coverage_lines(checked["coverage"]))
        with zipfile.ZipFile(FIXTURE) as old:
            (tmp_path / "old_verify.py").write_bytes(old.read("verify.py"))
        copy = tmp_path / "current.zip"
        shutil.copyfile(archive, copy)
        previous = subprocess.run([sys.executable, str(tmp_path / "old_verify.py"), str(copy), "--fingerprint",
                                   fingerprint(vault.public_key)], capture_output=True, text=True, timeout=120)
        assert previous.returncode == 0, previous.stdout + previous.stderr
    finally:
        archive.unlink(missing_ok=True)


def test_report_rows_and_parameters_are_described():
    say = report.Words("en")
    summary = feed(Sequences({"gap_service_estimate": True}), [event("message.new", CHANNEL, n) for n in (1, 4)])
    view = report.gap_overview(say, summary)
    assert view["headers"][-1] == "Estimated service messages" and view["measured"][0][3] == 2
    assert "A service-message estimate is shown." in view["note"]
    groups = {group["id"]: group for group in tuning.described(type("S", (), {"get_setting": lambda *_: {}})())["groups"]}
    assert {item["key"] for item in groups["gaps"]["items"]} == set(GAP_DEFAULTS)


def test_service_numbers_are_observed_once_and_estimated_inside_the_window():
    events = [event("scope.changed", payload={"after": WIDE}), event("chat.service", PERSON, 1)]
    events += [event("message.new", PERSON, 100), event("chat.service", PERSON, 100)] * 4
    events += [event("message.new", PERSON, 104), event("membership.service", PERSON, 102)]
    events += [event("message.new", CHANNEL, 1), event("chat.service", CHANNEL, 2), event("message.new", CHANNEL, 3)]
    measured = feed(Sequences({"gap_service_estimate": True}), events)
    assert measured["chats"][0]["missing"] == 0
    account = measured["account"]
    assert account["missing"] == 2 and account["observed_without_content"] == 0
    assert account["service_estimate"]["service_share"] == round(2 / 3, 4)


def test_applied_scope_needs_explicit_own_message_coverage():
    payload = {"mode": "account", "types": WIDE["types"], "excluded": []}
    messages = [event("message.new", PERSON, 10), event("message.new", PERSON, 12)]
    unknown = feed(Sequences(), [event("scope.applied", payload=payload)] + messages)
    assert unknown["account"]["status"] == "not_applicable"
    known = feed(Sequences(), [event("scope.applied", payload={**payload, "own_actions": True})] + messages)
    assert known["account"]["missing"] == 1
    partial = {"mode": "account", "types": {"private": True}, "own_actions": True}
    assert feed(Sequences(), account_events(partial))["account"]["status"] == "not_applicable"
    started = feed(Sequences(), [event("observation.started", payload={"scope": WIDE})] + messages)
    assert started["account"]["missing"] == 1, "A recorded start scope is sufficient without a scope change"


def test_stopped_collection_does_not_extend_account_measurement(journal):
    from tgwitness.gap_analysis import capture_summary
    _, store = journal
    store.append("observation.stopped", {"reason": "operator"})
    store.append("message.new", {"text": "outside live collection"}, PERSON, 1000)
    stopped = capture_summary(store)["account"]
    assert stopped["observed_to"] == 303
    store.append("observation.started", {})
    store.append("message.new", {"text": "resumed"}, PERSON, 1001)
    resumed = capture_summary(store)["account"]
    assert resumed["observed_to"] == 1001 and resumed["note"]


def test_expired_capture_budget_returns_partial_without_poisoning_later_reads(journal):
    from tgwitness.gap_analysis import capture_summary
    _, store = journal
    assert "partial" in capture_summary(store, budget=0)
    assert "partial" not in capture_summary(store)


@pytest.mark.parametrize("settings", [{"gap_analysis": "false"}, {"gap_clusters_listed": -1},
                                      {"gap_cluster_min": True}, {"gap_service_estimate": []}])
def test_gap_parameters_reject_invalid_types_and_ranges(settings):
    with pytest.raises(ValueError, match="gap parameter"):
        Sequences(settings)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
