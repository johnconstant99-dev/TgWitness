import pytest

from tgwitness.store import Store


@pytest.mark.parametrize("text,query", [
    ("Привет Мир", "привет"), ("Привет Мир", "ПРИВЕТ"),
    ("Straße", "STRASSE"), ("Café", "CAFE\u0301"), ("CAFÉ", "café"),
])
def test_unicode_search_preserves_signed_record_and_survives_reopen(journal, text, query):
    store, vault = journal
    original = store.append("message.new", {"text": text}, -123, 7)
    assert store.events(search=query) == [original]
    assert not store.events(search=query, chat_id=-456)
    with_other_connection = Store(store.root)
    try:
        assert with_other_connection.events(search=query) == [original]
        assert with_other_connection.verify(vault.public_key)["events"] == 1
    finally:
        with_other_connection.close()


def test_coverage_filter_includes_monitoring_policy_boundaries(journal):
    store, _ = journal
    change = store.append("monitoring.changed", {"before": {"messages": True}, "after": {"messages": False}})
    store.append("message.new", {"text": "Historical content"}, -123, 7)
    assert store.events(kind="coverage") == [change]
    assert store.events(kind="monitoring.changed") == [change]
