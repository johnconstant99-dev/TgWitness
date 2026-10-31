import hashlib
import json
import sqlite3

import pytest

from tgwitness.journal_index import JournalIndex
from tgwitness import message_content
from tgwitness.store import CHAT_KINDS, TEXT_KINDS, Store, canonical, search_text


def legacy_overview(store):
    rows = store.db.execute(
        "SELECT chat_id,count(DISTINCT CASE WHEN kind!='media.saved' THEN message_id END) AS messages,"
        "count(DISTINCT CASE WHEN kind='message.edited' THEN message_id END) AS edited,"
        "count(DISTINCT CASE WHEN kind='message.deleted' THEN message_id END) AS deleted,"
        "count(DISTINCT CASE WHEN kind='message.missing_on_recheck' THEN message_id END) AS missing,"
        "max(observed_at) AS last_observed_at FROM events WHERE chat_id IS NOT NULL "
        "AND message_id IS NOT NULL AND kind IN (" + ",".join("?"*len(CHAT_KINDS)) + ") GROUP BY chat_id",
        CHAT_KINDS).fetchall()
    result = {}
    for row in rows:
        newest = store.db.execute(
            "SELECT payload FROM events WHERE chat_id=? AND kind IN (?,?,?,?) "
            "ORDER BY message_id DESC,seq DESC LIMIT 1", (row["chat_id"], *TEXT_KINDS)).fetchone()
        payload = json.loads(newest[0]) if newest else {}
        values = dict(row)
        values.pop("chat_id")
        result[row["chat_id"]] = values | {"last_text": payload.get("text"),
            "last_sender": (payload.get("sender_observation") or {}).get("display_name")}
    return result


def remove_read_index(store):
    with store.transaction():
        for name in ("message_state_index", "chat_state_index", "known_chat_index", "journal_read_index",
                     "event_kind_counts", "chat_event_kind_counts"):
            store.db.execute("DROP TABLE " + name)
        if store.read_index.search_enabled:
            store.db.execute("DROP TABLE event_text_search")
        if store.read_index.payload_search_enabled:
            store.db.execute("DROP TABLE event_payload_search")


def seed(store):
    records = [
        ("message.new", 11, 10, "older"), ("message.new", 11, 20, "newer"),
        ("message.edited", 11, 10, "edit on old message"), ("message.deleted", 11, 10, None),
        ("message.missing_on_recheck", 11, 10, None), ("message.recovered", 11, 10, "recovered"),
        ("message.deleted", 11, 30, None), ("media.saved", 11, 40, None),
        ("message.snapshot", 11, 20, "latest"), ("message.edited", 11, 20, "latest edit"),
        ("message.new", 12, 99, "elsewhere"), ("message.new", -1000000000012, 99, "channel"),
        ("message.new", 13, None, "no id"), ("media.saved", 13, 1, None),
        ("message.new", None, 1, "unscoped"), ("other.event", 14, 1, "metadata"),
        ("actor.avatar_saved", 15, None, None),
    ]
    for kind, chat, message, text in records:
        store.append(kind, {"text": text, "sender_id": 77, "sender_observation": {"display_name": "Observer"}},
                     chat, message)


def test_projection_matches_legacy_and_rebuilds_without_rewriting_journal(journal):
    store, vault = journal
    seed(store)
    signed = store.all_events()
    expected = legacy_overview(store)
    assert store.chat_overview() == expected
    assert store.last_message_id(11) == 20
    assert store.last_message_id(999) is None
    assert store.alive_message_ids(11) == [20]
    assert store.alive_message_ids(11, below=20) == []
    assert store.account_message_chat(99) == 12
    store.append("message.new", {"text": "ambiguous"}, 16, 99)
    assert store.account_message_chat(99) is None
    assert store.message_state(11, 10)["deleted"] and store.message_state(11, 10)["missing"]
    assert store.message_state(11, 10)["content"]["text"] == "recovered"
    assert store.message_state(11, 30) == {"content": None, "deleted": True, "missing": False}
    assert store.message_state(999, 30) == {"content": None, "deleted": False, "missing": False}
    known = {r["chat_id"] for r in store.archive_chats(0, 100, None)}
    assert 14 in known and 15 not in known
    before = store.chat_overview()
    remove_read_index(store)
    with store.transaction():
        store.read_index = JournalIndex(store.db)
        JournalIndex(store.db)  # Opening twice must not double counts or FTS rows.
    assert store.chat_overview() == before
    assert store.all_events()[:len(signed)] == signed
    assert store.verify(vault.public_key)["events"] == len(signed) + 1
    assert store.events(search="covered", text_only=True)[0]["payload"]["text"] == "recovered"


def test_projection_and_search_roll_back_with_event_and_media_queue(journal):
    store, _ = journal
    store.append("message.new", {"text": "kept"}, 1, 1)
    before = store.chat_overview()
    with pytest.raises(RuntimeError):
        with store.transaction():
            store.append("message.edited", {"text": "rolled back unique"}, 1, 1)
            store.append("message.deleted", {}, 1, 1)
            raise RuntimeError("Synthetic rollback")
    assert store.chat_overview() == before
    assert store.alive_message_ids(1) == [1]
    assert not store.events(search="rolled", text_only=True)
    assert not store.events(search="rolled")
    with store.transaction():
        store.db.execute("CREATE TRIGGER reject_job BEFORE INSERT ON media_jobs "
                         "BEGIN SELECT RAISE(ABORT,'Synthetic full disk'); END")
    with pytest.raises(sqlite3.IntegrityError):
        store.append("message.new", {"text": "failed queued message"}, 1, 2,
                     media_job={"account_id": 1, "descriptor": b"x", "max_bytes": 10})
    assert store.chat_overview() == before
    assert store.last_message_id(1) == 1
    assert not store.events(search="failed queued", text_only=True)
    assert not store.events(search="failed queued")
    assert store.read_index.position("state") == 1
    assert store.read_index.position("payload_search") == 1
    assert store.read_index.position("counts") == 1
    assert store.stats()["counts"] == {"message.new": 1}


def test_search_survives_sqlite_json_strings_truncated_at_nul(journal, monkeypatch):
    store, vault = journal
    original = JournalIndex.search

    def legacy_tokenizer(index, event):
        text = event["payload"].get("text")
        if isinstance(text, str):
            event = {**event, "payload": {**event["payload"], "text": text.split("\0", 1)[0]}}
        original(index, event)

    monkeypatch.setattr(JournalIndex, "search", legacy_tokenizer)
    kept = store.append("message.new", {"text": "before\0after-nul xyz"}, 1, 1)
    store.append("message.new", {"text": "private\0after-nul hidden"}, 2, 2)

    # Older SQLite JSON1 builds return only the prefix of a decoded NUL string.
    # Keep the regression reproducible on newer Windows SQLite as well.
    def legacy_extract(payload, path):
        assert path == "$.text"
        value = json.loads(payload).get("text")
        return value.split("\0", 1)[0] if isinstance(value, str) else value

    store.db.create_function("json_extract", 2, legacy_extract, deterministic=True)
    for query in ("after-nul", "e\0a", "before"):
        assert store.events(search=query, text_only=True, chat_ids={1}) == [kept]
    assert not store.events(search="after-nul", text_only=True, chat_ids={3})
    assert not store.events(search="after-nul", text_only=True, chat_ids={1}, before=kept["seq"])
    plan = store.db.execute("EXPLAIN QUERY PLAN SELECT seq FROM events WHERE instr(payload,'\\u0000')>0")
    assert any("event_text_nul" in row[3] for row in plan)
    assert store.verify(vault.public_key)["events"] == 2


def test_failed_backfill_is_atomic_and_can_retry(journal, monkeypatch):
    store, _ = journal
    seed(store)
    expected = store.chat_overview()
    remove_read_index(store)
    original = JournalIndex.state

    def fail(index, event):
        original(index, event)
        if event["seq"] == 3:
            raise RuntimeError("Synthetic interrupted migration")

    monkeypatch.setattr(JournalIndex, "state", fail)
    with pytest.raises(RuntimeError), store.transaction():
        JournalIndex(store.db)
    assert not store.db.execute("SELECT 1 FROM sqlite_master WHERE name='message_state_index'").fetchone()
    monkeypatch.setattr(JournalIndex, "state", original)
    with store.transaction():
        store.read_index = JournalIndex(store.db)
    assert store.chat_overview() == expected


@pytest.mark.parametrize("missing", ["message_state_index", "chat_state_index", "known_chat_index",
    "event_kind_counts", "chat_event_kind_counts", "event_text_search", "event_payload_search", "journal_read_index",
    "counts_watermark"])
def test_missing_cache_member_rebuilds_its_group_despite_retained_watermark(journal, missing):
    store, vault = journal
    seed(store)
    before = {"events": store.all_events(), "stats": store.stats(), "overview": store.chat_overview(),
              "chats": store.archive_chats(0, 100, None), "alive": store.alive_message_ids(11),
              "text": store.events(search="latest", text_only=True), "payload": store.events(search="sender_id")}
    with store.transaction():
        if missing == "counts_watermark":
            store.db.execute("DELETE FROM journal_read_index WHERE name='counts'")
        else:
            store.db.execute("DROP TABLE " + missing)
    if missing not in ("journal_read_index", "counts_watermark"):
        assert store.read_index.position("state") == len(before["events"])
        assert store.read_index.position("counts") == len(before["events"])
    reopened = Store(store.root)
    try:
        assert reopened.stats() == before["stats"]
        assert reopened.chat_overview() == before["overview"]
        assert reopened.archive_chats(0, 100, None) == before["chats"]
        assert reopened.alive_message_ids(11) == before["alive"]
        assert reopened.events(search="latest", text_only=True) == before["text"]
        assert reopened.events(search="sender_id") == before["payload"]
        assert reopened.all_events() == before["events"]
        assert reopened.verify(vault.public_key)["events"] == len(before["events"])
        with reopened.transaction():
            JournalIndex(reopened.db)
        assert reopened.stats() == before["stats"]
    finally:
        reopened.close()


def test_interrupted_missing_counter_repair_rolls_back_and_retries(journal, monkeypatch):
    store, vault = journal
    seed(store)
    expected = store.stats()
    survivors = [tuple(r) for r in store.db.execute("SELECT * FROM chat_event_kind_counts ORDER BY chat_id,kind")]
    with store.transaction():
        store.db.execute("DROP TABLE event_kind_counts")
    original = JournalIndex.count

    def fail(index, *args):
        original(index, *args)
        raise RuntimeError("Synthetic interrupted counter repair")

    monkeypatch.setattr(JournalIndex, "count", fail)
    with pytest.raises(RuntimeError), store.transaction():
        JournalIndex(store.db)
    assert not store.db.execute("SELECT 1 FROM sqlite_master WHERE name='event_kind_counts'").fetchone()
    assert store.read_index.position("counts") == expected["total"]
    assert [tuple(r) for r in store.db.execute("SELECT * FROM chat_event_kind_counts ORDER BY chat_id,kind")] == survivors
    monkeypatch.setattr(JournalIndex, "count", original)
    with store.transaction():
        store.read_index = JournalIndex(store.db)
    assert store.stats() == expected
    assert store.verify(vault.public_key)["events"] == expected["total"]


def test_text_search_preserves_unicode_substrings_scope_and_pagination(journal):
    store, _ = journal
    texts = ["Straße and STRASSE", "Café CAFE\u0301", "Привет Мир", "İstanbul ςΣσ", "中文测试钱包",
             'prefix OR "quoted" AND a*b [x] suffix', "ab\0after-nul xyz", "🕵️‍♂️ investigator 🔒",
             "a_b 100% matches", "abc\nnext\tline", "a", "", None]
    for seq, text in enumerate(texts):
        store.append("message.new", {"text": text, "hidden": "not-public-search"}, 1+seq%2, seq+1)
    queries = ["strass", "CAFE\u0301", "ивет", "ΣΣ", "钱包", "测试钱", '"quoted"', "OR", "AND", "a*b",
               "[x]", "after-nul", "b\0a", "invest", "🔒", "100%", "a_b", "bc\nn", "", "not-public"]
    queries += [text[1:6] for text in texts if text and len(text) > 6]
    for query in queries:
        expected = [e for e in reversed(store.all_events())
                    if not query or search_text(query) in search_text(e["payload"].get("text") or "")]
        assert store.events(search=query, text_only=True, limit=100) == expected, query
        filtered = [e for e in expected if e["chat_id"] == 1 and e["seq"] < 11]
        assert store.events(search=query, text_only=True, chat_ids=[1], before=11, limit=2) == filtered[:2]
    assert store.events(search="not-public", text_only=False)
    # Optional FTS must not alter results on SQLite builds without trigram support.
    store.read_index.search_enabled = False
    assert len(store.events(search="strass", text_only=True)) == 1


def test_sender_and_media_lookups_keep_all_historical_scopes(journal):
    store, _ = journal
    store.append("message.new", {"sender_id": 7}, 1, 1)
    store.append("message.edited", {"sender_id": 8}, 1, 1)
    store.append("message.snapshot", {"sender_id": 7}, 1, 1)
    store.append("message.new", {}, 2, 1)
    assert store.sender_chats([7, 8, None]) == {7: {1: 1}, 8: {1: 1}, None: {2: 1}}
    assert store.sender_in_chats(7, {1}) and not store.sender_in_chats(7, {2})
    event = store.append("actor.avatar_saved", {"media_sha256": "a"*64}, 1, actor_id=7)
    assert store.media_in_chats("a"*64, {1}) and not store.media_in_chats("a"*64, {2})
    assert store.media_saved_after(event["seq"]-1) == [(event["seq"], "a"*64)]
    assert store.chat_overview()[1]["messages"] == 1


def test_structured_text_search_matches_legacy_sqlite_extraction(journal):
    store, _ = journal
    store.append("message.new", {"text": {"link": "Straße.example"}}, 1, 1)
    store.append("message.new", {"text": ["embedded", "Café"]}, 1, 2)
    for query in ("STRASSE", "embedded", '"link":', "CAFE\u0301"):
        expected = [r[0] for r in store.db.execute(
            "SELECT seq FROM events WHERE instr(search_text(coalesce(json_extract(payload,'$.text'),'')),?)>0 "
            "ORDER BY seq DESC", (search_text(query),))]
        assert [e["seq"] for e in store.events(search=query, text_only=True)] == expected


def test_scalar_text_search_is_consistent_and_does_not_break_other_records(journal):
    store, _ = journal
    values = [123456, 123.5, True, False, None, "ordinary text", "Straße"]
    for message, value in enumerate(values, 1):
        store.append("message.new", {"text": value}, 1, message)
    for query, expected in (("123", [2, 1]), ("123.5", [2]), ("1", [3, 2, 1]),
                            ("0", [4]), ("ordinary", [6]), ("STRASSE", [7])):
        assert [e["message_id"] for e in store.events(search=query, text_only=True)] == expected
        indexed = store.read_index.search_enabled
        store.read_index.search_enabled = False
        assert [e["message_id"] for e in store.events(search=query, text_only=True)] == expected
        store.read_index.search_enabled = indexed
    assert store.events(search="123", text_only=True, chat_ids=[2]) == []
    assert [e["message_id"] for e in store.events(search="true", text_only=False)] == [3]


def test_default_journal_search_indexes_exact_payload_and_preserves_scope_and_pages(journal):
    store, _ = journal
    payloads = [
        {"text": "Unremarkable label", "raw": {"entities": [
            {"_": "MessageEntityTextUrl", "offset": 0, "length": 18,
             "url": "https://pay.invalid/path?ref=A_B%20"}]}},
        {"text": "Buttons", "raw": {"reply_markup": {"_": "ReplyInlineMarkup", "rows": [
            {"buttons": [{"_": "KeyboardButtonUrl", "text": "Open", "url": "https://button.invalid/hidden"}]}]}}},
        {"reason": "metadata-only Straße Café Привет 中文测试 🕵️", "case": 123456, "active": True},
        {"quoted": 'a "quoted" word', "escaped": "line\nnext\tcolumn\0end", "path": "a\\b"},
        {"raw": {"url": "https://pay.invalid/path?ref=A_B%20"}, "foreign": "other chat"},
    ]
    for seq, payload in enumerate(payloads, 1):
        store.append("collector.note" if seq == 3 else "message.new", payload, 2 if seq == 5 else 1, seq)
    queries = ["pay.invalid", "A_B%20", "button.invalid/hidden", "KeyboardButtonUrl", "entities", "123456",
               '"active":true', "STRASSE", "CAFE\u0301", "рив", "文测试", "🕵️", "quoted", '"quoted"',
               r"\nnext", r"\u0000", "\0", "line\nnext", r"a\\b", "OR", "_", '"', "none-found"]
    for query in queries:
        for chats, before, limit in ((None, None, 100), ([1], None, 1), ([1], 4, 2), ([2], None, 10), ([], None, 10)):
            conditions, params = ["instr(search_text(payload),?)>0"], [search_text(query)]
            if chats is not None:
                conditions.append("chat_id IN (" + ",".join("?"*len(chats)) + ")")
                params.extend(chats)
            if before is not None:
                conditions.append("seq<?")
                params.append(before)
            expected = [store.decode(r) for r in store.db.execute(
                "SELECT * FROM events WHERE " + " AND ".join(conditions) + " ORDER BY seq DESC LIMIT ?",
                (*params, limit))]
            assert store.events(search=query, chat_ids=chats, before=before, limit=limit) == expected, query
    assert store.events(search="pay.invalid", text_only=True) == []
    assert store.events(search="metadata-only", kind="coverage")[0]["kind"] == "collector.note"
    assert store.events(search="metadata-only", message_only=True) == []
    statements = []
    store.db.set_trace_callback(statements.append)
    expected = store.events(search="pay.invalid")
    store.db.set_trace_callback(None)
    if store.read_index.payload_search_enabled:
        assert any("FROM event_payload_search JOIN events" in sql for sql in statements)
    store.read_index.payload_search_enabled = False
    assert store.events(search="pay.invalid") == expected


def test_payload_index_migrates_independently_without_resetting_text_or_state(journal, monkeypatch):
    store, vault = journal
    seed(store)
    signed = store.all_events()
    text_rows = [r[0] for r in store.db.execute("SELECT rowid FROM event_text_search")]
    positions = {key: store.read_index.position(key) for key in ("state", "search", "counts")}
    with store.transaction():
        store.db.execute("DROP TABLE event_payload_search")
        store.db.execute("DELETE FROM journal_read_index WHERE name='payload_search'")
    original = JournalIndex.search_payload

    def fail(index, seq, payload):
        original(index, seq, payload)
        if seq == 3:
            raise RuntimeError("Synthetic interrupted payload migration")

    monkeypatch.setattr(JournalIndex, "search_payload", fail)
    with pytest.raises(RuntimeError), store.transaction():
        JournalIndex(store.db)
    assert not store.db.execute("SELECT 1 FROM sqlite_master WHERE name='event_payload_search'").fetchone()
    assert [r[0] for r in store.db.execute("SELECT rowid FROM event_text_search")] == text_rows
    monkeypatch.setattr(JournalIndex, "search_payload", original)
    with store.transaction():
        store.read_index = JournalIndex(store.db)
        JournalIndex(store.db)
    assert {key: store.read_index.position(key) for key in positions} == positions
    assert [r[0] for r in store.db.execute("SELECT rowid FROM event_text_search")] == text_rows
    assert store.read_index.position("payload_search") == len(signed)
    assert store.events(search="metadata")[0]["chat_id"] == 14
    assert store.all_events() == signed
    assert store.verify(vault.public_key)["events"] == len(signed)


def test_chat_versions_expose_signed_hidden_links_without_changing_content_hashes(journal):
    store, _ = journal
    first = {"text": "Open wallet", "raw": {"entities": [
        {"_": "MessageEntityTextUrl", "offset": 0, "length": 11, "url": "https://original.invalid"}]}}
    second = {"text": first["text"], "entities": [{"url": "not-the-signed-source"}], "raw": {"entities": [
        {"_": "MessageEntityTextUrl", "offset": 0, "length": 11, "url": "https://replacement.invalid"}]}}
    store.append("message.new", first, 1, 1)
    store.append("message.edited", second, 1, 1)
    store.append("message.snapshot", second, 1, 1)
    store.append("message.new", {"text": "Plain text"}, 1, 2)
    messages = store.chat_messages(1)["messages"]
    versions = messages[0]["versions"]
    assert len(versions) == 2
    for version, payload in zip(versions, (first, second)):
        assert version["entities"] == payload["raw"]["entities"]
        assert version["content_hash"] == hashlib.sha256(canonical(message_content.of_payload(payload))).hexdigest()
    assert messages[1]["versions"][0]["entities"] == []


def test_index_reads_use_bounded_indexes_and_one_overview_query(journal):
    store, _ = journal
    seed(store)
    statements = []
    store.db.set_trace_callback(statements.append)
    store.chat_overview()
    store.db.set_trace_callback(None)
    assert len(statements) == 1 and "chat_state_index" in statements[0]
    plans = [
        ("SELECT message_id FROM message_state_index INDEXED BY message_alive WHERE chat_id=1 AND text_seq IS NOT NULL "
         "AND deleted=0 AND missing=0 ORDER BY message_id DESC LIMIT 200", "message_alive"),
        ("SELECT chat_id FROM message_state_index WHERE message_id=99 AND text_seq IS NOT NULL "
         "AND chat_id>-1000000000000 LIMIT 2", "message_account"),
        ("SELECT 1 FROM events WHERE json_extract(payload,'$.sender_id')=77 AND chat_id=11", "event_sender"),
        ("SELECT 1 FROM events WHERE json_extract(payload,'$.media_sha256')='a' AND chat_id=11", "event_media"),
    ]
    for sql, index in plans:
        plan = str([tuple(r) for r in store.db.execute("EXPLAIN QUERY PLAN " + sql)])
        assert index in plan, plan
    if store.read_index.search_enabled:
        for table in ("event_text_search", "event_payload_search"):
            plan = str([tuple(r) for r in store.db.execute("EXPLAIN QUERY PLAN SELECT events.* FROM " + table +
                " JOIN events ON events.seq=" + table + ".rowid WHERE " + table + " MATCH '\"older\"' "
                "ORDER BY " + table + ".rowid DESC LIMIT 20")])
            assert "VIRTUAL TABLE INDEX" in plan and "TEMP B-TREE" not in plan


def test_reopen_catches_up_legacy_appends(journal):
    store, vault = journal
    store.append("message.new", {"text": "first"}, 1, 1)
    # A previous release writes the same signed events, without these new caches.
    index = store.read_index
    store.read_index = type("Legacy", (), {"append": lambda self, event: None})()
    store.append("message.new", {"text": "later searchable"}, 1, 2)
    store.read_index = index
    reopened = Store(store.root)
    try:
        assert reopened.chat_overview()[1]["messages"] == 2
        assert reopened.events(search="searchable", text_only=True)[0]["message_id"] == 2
        assert reopened.verify(vault.public_key)["events"] == 2
    finally:
        reopened.close()


def test_optional_trigram_index_can_be_added_after_older_sqlite_fallback(journal):
    store, _ = journal
    store.append("message.new", {"text": "Straße search before upgrade"}, 1, 1)
    remove_read_index(store)

    class WithoutTrigram:
        def execute(self, sql, *args):
            if sql.startswith("CREATE VIRTUAL TABLE"):
                raise sqlite3.OperationalError("no such tokenizer: trigram")
            return store.db.execute(sql, *args)

    with store.transaction():
        store.read_index = JournalIndex(WithoutTrigram())
    assert not store.read_index.search_enabled
    assert not store.read_index.payload_search_enabled
    assert store.events(search="STRASSE", text_only=True)[0]["message_id"] == 1
    assert store.events(search="STRASSE")[0]["message_id"] == 1
    store.append("message.new", {"text": "search after upgrade"}, 1, 2)
    with store.transaction():
        store.read_index = JournalIndex(store.db)
    assert len(store.events(search="upgrade", text_only=True)) == 2
    assert len(store.events(search="upgrade")) == 2
    assert store.chat_overview()[1]["messages"] == 2


def test_stats_counts_preserve_scopes_and_global_head(journal):
    store, _ = journal
    assert store.stats() == {"counts": {}, "total": 0, "head": None}
    store.append("message.new", {"text": "allowed"}, 1, 1)
    store.append("message.edited", {"text": "allowed change"}, 1, 1)
    store.append("message.new", {"text": "outside scope"}, 2, 1)
    head = store.append("process.started", {})
    expected_head = {k: head[k] for k in ("seq", "hash", "observed_at")}
    assert store.stats() == {"counts": {"message.new": 2, "message.edited": 1, "process.started": 1},
                             "total": 4, "head": expected_head}
    assert store.stats([1]) == {"counts": {"message.new": 1, "message.edited": 1}, "total": 2, "head": expected_head}
    assert store.stats([1, 2])["counts"] == {"message.new": 2, "message.edited": 1}
    assert store.stats([]) == {"counts": {}, "total": 0, "head": expected_head}
    assert store.stats([999]) == store.stats([])
    # Counter reads must not revisit the signed payload/history table.
    statements = []
    store.db.set_trace_callback(statements.append)
    store.stats([1])
    store.db.set_trace_callback(None)
    assert len(statements) == 2 and "chat_event_kind_counts" in statements[0]


def test_counts_migrate_independently_and_catch_up_after_legacy_writes(journal):
    store, _ = journal
    seed(store)
    expected = store.stats()
    with store.transaction():
        store.db.execute("DROP TABLE event_kind_counts")
        store.db.execute("DROP TABLE chat_event_kind_counts")
        store.db.execute("DELETE FROM journal_read_index WHERE name='counts'")
        store.read_index = JournalIndex(store.db)
    assert store.stats() == expected
    # A pre-projection release may append between upgrades.
    index = store.read_index
    store.read_index = type("Legacy", (), {"append": lambda self, event: None})()
    store.append("legacy.additional", {}, 19, 1)
    store.read_index = index
    with store.transaction():
        store.read_index = JournalIndex(store.db)
        JournalIndex(store.db)
    assert store.stats()["total"] == expected["total"]+1
    assert store.stats([19])["counts"] == {"legacy.additional": 1}
    assert store.read_index.position("counts") == store.stats()["head"]["seq"]


def test_target_counts_include_paused_sources_without_loading_them(journal):
    store, _ = journal
    assert store.target_counts() == {"total": 0, "enabled": 0}
    store.set_target(1, "One", "group", True)
    store.set_target(2, "Two", "group", False)
    assert store.target_counts() == {"total": 2, "enabled": 1}
    store.set_target(2, "Two", "group", True)
    assert store.target_counts() == {"total": 2, "enabled": 2}
    store.remove_target(1)
    assert store.target_counts() == {"total": 1, "enabled": 1}


def test_legacy_media_queue_migration_preserves_signed_events(journal):
    store, vault = journal
    payloads = [{"raw": {"ttl_period": 5}}, {"raw": {"media": {"ttl_seconds": 8}}},
                {"raw": {"media": {"document": {"size": 2048}}}}, {"raw": {}},
                {"media_capture": {"estimated_bytes": 9000000, "priority": 4}}]
    store.set_target(1, "One", "group", True)
    for i, payload in enumerate(payloads):
        store.append("message.new", payload, 1, i+1,
                     media_job={"account_id": 7, "descriptor": b"original", "max_bytes": 10000000})
    signed = store.all_events()
    with store.transaction():
        store.db.execute("DROP INDEX media_lane")
        store.db.execute("ALTER TABLE media_jobs DROP COLUMN priority")
        store.db.execute("ALTER TABLE media_jobs DROP COLUMN estimated_bytes")
    reopened = Store(store.root)
    try:
        jobs = reopened.db.execute("SELECT priority,estimated_bytes FROM media_jobs ORDER BY message_event").fetchall()
        assert [tuple(r) for r in jobs] == [(0, None), (0, None), (1, 2048), (10, None), (4, 9000000)]
        assert reopened.all_events() == signed
        assert reopened.verify(vault.public_key)["events"] == len(signed)
        urgent = [reopened.claim_media(7, max_priority=1) for _ in range(3)]
        assert [j["priority"] for j in urgent] == [0, 0, 1]
        assert reopened.claim_media(7, max_priority=1) is None
        assert reopened.claim_media(8, min_priority=2) is None
        assert reopened.claim_media(7, min_priority=2)["priority"] == 4
        assert reopened.claim_media(7)["priority"] == 10
    finally:
        reopened.close()
