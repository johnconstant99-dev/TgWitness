"""Full-text search: word forms, scripts without spaces, references, scope, derived data and compatibility."""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import fulltext  # noqa: E402
from tgwitness.access import GrantSettings, Principal  # noqa: E402
from tgwitness.analysis import Question, retrieve  # noqa: E402
from tgwitness.archive import ArchiveQuery, ArchiveReader  # noqa: E402
from tgwitness.evidence import export_file  # noqa: E402
from tgwitness.security import Vault  # noqa: E402
from tgwitness.store import Store  # noqa: E402
from tgwitness.verify import fingerprint, verify_bundle  # noqa: E402

CHAT, OTHER = -1001000000001, -1001000000002
FIXTURE = ROOT / "tools" / "fixtures" / "evidence-before-fulltext.zip"
FIXTURE_FINGERPRINT = "c0de23aa500f303b7aaadcc0f5938451ca17c9290368ed37f41c630405a36abc"
MESSAGES = (
    (CHAT, 1, 7, "Оплата переводом на карту, пишите @fixture_seller"),
    (CHAT, 2, 8, "Переказ коштів на картку, деталі на pay.example-pay.test"),
    (CHAT, 3, 9, "我通过银行转账了五千元"),
    (CHAT, 4, 9, "振込はこちらのリンクからお願いします"),
    (OTHER, 5, 10, "Переводы принимаем только через бота"),
    (OTHER, 6, 11, "Running several transfers to the wallet"),
)


def clear_caches():
    for function in (fulltext.morph, fulltext.cyrillic_term, fulltext.cyrillic_forms, fulltext.part_of_speech,
                     fulltext.latin_term):
        getattr(function, "cache_clear", lambda: None)()


@pytest.fixture
def journal(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    for chat, message, sender, text in MESSAGES:
        store.append("message.new", {"text": text, "sender_id": sender,
                                     "sender_observation": {"username": "Fixture_Seller" if sender == 7 else None}},
                     chat, message, sender)
    store.append("message.new", {"text": "Получить выплату", "sender_id": 12, "raw": {
        "entities": [{"_": "MessageEntityTextUrl", "offset": 0, "length": 8, "url": "https://login.hidden-phish.example.org/a"}],
        "reply_markup": {"_": "ReplyInlineMarkup", "rows": [{"buttons": [
            {"_": "KeyboardButtonUrl", "text": "Открыть", "url": "https://t.me/payout_helper_bot"}]}]}}}, OTHER, 7, 12)
    store.append("message.edited", {"text": "Оплата только переводом", "sender_id": 7}, CHAT, 1)
    yield vault, store
    store.close()


def seqs(store, query, **options):
    return [hit["event"]["seq"] for hit in store.fulltext.search(query, **options)["hits"]]


def test_word_forms_share_one_term():
    terms = {term for term, _, _ in fulltext.tokens("перевод переводом переводы переводу")}
    assert terms == {"перевод"}
    assert fulltext.tokens("Running transfers")[1][0] == fulltext.tokens("transfer")[0][0]
    assert fulltext.tokens("кaрта")[0][0] == fulltext.tokens("карта")[0][0], "Latin look-alike letter"
    assert fulltext.tokens("ＢＡＮＫ ба\u200bнк")[0][0] == "bank" and fulltext.tokens("ба\u200bнк")[0][0] == "банк"


def test_requirements_examples(journal):
    _, store = journal
    assert set(seqs(store, "перевод")) == {1, 5, 8}
    assert set(seqs(store, "переводы")) == {1, 5, 8}
    assert seqs(store, "переказу") == [2]
    assert seqs(store, "银行转账") == [3], "Chinese phrase without spaces"
    assert seqs(store, "转账") == [3] and seqs(store, "元") == [3] and seqs(store, "银") == [3]
    assert seqs(store, "银转") == [], "Characters that are not adjacent"
    assert seqs(store, "リンク") == [4]
    assert seqs(store, "transfer") == [6] and seqs(store, "runs") == [6]


def test_references_and_filters(journal):
    _, store = journal
    assert seqs(store, "pay.example-pay.test") == [2] and seqs(store, "example-pay.test") == [2]
    assert seqs(store, "example.org") == [7], "Hidden entity link"
    assert seqs(store, "@payout_helper_bot") == [7] and seqs(store, "t.me/payout_helper_bot") == [7], "Button URL"
    assert seqs(store, "@fixture_seller") == [1] and set(seqs(store, "from:@fixture_seller")) == {1}
    assert seqs(store, "from:9 банк OR 银行") == [3]
    assert seqs(store, '"переводом на карту"') == [1]
    assert seqs(store, '"карту на переводом"') == [], "An exact phrase keeps its order"
    assert set(seqs(store, "перевод -карта")) == {5, 8}
    assert seqs(store, "kind:edited перевод") == [8]
    assert seqs(store, "id:3") == [3] and set(seqs(store, "id:1")) == {1, 8}
    assert set(seqs(store, "перевод", chat_ids={OTHER})) == {5}
    assert seqs(store, "chat:" + str(OTHER) + " перевод", chat_ids={CHAT}) == [], "Filters only narrow access"
    assert seqs(store, "перевод", chat_ids=set()) == []
    future = datetime.now(timezone.utc) + timedelta(days=1)
    assert seqs(store, "перевод", since=future) == []
    with pytest.raises(ValueError, match="Unsupported search filter"):
        store.fulltext.search("chat:abc")
    result = store.fulltext.search("переводы на карту")
    assert [t["forms"] for t in result["query"]["terms"] if not t["ignored"]] == [["перевод"], ["карта"]]


def test_period_and_phrase_use_the_journal_when_needed(tmp_path, monkeypatch):
    from tgwitness import store as store_module
    times = iter(["2026-01-01T10:00:00.000+00:00", "2025-12-31T10:00:00.000+00:00",
                  "2026-01-02T10:00:00.000+00:00", "2026-01-03T10:00:00.000+00:00"])
    monkeypatch.setattr(store_module, "utcnow", lambda: next(times))
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        for number, text in enumerate(("перевод на карту банка", "перевод после смены часов",
                                       "переводы на карты", "переказ на картку банку"), 1):
            store.append("message.new", {"text": text}, CHAT, number)
        january = datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert set(seqs(store, "перевод", since=january, until=january + timedelta(days=1, hours=12))) == {1, 3},             "A collector clock step back inside the range is filtered by the journal"
        assert seqs(store, "перевод", since=january + timedelta(days=1)) == [3]
        assert seqs(store, "since:2026-01-03 переказ") == [4] and seqs(store, "until:2025-12-31 перевод") == [2]
        assert seqs(store, '"переводы на карты"') == [3] and seqs(store, '"перевод на карту"') == [1]
        assert seqs(store, '"переказ на картку"') == [4] and seqs(store, '"на карту банка"') == [1]
        assert seqs(store, '"карту на перевод"') == []
    finally:
        store.close()


def test_ranking_prefers_dense_matches(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        for number in range(1, 21):
            store.append("message.new", {"text": "обычное сообщение номер " + str(number)}, CHAT, number)
        store.append("message.new", {"text": "кошелек " + "обычный текст " * 30}, CHAT, 30)
        store.append("message.new", {"text": "кошелек кошелька кошельки, проверьте кошелек"}, CHAT, 31)
        assert seqs(store, "кошелек")[0] == 22, "BM25 ranks the denser message first"
        assert seqs(store, "кошелек", order="newest") == [22, 21]
    finally:
        store.close()


def test_ukrainian_without_gpl_dictionary(tmp_path, monkeypatch):
    russian = fulltext.morph("ru")
    monkeypatch.setattr(fulltext, "morph", lambda lang: russian if lang == "ru" else None)
    clear_caches()
    try:
        assert fulltext.analyzer_id().endswith("light-uk+snowball-en")
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        try:
            store.append("message.new", {"text": "Переказ коштів на картку, гроші завтра"}, CHAT, 1)
            store.append("message.new", {"text": "Оплата переводом"}, CHAT, 2)
            for query in ("переказу", "картка", "грошей", "коштів"):
                assert seqs(store, query) == [1], query
            assert seqs(store, "переводы") == [2]
        finally:
            store.close()
    finally:
        monkeypatch.undo()
        clear_caches()


def test_index_follows_the_signed_journal(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    store.append("message.new", {"text": "первый перевод"}, CHAT, 1)
    status = store.fulltext.catch_up()
    head = store.stats()["head"]
    assert status["indexed_seq"] == head["seq"] and status["indexed_hash"] == head["hash"]
    assert (tmp_path / "search" / "fulltext.sqlite3").is_file()
    store.append("message.new", {"text": "второй перевод"}, CHAT, 2)
    assert seqs(store, "перевод") == [2, 1] or set(seqs(store, "перевод")) == {1, 2}, "New records searchable at once"
    store.close()

    index = __import__("sqlite3").connect(tmp_path / "search" / "fulltext.sqlite3")
    index.execute("UPDATE fulltext_state SET value=? WHERE key='hash'", (json.dumps("0" * 64),))
    index.commit()
    index.close()
    store = Store(tmp_path)
    store.bind(vault)
    try:
        assert store.fulltext.status()["indexed_seq"] == 0, "A position that differs from the journal is rebuilt"
        assert set(seqs(store, "перевод")) == {1, 2}
        assert store.fulltext.configure("memory")["mode"] == "memory"
        assert not (tmp_path / "search" / "fulltext.sqlite3").exists(), "Memory mode leaves nothing on disk"
        assert set(seqs(store, "перевод")) == {1, 2}
        store.fulltext.configure("off")
        with pytest.raises(ValueError, match="off"):
            store.fulltext.search("перевод")
        store.fulltext.configure("disk")
        assert store.fulltext.rebuild(background=False)["state"] == "ready"
    finally:
        store.close()


def derived_job(store, vault, chat, ident, text, engine="ocr"):
    data = (ident + text).encode()
    digest = hashlib.sha256(data).hexdigest()
    (store.root / "media").mkdir(exist_ok=True)
    (store.root / "media" / digest).write_bytes(data)
    message = store.append("message.new", {"text": "", "has_media": True}, chat, 900 + len(ident))
    media = store.append("media.saved", {"message_event": message["seq"], "media_sha256": digest, "size": len(data)},
                         chat, 900 + len(ident))
    source = {"workspace": "default", "chat_id": chat, "message_id": media["message_id"],
              "event_seq": media["seq"], "hash": media["hash"]}
    jobs = store.get_setting("media_analysis_jobs", [])
    jobs.append({"id": ident, "owner": "admin", "status": "completed", "source": source,
                 "request": {"workspace": "default", "chat_id": chat, "event_seq": media["seq"], "digest": digest,
                             "engine": engine, "language": ""}})
    store.set_setting("media_analysis_jobs", jobs)
    vault.save("media-analysis-" + ident, {"text": text, "media_sha256": digest, "engine": "tesseract",
                                           "model_version": "synthetic", "language": "rus",
                                           "completed_at": "2026-11-05T00:00:00.000+00:00"})
    return media["seq"]


def test_machine_recognition_is_separate_derived_data(journal):
    vault, store = journal
    first = derived_job(store, vault, CHAT, "a" * 32, "Реквизиты для перевода: карта банка")
    derived_job(store, vault, OTHER, "b" * 32, "Квитанция о переводе", "transcription")
    hits = store.fulltext.search("перевод", sources=("ocr",))["hits"]
    assert [h["event"]["seq"] for h in hits] == [first] and hits[0]["machine_recognition"] is True
    assert hits[0]["event"]["kind"] == "media.saved" and "перевода" in hits[0]["excerpt"]
    assert store.fulltext.search("перевод", sources=("ocr", "transcription"), chat_ids={CHAT})["matched"] == \
        {"ocr": 1, "transcription": 0}
    mixed = store.fulltext.search("перевод", sources=("messages", "ocr", "transcription"))["hits"]
    assert {h["source"] for h in mixed} == {"messages", "ocr", "transcription"}
    assert all("machine_recognition" not in h for h in mixed if h["source"] == "messages")
    assert not (store.root / "search" / "fulltext.sqlite3").read_bytes().count("Квитанция".encode()), \
        "Recognized text is not written to the index file"
    assert store.fulltext.derived.matching("квитанции") == ["b" * 32]


def reader(store, chats):
    principal = Principal(False, "Synthetic reviewer", {"id": "synthetic", "workspaces": {"default": chats},
                                                         "all_workspaces": False, "permissions": ["view"],
                                                         "expires_at": None})
    state = type("State", (), {"store": store, "collector": type("Collector", (), {"running": False})()})()
    registry = type("Registry", (), {"entries": {"default": {"app": type("App", (), {"state": state})(),
                                                             "label": "Synthetic"}}})()
    return ArchiveReader(registry, principal)


def test_archive_reader_ranked_search_respects_scope(journal):
    _, store = journal
    scoped = reader(store, [OTHER])
    result = scoped.read(ArchiveQuery(tool="search_messages", query="перевод", ranked=True))
    assert {item["source"]["event_seq"] for item in result["items"]} == {5}
    assert result["ranked"] and set(result["index"]) == {"complete"}, "Scoped access sees no journal totals"
    with pytest.raises(Exception, match="not open"):
        scoped.read(ArchiveQuery(tool="search_messages", query="перевод", chat_id=CHAT, ranked=True))
    everything = reader(store, None).read(ArchiveQuery(tool="search_messages", query="перевод", ranked=True))
    assert {item["source"]["event_seq"] for item in everything["items"]} == {1, 5, 8}
    assert everything["index"]["indexed_hash"] == store.stats()["head"]["hash"]


def test_ask_the_archive_uses_ranked_retrieval(journal):
    _, store = journal
    for number in range(40):
        store.append("message.new", {"text": "Перевожу деньги, перевод номер " + str(number)}, CHAT, 100 + number)
    store.append("message.new", {"text": "длинный текст " * 200 + " перевод в самом конце"}, CHAT, 200)
    now = datetime.now(timezone.utc)
    question = Question(workspace="default", chats=[CHAT, OTHER], question="Какие переводы обсуждали?",
                        since=now - timedelta(days=1), until=now + timedelta(minutes=1))
    result = retrieve(reader(store, None), question, 64000)
    assert result["retrieval"] == "ranked" and len(result["sources"]) == 24 and result["partial"]
    assert len({(s["source"]["chat_id"], s["source"]["message_id"], s["text"]) for s in result["sources"]}) == 24
    focused = retrieve(reader(store, None), question.model_copy(update={"query": "конце"}), 64000)
    assert [s["source"]["message_id"] for s in focused["sources"]] == [200]
    window = focused["sources"][0]
    assert "перевод в самом конце" in window["text"] and window["text_truncated"] and len(window["text"]) <= 1200
    assert window["text_offset"] > 0, "A long text is sent around its match, not cut before it"
    store.fulltext.configure("off")
    fallback = retrieve(reader(store, None), question, 64000)
    assert fallback["retrieval"] == "lexical"


def test_ranked_results_page_through_every_match(journal):
    _, store = journal
    for number in range(30):
        store.append("message.new", {"text": "Платёж номер " + str(number)}, OTHER, 300 + number)
    pages, offset = [], 0
    while offset is not None:
        result = store.fulltext.search("платёж", limit=12, offset=offset)
        pages.append([hit["event"]["seq"] for hit in result["hits"]])
        offset = result["next_offset"]
    assert [len(page) for page in pages] == [12, 12, 6] and len({s for page in pages for s in page}) == 30
    assert store.fulltext.search("платёж", limit=10, offset=1000)["next_offset"] is None
    scoped = reader(store, [OTHER]).read(ArchiveQuery(tool="search_messages", query="платёж", ranked=True, limit=20))
    assert len(scoped["items"]) == 20 and scoped["next_offset"] == 20
    rest = reader(store, [OTHER]).read(ArchiveQuery(tool="search_messages", query="платёж", ranked=True, limit=20,
                                                    offset=20))
    assert len(rest["items"]) == 10 and rest["next_offset"] is None


def test_ranked_pagination_stays_inside_the_result_window(journal):
    _, store = journal
    with store.transaction():
        for number in range(1005):
            store.append("message.new", {"text": "PaginationSentinel"}, OTHER, 2000 + number)
    penultimate = store.fulltext.search("PaginationSentinel", limit=50, offset=900)
    assert len(penultimate["hits"]) == 50 and penultimate["next_offset"] == 950
    last = store.fulltext.search("PaginationSentinel", limit=200, offset=950)
    assert len(last["hits"]) == 50 and last["next_offset"] is None
    end = store.fulltext.search("PaginationSentinel", limit=20, offset=1000)
    assert not end["hits"] and end["next_offset"] is None
    with pytest.raises(ValueError, match="1,000"):
        reader(store, [OTHER]).read(ArchiveQuery(tool="search_messages", query="PaginationSentinel", ranked=True,
                                               offset=1001))


@pytest.mark.parametrize("sources", [("ocr",), ("transcription",), ("messages", "ocr", "transcription")])
def test_newest_pages_keep_recognition_and_message_order(journal, sources):
    vault, store = journal
    expected = []
    for number in range(12):
        event = store.append("message.new", {"text": "Needle"}, CHAT, 3000 + number)
        if "messages" in sources:
            expected.append(event["seq"])
        engine = "ocr" if number % 2 == 0 else "transcription"
        seq = derived_job(store, vault, CHAT, f"{number:032x}", "Needle", engine)
        if engine in sources:
            expected.append(seq)
    observed, offset = [], 0
    while offset is not None:
        result = store.fulltext.search("Needle", sources=sources, order="newest", limit=3, offset=offset)
        observed.extend(hit["event"]["seq"] for hit in result["hits"])
        offset = result["next_offset"]
    assert observed == sorted(expected, reverse=True)


@pytest.mark.parametrize("text", ["ß" * 50 + " needle" + "\u200b" * 50,
                                  "x\u200b" * 50 + " needle " + "ß" * 50,
                                  "prefix e\u0301 needle", "prefix \ufb00 needle"],
                         ids=["expansion-before-removal", "removal-before-expansion", "combining", "ligature"])
def test_match_offsets_survive_combined_unicode_changes(text):
    assert fulltext.focus(text, fulltext.Query("needle")) == text.index("needle")


def test_long_questions_still_use_the_index(journal):
    _, store = journal
    now = datetime.now(timezone.utc)
    for question in (" ".join(["Скажи пожалуйста, какие переводы обсуждали участники этого чата?"] * 8),
                     "Какие переводы " + "очень " * 150):
        body = Question(workspace="default", chats=[CHAT, OTHER], question=question[:1000],
                        since=now - timedelta(days=1), until=now + timedelta(minutes=1))
        result = retrieve(reader(store, None), body, 64000)
        assert result["retrieval"] == "ranked" and result["sources"], len(question)
    filters = Question(workspace="default", chats=[CHAT], question="Что было?", query="chat:abc",
                       since=now - timedelta(days=1), until=now + timedelta(minutes=1))
    assert retrieve(reader(store, None), filters, 64000)["retrieval"] == "lexical", "Unreadable queries fall back"


def test_excerpt_follows_the_match_past_invisible_characters(journal):
    _, store = journal
    hidden = "x\u200b" * 2600 + " перевод в самом конце"
    store.append("message.new", {"text": hidden}, CHAT, 400)
    result = reader(store, None).read(ArchiveQuery(tool="search_messages", query="конце", ranked=True))
    item = next(i for i in result["items"] if i["source"]["message_id"] == 400)
    assert "перевод в самом конце" in item["text"] and item["text_offset"] > 0
    assert hidden[item["text_offset"] + item["match_offset"]:].startswith("конце")


def test_api_and_scoped_access(tmp_path):
    from tools.check_session_reservations import workspace

    async def run():
        async with workspace() as (app, client):
            store = app.state.store
            store.set_target(CHAT, "Synthetic one", "supergroup", True)
            store.set_target(OTHER, "Synthetic two", "supergroup", True)
            store.append("message.new", {"text": "Оплата переводом"}, CHAT, 1)
            store.append("message.new", {"text": "Переводы через бота"}, OTHER, 2)
            admin = await client.get("/api/search", params={"q": "перевод"})
            assert admin.status_code == 200, admin.text
            assert {e["chat_id"] for e in admin.json()["events"]} == {CHAT, OTHER}
            assert admin.json()["index"]["indexed_hash"] == store.stats()["head"]["hash"]
            token, _ = app.state.access.issue(GrantSettings(label="Synthetic scoped", workspaces={"default": [OTHER]},
                                                            permissions=["view"]))
            session, _ = app.state.access.login(token, "127.0.0.1", "Synthetic test")
            headers = {"Authorization": "Bearer " + session}
            scoped = await client.get("/api/search", params={"q": "перевод"}, headers=headers)
            assert scoped.status_code == 200 and {e["chat_id"] for e in scoped.json()["events"]} == {OTHER}
            assert "documents" not in scoped.json()["index"] and "indexed_seq" not in scoped.json()["index"]
            denied = await client.get("/api/search", params={"q": "перевод", "chat_id": CHAT}, headers=headers)
            assert denied.status_code == 403
            narrowed = await client.get("/api/search", params={"q": "chat:" + str(CHAT) + " перевод"}, headers=headers)
            assert narrowed.status_code == 200 and narrowed.json()["events"] == []
            status = await client.get("/api/search/status", headers=headers)
            assert status.status_code == 200 and "documents" not in status.json()
            for path, body in (("/api/search/settings", {"mode": "off"}), ("/api/search/rebuild", {})):
                assert (await client.post(path, json=body, headers=headers)).status_code == 403
            assert (await client.post("/api/search/settings", json={"mode": "memory"})).json()["mode"] == "memory"
            assert (await client.get("/api/search", params={"q": "chat:abc"})).status_code == 422
    asyncio.run(run())


def run_cli(*args, env=None):
    return subprocess.run([sys.executable, "-m", "tgwitness", "index", *args], capture_output=True, text=True,
                          cwd=ROOT, env=env, timeout=120)


def test_cli_keeps_stdout_structured(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    store.append("message.new", {"text": "перевод"}, CHAT, 1)
    store.close()
    rebuilt = run_cli("rebuild", "--json", "--data-dir", str(tmp_path))
    assert rebuilt.returncode == 0, rebuilt.stderr
    document = json.loads(rebuilt.stdout)
    assert document["workspaces"][0]["state"] == "ready"
    status = run_cli("status", "--json", "--data-dir", str(tmp_path))
    assert status.returncode == 0 and json.loads(status.stdout)["workspaces"][0]["indexed_seq"] == 1
    from tgwitness.security import InstanceLock
    lock = InstanceLock(tmp_path)
    try:
        busy = run_cli("rebuild", "--data-dir", str(tmp_path))
        assert busy.returncode == 3 and busy.stdout == ""
    finally:
        lock.close()
    assert run_cli("status", "--data-dir", str(tmp_path / "missing")).returncode == 1
    assert run_cli("explode").returncode == 2


def test_verifier_accepts_archive_from_before_full_text():
    result = verify_bundle(FIXTURE, expected_fingerprint=FIXTURE_FINGERPRINT)
    assert result["events"] == 7 and result["files_checked"] >= 10 and result["key_pinned"]


def test_previous_verifier_accepts_current_archive(journal, tmp_path):
    vault, store = journal
    archive = export_file(store, vault, "zip")
    try:
        with zipfile.ZipFile(archive) as bundle:
            assert not any(name.startswith("search/") for name in bundle.namelist()), "The index is never exported"
        with zipfile.ZipFile(FIXTURE) as old:
            (tmp_path / "old_verify.py").write_bytes(old.read("verify.py"))
        copy = tmp_path / "current.zip"
        shutil.copyfile(archive, copy)
        checked = subprocess.run([sys.executable, str(tmp_path / "old_verify.py"), str(copy), "--fingerprint",
                                  fingerprint(vault.public_key)], capture_output=True, text=True, timeout=120)
        assert checked.returncode == 0, checked.stdout + checked.stderr
    finally:
        archive.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
