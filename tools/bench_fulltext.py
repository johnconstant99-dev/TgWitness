"""Full-text search benchmark on a synthetic signed journal (default one million messages).

python tools/bench_fulltext.py --messages 1000000 --work <empty directory> [--json result.json]
The corpus is deterministic: Russian and Ukrainian word forms, English, Chinese, Japanese, links and handles."""
import argparse
import json
import platform
import random
import sqlite3
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import fulltext  # noqa: E402
from tgwitness.security import Vault  # noqa: E402
from tgwitness.store import Store  # noqa: E402

RUSSIAN = ("перевод оплата карта банк кошелек выплата бонус вывод депозит договор счет клиент заявка поддержка "
           "менеджер инвестиция прибыль доход ставка розыгрыш подарок ссылка аккаунт пароль код доступ "
           "сообщение платеж комиссия возврат гарантия обмен курс сделка партнер реклама канал").split()
VERBS = "перевести оплатить получить отправить вывести вложить проверить написать подтвердить".split()
UKRAINIAN = ("переказ коштів на картку, гроші надійдуть сьогодні", "оплата через банк, деталі в особистих",
             "виплата бонусу після підтвердження", "пишіть менеджеру для отримання доступу")
ENGLISH = ("send the transfer to the wallet", "withdrawals are processed daily", "guaranteed returns on deposits",
           "contact support to unlock your account", "running a giveaway for new investors")
CHINESE = ("我通过银行转账了五千元", "请把钱转到这个账户", "投资回报每天结算", "联系客服领取奖励")
JAPANESE = ("振込はこちらのリンクからお願いします", "出金は毎日処理されます", "サポートに連絡してください")
DOMAINS = ("pay-secure.example", "wallet-check.example", "bonus-claim.example", "login.verify-account.example")
QUERIES = (
    ("common word, word forms", "перевод"),
    ("two words", "оплата карта"),
    ("rare word", "розыгрыш подарок"),
    ("exact phrase", '"переказ коштів на картку"'),
    ("domain with subdomains", "verify-account.example"),
    ("@username", "@support_desk_bot"),
    ("Chinese without spaces", "银行转账"),
    ("Japanese", "リンク"),
    ("English stem", "withdrawal"),
    ("OR and exclusion", "бонус OR подарок -казино"),
    ("chat filter", "chat:-1000000000007 перевод"),
    ("period filter", "since:2026-01-01 until:2026-01-31 выплата"),
)


def forms(analyzer, word, cache={}):
    if word not in cache:
        parsed = analyzer.parse(word)[0]
        cache[word] = sorted({f.word for f in parsed.lexeme})[:12] or [word]
    return cache[word]


def message(rng, analyzer, number):
    kind = rng.random()
    if kind < 0.62:
        words = [rng.choice(forms(analyzer, rng.choice(RUSSIAN))) for _ in range(rng.randint(4, 14))]
        words.insert(rng.randint(0, len(words)), rng.choice(forms(analyzer, rng.choice(VERBS))))
        text = " ".join(words).capitalize()
        if rng.random() < 0.08:
            text += " https://" + rng.choice(("", "www.", "secure.")) + rng.choice(DOMAINS) + "/" + str(number)
        if rng.random() < 0.05:
            text += " пишите @" + rng.choice(("support_desk_bot", "pay_helper", "manager_" + str(number % 500)))
        return text
    if kind < 0.74:
        return rng.choice(UKRAINIAN) + " " + str(number % 1000)
    if kind < 0.88:
        return rng.choice(ENGLISH) + " #" + str(number % 97)
    if kind < 0.95:
        return rng.choice(CHINESE) + str(number % 50)
    return rng.choice(JAPANESE)


def build_journal(root, total, chats):
    import pymorphy3
    from tgwitness import store as store_module
    analyzer, rng = pymorphy3.MorphAnalyzer(lang="ru"), random.Random(20261105)
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    clock = [1767225600.0]

    def tick():
        clock[0] += 3.1
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(clock[0])) + ".000+00:00"
    store_module.utcnow = tick
    started = time.perf_counter()
    for start in range(0, total, 5000):
        with store.transaction():
            for number in range(start, min(total, start + 5000)):
                chat = -1000000000000 - number % chats
                store.append("message.new", {"text": message(rng, analyzer, number), "sender_id": 1000 + number % 3000},
                             chat, number // chats + 1, 1000 + number % 3000)
        if start % 100000 == 0:
            print("  journal:", start, "messages", file=sys.stderr, flush=True)
    store_module.utcnow = lambda: time.strftime("%Y-%m-%dT%H:%M:%S.000+00:00", time.gmtime())
    return vault, store, time.perf_counter() - started


def percentile(values, share):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(share * (len(ordered) - 1))))]


def measure(call, runs):
    times = []
    for _ in range(runs):
        started = time.perf_counter()
        result = call()
        times.append((time.perf_counter() - started) * 1000)
    return result, times


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--messages", type=int, default=1_000_000)
    parser.add_argument("--chats", type=int, default=200)
    parser.add_argument("--runs", type=int, default=7)
    parser.add_argument("--work", type=Path, required=True, help="Empty directory for the synthetic journal")
    parser.add_argument("--json", type=Path, help="Write the measurements here")
    parser.add_argument("--existing", action="store_true", help="Reuse the journal already in --work; rebuild only the index")
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    if args.existing:
        vault, store, journal_seconds = Vault(args.work), Store(args.work), None
        store.bind(vault)
    elif any(args.work.iterdir()):
        parser.error("Use an empty work directory.")
    else:
        vault, store, journal_seconds = build_journal(args.work, args.messages, args.chats)
    try:
        store.fulltext.close()
        started = time.perf_counter()
        status = store.fulltext.rebuild(background=False, progress=lambda s: print(
            "  index:", s["indexed_seq"], "of", s["head_seq"], file=sys.stderr, flush=True))
        index_seconds = time.perf_counter() - started
        index_file = args.work / "search" / "fulltext.sqlite3"
        with sqlite3.connect(index_file) as index:
            index.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        rows = []
        for label, text in QUERIES:
            store.fulltext.search(text, limit=50)
            result, times = measure(lambda: store.fulltext.search(text, limit=50), args.runs)
            newest, newest_times = measure(lambda: store.fulltext.search(text, limit=50, order="newest"), args.runs)
            rows.append({"case": label, "query": text, "matched": result["matched"]["messages"],
                         "p50_ms": round(statistics.median(times), 1), "p95_ms": round(percentile(times, 0.95), 1),
                         "newest_p50_ms": round(statistics.median(newest_times), 1)})
        legacy = []
        for word in ("перевод", "银行转账", "verify-account.example"):
            _, times = measure(lambda: store.events(search=word, limit=50, text_only=True, message_only=True), 3)
            legacy.append({"query": word, "p50_ms": round(statistics.median(times), 1)})
        appended = []
        for number in range(200):
            store.append("message.new", {"text": "новый перевод " + str(number)}, -1000000000000, 10_000_000 + number)
            started = time.perf_counter()
            store.fulltext.search("перевод", chat_ids={-1000000000000}, limit=1)
            appended.append((time.perf_counter() - started) * 1000)
        report = {
            "messages": args.messages, "chats": args.chats, "runs": args.runs,
            "machine": {"cpu": platform.processor(), "system": platform.platform(), "python": platform.python_version(),
                        "sqlite": sqlite3.sqlite_version, "analyzer": fulltext.analyzer_id()},
            "journal_build_seconds": round(journal_seconds, 1) if journal_seconds else None,
            "index_build_seconds": round(index_seconds, 1),
            "index_messages_per_second": round(args.messages / index_seconds),
            "journal_bytes": (args.work / "journal.sqlite3").stat().st_size, "index_bytes": index_file.stat().st_size,
            "documents": status["documents"], "queries": rows, "legacy_substring": legacy,
            "search_after_append_p50_ms": round(statistics.median(appended), 1),
            "search_after_append_p95_ms": round(percentile(appended, 0.95), 1)}
    finally:
        store.close()
    text = json.dumps(report, ensure_ascii=False, indent=1)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
