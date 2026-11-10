import json
import logging
import os
import re
import sqlite3
import threading
import time
import unicodedata
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from . import indicators, keyboard
from .journal_index import TEXT_KINDS, search_text

LOG = logging.getLogger("tgwitness.fulltext")
VERSION = "fulltext-v1"
MODES = ("disk", "memory", "off")
SOURCES = ("messages", "ocr", "transcription")
TOKENIZE = "unicode61 remove_diacritics 0 categories 'L* N* Co M* Pc' tokenchars '.@:#-'"
RANK = "bm25(fulltext, 1.0, 1.5, 0.0)"
BATCH = 2000
CATCH_UP = 5000
MAX_CLAUSES = 24
MAX_FORMS = 8
KIND_TAGS = {"message.new": "new", "message.snapshot": "snapshot", "message.edited": "edited",
             "message.recovered": "recovered"}

SEGMENTED = ("\u0e00-\u0eff\u1000-\u109f\u1100-\u11ff\u1780-\u17ff\u3040-\u30ff\u3130-\u318f\u31f0-\u31ff"
             "\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7af\uf900-\ufaff\uff66-\uff9f\U00020000-\U0003134f")
RUNS = re.compile("([" + SEGMENTED + "]+)|([^" + SEGMENTED + "]+)")
HAN = re.compile("[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\U00020000-\U0003134f]")
WORD = re.compile(r"[^\W\d_]+(?:'[^\W\d_]+)*|\d+")
CYRILLIC = re.compile("[\u0400-\u052f]")
LATIN = re.compile("[a-z\u00df-\u024f]")
INVISIBLE = re.compile("[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180e\u200b-\u200f\u202a-\u202e"
                       "\u2060-\u206f\ufe00-\ufe0f\ufeff]")
APOSTROPHES = str.maketrans("\u2019\u02bc`\u00b4\u02b9", "'''''")
LOOKALIKE_LATIN = "aceopxykmthb"
LOOKALIKE_CYRILLIC = "\u0430\u0441\u0435\u043e\u0440\u0445\u0443\u043a\u043c\u0442\u043d\u0432"
TO_CYRILLIC = str.maketrans(LOOKALIKE_LATIN, LOOKALIKE_CYRILLIC)
TO_LATIN = str.maketrans(LOOKALIKE_CYRILLIC, LOOKALIKE_LATIN)
UKRAINIAN_LETTERS = "іїєґ"
UKRAINIAN_ENDINGS = tuple(sorted((
    "ами ями ові еві єві ах ях ою ею єю ам ям ом ем ів їв ий ій ої ого ому им ім их іх ими іми "
    "ують ють ує ать ять ити ати яти іти ла ли ло а я у ю і ї и о е є ь").split(), key=len, reverse=True))
RUSSIAN_LETTERS = "ыэъё"
HASHTAG = re.compile(r"(?<![\w#])#([^\W_]\w{1,63})")
HANDLE = re.compile(r"@?([a-z][a-z0-9_]{3,31})")
STOP_POS = {"PREP", "CONJ", "PRCL", "INTJ"}
QUESTION_POS = STOP_POS | {"NPRO", "PRED"}
ENGLISH_STOP = frozenset((
    "a an and are as at be by for from has have in is it its of on or that the to was were will with "
    "what where which who whom why how when this these those there do does did can could about into "
    "any all some me my we our you your he she they them his her their").split())
QUESTION_WORDS = frozenset((
    "что где когда какие "
    "какой какая кто почему "
    "как сколько найди "
    "покажи было чат чате "
    "архив архиве сообщение "
    "сообщения сообщениях "
    "що де коли які який хто "
    "чому як знайди повідомлення "
    "message messages chat chats archive find show tell list mentioned mention").split())
QUERY = re.compile(r'(-?)(?:"([^"]*)"|«([^»]*)»|“([^”]*)”|(\S+))')
FILTER = re.compile(r"(chat|from|id|since|until|source|kind):(\S+)", re.I)
SOURCE_NAMES = {"messages": "messages", "message": "messages", "text": "messages", "msg": "messages",
                "ocr": "ocr", "image": "ocr", "transcription": "transcription", "transcript": "transcription",
                "asr": "transcription", "audio": "transcription", "voice": "transcription"}
LOCK = threading.RLock()


def normalize(text):
    text = unicodedata.normalize("NFKC", text if isinstance(text, str) else "")
    return INVISIBLE.sub("", text).casefold().translate(APOSTROPHES)


def unmix(word):
    cyrillic, latin = len(CYRILLIC.findall(word)), len(LATIN.findall(word))
    if not cyrillic or not latin:
        return word
    return word.translate(TO_CYRILLIC if cyrillic >= latin else TO_LATIN)


@lru_cache(maxsize=None)
def morph(lang):
    try:
        import pymorphy3
        return pymorphy3.MorphAnalyzer(lang=lang)
    except Exception:
        return None


@lru_cache(maxsize=None)
def stemmer(name):
    try:
        import snowballstemmer
        return snowballstemmer.stemmer(name)
    except Exception:
        return None


@lru_cache(maxsize=None)
def segmenter():
    try:
        import jieba
        jieba.setLogLevel(logging.WARNING)
        return jieba
    except Exception:
        return None


def analyzer_id():
    return "+".join((VERSION, "pymorphy3-ru" if morph("ru") else "snowball-ru",
                     "pymorphy3-uk" if morph("uk") else "light-uk", "snowball-en" if stemmer("english") else "plain-latin"))


def stem(name, word):
    found = stemmer(name)
    if found is None:
        return word
    with LOCK:
        return found.stemWord(word)


@lru_cache(maxsize=131072)
def latin_term(word):
    plain = "".join(c for c in unicodedata.normalize("NFKD", word) if not unicodedata.combining(c))
    return stem("english", unicodedata.normalize("NFC", plain)).replace("'", "")


def known(lang, word):
    analyzer = morph(lang)
    return analyzer is not None and analyzer.word_is_known(word)


def lemma(lang, word):
    return morph(lang).parse(word)[0].normal_form


def plain_form(value):
    return value.replace("ё", "е").replace("'", "")


def ukrainian_stem(word):
    for ending in UKRAINIAN_ENDINGS:
        if word.endswith(ending) and len(word) - len(ending) >= 3:
            return word[:-len(ending)]
    return word


@lru_cache(maxsize=131072)
def cyrillic_term(word, first="ru"):
    with LOCK:
        for lang in ("uk", "ru") if first == "uk" else ("ru", "uk"):
            if known(lang, word):
                return plain_form(lemma(lang, word))
        if first == "uk" or any(c in UKRAINIAN_LETTERS for c in word):
            return plain_form(lemma("uk", word)) if morph("uk") else plain_form(ukrainian_stem(word))
        return plain_form(lemma("ru", word)) if morph("ru") else plain_form(stem("russian", word))


@lru_cache(maxsize=65536)
def cyrillic_forms(word):
    forms, raw = [cyrillic_term(word, "ru"), cyrillic_term(word, "uk")], []
    with LOCK:
        for lang in ("ru", "uk"):
            if known(lang, word):
                raw += [p.normal_form for p in morph(lang).parse(word)[:4]]
        for form in list(raw):
            for lang in ("ru", "uk"):
                if known(lang, form):
                    raw += [p.normal_form for p in morph(lang).parse(form)[:3]]
    return tuple(list(dict.fromkeys(forms + [plain_form(f) for f in raw]))[:MAX_FORMS])


@lru_cache(maxsize=65536)
def part_of_speech(word):
    tags = set()
    with LOCK:
        for lang in ("ru", "uk"):
            if known(lang, word):
                tags.add(morph(lang).parse(word)[0].tag.POS)
    return frozenset(tags)


def word_term(word, first):
    word = unmix(word)
    if CYRILLIC.search(word):
        return cyrillic_term(word, first)
    if LATIN.search(word):
        return latin_term(word)
    return word


def word_forms(word):
    word = unmix(word)
    if CYRILLIC.search(word):
        return cyrillic_forms(word)
    if LATIN.search(word):
        return (latin_term(word),)
    return (word,)


def stopword(word, question=False):
    word = unmix(word)
    if word in ENGLISH_STOP or question and word in QUESTION_WORDS:
        return True
    return bool(CYRILLIC.search(word) and part_of_speech(word) & (QUESTION_POS if question else STOP_POS))


def first_language(text):
    ukrainian = sum(text.count(c) for c in UKRAINIAN_LETTERS)
    return "uk" if ukrainian > sum(text.count(c) for c in RUSSIAN_LETTERS) else "ru"


def grams(run, start=0):
    if len(run) == 1:
        return [(run, start, start + 1)]
    pairs = [(run[i:i + 2], start + i, start + i + 2) for i in range(len(run) - 1)]
    return pairs + [(run[-1], start + len(run) - 1, start + len(run))]


def tokens(text, normalized=False):
    text = text if normalized else normalize(text)
    first, result = first_language(text), []
    for run in RUNS.finditer(text):
        if run.group(1):
            result += grams(run.group(1), run.start())
            continue
        for match in WORD.finditer(run.group(2)):
            start = run.start() + match.start()
            result.append((word_term(match.group(0), first), start, start + len(match.group(0))))
    return result


def domain_tokens(host):
    labels = [label for label in host.strip(".").split(".") if label]
    return [".".join(labels[i:]) for i in range(max(0, len(labels) - 1))][:5]


def reference_items(text, urls=()):
    found = indicators.Indicators()
    if text:
        found.text(text, "text", None, None)
    for url in urls:
        found.link(url, "link", None, None)
    return list(found.found.values())


def reference_token(item):
    kind, value = item["kind"], item["value"]
    if kind == "telegram":
        return value.casefold()
    if kind == "telegram-invite":
        path = [p for p in re.split(r"[/?#]", value.split("://", 1)[-1])[1:] if p]
        code = path[1] if path and path[0] == "joinchat" and len(path) > 1 else path[0].lstrip("+") if path else ""
        return "invite:" + code.casefold() if code else None
    if kind == "email":
        return value.casefold()
    if kind == "phone":
        return "tel:" + value.lstrip("+")
    if kind == "wallet":
        return "w:" + value.casefold()
    return None


def references(text, urls=()):
    result = []
    for item in reference_items(text, urls):
        if item["kind"] == "domain":
            result += domain_tokens(item["value"])
            if item.get("punycode"):
                result += domain_tokens(item["punycode"])
        elif token := reference_token(item):
            result.append(token)
    result += ["#" + tag for tag in HASHTAG.findall(normalize(text))]
    return list(dict.fromkeys(result))


def message_urls(payload):
    raw = payload.get("raw") if isinstance(payload.get("raw"), dict) else {}
    urls = [e["url"] for e in raw.get("entities") or [] if isinstance(e, dict) and isinstance(e.get("url"), str)]
    buttons = keyboard.of_payload(payload) or {}
    labels = []
    for row in buttons.get("rows") or []:
        for button in row:
            if isinstance(button.get("text"), str):
                labels.append(button["text"])
            if isinstance(button.get("url"), str):
                urls.append(button["url"])
    media = raw.get("media") if isinstance(raw.get("media"), dict) else {}
    page = media.get("webpage") if isinstance(media.get("webpage"), dict) else {}
    if isinstance(page.get("url"), str):
        urls.append(page["url"])
    return urls[:200], " ".join(labels)[:4000]


def message_document(chat_id, kind, payload):
    text = payload.get("text") if isinstance(payload.get("text"), str) else ""
    urls, labels = message_urls(payload)
    body = " ".join(term for term, _, _ in tokens(text + ("\n" + labels if labels else "")))
    meta = ["k:" + KIND_TAGS.get(kind, "other")]
    if chat_id is not None:
        meta.append("c:" + str(chat_id))
    sender = payload.get("sender_id")
    if type(sender) is int:
        meta.append("s:" + str(sender))
    observed = payload.get("sender_observation") if isinstance(payload.get("sender_observation"), dict) else {}
    if isinstance(observed.get("username"), str) and observed["username"]:
        meta.append("u:" + observed["username"].casefold())
    return body, " ".join(references(text, urls)), " ".join(meta)


def quote(term):
    return '"' + term.replace('"', '""') + '"'


def segmented_clauses(run, split=True):
    words = [run]
    if split and HAN.search(run) and (jieba := segmenter()) is not None:
        with LOCK:
            words = [w for w in jieba.cut(run) if w.strip()]
    clauses = []
    for word in words:
        if len(word) == 1:
            clauses.append(("body:" + quote(word) + " *", False, [word], word))
        else:
            clauses.append(("body:" + quote(" ".join(word[i:i + 2] for i in range(len(word) - 1))), False, [word], word))
    return clauses


def text_clauses(text, question=False, split=True):
    text, clauses = normalize(text), []
    for run in RUNS.finditer(text):
        if run.group(1):
            clauses += segmented_clauses(run.group(1), split)
            continue
        for match in WORD.finditer(run.group(2)):
            word = match.group(0)
            forms = word_forms(word)
            clauses.append(("body:(" + " OR ".join(quote(f) for f in forms) + ")", stopword(word, question),
                            list(forms), word))
    return clauses


def phrase_units(units, limit=16):
    if len(units) < 2 or any(not e.startswith("body:(") for e, _, _, _ in units):
        return units
    combinations = [[]]
    for _, _, forms, _ in units:
        combinations = [done + [form] for done in combinations for form in forms]
        if len(combinations) > limit:
            return units
    phrases = " OR ".join(quote(" ".join(words)) for words in combinations)
    return [("body:(" + phrases + ")", False, [form for _, _, forms, _ in units for form in forms],
             " ".join(original for _, _, _, original in units))]


def reference_clauses(token):
    result = []
    for item in reference_items(token):
        if item["kind"] == "domain":
            host = domain_tokens(item["value"])
            if host:
                result.append(("ref:" + quote(host[0]), False, [item["value"]], item["value"]))
        elif item["kind"] == "telegram":
            name = item["value"][1:].casefold()
            result.append(("(ref:" + quote("@" + name) + " OR meta:" + quote("u:" + name) + ")", False,
                           ["@" + name], "@" + name))
        elif (value := reference_token(item)) is not None:
            result.append(("ref:" + quote(value), False, [item["value"]], item["value"]))
    return result


def moment(value, end=False):
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError("Use dates such as since:2026-01-31 or until:2026-02-01T12:00+00:00.") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
        if end and len(value) == 10:
            parsed = parsed.replace(hour=23, minute=59, second=59, microsecond=999000)
    return parsed


class Query:

    def __init__(self, text, match="all"):
        if match not in ("all", "any"):
            raise ValueError("Choose all or any words.")
        if not isinstance(text, str) or len(text) > 500:
            raise ValueError("Enter a search of at most 500 characters.")
        self.text, self.match = text.strip(), match
        self.clauses, self.negative, self.phrases, self.terms, self.literals = [], [], [], [], []
        self.chats, self.senders, self.usernames, self.message_ids = set(), set(), set(), set()
        self.since = self.until = None
        self.sources, self.kinds = set(), set()
        pending_or = False
        for found in QUERY.finditer(self.text):
            negative, token = found.group(1) == "-", found.group(5)
            quoted = next((g for g in found.groups()[1:4] if g is not None), None)
            if quoted is None and token == "OR":
                pending_or = bool(self.clauses)
                continue
            if quoted is None and not negative and (option := FILTER.fullmatch(token)):
                self.option(option.group(1).lower(), option.group(2))
                continue
            if quoted is not None:
                units = [(e, False, f, o) for e, _, f, o in text_clauses(quoted, split=False)]
                if units and not negative:
                    self.phrases.append(search_text(quoted.strip()))
                units = phrase_units(units)
            else:
                units = self.token_clauses(token)
            if not units:
                continue
            expression = " AND ".join(u[0] for u in units)
            expression = "(" + expression + ")" if len(units) > 1 else expression
            if negative:
                self.negative.append(expression)
                continue
            stop = all(u[1] for u in units)
            if pending_or:
                previous, previous_stop = self.clauses.pop()
                self.clauses.append(("(" + previous + " OR " + expression + ")", previous_stop and stop))
            else:
                self.clauses.append((expression, stop))
            for _, unit_stop, forms, original in units:
                self.terms.append({"text": original, "forms": forms, "ignored": unit_stop})
            pending_or = False
        if len(self.clauses) + len(self.negative) > MAX_CLAUSES:
            raise ValueError("Use at most 24 search terms.")

    def token_clauses(self, token):
        if token.startswith("#") and len(token) > 2:
            tag = normalize(token[1:])
            words = text_clauses(tag)
            alternatives = "ref:" + quote("#" + tag) + (" OR " + words[0][0] if len(words) == 1 else "")
            return [("(" + alternatives + ")", False, ["#" + tag], "#" + tag)]
        if token.startswith("@") and (handle := HANDLE.fullmatch(token.casefold())):
            name = handle.group(1)
            return [("(ref:" + quote("@" + name) + " OR meta:" + quote("u:" + name) + ")", False, ["@" + name],
                     "@" + name)]
        if (re.search(r"[./:@+]", token) or len(token) >= 25) and (found := reference_clauses(token)):
            self.literals += [f[3].casefold() for f in found]
            return found
        return text_clauses(token, question=self.match == "any")

    def option(self, key, value):
        def number(text):
            found = int(text)
            if not -2**63 <= found < 2**63:
                raise ValueError
            return found
        try:
            if key == "chat":
                self.chats.add(number(value))
            elif key == "id":
                self.message_ids.add(number(value.lstrip("#")))
            elif key == "from":
                if re.fullmatch(r"-?\d+", value):
                    self.senders.add(number(value))
                elif handle := HANDLE.fullmatch(value.casefold()):
                    self.usernames.add(handle.group(1))
                else:
                    raise ValueError
            elif key in ("since", "until"):
                setattr(self, key, moment(value, end=key == "until"))
            elif key == "source":
                self.sources.update(SOURCES if value.lower() == "all" else [SOURCE_NAMES[value.lower()]])
            elif key == "kind":
                if value.lower() not in KIND_TAGS.values():
                    raise ValueError
                self.kinds.add(value.lower())
        except (ValueError, KeyError):
            raise ValueError("Unsupported search filter: " + key + ":" + value[:40]) from None

    def core(self):
        required = [e for e, stop in self.clauses if not stop] or [e for e, _ in self.clauses]
        if not required:
            return None
        if self.match == "any" and len(required) > 1:
            return "(" + " OR ".join(required) + ")"
        return " AND ".join(required)

    def expression(self, chats=None, senders=None, usernames=None, kinds=None):
        core = self.core()
        parts = [core] if core else []
        for prefix, values in (("c:", chats), ("s:", senders), ("u:", usernames), ("k:", kinds)):
            if values:
                parts.append("meta:(" + " OR ".join(quote(prefix + str(v)) for v in sorted(values, key=str)) + ")")
        if not parts and (self.message_ids or self.since or self.until):
            parts.append("meta:(" + " OR ".join(quote("k:" + tag) for tag in KIND_TAGS.values()) + ")")
        if not parts:
            raise ValueError("Enter words, a phrase, a domain or an @username to search.")
        expression = " AND ".join(parts)
        if self.negative:
            expression = "(" + expression + ") NOT (" + " OR ".join(self.negative) + ")"
        return expression

    def matched_terms(self):
        result = set()
        for term in self.terms:
            for form in term["forms"]:
                if RUNS.fullmatch(form) and RUNS.fullmatch(form).group(1):
                    result.update(t for t, _, _ in grams(form))
                else:
                    result.add(form)
        return result

    def explain(self):
        return {"text": self.text, "match": self.match, "terms": self.terms[:MAX_CLAUSES],
                "phrases": self.phrases, "excluded": len(self.negative),
                "filters": {"chats": sorted(self.chats), "senders": sorted(self.senders),
                            "usernames": sorted(self.usernames), "message_ids": sorted(self.message_ids),
                            "since": self.since.isoformat() if self.since else None,
                            "until": self.until.isoformat() if self.until else None,
                            "sources": sorted(self.sources), "kinds": sorted(self.kinds)}}


def original_offset(text, offset):
    low, high = 0, len(text)
    while low < high:
        middle = (low + high) // 2
        if len(normalize(text[:middle + 1])) > offset:
            high = middle
        else:
            low = middle + 1
    return min(low, max(0, len(text) - 1))


def focus(text, query):
    normalized = normalize(text)
    found = [normalized.find(value) for value in query.literals + query.phrases]
    wanted = query.matched_terms()
    found.append(next((start for term, start, _ in tokens(normalized, True) if term in wanted), -1))
    found = [value for value in found if value >= 0]
    if not found:
        return None
    first = min(found)
    return first if normalized == text else original_offset(text, first)


def payload_text(payload):
    try:
        value = json.loads(payload).get("text")
    except (TypeError, ValueError, AttributeError):
        return ""
    return search_text(value) if isinstance(value, str) else ""


def iso(value):
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def narrowed(first, second):
    if first is None:
        return set(second) if second is not None else None
    return set(first) if second is None else set(first) & set(second)


def configured_mode(store):
    value = (store.get_setting("fulltext", {}) or {}).get("mode") or os.environ.get("TGWITNESS_FULLTEXT", "disk")
    return value if value in MODES else "disk"


class FullText:
    def __init__(self, store):
        self.store, self.lock = store, threading.RLock()
        self.db, self.mode, self.thread, self.error = None, None, None, None
        self.stopping, self.wake = threading.Event(), threading.Event()
        self.derived = DerivedIndex(store)
        store.listeners.append(self.notify)

    @property
    def path(self):
        return self.store.root / "search" / "fulltext.sqlite3"

    def notify(self, event):
        if event["kind"] in TEXT_KINDS:
            self.wake.set()

    def remove_files(self):
        for suffix in ("", "-wal", "-shm", "-journal"):
            Path(str(self.path) + suffix).unlink(missing_ok=True)

    def connection(self):
        if self.db is not None or self.mode == "unavailable":
            return self.db
        mode = configured_mode(self.store)
        if mode == "off":
            self.mode = "off"
            return None
        if mode == "disk":
            self.path.parent.mkdir(mode=0o700, exist_ok=True)
        else:
            self.remove_files()
        db = sqlite3.connect(str(self.path) if mode == "disk" else ":memory:", check_same_thread=False,
                             isolation_level=None)
        try:
            db.row_factory = sqlite3.Row
            if mode == "disk":
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("PRAGMA synchronous=NORMAL")
            db.execute("PRAGMA busy_timeout=5000")
            db.execute("ATTACH DATABASE ? AS j", (str(self.store.root / "journal.sqlite3"),))
            db.create_function("tgw_text", 1, payload_text, deterministic=True)
            self.prepare(db)
        except sqlite3.OperationalError as exc:
            db.close()
            if any(word in str(exc) for word in ("no such module", "tokenize", "categories")):
                self.mode, self.error = "unavailable", "This SQLite build lacks the FTS5 features full-text search needs."
                return None
            raise
        self.db, self.mode = db, mode
        return db

    def prepare(self, db):
        db.execute("CREATE TABLE IF NOT EXISTS fulltext_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        state = self.state(db)
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE name='fulltext'").fetchone() is not None
        valid = exists and state.get("analyzer") == analyzer_id()
        if valid and state.get("seq"):
            row = db.execute("SELECT hash FROM j.events WHERE seq=?", (state["seq"],)).fetchone()
            valid = row is not None and row[0] == state.get("hash")
        if not valid:
            db.execute("DROP TABLE IF EXISTS fulltext")
            db.execute("DELETE FROM fulltext_state")
            state = {"analyzer": analyzer_id(), "seq": 0, "hash": None, "documents": 0,
                     "created_at": iso(datetime.now(timezone.utc))}
            for key, value in state.items():
                db.execute("INSERT INTO fulltext_state VALUES (?,?)", (key, json.dumps(value)))
            db.execute("CREATE VIRTUAL TABLE fulltext USING fts5(body, ref, meta, content='', tokenize=\"" + TOKENIZE + "\")")

    @staticmethod
    def state(db):
        return {row[0]: json.loads(row[1]) for row in db.execute("SELECT key,value FROM fulltext_state")}

    def start(self):
        with self.lock:
            if self.thread is not None and self.thread.is_alive():
                return
            if self.connection() is None:
                return
            self.stopping.clear()
            self.thread = threading.Thread(target=self.run, name="tgwitness-fulltext", daemon=True)
            self.thread.start()

    def run(self):
        while not self.stopping.is_set():
            try:
                more = self.step()
                self.error = None
            except Exception as exc:
                self.error = "Indexing stopped: " + type(exc).__name__
                LOG.warning("Full-text indexing failed (%s); retrying in one minute", type(exc).__name__)
                self.stopping.wait(60)
                continue
            if not more:
                self.wake.wait(30)
                self.wake.clear()
                self.stopping.wait(0.25)

    def step(self, batch=BATCH):
        with self.lock:
            db = self.connection()
            if db is None:
                return False
            db.execute("BEGIN")
            try:
                state = self.state(db)
                head = db.execute("SELECT seq,hash FROM j.events ORDER BY seq DESC LIMIT 1").fetchone()
                if head is None or head["seq"] <= state["seq"]:
                    db.execute("COMMIT")
                    return False
                rows = db.execute(
                    "SELECT seq,hash,kind,chat_id,payload FROM j.events WHERE seq>? AND seq<=? AND kind IN ("
                    + ",".join("?" * len(TEXT_KINDS)) + ") ORDER BY seq LIMIT ?",
                    (state["seq"], head["seq"], *TEXT_KINDS, batch)).fetchall()
                for row in rows:
                    db.execute("INSERT INTO fulltext(rowid,body,ref,meta) VALUES (?,?,?,?)",
                               (row["seq"], *message_document(row["chat_id"], row["kind"], json.loads(row["payload"]))))
                end, end_hash = (rows[-1]["seq"], rows[-1]["hash"]) if len(rows) == batch else (head["seq"], head["hash"])
                for key, value in (("seq", end), ("hash", end_hash), ("documents", state["documents"] + len(rows))):
                    db.execute("UPDATE fulltext_state SET value=? WHERE key=?", (json.dumps(value), key))
                db.execute("COMMIT")
                return end < head["seq"]
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def catch_up(self, progress=None):
        while self.step():
            if progress:
                progress(self.status())
        return self.status()

    def lag(self):
        db = self.connection()
        if db is None:
            return 0
        head = db.execute("SELECT coalesce(max(seq),0) FROM j.events").fetchone()[0]
        return head - self.state(db)["seq"]

    def current(self, public=False):
        with self.lock:
            if self.connection() is not None and 0 < self.lag() <= CATCH_UP:
                self.catch_up()
        return self.status(public)

    def status(self, public=False):
        with self.lock:
            db = self.connection()
            if db is None:
                return {"mode": configured_mode(self.store), "state": self.mode or "off", "complete": False,
                        "error": self.error}
            state = self.state(db)
            head = db.execute("SELECT coalesce(max(seq),0) FROM j.events").fetchone()[0]
        building = state["seq"] < head
        result = {"mode": self.mode, "state": "building" if building else "ready", "complete": not building,
                  "error": self.error}
        if not public:
            result.update(analyzer=state["analyzer"], indexed_seq=state["seq"], indexed_hash=state["hash"],
                          head_seq=head, documents=state["documents"],
                          progress=round(state["seq"] / head, 4) if head else 1.0)
        return result

    def close(self):
        self.stopping.set()
        self.wake.set()
        thread = self.thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=15)
        with self.lock:
            if self.db is not None:
                self.db.close()
            self.db, self.thread, self.mode = None, None, None
        self.derived.reset()

    def configure(self, mode):
        if mode not in MODES:
            raise ValueError("Choose disk, memory or off.")
        self.close()
        self.store.set_setting("fulltext", {"mode": mode})
        if mode != "disk":
            self.remove_files()
        self.start()
        return self.status()

    def rebuild(self, background=True, progress=None):
        self.close()
        with self.lock:
            self.remove_files()
        if background:
            self.start()
            return self.status()
        return self.catch_up(progress)

    def search(self, query, *, chat_ids=None, since=None, until=None, sources=None, order="relevance",
               limit=50, offset=0, timeout_s=3, public=False):
        query = query if isinstance(query, Query) else Query(query)
        if order not in ("relevance", "newest"):
            raise ValueError("Order results by relevance or newest.")
        if not 1 <= limit <= 200 or not 0 <= offset <= 1000:
            raise ValueError("Choose at most 200 results from the first 1,000.")
        chats = narrowed(query.chats or None, chat_ids)
        since = max(filter(None, (since, query.since)), default=None)
        until = min(filter(None, (until, query.until)), default=None)
        wanted = set(query.sources or sources or ("messages",))
        if not wanted <= set(SOURCES):
            raise ValueError("Choose messages, ocr or transcription sources.")
        found, matched = [], {}
        end = min(offset + limit, 1000)
        wanted_hits = end + 1
        if "messages" in wanted:
            hits, matched["messages"] = self.messages(query, chats, since, until, order, wanted_hits, timeout_s)
            found.append(hits)
        derived = wanted & {"ocr", "transcription"}
        if derived:
            hits = self.derived.search(query, chats, since, until, derived, wanted_hits, order=order)
            matched.update({name: sum(hit["source"] == name for hit in hits) for name in sorted(derived)})
            found.append(hits)
        merged = found[0] if len(found) == 1 else fused(found, order)
        more = len(merged) > end and end < 1000
        return {"hits": merged[offset:end], "next_offset": end if more else None,
                "matched": matched, "query": query.explain(), "index": self.status(public=public), "order": order}

    def ready(self):
        db = self.connection()
        if db is None:
            raise ValueError("Full-text search is off for this workspace." if self.mode == "off"
                             else self.error or "Full-text search is unavailable.")
        return db

    def messages(self, query, chats, since, until, order, limit, timeout_s):
        if chats is not None and not chats:
            return [], 0
        meta_chats = chats if chats is not None and len(chats) <= 500 else None
        expression = query.expression(meta_chats, query.senders, query.usernames, query.kinds)
        where, params = [], []
        if since is not None or until is not None:
            low, high = iso(since) if since else "", iso(until) if until else "9999"
            with self.lock:
                first, last, inside = self.ready().execute(
                    "SELECT min(seq), max(seq), count(*) FROM j.events WHERE observed_at>=? AND observed_at<=?",
                    (low, high)).fetchone()
            if not inside:
                return [], 0
            where.append("fulltext.rowid>=? AND fulltext.rowid<=?")
            params += [first, last]
            if inside != last - first + 1:
                where.append("e.observed_at>=? AND e.observed_at<=?")
                params += [low, high]
        if chats is not None and meta_chats is None:
            where.append("e.chat_id IN (" + ",".join("?" * len(chats)) + ")")
            params += sorted(chats)
        if query.message_ids:
            where.append("e.message_id IN (" + ",".join("?" * len(query.message_ids)) + ")")
            params += sorted(query.message_ids)
        joined = any("e." in condition for condition in where)
        source = (" FROM fulltext" + (" JOIN j.events e ON e.seq=fulltext.rowid" if joined else "")
                  + " WHERE fulltext MATCH ?" + "".join(" AND " + condition for condition in where))
        params = [expression, *params]
        ordering = " ORDER BY score, fulltext.rowid DESC" if order == "relevance" else " ORDER BY fulltext.rowid DESC"
        selected = []
        with self.lock:
            db = self.ready()
            if 0 < self.lag() <= CATCH_UP:
                self.catch_up()
            deadline = time.monotonic() + timeout_s
            db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            try:
                cursor = db.execute("SELECT fulltext.rowid, " + RANK + " AS score" + source + ordering
                                    + ("" if query.phrases else " LIMIT " + str(int(limit))), params)
                while len(selected) < limit and (batch := cursor.fetchmany(max(limit, 200))):
                    rows = {row["seq"]: row for row in db.execute(
                        "SELECT * FROM j.events WHERE seq IN (" + ",".join("?" * len(batch)) + ")", [b[0] for b in batch])}
                    for seq, score in batch:
                        row = rows.get(seq)
                        if row is None or row["kind"] not in TEXT_KINDS or chats is not None and row["chat_id"] not in chats:
                            continue
                        if query.phrases and not all(p in payload_text(row["payload"]) for p in query.phrases):
                            continue
                        selected.append((row, score))
                        if len(selected) >= limit:
                            break
                cursor.close()
            except sqlite3.OperationalError as exc:
                db.set_progress_handler(None, 0)
                if time.monotonic() >= deadline:
                    raise TimeoutError("Search timed out. Add words or narrow the chats and period.") from None
                if "fts5" in str(exc) or "syntax" in str(exc):
                    raise ValueError("This search could not be read. Remove special characters and retry.") from None
                raise
            except BaseException:
                db.set_progress_handler(None, 0)
                raise
            total = None
            if not query.phrases:
                counted = min(deadline, time.monotonic() + 0.5)
                db.set_progress_handler(lambda: int(time.monotonic() >= counted), 1000)
                try:
                    total = db.execute("SELECT count(*)" + source, params).fetchone()[0]
                except sqlite3.OperationalError:
                    total = None
            db.set_progress_handler(None, 0)
        hits = []
        for row, score in selected:
            event = dict(row)
            event["payload"] = json.loads(event["payload"])
            text = event["payload"].get("text") if isinstance(event["payload"].get("text"), str) else ""
            hits.append({"source": "messages", "score": round(-score, 6), "event": event, "focus": focus(text, query)})
        return hits, total


def fused(lists, order, k=60):
    scored = {}
    for hits in lists:
        for rank, hit in enumerate(hits, 1):
            key = (hit["source"], hit.get("job_id"), hit["event"]["seq"])
            scored[key] = (scored.get(key, (0, hit))[0] + 1 / (k + rank), hit)
    if order == "newest":
        return [hit for _, hit in sorted(scored.values(), key=lambda item: -item[1]["event"]["seq"])]
    return [hit for _, hit in sorted(scored.values(), key=lambda item: (-item[0], -item[1]["event"]["seq"]))]


class DerivedIndex:

    def __init__(self, store):
        self.store, self.lock = store, threading.Lock()
        self.db, self.signature, self.items = None, None, {}

    def reset(self):
        with self.lock:
            if self.db is not None:
                self.db.close()
            self.db, self.signature, self.items = None, None, {}

    def refresh(self):
        jobs = [e for e in self.store.get_setting("media_analysis_jobs", []) if e.get("status") == "completed"]
        signature = tuple(sorted(e["id"] for e in jobs))
        if self.db is not None and signature == self.signature:
            return
        vault = self.store.signer
        db = sqlite3.connect(":memory:", check_same_thread=False)
        db.execute("CREATE VIRTUAL TABLE fulltext USING fts5(body, ref, meta, content='', tokenize=\"" + TOKENIZE + "\")")
        items = {}
        for number, entry in enumerate(jobs, 1):
            artifact = vault.read("media-analysis-" + entry["id"]) if vault is not None else {}
            text = artifact.get("text") if isinstance(artifact.get("text"), str) else ""
            request = entry.get("request") or {}
            if not text or type(request.get("chat_id")) is not int:
                continue
            engine = request.get("engine") if request.get("engine") in ("ocr", "transcription") else "ocr"
            db.execute("INSERT INTO fulltext(rowid,body,ref,meta) VALUES (?,?,?,?)", (
                number, " ".join(t for t, _, _ in tokens(text)), " ".join(references(text)),
                "c:" + str(request["chat_id"]) + " k:" + engine))
            items[number] = {"job_id": entry["id"], "source": engine, "chat_id": request["chat_id"],
                             "event_seq": (entry.get("source") or {}).get("event_seq"),
                             "media_sha256": artifact.get("media_sha256"), "text": text,
                             "engine": artifact.get("engine"), "model_version": artifact.get("model_version"),
                             "language": artifact.get("language"), "completed_at": artifact.get("completed_at")}
        if self.db is not None:
            self.db.close()
        self.db, self.signature, self.items = db, signature, items

    def search(self, query, chats, since, until, engines, limit, *, order="relevance"):
        if chats is not None and not chats or query.senders or query.usernames or query.message_ids or query.kinds:
            return []
        expression = query.expression(chats if chats is not None and len(chats) <= 500 else None, None, None, engines)
        with self.lock:
            self.refresh()
            try:
                rows = self.db.execute("SELECT rowid, " + RANK + " FROM fulltext WHERE fulltext MATCH ? ORDER BY 2, rowid",
                                       (expression,)).fetchall()
            except sqlite3.OperationalError:
                raise ValueError("This search could not be read. Remove special characters and retry.") from None
            items = dict(self.items)
        if order == "newest":
            def observed_seq(row):
                seq = items.get(row[0], {}).get("event_seq")
                return seq if type(seq) is int else -1
            rows.sort(key=observed_seq, reverse=True)
        hits = []
        for rowid, score in rows:
            item = items.get(rowid)
            if item is None or chats is not None and item["chat_id"] not in chats:
                continue
            if any(phrase not in search_text(item["text"]) for phrase in query.phrases):
                continue
            if type(item["event_seq"]) is not int or not isinstance(item["media_sha256"], str):
                continue
            if not self.store.media_in_chats(item["media_sha256"], {item["chat_id"]}):
                continue
            events = self.store.events(before=item["event_seq"] + 1, limit=1, chat_ids={item["chat_id"]})
            if not events or events[0]["seq"] != item["event_seq"]:
                continue
            when = datetime.fromisoformat(events[0]["observed_at"])
            if since is not None and when < since or until is not None and when > until:
                continue
            begin = max(0, (focus(item["text"], query) or 0) - 80)
            hits.append({"source": item["source"], "score": round(-score, 6), "event": events[0],
                         "job_id": item["job_id"], "machine_recognition": True,
                         "excerpt": item["text"][begin:begin + 320],
                         "excerpt_truncated": begin > 0 or len(item["text"]) > begin + 320,
                         "engine": item["engine"], "model_version": item["model_version"],
                         "language": item["language"], "completed_at": item["completed_at"]})
            if len(hits) >= limit:
                break
        return hits

    def matching(self, text):
        return [hit["job_id"] for hit in self.search(Query(text), None, None, None, {"ocr", "transcription"}, 100)]
