import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from tgwitness.indicators import Indicators

from .graphs import EVENT_LIMIT, mapping, read_messages, reference
from .stopwords import STOP

FORMAT = "tgwitness-analyzer-linking-v1"
MIN_MESSAGES = 15
MAX_ACCOUNTS = 200
MIN_Z = 2.0
MIN_SIGNALS = 2
STANDOUT = 0.98
TOP_WORDS = 400
PROFILE_WORDS = 150
BUCKET_SECONDS = 600
HANDOFF_WINDOW = 21 * 86400
TIERS = ((3.0, "strong"), (2.4, "notable"), (2.0, "weak"))
MIN_SET = 3
SMALL_POPULATION = 60
PRIOR_WEIGHT = 0.3
PRIOR_RANK = 0.5
MAX_PAIRS = 200
SHARED_KINDS = ("wallet", "domain", "url", "telegram", "telegram-invite", "email")
TOKEN = re.compile(r"[^\W\d_]{3,}", re.UNICODE)
EMOJI = re.compile("[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F1E6-\U0001F1FF"
                   "\U00002190-\U000021FF\U00002B00-\U00002BFF\U0000FE0F]")
LATIN = re.compile(r"[a-z]", re.I)
CYRILLIC = re.compile(r"[а-яёіїєґ]", re.I)
WEIGHTS = {"lexical": 0.20, "emoji": 0.08, "style": 0.17, "hours": 0.13, "handoff": 0.12, "exclusive": 0.10,
           "peers": 0.05, "forwards": 0.04, "shared": 0.11}
SIGNALS = tuple(WEIGHTS)
FLOOR = {"lexical": 0.10, "emoji": 0.30, "style": 0.60, "hours": 0.60, "handoff": 0.30, "exclusive": 0.50,
         "peers": 0.20, "forwards": 0.20, "shared": 0.05}
LABELS = {"lexical": "Same vocabulary", "emoji": "Same emoji", "style": "Same writing habits", "hours": "Same hours",
          "handoff": "One stops, other starts", "exclusive": "Rarely online together", "peers": "Same people",
          "forwards": "Same sources", "shared": "Same indicators"}
STYLE_FIELDS = ("avg_len", "len_spread", "caps_ratio", "emoji_rate", "exclaim", "question", "comma", "period",
                "ellipsis", "newline", "paren_smile", "latin_ratio", "digit_ratio", "no_capital_start", "link_rate",
                "word_len")
LIMITS = (
    "Each pair is a lead for an investigator, not identification. Similar accounts can belong to different people.",
    "Signals are computed independently from observed messages in the chosen chats; the explanation shows which "
    "ones stood out.",
    "Shared operators, scripts, templates and copied texts produce the same signals as one person with two accounts.",
    "Accounts with fewer authored messages than the minimum are not compared. Outgoing messages of this workspace "
    "are excluded.",
    "With fewer than 60 compared pairs fixed thresholds are used instead of ranking against the chat, and tiers are "
    "less reliable.",
    "Confirm a lead with independent evidence before you report it or act on it.",
)


def style_vector(texts):
    count, lengths = len(texts), [len(text) for text in texts]
    totals = Counter()
    for text in texts:
        totals["caps"] += sum(char.isupper() for char in text)
        for key, mark in (("exclaim", "!"), ("question", "?"), ("comma", ","), ("period", "."), ("ellipsis", "..."),
                          ("newline", "\n"), ("links", "http")):
            totals[key] += text.count(mark)
        totals["paren"] += len(re.findall(r"\)\)+", text))
        totals["latin"] += len(LATIN.findall(text))
        totals["cyrillic"] += len(CYRILLIC.findall(text))
        totals["digits"] += sum(char.isdigit() for char in text)
        totals["emoji"] += len(EMOJI.findall(text))
        stripped = text.lstrip()
        totals["no_cap"] += bool(stripped and stripped[0].isalpha() and not stripped[0].isupper())
        words = TOKEN.findall(text)
        totals["word_chars"] += sum(len(word) for word in words)
        totals["words"] += len(words)
    chars, mean = max(sum(lengths), 1), sum(lengths) / count
    letters = max(totals["latin"] + totals["cyrillic"], 1)
    return {"avg_len": mean, "len_spread": math.sqrt(sum((x - mean) ** 2 for x in lengths) / count),
            "caps_ratio": totals["caps"] / chars, "emoji_rate": totals["emoji"] / count,
            "exclaim": totals["exclaim"] / count, "question": totals["question"] / count,
            "comma": totals["comma"] / count, "period": totals["period"] / count,
            "ellipsis": totals["ellipsis"] / count, "newline": totals["newline"] / count,
            "paren_smile": totals["paren"] / count, "latin_ratio": totals["latin"] / letters,
            "digit_ratio": totals["digits"] / chars, "no_capital_start": totals["no_cap"] / count,
            "link_rate": totals["links"] / count, "word_len": totals["word_chars"] / max(totals["words"], 1)}


def features(messages, min_messages):
    texts, words, emoji = defaultdict(list), defaultdict(Counter), defaultdict(Counter)
    hours, buckets = defaultdict(lambda: [0] * 24), defaultdict(set)
    forwards, peers, shared, shared_refs = defaultdict(set), defaultdict(set), defaultdict(set), {}
    first, last, names, counts = {}, {}, {}, Counter()
    index = {(m["chat"], m["id"]): m for m in messages}
    for message in sorted(messages, key=lambda m: (m["sent"] is None, m["sent"] or 0, m["seq"])):
        user = message["sender"]
        if user is None or message["outgoing"] or message["sent"] is None:
            continue
        counts[user] += 1
        names[user] = message["name"] or names.get(user)
        stamp = int(message["sent"].timestamp())
        hours[user][message["sent"].astimezone(timezone.utc).hour] += 1
        buckets[user].add(stamp // BUCKET_SECONDS)
        first.setdefault(user, (stamp, message))
        last[user] = (stamp, message)
        parent = index.get((message["chat"], message["reply_to"])) if message["reply_to"] else None
        if parent and parent["sender"] is not None and parent["sender"] != user:
            peers[user].add(parent["sender"])
            peers[parent["sender"]].add(user)
        found = Indicators()
        found.message(message["text"], message["details"], None, None)
        for item in found.result()["items"]:
            if item["kind"] in SHARED_KINDS:
                key = item["kind"] + ":" + (item["value"].lower() if item["kind"] == "telegram" else item["value"])
                shared[user].add(key)
                shared_refs.setdefault((user, key), reference(message))
        forward = mapping(message["details"].get("forwarded_from"))
        origin = forward.get("from_id") if forward.get("from_id") is not None else forward.get("from_name")
        if origin is not None:
            forwards[user].add(str(origin))
            continue
        text = message["text"]
        if text.strip():
            texts[user].append(text)
            for token in TOKEN.findall(text.lower()):
                if len(token) >= 4 and token not in STOP:
                    words[user][token] += 1
            emoji[user].update(EMOJI.findall(text))
    result = {}
    for user in counts:
        if len(texts[user]) < max(5, min_messages):
            continue
        result[user] = {"id": user, "name": names.get(user), "messages": counts[user],
                        "authored_messages": len(texts[user]), "words": Counter(dict(words[user].most_common(TOP_WORDS))),
                        "emoji": emoji[user], "hours": hours[user], "buckets": buckets[user], "peers": peers[user],
                        "forwards": forwards[user], "shared": shared[user],
                        "shared_refs": {key: shared_refs[(user, key)] for key in shared[user]},
                        "first_ts": first[user][0], "last_ts": last[user][0],
                        "first_ref": reference(first[user][1]), "last_ref": reference(last[user][1]),
                        "style": style_vector(texts[user])}
    return result


def inverse_frequency(found):
    frequency = Counter()
    for record in found.values():
        frequency.update(record["words"].keys())
    count = max(len(found), 1)
    return {term: math.log(1 + count / seen) for term, seen in frequency.items()}


def profile(record, idf):
    total = sum(record["words"].values()) or 1
    vector = {term: seen / total * idf.get(term, 1.0) for term, seen in record["words"].items()}
    top = sorted(vector.items(), key=lambda item: (-item[1], item[0]))[:PROFILE_WORDS]
    norm = math.sqrt(sum(value * value for _, value in top)) or 1.0
    return {term: value / norm for term, value in top}


def cosine(a, b):
    if len(a) > len(b):
        a, b = b, a
    return sum(value * b.get(term, 0.0) for term, value in a.items())


def counter_cosine(a, b):
    common = set(a) & set(b)
    if not common:
        return 0.0
    na, nb = math.sqrt(sum(v * v for v in a.values())), math.sqrt(sum(v * v for v in b.values()))
    return sum(a[key] * b[key] for key in common) / (na * nb) if na and nb else 0.0


def hour_cosine(a, b):
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(y * y for y in b))
    return sum(x * y for x, y in zip(a, b)) / (na * nb) if na and nb else 0.0


def weighted_jaccard(a, b, weight):
    union = a | b
    total = sum(weight.get(value, 1.0) for value in union)
    return sum(weight.get(value, 1.0) for value in a & b) / total if total else 0.0


def style_spread(found):
    spread = {}
    for field in STYLE_FIELDS:
        values = [record["style"][field] for record in found.values()]
        mean = sum(values) / len(values)
        spread[field] = math.sqrt(sum((v - mean) ** 2 for v in values) / len(values)) or 1e-9
    return spread


def style_similarity(a, b, spread):
    distance = math.sqrt(sum(((a[f] - b[f]) / spread[f]) ** 2 for f in STYLE_FIELDS) / len(STYLE_FIELDS))
    return 1.0 / (1.0 + distance)


def handoff(a, b):
    earlier, later = (a, b) if a["last_ts"] <= b["last_ts"] else (b, a)
    gap = later["first_ts"] - earlier["last_ts"]
    detail = {"gone": earlier["id"], "arrived": later["id"], "gap_seconds": gap, "gap_days": round(gap / 86400, 1),
              "refs": [earlier["last_ref"], later["first_ref"]]}
    if gap < -86400 or gap > HANDOFF_WINDOW:
        return 0.0, detail
    return 1.0 - max(gap, 0) / HANDOFF_WINDOW, detail


def co_presence(a, b):
    start, end = max(a["first_ts"], b["first_ts"]), min(a["last_ts"], b["last_ts"])
    detail = {"overlap_days": round(max(end - start, 0) / 86400, 1)}
    if end - start < 7 * 86400:
        return None, detail
    window = set(range(start // BUCKET_SECONDS, end // BUCKET_SECONDS + 1))
    a_in, b_in = a["buckets"] & window, b["buckets"] & window
    if len(a_in) < 20 or len(b_in) < 20:
        return None, detail
    together, chance = len(a_in & b_in), len(a_in) * len(b_in) / max(len(window), 1)
    detail.update({"shared_slots": together, "slots_a": len(a_in), "slots_b": len(b_in), "by_chance": round(chance, 1)})
    if chance < 1:
        return None, detail
    detail["ratio"] = round(together / chance, 2)
    return together / chance, detail


def ranks(values):
    measured = [i for i, value in enumerate(values) if value is not None]
    result, count = [None] * len(values), len(measured)
    order = sorted(measured, key=lambda i: values[i])
    i = 0
    while i < count:
        j = i
        while j + 1 < count and values[order[j + 1]] == values[order[i]]:
            j += 1
        for k in range(i, j + 1):
            result[order[k]] = i / count
        i = j + 1
    return result


def peak(hours, offset_minutes):
    best = max(range(24), key=lambda hour: (hours[hour], -hour))
    shifted = (best * 60 + offset_minutes) % 1440
    return "%02d:%02d" % divmod(shifted, 60)


def gap_text(seconds):
    if seconds <= 0:
        return "while the first was still active"
    if seconds < 2 * 86400:
        return str(round(seconds / 3600, 1)) + " hours later"
    return str(round(seconds / 86400, 1)) + " days later"


def when(stamp, offset_minutes):
    return datetime.fromtimestamp(stamp, timezone(timedelta(minutes=offset_minutes))).isoformat(timespec="minutes")


def label(record):
    return (record["name"] + " (ID " + str(record["id"]) + ")") if record["name"] else "ID " + str(record["id"])


def explanation(a, b, standout, details, offset_minutes):
    lines = []
    for signal in standout:
        if signal == "lexical":
            words = ", ".join(item["term"] for item in details["shared_words"][:8])
            lines.append("Same vocabulary: both often use rare words such as " + words + ".")
        elif signal == "emoji":
            lines.append("Same emoji: " + " ".join(item["emoji"] for item in details["shared_emoji"][:8]) + ".")
        elif signal == "style":
            lines.append("Same writing habits: message length, punctuation, capitals and alphabet mix are close.")
        elif signal == "hours":
            lines.append("Same hours: both are most active around " + peak(a["hours"], offset_minutes) + " and "
                         + peak(b["hours"], offset_minutes) + ".")
        elif signal == "handoff":
            gone, arrived = (a, b) if details["handoff"]["gone"] == a["id"] else (b, a)
            lines.append("One stops, other starts: " + label(gone) + " last wrote " + when(gone["last_ts"], offset_minutes)
                         + "; " + label(arrived) + " first wrote " + gap_text(details["handoff"]["gap_seconds"]) + ".")
        elif signal == "exclusive":
            seen = details["co_presence"]
            lines.append("Rarely online together: " + str(seen.get("shared_slots")) + " shared ten-minute slots where "
                         + str(seen.get("by_chance")) + " were expected by chance.")
        elif signal == "peers":
            lines.append("Same people: " + str(details["shared_peers"]) + " accounts replied to or by both.")
        elif signal == "forwards":
            lines.append("Same sources: both forward from the same channels or users.")
        elif signal == "shared":
            values = ", ".join(item["value"] for item in details["shared_indicators"][:5])
            lines.append("Same indicators: both posted " + values + ".")
    return lines


def candidates(reader, chats, min_messages=MIN_MESSAGES, min_z=MIN_Z, limit=MAX_PAIRS, offset_minutes=0,
               event_limit=EVENT_LIMIT):
    messages, truncated = read_messages(reader, chats, event_limit)
    return rank(messages, chats, min_messages, min_z, limit, offset_minutes, truncated)


def rank(messages, chats=(), min_messages=MIN_MESSAGES, min_z=MIN_Z, limit=MAX_PAIRS, offset_minutes=0,
         truncated=False):
    found = features(messages, min_messages)
    ids = sorted(found, key=lambda user: (-found[user]["messages"], user))[:MAX_ACCOUNTS]
    base = {"format": FORMAT, "chats": sorted(chats), "accounts": len(ids), "compared": 0, "found": 0,
            "basis": "absolute", "weights": WEIGHTS, "labels": LABELS, "min_z": min_z, "min_messages": min_messages,
            "pairs": [], "truncated": truncated or len(found) > MAX_ACCOUNTS, "limits": list(LIMITS)}
    if len(ids) < 2:
        return base
    found = {user: found[user] for user in ids}
    idf = inverse_frequency(found)
    vectors = {user: profile(found[user], idf) for user in ids}
    spread = style_spread(found)
    rarity = {}
    for field in ("shared", "peers", "forwards"):
        seen = Counter()
        for user in ids:
            seen.update(found[user][field])
        rarity[field] = {value: 1.0 / count for value, count in seen.items()}
    raw, meta, ratios = {signal: [] for signal in SIGNALS}, [], []
    for i, a_id in enumerate(ids):
        a = found[a_id]
        for b_id in ids[i + 1:]:
            b = found[b_id]
            moved, moved_detail = handoff(a, b)
            ratio, together = co_presence(a, b)
            ratios.append(ratio)
            raw["lexical"].append(cosine(vectors[a_id], vectors[b_id]))
            raw["emoji"].append(counter_cosine(a["emoji"], b["emoji"]) if a["emoji"] and b["emoji"] else None)
            raw["style"].append(style_similarity(a["style"], b["style"], spread))
            raw["hours"].append(hour_cosine(a["hours"], b["hours"]))
            raw["handoff"].append(moved)
            raw["exclusive"].append(None)
            for field in ("peers", "forwards"):
                raw[field].append(weighted_jaccard(a[field], b[field], rarity[field])
                                  if len(a[field]) >= MIN_SET and len(b[field]) >= MIN_SET else None)
            raw["shared"].append(weighted_jaccard(a["shared"], b["shared"], rarity["shared"])
                                 if a["shared"] and b["shared"] else None)
            meta.append({"a": a_id, "b": b_id, "handoff": moved_detail, "co_presence": together})
    known = sorted(ratio for ratio in ratios if ratio is not None)
    typical = known[len(known) // 2] if known else 0.0
    if typical > 0:
        raw["exclusive"] = [None if ratio is None else max(0.0, 1.0 - ratio / typical) for ratio in ratios]
    use_ranks = len(meta) >= SMALL_POPULATION
    ranked = {signal: ranks(values) for signal, values in raw.items()}

    def score(i):
        total = weight = 0.0
        for signal in SIGNALS:
            value = ranked[signal][i] if use_ranks else raw[signal][i]
            if value is not None:
                total += WEIGHTS[signal] * value
                weight += WEIGHTS[signal]
        return (total + PRIOR_WEIGHT * PRIOR_RANK) / (weight + PRIOR_WEIGHT)

    scores = [score(i) for i in range(len(meta))]
    mean = sum(scores) / len(scores)
    deviation = math.sqrt(sum((value - mean) ** 2 for value in scores) / len(scores)) or 1e-9
    pairs = []
    for i, info in enumerate(meta):
        z = (scores[i] - mean) / deviation
        standout = [signal for signal in SIGNALS if raw[signal][i] is not None and raw[signal][i] >= FLOOR[signal]
                    and (not use_ranks or ranked[signal][i] >= STANDOUT)]
        if len(standout) < MIN_SIGNALS or use_ranks and z < min_z:
            continue
        a, b = found[info["a"]], found[info["b"]]
        common = sorted(set(vectors[a["id"]]) & set(vectors[b["id"]]),
                        key=lambda term: (-min(vectors[a["id"]][term], vectors[b["id"]][term]), term))
        values = sorted(a["shared"] & b["shared"], key=lambda key: (-rarity["shared"].get(key, 1.0), key))
        details = {
            "handoff": info["handoff"], "co_presence": info["co_presence"],
            "shared_words": [{"term": term, "a": a["words"][term], "b": b["words"][term]} for term in common[:20]],
            "shared_emoji": [{"emoji": char, "a": a["emoji"][char], "b": b["emoji"][char]} for char in
                             sorted(set(a["emoji"]) & set(b["emoji"]), key=lambda c: (-(a["emoji"][c] + b["emoji"][c]), c))[:10]],
            "shared_indicators": [{"kind": key.split(":", 1)[0], "value": key.split(":", 1)[1],
                                   "refs": [a["shared_refs"][key], b["shared_refs"][key]]} for key in values[:25]],
            "shared_peers": len(a["peers"] & b["peers"])}
        side = {}
        for name, record in (("a", a), ("b", b)):
            side[name] = {"id": record["id"], "name": record["name"], "messages": record["messages"],
                          "authored_messages": record["authored_messages"],
                          "first_seen": when(record["first_ts"], offset_minutes),
                          "last_seen": when(record["last_ts"], offset_minutes),
                          "refs": [record["first_ref"], record["last_ref"]]}
        pairs.append({
            "key": "|".join(sorted((str(a["id"]), str(b["id"])))), **side, "score": round(scores[i], 3),
            "z": round(z, 2) if use_ranks else None,
            "tier": next((name for edge, name in TIERS if z >= edge), "weak") if use_ranks
            else "strong" if len(standout) >= 4 else "notable" if len(standout) == 3 else "weak",
            "signals": {signal: None if raw[signal][i] is None else round(raw[signal][i], 3) for signal in SIGNALS},
            "ranks": {signal: None if ranked[signal][i] is None else round(ranked[signal][i], 3) for signal in SIGNALS},
            "measured": [signal for signal in SIGNALS if raw[signal][i] is not None], "standout": standout,
            "explanation": explanation(a, b, standout, details, offset_minutes), **details,
            "shared_count": len(a["shared"] & b["shared"])})
    pairs.sort(key=lambda pair: (-pair["score"], pair["key"]))
    return {**base, "compared": len(meta), "found": len(pairs), "basis": "ranks" if use_ranks else "absolute",
            "typical_co_presence": round(typical, 2), "pairs": pairs[:limit]}
