"""Profiles of the people seen in one chat, built only from what this workspace already saved.

Nothing here contacts Telegram or writes profile contents to the signed journal. Every fact
lists the journal records (seq) it comes from, and the export carries the SHA-256 of each
referenced record, so verify.py can check the facts against an evidence export. Avatar hashes
come from the panel's local avatar cache and are labelled as such: that cache is not part of
the journal. Profiles are switched on per chat by the operator, exported as a separate signed
file and deleted together with the chat (removing the chat from sources).
"""
import hashlib
import json
import math
import re
import secrets
from datetime import datetime, timezone

from . import tuning
from .security import private_write
from .store import GONE_KINDS, TEXT_KINDS, canonical, utcnow
from .verify import fingerprint

FORMAT = "tgwitness-dossier-v1"
# Records cited per fact, the similar-avatar threshold, which mentions are looked for and the
# operator's own patterns are panel parameters (tuning.PARAMETERS, group "people").
MENTION_TYPES = ("wallets", "phones", "usernames", "links")
LIMITS = [
    "Built only from records this workspace saved; people who never wrote in the observed time are absent.",
    "Names, usernames and flags are the profile Telegram showed when a message was saved; they are mutable.",
    "Deleted and edited counts cover saved messages only. Telegram does not say who deleted a message.",
    "Mentions are found by patterns in saved text and links; they are leads to check, not verified facts.",
    "Avatar hashes come from the local avatar cache, downloaded when the panel showed the avatar; not journal records.",
    "Reply links count replies to saved messages only.",
]

BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58 = "[1-9A-HJ-NP-Za-km-z]"
WALLETS = [
    ("BTC", re.compile(r"(?<![\w])(bc1[ac-hj-np-z02-9]{11,71})(?![\w])", re.I)),
    ("BTC", re.compile(r"(?<![\w])([13]" + B58 + r"{25,34})(?![\w])")),
    ("EVM", re.compile(r"(?<![\w])(0x[a-fA-F0-9]{40})(?![\w])")),
    ("TRON", re.compile(r"(?<![\w])(T" + B58 + r"{33})(?![\w])")),
    ("TON", re.compile(r"(?<![\w-])((?:EQ|UQ|Ef|Uf|kQ|0Q)[A-Za-z0-9_-]{46})(?![\w-])")),
    ("LTC", re.compile(r"(?<![\w])(ltc1[ac-hj-np-z02-9]{11,71})(?![\w])", re.I)),
    ("LTC", re.compile(r"(?<![\w])([LM]" + B58 + r"{26,33})(?![\w])")),
    ("DOGE", re.compile(r"(?<![\w])(D[5-9A-HJ-NP-U]" + B58 + r"{32})(?![\w])")),
    ("XMR", re.compile(r"(?<![\w])([48][0-9AB]" + B58 + r"{93})(?![\w])")),
    ("SOL", re.compile(r"(?<![\w])(" + B58 + r"{32,44})(?![\w])")),
]
# Base58Check version bytes that make a match a real address of that network.
VERSIONS = {"BTC": {0x00, 0x05}, "TRON": {0x41}, "LTC": {0x30, 0x32, 0x05}, "DOGE": {0x1e, 0x16}}
PHONE = re.compile(r"(?<![\w+])(\+\d[\d ()-]{8,18}\d|[78]\d{10})(?![\w])")
USERNAME = re.compile(r"(?<![\w@/])@([A-Za-z][A-Za-z0-9_]{3,31})(?![\w])")
LINK = re.compile(r"(?i)\b((?:https?://|(?:www\.|t\.me/|telegram\.me/))[^\s<>\"'«»]+)")
TME_USER = re.compile(r"(?i)^(?:https?://)?(?:t\.me|telegram\.me)/([A-Za-z][A-Za-z0-9_]{3,31})/?$")


def b58decode(text):
    number = 0
    for char in text:
        number = number * 58 + BASE58.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * (len(text) - len(text.lstrip("1"))) + raw


def base58check(text, versions):
    try:
        raw = b58decode(text)
    except ValueError:
        return False
    if len(raw) < 5:
        return False
    body, check = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] == check and body[0] in versions


def wallets(text):
    found, taken = [], set()
    for network, pattern in WALLETS:
        for match in pattern.finditer(text):
            value = match.group(1)
            if value in taken:
                continue
            if network in VERSIONS and not value.lower().startswith(("bc1", "ltc1")) \
                    and not base58check(value, VERSIONS[network]):
                continue
            if network == "SOL":
                try:
                    if len(b58decode(value)) != 32:
                        continue
                except ValueError:
                    continue
            taken.add(value)
            found.append((network, value))
    return found


def mentions(payload, find=None, patterns=()):
    """(category, value, extra) found in saved text and its link entities.

    find switches the built-in categories on or off (all on by default); patterns are the
    operator's own (name, compiled regular expression) pairs, reported as category "patterns".
    """
    find = find or dict.fromkeys(MENTION_TYPES, True)
    text = payload.get("text") or ""
    items = [("wallets", value, network) for network, value in wallets(text)] if find["wallets"] else []
    if find["phones"]:
        for match in PHONE.finditer(text):
            digits = re.sub(r"\D", "", match.group(1))
            if 10 <= len(digits) <= 15:
                items.append(("phones", "+" + digits if match.group(1).startswith("+") else digits, None))
    links = [m.group(1).rstrip(".,;:!?)") for m in LINK.finditer(text)]
    for entity in (payload.get("raw") or {}).get("entities") or []:
        if entity.get("_") == "MessageEntityTextUrl" and entity.get("url"):
            links.append(entity["url"])  # a link hidden behind other text
        if entity.get("_") == "MessageEntityMentionName" and entity.get("user_id") and find["usernames"]:
            items.append(("usernames", "id" + str(entity["user_id"]), "mention by name"))
    for link in dict.fromkeys(links):
        if find["links"]:
            items.append(("links", link, None))
        user = TME_USER.match(link)
        if user and find["usernames"]:
            items.append(("usernames", "@" + user.group(1).lower(), "t.me link"))
    if find["usernames"]:
        for match in USERNAME.finditer(text):
            items.append(("usernames", "@" + match.group(1).lower(), None))
    for name, pattern in patterns:
        for match in pattern.finditer(text):
            if match.group(0):
                items.append(("patterns", match.group(0), name))
    return items


def options(store):
    """How profiles are built in this workspace (panel parameters); recorded in every profile file."""
    values = tuning.values(store)
    return {"max_refs": values["dossier_max_refs"], "similar_bits": values["dossier_similar_bits"],
            "find": {kind: values["dossier_" + kind] for kind in MENTION_TYPES},
            "patterns": values["dossier_patterns"]}


# Avatars --------------------------------------------------------------------------------

def phash(path):
    """64-bit perceptual hash (DCT of a 32x32 grey image), the same bits as imagehash.phash."""
    from PIL import Image  # decoding JPEG needs Pillow; only profiles use it
    with Image.open(path) as image:
        resample = getattr(getattr(Image, "Resampling", Image), "LANCZOS")
        pixels = list(image.convert("L").resize((32, 32), resample).tobytes())  # one byte per grey pixel
    cos = [[math.cos(math.pi * u * (2 * x + 1) / 64) for x in range(32)] for u in range(8)]
    rows = [[sum(pixels[y * 32 + x] * cos[u][x] for x in range(32)) for u in range(8)] for y in range(32)]
    low = [sum(rows[y][u] * cos[v][y] for y in range(32)) for v in range(8) for u in range(8)]
    ordered = sorted(low)
    median = (ordered[31] + ordered[32]) / 2
    return "%016x" % int("".join("1" if value > median else "0" for value in low), 2)


def avatar_index(root):
    """{peer_id: {sha256, phash, cached_at}} for the local avatar cache; hashes kept beside it."""
    folder = root / "avatars"
    if not folder.is_dir():
        return {}
    index_path = folder / "hashes.json"
    try:
        saved = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        saved = {}
    result, changed = {}, False
    for path in folder.glob("*.jpg"):
        if not path.stem.lstrip("-").isdigit():
            continue
        stat = path.stat()
        key = path.name + ":" + str(stat.st_size) + ":" + str(int(stat.st_mtime))
        entry = saved.get(key)
        if entry is None:
            data = path.read_bytes()
            try:
                perceptual = phash(path)
            except Exception:
                perceptual = None
            entry = {"sha256": hashlib.sha256(data).hexdigest(), "phash": perceptual,
                     "cached_at": datetime.fromtimestamp(stat.st_mtime).astimezone().isoformat(timespec="seconds")}
            saved[key], changed = entry, True
        result[int(path.stem)] = entry
    if changed:
        live = {p.name + ":" + str(p.stat().st_size) + ":" + str(int(p.stat().st_mtime)) for p in folder.glob("*.jpg")}
        private_write(index_path, json.dumps({k: v for k, v in saved.items() if k in live}).encode())
    return result


def distance(a, b):
    return bin(int(a, 16) ^ int(b, 16)).count("1")


# Building -------------------------------------------------------------------------------

def enabled_chats(store):
    return sorted(int(k) for k in store.get_setting("dossiers", {}))


def set_enabled(store, chat_id, enabled):
    with store.transaction():
        chats = store.get_setting("dossiers", {})
        if enabled:
            chats.setdefault(str(chat_id), {"enabled_at": utcnow(), "generation": secrets.token_hex(16)})
        else:
            chats.pop(str(chat_id), None)
            cache_path(store, chat_id).unlink(missing_ok=True)
        store.set_setting("dossiers", chats)
        store.append("dossier.changed", {"enabled": enabled, "contents_in_journal": False,
                                         "meaning": "people profiles for this chat are built from saved records "
                                                    "on request; their contents never enter the journal"}, chat_id)


def remove(store, chat_id):
    """Forget the chat's profiles (setting and cached file). Returns whether any existed."""
    with store.transaction():
        chats = store.get_setting("dossiers", {})
        existed = chats.pop(str(chat_id), None) is not None or cache_path(store, chat_id).exists()
        store.set_setting("dossiers", chats)
        cache_path(store, chat_id).unlink(missing_ok=True)
    return existed


def cache_path(store, chat_id):
    return store.root / "dossiers" / (str(chat_id) + ".json")


class Facts:
    """Distinct values, each with the first/last time seen and the records that show it."""
    def __init__(self, max_refs=25):
        self.items, self.max_refs = {}, max_refs

    def add(self, value, event, extra=None):
        if value in (None, ""):
            return
        item = self.items.setdefault(value, {"value": value, "count": 0, "first_at": event["observed_at"],
                                             "records": []})
        if extra and "detail" not in item:
            item["detail"] = extra
        item["count"] += 1
        item["last_at"] = event["observed_at"]
        if event["seq"] not in item["records"] and len(item["records"]) < self.max_refs:
            item["records"].append(event["seq"])

    def out(self):
        return sorted(self.items.values(), key=lambda i: i["first_at"])


def build(store, chat_id, title=None):
    """Profiles of everyone with a saved message in this chat, as a signable statement body."""
    settings = options(store)
    refs, find, patterns = settings["max_refs"], settings["find"], tuning.patterns(settings["patterns"])
    records = store.chat_records(chat_id, TEXT_KINDS + GONE_KINDS)
    people, owner, message_seq = {}, {}, {}
    gone = {}
    for event in records:
        if event["kind"] in GONE_KINDS:
            gone.setdefault(event["message_id"], []).append(event)
            continue
        payload = event["payload"]
        observed = payload.get("sender_observation") or {}
        sender = payload.get("sender_id", observed.get("id"))
        if sender is None or (sender == chat_id and chat_id < 0):
            continue  # channel posts signed by the channel itself (in a private chat this is the other person)
        person = people.setdefault(sender, {
            "id": sender, "names": Facts(refs), "usernames": Facts(refs), "photo_ids": Facts(refs), "flags": {},
            "messages": set(), "edited": set(), "first": None, "last": None, "hours": [0] * 24,
            "replies_to": {}, "replied_by": {},
            "mentions": {kind: Facts(refs) for kind in MENTION_TYPES + ("patterns",)}})
        person["names"].add(observed.get("display_name"), event)
        person["usernames"].add(("@" + observed["username"].lower()) if observed.get("username") else None, event)
        person["photo_ids"].add(observed.get("photo_id"), event)
        for flag, value in (observed.get("flags") or {}).items():
            current = person["flags"].get(flag)
            if current is None or current["value"] != value:
                person["flags"][flag] = {"value": value, "since_record": event["seq"], "since": event["observed_at"]}
        message_id = event["message_id"]
        owner.setdefault(message_id, sender)
        message_seq.setdefault(message_id, event["seq"])
        if event["kind"] == "message.edited":
            person["edited"].add(message_id)
        if message_id not in person["messages"]:
            person["messages"].add(message_id)
            when = payload.get("sent_at") or event["source_at"] or event["observed_at"]
            stamp = {"at": when, "record": event["seq"], "message_id": message_id}
            if person["first"] is None or when < person["first"]["at"]:
                person["first"] = stamp
            if person["last"] is None or when > person["last"]["at"]:
                person["last"] = stamp
            try:
                person["hours"][datetime.fromisoformat(when).astimezone(timezone.utc).hour] += 1
            except (TypeError, ValueError):
                pass
        reply = payload.get("reply_to_message_id")
        if reply:
            # Keyed by the replying message: its snapshots and edits add records, not replies.
            person["replies_to"].setdefault(reply, {}).setdefault(message_id, []).append(event["seq"])
        for category, value, extra in mentions(payload, find, patterns):
            person["mentions"][category].add(value, event, extra)
    avatars = avatar_index(store.root)
    elsewhere = store.sender_chats(list(people))
    titles = {t["chat_id"]: t["title"] for t in store.targets()}
    result, referenced = [], set()
    for person in people.values():
        replies, replying = {}, {}
        for parent, by_message in person.pop("replies_to").items():
            target = owner.get(parent)
            if target is not None and target != person["id"]:
                entry = replies.setdefault(target, {"id": target, "count": 0, "records": []})
                replying.setdefault(target, set()).update(by_message)
                entry["count"] = len(replying[target])  # each replying message once
                entry["records"] = (entry["records"] + [seq for seqs in by_message.values() for seq in seqs])[:refs]
        for target, entry in replies.items():
            people[target]["replied_by"][person["id"]] = entry["count"]
        person["replies_to"] = sorted(replies.values(), key=lambda r: -r["count"])
    for person in people.values():
        ids = person.pop("messages")
        deleted = {m: [e for e in gone.get(m, []) if e["kind"] == "message.deleted"] for m in ids}
        missing = {m: [e for e in gone.get(m, []) if e["kind"] == "message.missing_on_recheck"] for m in ids}
        deleted_ids = [m for m, events in deleted.items() if events]
        missing_ids = [m for m, events in missing.items() if events and not deleted[m]]
        total = len(ids)
        avatar = avatars.get(person["id"])
        similar = []
        if avatar and avatar.get("phash"):
            for other, entry in avatars.items():
                if other != person["id"] and entry.get("phash") and distance(avatar["phash"], entry["phash"]) <= settings["similar_bits"]:
                    similar.append({"id": other, "distance": distance(avatar["phash"], entry["phash"]),
                                    "in_this_chat": other in people})
        mentioned = {k: v.out() for k, v in person["mentions"].items()}
        profile = {
            "id": person["id"],
            "names": person["names"].out(), "usernames": person["usernames"].out(),
            "flags": person["flags"],
            "avatar": {"photo_ids": person["photo_ids"].out(),
                       "cached": {**avatar, "source": "local avatar cache (not a journal record)"} if avatar else None,
                       "similar": sorted(similar, key=lambda s: s["distance"])[:20]},
            "activity": {
                "first_message": person["first"], "last_message": person["last"], "messages": total,
                "edited": len(person["edited"]), "deleted": len(deleted_ids), "missing": len(missing_ids),
                "edited_share": round(len(person["edited"]) / total, 3) if total else 0,
                "deleted_share": round(len(deleted_ids) / total, 3) if total else 0,
                "deleted_records": [deleted[m][0]["seq"] for m in sorted(deleted_ids)][:refs],
                "hours_utc": person["hours"]},
            "relations": {
                "replies_to": person["replies_to"],
                "replied_by": sorted(({"id": k, "count": v} for k, v in person["replied_by"].items()),
                                     key=lambda r: -r["count"]),
                "other_chats": sorted(({"chat_id": c, "title": titles.get(c), "messages": n}
                                       for c, n in elsewhere.get(person["id"], {}).items() if c != chat_id),
                                      key=lambda r: -r["messages"])},
            "mentions": mentioned,
        }
        for facts in (profile["names"], profile["usernames"], profile["avatar"]["photo_ids"],
                      *mentioned.values(), *(r["records"] for r in profile["relations"]["replies_to"])):
            for item in facts:
                referenced.update(item["records"] if isinstance(item, dict) else [item])
        referenced.update(profile["activity"]["deleted_records"])
        referenced.update(f["since_record"] for f in profile["flags"].values())
        for stamp in (person["first"], person["last"]):
            if stamp:
                referenced.add(stamp["record"])
        result.append(profile)
    result.sort(key=lambda p: (-p["activity"]["messages"], str(p["id"])))
    hashes = {}
    with store.snapshot() as snapshot:
        head = snapshot.head
        for seq in sorted(referenced):
            if head and seq <= head["seq"]:
                hashes[str(seq)] = snapshot.hash_at(seq)
    return {"format": FORMAT, "chat": {"id": chat_id, "title": title or titles.get(chat_id)},
            "built_at": utcnow(), "journal": {"event_count": head["seq"] if head else 0,
                                              "head_hash": head["hash"] if head else None},
            "people": result, "record_hashes": hashes, "settings": settings, "limitations": LIMITS,
            "contents_in_journal": False}


def signed(store, vault, chat_id, title=None, producer=None):
    enabled = store.get_setting("dossiers", {}).get(str(chat_id))
    statement = build(store, chat_id, title)
    statement.update(public_key=vault.public_key, producer=producer)
    value = {"statement": statement, "signature": vault.sign(canonical(statement)),
             "fingerprint": fingerprint(vault.public_key)}
    with store.lock:
        # A worker finishing after disable/remove must not recreate the deleted file.
        if enabled and enabled == store.get_setting("dossiers", {}).get(str(chat_id)):
            path = cache_path(store, chat_id)
            path.parent.mkdir(mode=0o700, exist_ok=True)
            private_write(path, json.dumps(value, ensure_ascii=False).encode("utf-8"))
    return value
