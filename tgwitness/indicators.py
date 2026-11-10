import base64
import csv
import hashlib
import io
import json
import re
import uuid
import warnings
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import crypto_ids

NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/phishdestroy/TgWitness#indicators")
MAX_INDICATORS = 20000
MAX_REFS = 50
KINDS = ("url", "domain", "wallet", "telegram", "telegram-invite", "email", "phone", "image", "transaction",
         "payment-uri")
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BASE58_CHAINS = {0x00: "Bitcoin", 0x05: "Bitcoin", 0x30: "Litecoin", 0x32: "Litecoin", 0x1E: "Dogecoin",
                 0x41: "TRON"}
BECH32_CHAINS = {"bc": "Bitcoin", "ltc": "Litecoin"}
TELEGRAM_HOSTS = ("t.me", "telegram.me", "telegram.dog")
TELEGRAM_PATHS = ("joinchat", "addstickers", "addemoji", "share", "proxy", "socks", "setlanguage", "login",
                  "iv", "s", "c", "contact", "boost", "giftcode", "addlist", "m", "bg", "addtheme")
FILE_ENDINGS = {"txt", "jpg", "jpeg", "png", "gif", "pdf", "doc", "docx", "xls", "xlsx", "csv", "json", "html", "htm",
                "js", "py", "exe", "dll", "apk", "ipa", "php", "mp4", "mp3", "webp", "svg", "log", "md", "ini", "cfg",
                "bat", "sh", "jar", "rar", "7z", "tar", "gz", "heic", "webm", "ogg", "wav", "tgs"}
TRAILING = ".,;:!?)]}>'\"»”’…"
URL = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`«»“”‘’]+")
HOST = re.compile(r"(?i)(?<![\w@./-])((?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?\.)+"
                  r"(?:[a-z¡-￿]{2,24}|xn--[a-z0-9-]{2,59}))(/[^\s<>\"'`«»“”‘’]*)?")
EMAIL = re.compile(r"(?i)(?<![\w.+-])[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,24}\b")
USERNAME = re.compile(r"(?<![\w@/.])@([A-Za-z][A-Za-z0-9_]{3,31})\b")
PHONE = re.compile(r"(?<![\w+])\+\d[\d\s().-]{6,20}\d")
BASE58_WORD = re.compile(r"(?<![A-Za-z0-9])[1-9A-HJ-NP-Za-km-z]{25,44}(?![A-Za-z0-9])")
BECH32_WORD = re.compile(r"(?i)(?<![A-Za-z0-9])(?:bc|ltc)1[ac-hj-np-z02-9]{8,87}(?![A-Za-z0-9])")
EVM = re.compile(r"(?<![A-Za-z0-9])0x[0-9a-fA-F]{40}(?![A-Za-z0-9])")
WORD = re.compile(r"\S+")
TON = re.compile(r"(?<![A-Za-z0-9_+/-])[EUk0]Q[A-Za-z0-9_+/-]{46}(?![A-Za-z0-9_+/-])")
TON_RAW = re.compile(r"(?<![\w:-])(?:0|-1):[0-9a-fA-F]{64}(?![0-9a-fA-F])")

IMAGE_PIXELS = 40_000_000


def b58decode(text):
    number = 0
    for char in text:
        number = number * 58 + B58.index(char)
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * (len(text) - len(text.lstrip("1"))) + body


def base58check_chain(text):
    try:
        data = b58decode(text)
    except ValueError:
        return None
    if len(data) != 25 or hashlib.sha256(hashlib.sha256(data[:-4]).digest()).digest()[:4] != data[-4:]:
        return None
    return BASE58_CHAINS.get(data[0])


def bech32_valid(text):
    text = text.lower()
    hrp, _, data = text.rpartition("1")
    if not hrp or len(data) < 6 or any(c not in BECH32 for c in data):
        return False
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + [BECH32.index(c) for c in data]
    check = 1
    for value in values:
        top = check >> 25
        check = (check & 0x1FFFFFF) << 5 ^ value
        for bit, generator in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)):
            if top >> bit & 1:
                check ^= generator
    return check in (1, 0x2BC830A3)


def crc16(data):
    value = 0
    for byte in data:
        value ^= byte << 8
        for _ in range(8):
            value = (value << 1 ^ 0x1021 if value & 0x8000 else value << 1) & 0xFFFF
    return value


def ton_valid(text):
    try:
        data = base64.b64decode(text.replace("-", "+").replace("_", "/"), validate=True)
    except ValueError:
        return False
    return len(data) == 36 and crc16(data[:34]).to_bytes(2, "big") == data[34:]


def by_word(pattern, text, longest=1024):
    for word in WORD.finditer(text):
        if word.end() - word.start() <= longest:
            yield from pattern.finditer(text, word.start(), word.end())


def image_hash(path):
    try:
        from PIL import Image
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(path) as picture:
                if picture.width * picture.height > IMAGE_PIXELS:
                    return None
                picture.draft("L", (64, 64))
                small = picture.convert("L").resize((9, 8), Image.Resampling.LANCZOS)
                pixels = list(small.tobytes())
    except Exception:
        return None
    bits = [pixels[row * 9 + column] > pixels[row * 9 + column + 1] for row in range(8) for column in range(8)]
    return "%016x" % int("".join("1" if b else "0" for b in bits), 2)


def strip(value):
    while value and value[-1] in TRAILING:
        if value[-1] == ")" and value.count("(") >= value.count(")"):
            break
        value = value[:-1]
    return value


def host_of(url):
    try:
        host = urlsplit(url if "://" in url else "http://" + url).hostname or ""
    except ValueError:
        return ""
    return host.rstrip(".").lower()


def defang(kind, value):
    if kind == "url":
        scheme, sep, rest = value.partition("://")
        host_end = len(rest.split("/", 1)[0])
        rest = rest[:host_end].replace(".", "[.]") + rest[host_end:]
        return (scheme.replace("http", "hxxp") + "[://]" + rest) if sep else rest
    if kind == "domain":
        return value.replace(".", "[.]")
    if kind == "email":
        name, _, host = value.partition("@")
        return name + "[@]" + host.replace(".", "[.]")
    if kind == "telegram-invite":
        return defang("url", value)
    return value


class Indicators:
    def __init__(self):
        self.found, self.dropped = {}, 0

    def note(self, kind, value, source, ref, at, **extra):
        key = (kind, value.lower() if kind in ("domain", "email", "telegram") else value)
        item = self.found.get(key)
        if item is None:
            if len(self.found) >= MAX_INDICATORS:
                self.dropped += 1
                return
            item = self.found[key] = {"kind": kind, "value": value, **extra, "count": 0, "first_seen": at,
                                      "last_seen": at, "sources": [], "refs": []}
        item["count"] += 1
        if at and (not item["first_seen"] or at < item["first_seen"]):
            item["first_seen"] = at
        if at and (not item["last_seen"] or at > item["last_seen"]):
            item["last_seen"] = at
        if source not in item["sources"]:
            item["sources"].append(source)
        if ref and ref not in item["refs"] and len(item["refs"]) < MAX_REFS:
            item["refs"].append(ref)

    def link(self, url, source, ref, at):
        url = strip(url.strip())
        if not url:
            return
        if not re.match(r"(?i)https?://", url):
            url = "http://" + url
        host = host_of(url)
        if not host:
            return
        if host in TELEGRAM_HOSTS:
            self.telegram_link(url, source, ref, at)
        self.note("url", url, source, ref, at)
        self.domain(host, source, ref, at)

    def domain(self, host, source, ref, at):
        host = host.rstrip(".").lower()
        if host in TELEGRAM_HOSTS:
            return
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            ascii_host = host
        extra = {"punycode": ascii_host} if ascii_host != host else {}
        self.note("domain", host, source, ref, at, **extra)

    def telegram_link(self, url, source, ref, at):
        path = [p for p in (urlsplit(url).path or "").split("/") if p]
        if not path:
            return
        if path[0].startswith("+") or path[0] == "joinchat":
            self.note("telegram-invite", url, source, ref, at)
        elif path[0] not in TELEGRAM_PATHS and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,31}", path[0]):
            self.note("telegram", "@" + path[0], source, ref, at)
        elif path[0] == "s" and len(path) > 1 and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,31}", path[1]):
            self.note("telegram", "@" + path[1], source, ref, at)

    def text(self, text, source, ref, at):
        if not isinstance(text, str) or not text:
            return
        taken = []
        for match in URL.finditer(text):
            self.link(match.group(0), source, ref, at)
            taken.append(match.span())
        for match in by_word(EMAIL, text):
            self.note("email", match.group(0).lower(), source, ref, at)
            self.domain(match.group(0).split("@", 1)[1], source, ref, at)
            taken.append(match.span())
        inside = lambda span: any(a <= span[0] and span[1] <= b for a, b in taken)
        for match in by_word(HOST, text):
            if inside(match.span()):
                continue
            host, path = match.group(1).lower(), match.group(2) or ""
            if host.rsplit(".", 1)[-1] in FILE_ENDINGS and not path:
                continue
            if host in TELEGRAM_HOSTS and path:
                self.telegram_link("https://" + host + strip(path), source, ref, at)
            self.domain(host, source, ref, at)
        for match in USERNAME.finditer(text):
            self.note("telegram", "@" + match.group(1), source, ref, at)
        for match in PHONE.finditer(text):
            digits = re.sub(r"\D", "", match.group(0))
            if 8 <= len(digits) <= 15:
                self.note("phone", "+" + digits, source, ref, at)
        self.wallets(text, source, ref, at)

    def wallets(self, text, source, ref, at):
        for match in BECH32_WORD.finditer(text):
            if bech32_valid(match.group(0)):
                address = match.group(0).lower()
                self.note("wallet", address, source, ref, at, chain=BECH32_CHAINS[address.split("1", 1)[0]],
                          checksum="valid")
        for match in BASE58_WORD.finditer(text):
            word = match.group(0)
            chain = base58check_chain(word) if len(word) <= 35 else None
            if chain:
                self.note("wallet", word, source, ref, at, chain=chain, checksum="valid")
            elif len(word) >= 32 and not word.startswith("T") and len(b58decode(word)) == 32 \
                    and re.search(r"\d", word) and re.search(r"[a-z]", word) and re.search(r"[A-Z]", word):
                self.note("wallet", word, source, ref, at, chain="Solana", checksum="none")
        for match in EVM.finditer(text):
            address = match.group(0)
            checksum = crypto_ids.evm_checksum(address)
            if checksum == "failed":
                continue
            self.note("wallet", address, source, ref, at, chain="EVM (Ethereum, BNB Chain, Polygon…)",
                      checksum=checksum, normalized=address.lower(),
                      chain_note="The same address exists on every EVM network; the chain follows from the context.")
        for match in TON.finditer(text):
            if ton_valid(match.group(0)):
                self.note("wallet", match.group(0), source, ref, at, chain="TON", checksum="valid",
                          normalized=crypto_ids.normalise(match.group(0), "TON"),
                          chain_note="One TON account has several spellings; the raw form identifies it.")
        for match in TON_RAW.finditer(text):
            self.note("wallet", match.group(0).lower(), source, ref, at, chain="TON", checksum="none",
                      normalized=crypto_ids.normalise(match.group(0), "TON"))
        for match in crypto_ids.XRP_WORD.finditer(text):
            if crypto_ids.xrp_valid(match.group(0)):
                self.note("wallet", match.group(0), source, ref, at, chain="XRP Ledger", checksum="valid",
                          chain_note="Exchange deposits on the XRP Ledger also need the destination tag.")
        for item in crypto_ids.transactions(text):
            self.note("transaction", item["value"], source, ref, at,
                      **{key: item[key] for key in ("chain", "form", "explorer", "note") if item.get(key)})
        for item in crypto_ids.payment_uris(text):
            self.note("payment-uri", item["uri"], source, ref, at,
                      **{key: item[key] for key in ("chain", "address", "amount", "token", "token_contract", "label")
                         if item.get(key)})
            if item.get("address") and len(item["address"]) >= 20:
                self.note("wallet", item["address"], source, ref, at, chain=item.get("chain"), checksum="from payment link",
                          chain_note="Taken from a payment link in the message.")

    def image(self, sha256, path, ref, at):
        dhash = image_hash(path)
        if dhash:
            self.note("image", sha256, "attachment", ref, at, dhash=dhash)

    def message(self, text, details, ref, at):
        self.text(text, "text", ref, at)
        details = details if isinstance(details, dict) else {}
        for entity in details.get("text_entities") or []:
            kind, shown = entity.get("type"), entity.get("text") or ""
            if kind == "text_link" and entity.get("href"):
                self.link(entity["href"], "hidden link", ref, at)
            elif kind == "phone":
                digits = re.sub(r"\D", "", shown)
                if 7 <= len(digits) <= 15:
                    self.note("phone", ("+" if shown.strip().startswith("+") else "") + digits, "text", ref, at)
            elif kind == "bank_card":
                continue
        for row in (details.get("buttons") or {}).get("rows") or []:
            for button in row:
                if isinstance(button, dict) and isinstance(button.get("url"), str):
                    self.link(button["url"], "button", ref, at)
        preview = (details.get("media_info") or {}).get("url")
        if isinstance(preview, str):
            self.link(preview, "link preview", ref, at)

    def result(self):
        items = sorted(self.found.values(), key=lambda i: (KINDS.index(i["kind"]), i["first_seen"] or "", i["value"]))
        return {"items": items, "total": len(items), "not_listed": self.dropped}


def csv_bytes(items):
    from .evidence import safe_cell
    out = io.StringIO(newline="")
    writer = csv.writer(out)
    columns = ("kind", "value", "defanged", "chain", "checksum", "dhash", "count", "first_seen", "last_seen", "sources",
               "messages")
    writer.writerow(columns)
    for item in items:
        row = {**item, "defanged": defang(item["kind"], item["value"]), "sources": "; ".join(item["sources"]),
               "messages": " ".join(ref_text(r) for r in item["refs"])}
        writer.writerow([safe_cell(row.get(c)) for c in columns])
    return b"\xef\xbb\xbf" + out.getvalue().encode("utf-8")


def ref_text(ref):
    text = "message " + str(ref.get("message")) if ref.get("message") is not None else ""
    if ref.get("chat") is not None:
        text = "chat " + str(ref["chat"]) + (":" + text if text else "")
    return text + (" (#" + str(ref["seq"]) + ")" if ref.get("seq") is not None else "")


def stix_value(value):
    return value.replace("\\", "\\\\").replace("'", "\\'")


def stix_pattern(item):
    value = stix_value(item["value"])
    if item["kind"] in ("url", "telegram-invite"):
        return "[url:value = '" + value + "']"
    if item["kind"] == "domain":
        return "[domain-name:value = '" + stix_value(item.get("punycode") or item["value"]) + "']"
    if item["kind"] == "email":
        return "[email-addr:value = '" + value + "']"
    if item["kind"] == "telegram":
        return "[user-account:account_type = 'telegram' AND user-account:account_login = '" + value[1:] + "']"
    if item["kind"] == "phone":
        return "[x-phone-number:value = '" + value + "']"
    if item["kind"] == "image":
        return "[file:hashes.'SHA-256' = '" + value + "']"
    return "[x-cryptocurrency-wallet:address = '" + value + "' AND x-cryptocurrency-wallet:chain = '" \
        + stix_value(item.get("chain") or "") + "']"


def item_id(item):
    return str(uuid.uuid5(NAMESPACE, item["kind"] + ":" + item["value"]))


def stix_time(value):
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    moment = moment.astimezone(timezone.utc) if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (moment.microsecond // 1000)


def stix_bundle(items, context):
    created, case = stix_time(context["created_at"]), context.get("case") or {}
    who = case.get("organization") or "TgWitness workspace " + context["fingerprint"][:16]
    identity = {"type": "identity", "spec_version": "2.1", "id": "identity--" + str(uuid.uuid5(NAMESPACE, who)),
                "created": created, "modified": created, "name": who, "identity_class": "organization"}
    indicators = [{"type": "indicator", "spec_version": "2.1", "id": "indicator--" + item_id(item), "created": created,
                   "modified": created, "created_by_ref": identity["id"],
                   "name": (item.get("chain") + " address " if item["kind"] == "wallet" else item["kind"] + " ") + item["value"],
                   "description": "Seen " + str(item["count"]) + " time(s) in Telegram messages recorded by TgWitness ("
                                  + ", ".join(item["sources"]) + "); first " + str(item["first_seen"]) + ", last "
                                  + str(item["last_seen"]) + "."
                                  + (" Perceptual hash (dHash, 64 bits): " + item["dhash"] + "." if item.get("dhash") else "")
                                  + " Not assessed: analyst review needed.",
                   "indicator_types": ["unknown"], "pattern": stix_pattern(item), "pattern_type": "stix",
                   "valid_from": stix_time(item["first_seen"]) or created} for item in items]
    objects = [identity] + indicators
    if indicators:
        report = {"type": "report", "spec_version": "2.1", "id": "report--" + context["report_id"], "created": created,
                  "modified": created, "created_by_ref": identity["id"],
                  "name": case.get("title") or "TgWitness indicators", "published": created,
                  "report_types": ["observed-data"], "object_refs": [i["id"] for i in indicators],
                  "description": "Indicators found in Telegram messages of a signed TgWitness export (report "
                                 + context["report_id"] + ", key " + context["fingerprint"] + ")."}
        if case.get("id"):
            report["external_references"] = [{"source_name": "case", "external_id": case["id"]}]
        objects.append(report)
    return {"type": "bundle", "id": "bundle--" + context["report_id"], "objects": objects}


MISP_TYPES = {"url": ("url", "Network activity"), "telegram-invite": ("url", "Social network"),
              "domain": ("domain", "Network activity"), "email": ("email", "Social network"),
              "phone": ("phone-number", "Person"), "telegram": ("text", "Social network"),
              "image": ("sha256", "External analysis")}


def misp_event(items, context):
    case = context.get("case") or {}
    attributes = []
    for item in items:
        if item["kind"] == "wallet":
            kind, category = ("btc" if item.get("chain") == "Bitcoin" else "text"), "Financial fraud"
        else:
            kind, category = MISP_TYPES[item["kind"]]
        value = item.get("punycode") or item["value"] if item["kind"] == "domain" else item["value"]
        attributes.append({"uuid": item_id(item), "type": kind, "category": category, "value": value, "to_ids": False,
                           "comment": ((item.get("chain") + " address; " if item["kind"] == "wallet" else "")
                                       + ("Telegram username; " if item["kind"] == "telegram" else "")
                                       + ("image, dHash " + item["dhash"] + "; " if item.get("dhash") else "")
                                       + "seen " + str(item["count"]) + " time(s): " + ", ".join(item["sources"])),
                           "first_seen": item["first_seen"], "last_seen": item["last_seen"]})
    info = (case.get("title") or "TgWitness indicators") + (" (" + case["id"] + ")" if case.get("id") else "")
    return {"Event": {"uuid": context["report_id"], "info": info, "date": context["created_at"][:10],
                      "threat_level_id": "4", "analysis": "0", "distribution": "0", "published": False,
                      "Attribute": attributes}}


def files(result, context):
    items = result["items"]
    if not items:
        return []
    dump = lambda value: (json.dumps(value, ensure_ascii=False, indent=1) + "\n").encode("utf-8")
    return [("indicators.csv", csv_bytes(items)), ("indicators.stix.json", dump(stix_bundle(items, context))),
            ("indicators.misp.json", dump(misp_event(items, context)))]
