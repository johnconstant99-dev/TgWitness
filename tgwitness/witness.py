import argparse
import asyncio
import base64
import hashlib
import json
import os
import re
import secrets
import signal
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import __version__, verification_kit
from . import continuity
from .anchoring import DEFAULT_OTS, ots_stamp, service_name, upgrade_pending_ots
from .evidence import producer
from .netclient import HTTPError, RouteError, request
from .network import NetworkConfig
from .security import InstanceLock, private_write
from .store import Store, canonical, utcnow
from .verify import fingerprint, is_format, post_statement, post_token, verify_events, verify_capture
from .verify import verify_continuity
from .verify import DRAND_CHAIN, DRAND_RELAYS, DRAND_GENESIS, DRAND_PERIOD, drand_beacon, witness_challenge
from .verify import daily_payload

DEFAULT_INTERVAL = 10
TIMEOUT = 30
TITLE = "TgWitness witness"
POST_POLICIES = ("all", "changes", "problems")


def utc_date():
    return datetime.now(timezone.utc).date()

TEXTS = {"ok": "journal head", "key_changed": "COLLECTOR KEY CHANGED", "rollback": "JOURNAL GOT SHORTER",
         "fork": "SAME LENGTH, DIFFERENT HEAD", "invalid": "ANSWER FAILED VERIFICATION",
         "no_response": "no answer from the collector", "collector": "Collector", "records": "records",
         "head": "Head"}
OPTIONS = ("collector", "token", "token_file", "bot_token", "bot_token_file", "channel", "interval", "timeout",
           "post", "title", "texts", "collector_fingerprint", "proxy", "bot_api", "data_dir",
           "discord_webhook", "discord_webhook_file")


def key_cipher(root):
    external = os.environ.get("TGWITNESS_VAULT_KEY_FILE")
    if external:
        source = Path(external).resolve(strict=True)
        if source.is_relative_to(Path(root).resolve()) or source.stat().st_size > 128:
            raise RuntimeError("Provide a small master-key file outside the witness data directory.")
        master = source.read_bytes().strip()
        Fernet(master)
        derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                       info=b"TgWitness witness key v1").derive(base64.urlsafe_b64decode(master))
        return Fernet(base64.urlsafe_b64encode(derived))
    path = Path(root) / "witness-vault.key"
    if not path.exists():
        if (Path(root) / "witness-key.enc").exists():
            raise RuntimeError("The witness key file is sealed with a key that is missing here. Restore "
                               "witness-vault.key or set TGWITNESS_VAULT_KEY_FILE; a new key is never made over it.")
        private_write(path, Fernet.generate_key())
    return Fernet(path.read_bytes())


class WitnessKey:
    def __init__(self, root):
        root = Path(root)
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        sealed, plain = root / "witness-key.enc", root / "witness-key.json"
        cipher = key_cipher(root)
        if plain.exists():
            original = plain.read_bytes()
            if not sealed.exists():
                private_write(sealed, cipher.encrypt(original))
            elif original.strip(b"\0"):
                try:
                    same = json.loads(cipher.decrypt(sealed.read_bytes()))["private_key"] == json.loads(original)["private_key"]
                except (InvalidToken, ValueError, KeyError, TypeError):
                    same = False
                if not same:
                    raise RuntimeError("witness-key.json and witness-key.enc do not hold the same witness key. Move the "
                                       "file you do not intend to keep out of the data directory, then start again.")
            plain.write_bytes(b"\0" * len(original))
            plain.unlink()
        if not sealed.exists():
            key = Ed25519PrivateKey.generate()
            private_write(sealed, cipher.encrypt(json.dumps({"format": "tgwitness-witness-key-v1", "private_key":
                base64.b64encode(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                   serialization.NoEncryption())).decode()}).encode()))
        try:
            data = json.loads(cipher.decrypt(sealed.read_bytes()))
        except InvalidToken:
            raise RuntimeError("The witness key cannot be opened with this key; restore the original key file") from None
        self.signer = Ed25519PrivateKey.from_private_bytes(base64.b64decode(data["private_key"]))
        self.public_key = base64.b64encode(self.signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

    def sign(self, value: bytes):
        return base64.b64encode(self.signer.sign(value)).decode()


class InvalidAnswer(ValueError):
    pass


async def drand_latest(network):
    """Get a structurally valid beacon over TLS; independent verification is separate."""
    for relay in DRAND_RELAYS:
        try:
            _, _, body = await request("GET", relay + "/" + DRAND_CHAIN + "/public/latest", network,
                                       {"Accept": "application/json"}, timeout=5, limit=4096)
            beacon = drand_beacon(json.loads(body))
            if DRAND_GENESIS + (beacon["round"] - 1) * DRAND_PERIOD > time.time() + 60:
                continue
            return beacon
        except Exception:
            continue
    return None


def proxy_config(url):
    if not url:
        return NetworkConfig(kind="direct")
    try:
        if not isinstance(url, str) or len(url) > 2048:
            raise ValueError
        parts = urlsplit(url)
        kind = {"socks5": "socks5", "socks5h": "socks5", "http": "http"}.get(parts.scheme)
        port = parts.port if parts.port is not None else (80 if kind == "http" else None)
        if (not kind or not parts.hostname or not port or parts.query or parts.fragment
                or parts.path not in ("", "/")):
            raise ValueError
        return NetworkConfig(kind=kind, host=parts.hostname, port=port, username=unquote(parts.username or ""),
                             password=unquote(parts.password or ""))
    except (TypeError, ValueError):
        raise ValueError("Use a proxy address like socks5://host:1080 or http://host:3128.") from None


def http_address(value):
    try:
        if not isinstance(value, str):
            raise ValueError
        parts = urlsplit(value)
        if (not isinstance(value, str) or not value or len(value) > 2048 or any(c.isspace() for c in value)
                or parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password
                or parts.query or parts.fragment or (parts.port is not None and parts.port < 1)):
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("Use HTTP(S) addresses without credentials, query or fragment.") from None
    return value.rstrip("/")


def describe(exc):
    if isinstance(exc, HTTPError):
        try:
            detail = json.loads(exc.body).get("description") or json.loads(exc.body).get("detail")
        except (ValueError, AttributeError):
            detail = None
        return "HTTP " + str(exc.status) + (": " + str(detail)[:160] if detail else "")
    if isinstance(exc, (InvalidAnswer, RouteError)):
        return str(exc)[:200]
    return type(exc).__name__


class Witness:
    def __init__(self, root, collector, token, channel=None, bot_token=None, interval=DEFAULT_INTERVAL,
                 pinned=None, network=None, bot_api="https://api.telegram.org", fetch=None, send=None,
                 timeout=TIMEOUT, post="all", title=TITLE, texts=None, discord_webhook=None):
        if post not in POST_POLICIES:
            raise ValueError("--post must be one of: " + ", ".join(POST_POLICIES) + ".")
        unknown = set(texts or {}) - set(TEXTS)
        if unknown or not all(isinstance(v, str) and v.strip() for v in (texts or {}).values()):
            raise ValueError("Post texts must be words for: " + ", ".join(TEXTS) + ".")
        root = Path(root)
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = InstanceLock(root)
        try:
            self.key = WitnessKey(root)
            self.store = Store(root)
            self.store.bind(self.key)
        except BaseException:
            self.lock.close()
            raise
        self.fingerprint = fingerprint(self.key.public_key)
        self.collector, self.token = collector.rstrip("/"), token
        self.channel, self.bot_token, self.bot_api = channel, bot_token, bot_api.rstrip("/")
        if discord_webhook and (not isinstance(discord_webhook, str) or len(discord_webhook) > 2048
                                or not re.fullmatch(r"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", discord_webhook)):
            self.close()
            raise ValueError("Use a Discord channel webhook from Channel Settings → Integrations.")
        if discord_webhook and channel:
            self.close()
            raise ValueError("Choose one witness publisher: a Telegram channel or a Discord webhook.")
        self.discord_webhook = discord_webhook
        if discord_webhook:
            self.channel = "Discord webhook"
        self.interval, self.timeout = interval, timeout
        self.post, self.title, self.texts = post, title, {**TEXTS, **(texts or {})}
        self.network = network or NetworkConfig(kind="direct")
        if pinned and self.store.get_setting("collector_fingerprint") not in (None, pinned):
            self.close()
            raise ValueError("This witness already follows another collector key. Use a new data directory.")
        if pinned:
            self.store.set_setting("collector_fingerprint", pinned)
        self.pinned = pinned or self.store.get_setting("collector_fingerprint")
        self.fetch = fetch or self.http_fetch
        self.send = send if send is not None else (self.discord_send if discord_webhook else self.bot_send if channel and bot_token else None)
        self.host = urlsplit(self.collector).hostname
        self._freshness = None

    def close(self):
        self.store.close()
        self.lock.close()

    async def http_fetch(self):
        self._freshness = None
        nonce = secrets.token_hex(16)
        try:
            beacon = await asyncio.wait_for(drand_latest(self.network), 5)
        except TimeoutError:
            beacon = None
        if beacon is not None:
            # The signature is indispensable: randomness is its one-way hash.
            self._freshness = {"drand_round": beacon["round"], "drand_randomness": beacon["randomness"],
                               "drand_signature": beacon["signature"], "nonce": nonce}
        challenge = witness_challenge(self._freshness) if self._freshness else nonce
        previous = self.store.get_setting("last_seen") or {"event_count": 0}
        _, _, data = await request("GET", self.collector + "/api/witness/head", self.network, {
            "Authorization": "Bearer " + self.token, "Accept": "application/json",
            "X-TgWitness-Witness": self.fingerprint, "X-TgWitness-Interval": str(self.interval),
            "X-TgWitness-Challenge": challenge,
            "X-TgWitness-Consistency-From": str(previous["event_count"])},
            timeout=self.timeout, limit=64 * 1024, private=True)
        answer = json.loads(data)
        capture = answer.get("capture") if isinstance(answer, dict) else None
        statement = capture.get("statement") if isinstance(capture, dict) else None
        if not isinstance(statement, dict):
            raise InvalidAnswer("collector did not provide a signed freshness proof; update the collector")
        if statement.get("challenge") != challenge:
            raise InvalidAnswer("capture answer did not echo this check's challenge")
        if not isinstance(answer.get("continuity"), dict):
            raise InvalidAnswer("collector did not provide a journal continuity proof; update the collector")
        return answer

    async def bot_send(self, text):
        body = json.dumps({"chat_id": self.channel, "text": text, "disable_web_page_preview": True}).encode()
        _, _, data = await request("POST", self.bot_api + "/bot" + self.bot_token + "/sendMessage", self.network,
                                   {"Content-Type": "application/json"}, body, timeout=self.timeout, limit=256 * 1024,
                                   private=True)
        answer = json.loads(data)
        if not answer.get("ok"):
            raise InvalidAnswer(answer.get("description") or "The Bot API refused the message.")
        return answer["result"]["message_id"]

    async def discord_send(self, text):
        payload = {"content": text if len(text) <= 2000 else "TgWitness witness · full signed check attached.",
                   "allowed_mentions": {"parse": []}}
        headers = {"Content-Type": "application/json"}
        body = json.dumps(payload).encode()
        if len(text) > 2000:
            boundary = "tgwitness-" + secrets.token_hex(16)
            headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
            body = (f'--{boundary}\r\nContent-Disposition: form-data; name="payload_json"\r\n'
                    'Content-Type: application/json\r\n\r\n').encode() + json.dumps(payload).encode()
            body += (f'\r\n--{boundary}\r\nContent-Disposition: form-data; name="files[0]"; '
                     'filename="witness-check.txt"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n').encode()
            body += text.encode() + f'\r\n--{boundary}--\r\n'.encode()
        _, _, answer = await request("POST", self.discord_webhook + "?wait=true", self.network, headers, body,
                                    timeout=self.timeout, limit=256 * 1024)
        return json.loads(answer)["id"]

    def check(self, answer):
        try:
            value = answer["checkpoint"]
            statement = value["statement"]
            if not is_format(statement["format"], "checkpoint-v1"):
                raise InvalidAnswer("not a TgWitness checkpoint")
            Ed25519PublicKey.from_public_bytes(base64.b64decode(statement["public_key"], validate=True)).verify(
                base64.b64decode(value["signature"], validate=True), canonical(statement))
            count, head = statement["event_count"], statement["head_hash"]
            if (type(count) is not int or count < 0 or not isinstance(head, str)
                    or re.fullmatch(r"[0-9a-f]{64}", head) is None
                    or (count == 0) != (head == "0" * 64)):
                raise InvalidAnswer("malformed record count or head hash")
        except InvalidAnswer:
            raise
        except Exception as exc:
            raise InvalidAnswer("answer failed verification: " + type(exc).__name__) from None
        key = fingerprint(statement["public_key"])
        last = self.store.get_setting("last_seen")
        status = "ok"
        if self.pinned is not None and key != self.pinned:
            status = "key_changed"
        elif last and count < last["event_count"]:
            status = "rollback"
        elif last and count == last["event_count"] and head != last["head_hash"]:
            status = "fork"
        capture, delta = answer.get("capture"), None
        if capture is not None:
            try:
                captured = verify_capture(capture, statement)
                previous = self.store.get_setting("last_capture_counts")
                if status == "ok" and previous is not None:
                    delta = {kind: n - previous[kind] for kind, n in captured["counts"].items()}
                    if any(n < 0 for n in delta.values()):
                        raise ValueError("capture counters decreased in a growing journal")
            except Exception as exc:
                raise InvalidAnswer("capture proof failed verification: " + type(exc).__name__) from None
        keys = captured.get("keys") if capture is not None else None
        accepted = status == "ok"
        if accepted and last and last.get("keys") is not None and keys != last["keys"]:
            status, accepted = "key_changed", keys is not None
        continuity = answer.get("continuity")
        tree = self.store.get_setting("last_tree")
        committed = None
        if accepted:
            if tree is not None and (last is None or any(tree[k] != last[k] for k in ("event_count", "head_hash"))):
                raise InvalidAnswer("retained journal and tree boundaries differ")
            if tree is not None and continuity is None:
                raise InvalidAnswer("collector removed the required journal continuity proof")
            if continuity is not None:
                try:
                    if capture is None:
                        raise ValueError("continuity requires a fresh capture proof")
                    previous = {**last, **({"root": tree["root"]} if tree else {})} if last else None
                    committed = verify_continuity(continuity, statement, previous, captured["challenge"])
                except Exception as exc:
                    raise InvalidAnswer("journal continuity failed verification: " + type(exc).__name__) from None
        if accepted:
            if self.pinned is None:
                self.pinned = key
                self.store.set_setting("collector_fingerprint", key)
            self.store.set_setting("last_seen", {"event_count": count, "head_hash": head, "keys": keys})
            self.store.set_setting("last_capture_counts", captured["counts"] if capture is not None else None)
            if committed is not None:
                self.store.set_setting("last_tree", {"root": committed["root"], "event_count": count, "head_hash": head})
        payload = {"status": status, "collector": self.host, "collector_fingerprint": key,
                "pinned_fingerprint": self.pinned, "event_count": count, "head_hash": head,
                "checkpoint_created_at": statement.get("created_at"),
                "checkpoint_sha256": hashlib.sha256(canonical(value)).hexdigest(), "freshness": self._freshness}
        if capture is not None:
            payload.update(checkpoint={"statement": statement, "signature": value["signature"], "fingerprint": key},
                           capture=capture, capture_delta=delta)
            if keys is not None:
                payload["keys"] = keys
        if accepted and status == "key_changed":
            payload["previous_keys"] = last["keys"]
        if committed is not None:
            payload.update(continuity=continuity, continuity_status="extended" if tree is not None else "baseline")
        return payload

    def post_text(self, event):
        statement = post_statement(event, self.fingerprint)
        token = post_token(statement, self.key.sign(canonical(statement)))
        payload, words, title = event["payload"], self.texts, self.title + " #" + str(event["seq"])
        if event["kind"] == "witness.daily":
            lines = [title + " · daily seal " + payload["date"],
                     "Witness records " + str(payload["from_seq"]) + ".." + str(payload["to_seq"]),
                     "Merkle root " + payload["root"], "Checks " + json.dumps(payload["checks"], sort_keys=True),
                     "External timestamp verification is separate."]
        elif event["kind"] == "witness.no_response":
            lines = [title + ": " + words["no_response"], event["observed_at"] + " · " + str(payload.get("error"))]
        elif payload.get("status") == "invalid":
            lines = [title + ": " + words["invalid"], event["observed_at"] + " · " + str(payload.get("error"))]
        else:
            lines = [title + " · " + words[payload["status"]],
                     words["collector"] + " " + payload["collector_fingerprint"][:16] + ": "
                     + str(payload["event_count"]) + " " + words["records"],
                     words["head"] + " " + payload["head_hash"], event["observed_at"]]
            if payload.get("capture"):
                capture = payload["capture"]["statement"]
                counts, delta = capture["counts"], payload.get("capture_delta")
                lines.append("Captured: " + str(counts["message.new"]) + " new / "
                             + str(counts["message.edited"]) + " edits / " + str(counts["message.deleted"]) + " deletion notices")
                if delta is not None:
                    lines.append("Since previous valid check: +" + str(delta["message.new"]) + " new / +"
                                 + str(delta["message.edited"]) + " edits / +" + str(delta["message.deleted"]) + " deletion notices")
                lines.append("Last captured message event: " + str(capture.get("last_message_at") or "none"))
        return "\n".join(lines + [token])

    def worth_posting(self, event):
        problem = event["kind"] == "witness.no_response" or event["payload"].get("status") != "ok"
        if self.post == "all" or problem:
            return True
        if self.post == "problems":
            return False
        head = event["payload"].get("head_hash")
        if head == self.store.get_setting("last_posted_head"):
            return False
        return True

    async def tick(self):
        self._freshness = None
        try:
            answer = await asyncio.wait_for(self.fetch(), self.timeout + 5)
            with self.store.transaction():
                event = self.store.append("witness.anchor", self.check(answer))
        except InvalidAnswer as exc:
            self.pinned = self.store.get_setting("collector_fingerprint")
            event = self.store.append("witness.anchor", {"status": "invalid", "collector": self.host,
                                                         "collector_fingerprint": None, "error": describe(exc)})
        except Exception as exc:
            self.pinned = self.store.get_setting("collector_fingerprint")
            event = self.store.append("witness.no_response", {"collector": self.host, "error": describe(exc)})
        if self.send and self.worth_posting(event):
            try:
                message_id = await asyncio.wait_for(self.send(self.post_text(event)), self.timeout + 5)
                self.store.append("witness.posted", {"record": event["seq"], "channel": self.channel,
                                                     "message_id": message_id})
                if event["payload"].get("status") == "ok":
                    self.store.set_setting("last_posted_head", event["payload"]["head_hash"])
            except Exception as exc:
                self.store.append("witness.post_failed", {"record": event["seq"], "channel": self.channel,
                                                          "error": describe(exc)})
        return event

    async def daily(self):
        date = (utc_date() - timedelta(days=1)).isoformat()
        # The journal, rather than a mutable setting, is authoritative after a crash.
        with self.store.snapshot() as snapshot:
            events = list(snapshot.events())
        existing = [e for e in events if e["kind"] == "witness.daily" and e["payload"].get("date") == date]
        if existing:
            event = existing[-1]
            if any(e["kind"] == "witness.anchored" and e["payload"].get("record") == event["seq"] for e in events):
                self.store.set_setting("last_daily_date", date)
                return event
        else:
            payload = daily_payload(events, date)
            payload["root"] = continuity.Tree(self.store.db).root(0, payload["to_seq"]).hex()
            event = self.store.append("witness.daily", payload)
        await self.stamp_daily(event)
        self.store.set_setting("last_daily_date", date)
        if self.send:
            try:
                message_id = await asyncio.wait_for(self.send(self.post_text(event)), self.timeout + 5)
                self.store.append("witness.posted", {"record": event["seq"], "channel": self.channel, "message_id": message_id})
            except Exception as exc:
                self.store.append("witness.post_failed", {"record": event["seq"], "error": describe(exc)})
        return event

    async def stamp_daily(self, event):
        date = event['payload']['date']
        if not isinstance(date, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', date):
            raise ValueError('Invalid retained daily seal date')
        datetime.strptime(date, '%Y-%m-%d')
        folder, name = self.store.root / 'anchors', 'daily-' + date
        folder.mkdir(exist_ok=True, mode=0o700)
        raw = canonical(event)
        private_write(folder / (name + '.json'), raw)
        results = await ots_stamp(hashlib.sha256(raw).digest(), DEFAULT_OTS, folder, name, self.network)
        self.store.append('witness.anchored', {'record': event['seq'], 'results': results})
        return results

    async def retry_daily_ots(self):
        """Retry seals with no retained submission, including after restarts and date changes."""
        cursor = self.store.get_setting('witness_daily_retry_cursor', 0)
        with self.store.lock:
            rows = self.store.db.execute("SELECT * FROM events WHERE kind='witness.daily' AND seq>? ORDER BY seq LIMIT 32",
                                         (cursor,)).fetchall()
            if not rows:
                rows = self.store.db.execute("SELECT * FROM events WHERE kind='witness.daily' ORDER BY seq LIMIT 32").fetchall()
        deadline, attempts = time.monotonic() + 60, []
        for row in rows:
            event = self.store.decode(row)
            name = 'daily-' + str(event['payload']['date'])
            # Existing submissions are handled by upgrade_pending_ots. Their existence is not a verdict.
            if any((self.store.root / 'anchors' / (name + '.' + service_name(url) + '.ots')).is_file()
                   for url in DEFAULT_OTS):
                cursor = event['seq']
                continue
            if len(attempts) >= 2 or time.monotonic() >= deadline:
                break
            try:
                async with asyncio.timeout(max(0.1, deadline - time.monotonic())):
                    results = await self.stamp_daily(event)
            except TimeoutError:
                results = [{'kind': 'opentimestamps', 'ok': False, 'error': 'retry deadline exceeded'}]
                self.store.append('witness.anchored', {'record': event['seq'], 'results': results})
            attempts.append({'record': event['seq'], 'results': results})
            cursor = event['seq']
        self.store.set_setting('witness_daily_retry_cursor', cursor)
        return attempts

    async def run(self, ticks=None):
        self.store.append("witness.started", {
            "collector": self.host, "channel": self.channel, "interval_minutes": self.interval,
            "witness_fingerprint": self.fingerprint, "pinned_fingerprint": self.pinned, "version": __version__,
            "posting": bool(self.send), "post_policy": self.post if self.send else None,
            "timeout_seconds": self.timeout,
            "access": "read-only witness token; no collector session, vault or panel token"})
        done = 0
        try:
            while ticks is None or done < ticks:
                started = time.monotonic()
                await self.tick()
                try:
                    if self.store.get_setting("last_daily_date") != (utc_date() - timedelta(days=1)).isoformat():
                        await self.daily()
                except Exception as exc:
                    self.store.append("witness.upkeep_failed", {"step": "daily seal", "error": describe(exc)})
                last_upgrade = self.store.get_setting("witness_ots_upgrade_at", 0)
                if time.time() - last_upgrade >= 3600:
                    try:
                        await self.retry_daily_ots()
                        await upgrade_pending_ots(self.store, self.network, {"ots_calendars": DEFAULT_OTS},
                                                  folder=self.store.root / "anchors")
                    except Exception as exc:
                        self.store.append("witness.upkeep_failed", {"step": "timestamp upkeep", "error": describe(exc)})
                    self.store.set_setting("witness_ots_upgrade_at", time.time())
                done += 1
                if ticks is None or done < ticks:
                    await asyncio.sleep(max(1.0, self.interval * 60 - (time.monotonic() - started)))
        finally:
            self.store.append("witness.stopped", {"reason": "process stopping"})


def export(root, out):
    root, out = Path(root), Path(out)
    key = WitnessKey(root)
    store = Store(root)
    try:
        with store.snapshot() as snapshot:
            events = list(snapshot.events())
        collector = store.get_setting("collector_fingerprint")
    finally:
        store.close()
    result = verify_events(events, key.public_key)
    started = [e for e in events if e["kind"] == "witness.started"]
    data = b"".join(canonical(e) + b"\n" for e in events)
    verifier = Path(__file__).with_name("verify.py").read_bytes()
    readme = ("TgWitness independent witness journal.\n\n"
              "events.jsonl: the witness's own hash-chained, Ed25519-signed records: each journal head it\n"
              "fetched from the collector (record count and head hash), answers that failed, and posts.\n"
              "Check it against a collector evidence export and the channel posts:\n"
              "  python verify.py tgwitness-evidence.zip --witness witness.zip --witness-fingerprint WITNESS_SHA256 \\\n"
              "      --channel result.json\n"
              "Witness times come from the witness computer's clock; Telegram post dates in the channel are an\n"
              "independent clock. A witness shows what the collector reported at those times, not message truth.\n"
              "Produced by TgWitness (PhishDestroy, https://phishdestroy.io).\n").encode()
    files = {"events.jsonl": data, "verify.py": verifier, **verification_kit.files(),
             "README.txt": verification_kit.quickstart() + b"\n" + readme}
    for path in sorted((root / "anchors").glob("daily-*")):
        if path.is_file() and not path.is_symlink() and path.suffix in (".ots", ".json"):
            files["anchors/" + path.name] = path.read_bytes()
    manifest = {"format": "tgwitness-witness-v1", "created_at": utcnow(), "public_key": key.public_key,
                "fingerprint": result["fingerprint"], "event_count": result["events"], "head_hash": result["head_hash"],
                "collector_fingerprint": collector, "channel": started[-1]["payload"].get("channel") if started else None,
                "producer": producer(), "files": {name: hashlib.sha256(body).hexdigest() for name, body in files.items()}}
    manifest_bytes = canonical(manifest)
    temporary = out.with_name(out.name + ".tmp")
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, body in files.items():
            archive.writestr(name, body)
        archive.writestr("manifest.json", manifest_bytes)
        archive.writestr("manifest.sig", key.sign(manifest_bytes))
    os.replace(temporary, out)
    return {"events": result["events"], "fingerprint": result["fingerprint"], "out": str(out)}


def load_config(path):
    if not path:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("The config file must hold a JSON object.")
    unknown = set(data) - set(OPTIONS)
    if unknown:
        raise ValueError("Unknown config options: " + ", ".join(sorted(unknown)) + ". Known: " + ", ".join(OPTIONS) + ".")
    return data


def resolve(args, config):
    env_names = {"data_dir": "DATA"}
    defaults = {"interval": DEFAULT_INTERVAL, "timeout": TIMEOUT, "post": "all", "title": TITLE,
                "bot_api": "https://api.telegram.org", "data_dir": "witness-data"}
    config_path = getattr(args, "config", None) or os.environ.get("TGWITNESS_WITNESS_CONFIG")

    def file_path(name, value):


        env = os.environ.get("TGWITNESS_WITNESS_" + env_names.get(name, name.upper()))
        base = Path(config_path).resolve().parent if config_path and getattr(args, name, None) is None and not env else Path.cwd()
        return base / value

    def pick(name):
        given = getattr(args, name, None)
        if given is not None:
            return given
        env = os.environ.get("TGWITNESS_WITNESS_" + env_names.get(name, name.upper()))
        if env:
            return env
        return config.get(name, defaults.get(name))

    def secret(name):
        value, path = pick(name), pick(name + "_file")
        if value:
            return str(value).strip()
        return file_path(name + "_file", path).read_text(encoding="utf-8").strip() if path else None

    options = {name: pick(name) for name in OPTIONS if name not in ("token", "token_file", "bot_token",
                                  "bot_token_file", "discord_webhook", "discord_webhook_file", "texts")}
    options.update(token=secret("token"), bot_token=secret("bot_token"), discord_webhook=secret("discord_webhook"),
                   texts=config.get("texts") or {})
    for name in ("interval", "timeout"):
        try:
            options[name] = int(options[name])
        except (TypeError, ValueError):
            raise ValueError("--" + name + " must be a whole number.") from None
    if not isinstance(options["texts"], dict):
        raise ValueError('"texts" in the config file must be an object of words.')
    options["data_dir"] = file_path("data_dir", options["data_dir"])
    return options


def main():
    parser = argparse.ArgumentParser(description="TgWitness independent witness")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "export", "fingerprint"):
        command = commands.add_parser(name)
        command.add_argument("--data-dir", type=Path)
        command.add_argument("--config", help="JSON file with any of the run options (see the module help)")
    run = commands.choices["run"]
    run.add_argument("--collector", help="Collector address, e.g. https://collector.example.org")
    run.add_argument("--token", help="Witness token (prefer --token-file or TGWITNESS_WITNESS_TOKEN)")
    run.add_argument("--token-file")
    run.add_argument("--bot-token", help="Telegram bot token (prefer --bot-token-file)")
    run.add_argument("--bot-token-file")
    run.add_argument("--discord-webhook-file", help="File containing your Discord channel webhook URL")
    run.add_argument("--discord-webhook", help="Discord webhook (prefer --discord-webhook-file)")
    run.add_argument("--channel", help="@channel or numeric chat ID the bot posts to")
    run.add_argument("--interval", type=int, help="Minutes between checks (default 10)")
    run.add_argument("--timeout", type=int, help="Seconds to wait for the collector and the Bot API (default 30)")
    run.add_argument("--post", choices=POST_POLICIES,
                     help="all: post every check (default); changes: only a new head or a problem; problems: only problems")
    run.add_argument("--title", help='First words of every channel post (default "TgWitness witness")')
    run.add_argument("--collector-fingerprint", help="Collector key fingerprint to pin instead of trusting the first answer")
    run.add_argument("--proxy", help="socks5://host:port or http://host:port")
    run.add_argument("--bot-api", help="Bot API address (default https://api.telegram.org)")
    run.add_argument("--check-config", action="store_true", help="Validate config and token files without network access or creating witness keys")
    commands.choices["export"].add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        options = resolve(args, load_config(args.config or os.environ.get("TGWITNESS_WITNESS_CONFIG")))
        if args.command == "fingerprint":
            print(fingerprint(WitnessKey(options["data_dir"]).public_key))
            return
        if args.command == "export":
            print(json.dumps(export(options["data_dir"], args.out), indent=2))
            return
        if not options["collector"] or not options["token"]:
            parser.error("--collector and a witness token are required (see the panel's Witness page).")
        if not 1 <= options["interval"] <= 1440:
            parser.error("--interval must be 1-1440 minutes.")
        if not 5 <= options["timeout"] <= 600:
            parser.error("--timeout must be 5-600 seconds.")
        if bool(options["channel"]) != bool(options["bot_token"]):
            parser.error("Posting needs both --channel and a bot token; give both or neither.")
        if options["discord_webhook"] and options["channel"]:
            parser.error("Choose either a Discord webhook or a Telegram bot for this witness.")
        options["collector"] = http_address(options["collector"])
        options["bot_api"] = http_address(options["bot_api"])
        if options["collector_fingerprint"] and not re.fullmatch(r"[0-9a-f]{64}", options["collector_fingerprint"]):
            parser.error("Pin the collector's 64-character lowercase hexadecimal fingerprint.")
        if options["channel"] and not re.fullmatch(r"@[A-Za-z0-9_]{5,32}|-?\d{1,20}", options["channel"]):
            parser.error("Use a Telegram @channel or numeric chat ID.")
        if options["post"] not in POST_POLICIES:
            parser.error("--post must be one of: " + ", ".join(POST_POLICIES))
        if (set(options["texts"]) - set(TEXTS) or
                not all(isinstance(v, str) and v.strip() for v in options["texts"].values())):
            parser.error("Post texts must be nonempty strings for known message labels.")
        network = proxy_config(options["proxy"])
        if args.check_config:
            print(json.dumps({"valid": True, "key_pinned": bool(options["collector_fingerprint"]),
                              "posting": bool(options["channel"] or options["discord_webhook"]), "interval_minutes": options["interval"],
                              "post_policy": options["post"], "route": network.kind,
                              "network_checked": False}))
            return
        parts = urlsplit(options["collector"])
        if parts.scheme == "http" and "." in parts.hostname and parts.hostname not in ("127.0.0.1",):
            print("Warning: the collector address is plain HTTP; use HTTPS outside a private network.")
        witness = Witness(options["data_dir"], options["collector"], options["token"], options["channel"],
                          options["bot_token"], options["interval"], options["collector_fingerprint"],
                          network, options["bot_api"], timeout=options["timeout"],
                          post=options["post"], title=options["title"], texts=options["texts"], discord_webhook=options["discord_webhook"])
    except (ValueError, RuntimeError, OSError) as exc:
        parser.exit(1, str(exc) + "\n")
    print("TgWitness witness", __version__, flush=True)
    print("Witness key fingerprint:", witness.fingerprint, "(keep a copy elsewhere)", flush=True)
    print("Collector:", witness.host, "- every", options["interval"], "min -",
          ("posting to " + witness.channel + " (" + options["post"] + ")") if witness.send
          else "not posting (no channel configured)", flush=True)

    async def serve():
        task = asyncio.current_task()
        try:
            asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, task.cancel)
        except (NotImplementedError, RuntimeError, AttributeError):
            pass
        try:
            await witness.run()
        except asyncio.CancelledError:
            pass
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
    finally:
        witness.close()


if __name__ == "__main__":
    main()
