import csv
import hashlib
import html
import io
import json
import tempfile
import zipfile
from pathlib import Path

from . import __version__
from . import tuning
from .store import ZERO, canonical, utcnow
from .verify import Coverage, fingerprint, verify_events, verify_checkpoint
from .security import private_write

LIMITS = [
    "This journal records observations made by a Telegram client, not Telegram-signed evidence.",
    "Observed time uses the collector's system clock; it is not a trusted timestamp.",
    "Messages deleted before collection and unobserved intermediate edits cannot be recovered.",
    "Deletion actors are generally unavailable. Unscoped deletions are not attributed to a chat.",
    "Reaction identities and membership changes are partial and depend on Telegram visibility.",
    "Backfill is a current history snapshot, not reconstruction of missed events.",
    "Signatures detect changes relative to a trusted key. Retain the fingerprint and checkpoints elsewhere.",
]


def producer():
    """Who made an export. Part of every signed manifest, so verify.py can show it as verified."""
    return {"software": "TgWitness", "version": __version__, "project": "PhishDestroy",
            "homepage": "https://phishdestroy.io", "source": "https://github.com/phishdestroy/TgWitness"}


def checkpoint(store, vault):
    head = store.stats()["head"]
    statement = {"format": "tgwitness-checkpoint-v1", "created_at": utcnow(),
                 "public_key": vault.public_key, "event_count": head["seq"] if head else 0,
                 "head_hash": head["hash"] if head else ZERO}
    return {"statement": statement, "signature": vault.sign(canonical(statement)),
            "fingerprint": fingerprint(vault.public_key)}


def retain_checkpoint(store, vault):
    value = checkpoint(store, vault)
    directory = store.root / "checkpoints"
    directory.mkdir(exist_ok=True, mode=0o700)
    data = canonical(value)
    numbered = directory / ("checkpoint-" + str(value["statement"]["event_count"]).zfill(12) + ".json")
    if not numbered.exists():
        private_write(numbered, data)
    private_write(directory / "latest.json", data)
    return value


def safe_cell(value):
    text = "" if value is None else str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def csv_bytes(events):
    return b"".join(csv_chunks(events))


def csv_chunks(events):
    def row(values):
        out = io.StringIO(newline="")
        csv.writer(out).writerow(values)
        return out.getvalue().encode("utf-8")
    yield b"\xef\xbb\xbf"
    yield row(["sequence", "observed_at_UTC", "source_at", "event", "chat_id",
               "message_id", "actor_id_if_visible", "content", "payload_json", "sha256"])
    for e in events:
        yield row([safe_cell(v) for v in (
            e["seq"], e["observed_at"], e["source_at"], e["kind"], e["chat_id"],
            e["message_id"], e["actor_id"], e["payload"].get("text", ""),
            canonical(e["payload"]).decode(), e["hash"])])


def html_bytes(events, coverage=None):
    return b"".join(html_chunks(events, coverage))


def coverage_html(coverage, escape):
    from .verify import coverage_lines
    rows = "".join("<li>" + escape(line) + "</li>" for line in coverage_lines(coverage))
    notes = ("<p>" + escape(coverage["notes_total"]) + " chat-level coverage note(s), listed as coverage events below.</p>"
             if coverage["notes_total"] else "")
    return ('<section class="coverage"><h2>Coverage</h2><ul>' + rows + "</ul>" + notes
            + "<p><small>" + escape(coverage["meaning"]) + "</small></p></section>")


def html_chunks(events, coverage=None):
    escape = lambda v: html.escape(str(v) if v is not None else "Unavailable")
    made = producer()
    yield ('<!doctype html><html lang="en"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width"><title>TgWitness · Observation report</title>'
            '<style>body{font:16px system-ui;max-width:1000px;margin:50px auto;padding:24px;'
            'background:#f6f7fa;color:#182434}article,section{background:white;padding:24px;margin:16px 0;'
            'border:1px solid #dce2e9;border-radius:12px}pre{white-space:pre-wrap;overflow-wrap:anywhere}'
            'small{overflow-wrap:anywhere}h2{font-size:18px}li{margin:8px 0}'
            '.brand{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;color:#475467;font-size:14px}'
            '.brand b{color:#182434}</style>'
            '<header class="brand"><span><b>' + escape(made["software"]) + '</b> ' + escape(made["version"])
            + ' · ' + escape(made["project"]) + '</span><span>' + escape(made["homepage"]) + ' · '
            + escape(made["source"]) + '</span></header>'
            '<h1>TgWitness / Observation report</h1><p>Readable derivative. Verify the signed ZIP for integrity; '
            'its signed manifest names the producer shown above.</p>'
            '<ul>' + "".join("<li>" + escape(x) + "</li>" for x in LIMITS) + "</ul>"
            + (coverage_html(coverage, escape) if coverage else "")).encode("utf-8")
    for e in events:
        yield ('<article><h2>#' + str(e["seq"]) + ' · ' + escape(e["kind"]) + '</h2>'
               '<p>Observed ' + escape(e["observed_at"]) + ' · Chat ' + escape(e["chat_id"])
               + ' · Message ' + escape(e["message_id"]) + '</p><pre>'
               + escape(json.dumps(e["payload"], ensure_ascii=False, indent=2))
               + '</pre><small>SHA-256 ' + e["hash"] + '</small></article>').encode("utf-8")
    yield b"</html>"


def export_file(store, vault, fmt):
    if fmt not in ("jsonl", "csv", "html", "zip"):
        raise ValueError("Unsupported export format")
    directory = store.root / "temporary-exports"
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.resolve().parent != store.root.resolve():
        raise ValueError("Temporary export directory must belong to this profile")
    temp = tempfile.NamedTemporaryFile(prefix="tgwitness-export-", suffix="." + fmt, dir=directory, delete=False)
    path = Path(temp.name)
    temp.close()
    try:
        retained = store.retained_checkpoint()
        with store.snapshot() as snapshot:
            observed = Coverage()

            def measured(events):
                for event in events:
                    observed.add(event)
                    yield event
            result = verify_events(measured(snapshot.events()), vault.public_key)
            if retained:
                verify_checkpoint(retained, vault.public_key, result["events"], snapshot.hash_at)
            coverage = observed.result()

            def chunks(format):
                events = snapshot.events()
                return {"jsonl": lambda: (canonical(e) + b"\n" for e in events),
                        "csv": lambda: csv_chunks(events), "html": lambda: html_chunks(events, coverage)}[format]()

            if fmt != "zip":
                with path.open("wb") as out:
                    for chunk in chunks(fmt):
                        out.write(chunk)
                return path

            hashes, total, limit = {}, 0, tuning.value(store, "export_max_gib") * 1024**3
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                def write_member(name, values):
                    nonlocal total
                    digest = hashlib.sha256()
                    with archive.open(name, "w", force_zip64=True) as outgoing:
                        for chunk in values:
                            total += len(chunk)
                            if total > limit - 4 * 1024**2:
                                raise ValueError("Bundle exceeds the uncompressed size limit set in Parameters")
                            outgoing.write(chunk)
                            digest.update(chunk)
                    hashes[name] = digest.hexdigest()
                    return digest.hexdigest()

                for format, name in (("jsonl", "events.jsonl"), ("csv", "events.csv"), ("html", "report.html")):
                    write_member(name, chunks(format))
                write_member("coverage.json", [json.dumps(coverage, ensure_ascii=False, indent=1).encode("utf-8")])
                write_member("verify.py", [Path(__file__).with_name("verify.py").read_bytes()])
                write_member("README.txt", [("\n".join(LIMITS) +
                    "\n\nUse a verifier from a trusted checkout, not solely from an untrusted ZIP.\n"
                    "Verify: python verify.py evidence.zip --fingerprint TRUSTED_SHA256\n"
                    "Require a witnessed export boundary: add --witness witness.zip\n"
                    "  --witness-fingerprint TRUSTED_WITNESS_SHA256 --require-witness\n"
                    "The witness must have retained the exact exported head. This verifies consistency\n"
                    "with its retained records, not the truth of the recorded messages.\n"
                    "Archives above 4 GiB uncompressed also need --max-gib with their size in GiB.\n"
                    "Requires Python 3.11+ and cryptography. CSV cells are formula-escaped.\n"
                    "events.jsonl is authoritative. Export is a stable journal prefix.\n"
                    "coverage.json lists continuous observation periods, gaps and message IDs that were\n"
                    "never observed (not evidence of deletion); verify.py recomputes it from events.jsonl.\n"
                    "Produced by TgWitness (PhishDestroy, https://phishdestroy.io); the producer is part of\n"
                    "the signed manifest.\n").encode()])
                for event in snapshot.events():
                    digest = event["payload"].get("media_sha256") if event["kind"] == "media.saved" else None
                    if not digest:
                        continue
                    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                        raise ValueError("Invalid attachment hash")
                    name = "media/" + digest
                    if name in hashes:
                        continue
                    source = store.root / "media" / digest
                    with source.open("rb") as incoming:
                        calculated = write_member(name, iter(lambda: incoming.read(1024 * 1024), b""))
                    if calculated != digest:
                        raise ValueError("Attachment changed: " + digest)

                anchors = store.root / "checkpoints" / "anchors"
                for proof in sorted(anchors.iterdir()) if anchors.is_dir() else []:
                    stem = proof.name.split(".", 1)[0]
                    source = store.root / "checkpoints" / (stem + ".json")
                    if not (stem.startswith("checkpoint-") and stem[11:].isdigit() and source.is_file()):
                        continue
                    if int(stem[11:]) > result["events"]:
                        continue
                    if "anchors/" + source.name not in hashes:
                        write_member("anchors/" + source.name, [source.read_bytes()])
                    write_member("anchors/" + proof.name, [proof.read_bytes()])
                manifest = {"format": "tgwitness-evidence-v1", "created_at": utcnow(),
                            "public_key": vault.public_key, "fingerprint": result["fingerprint"],
                            "event_count": result["events"], "head_hash": result["head_hash"],
                            "scope": "Complete stable journal prefix from sequence 1, including operational events",
                            "producer": producer(), "limitations": LIMITS, "files": hashes}
                manifest_bytes = canonical(manifest)
                if total + len(manifest_bytes) + 88 > limit:
                    raise ValueError("Manifest pushes bundle above the verification size limit")
                archive.writestr("manifest.json", manifest_bytes)
                archive.writestr("manifest.sig", vault.sign(manifest_bytes))
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def encrypt_export(path, fmt, password, inner_name=None):
    """Put a finished export, unchanged, into a WinZip AES-256 ZIP that 7-Zip and WinRAR open."""
    import pyzipper
    out = path.with_name(path.name + ".zip")
    try:
        with pyzipper.AESZipFile(out, "w", compression=pyzipper.ZIP_STORED if fmt == "zip" else pyzipper.ZIP_DEFLATED,
                                 encryption=pyzipper.WZ_AES) as archive:
            archive.setpassword(password.encode("utf-8"))
            archive.setencryption(pyzipper.WZ_AES, nbits=256)
            archive.write(path, inner_name or "tgwitness-evidence." + fmt)
        return out
    except BaseException:
        out.unlink(missing_ok=True)
        raise
    finally:
        path.unlink(missing_ok=True)


def cleanup_exports(root):
    """Called with the profile instance lock held; remove only our interrupted temporary exports."""
    directory = root / "temporary-exports"
    if directory.is_symlink() or not directory.is_dir() or directory.resolve().parent != root.resolve():
        return
    for item in directory.glob("tgwitness-export-*"):
        if item.is_file() and not item.is_symlink() and item.suffix in (".zip", ".jsonl", ".csv", ".html", ".json"):
            item.unlink()
