import csv
import hashlib
import io
import json
import tempfile
import uuid
import zipfile
from pathlib import Path

from . import __version__
from . import report
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


README = (
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
    "report.html is a readable derivative sealed with the same key; custody.json records how\n"
    "the material was acquired and exported; SHA256SUMS repeats the manifest for sha256sum -c.\n"
    "Produced by TgWitness (PhishDestroy, https://phishdestroy.io); the producer is part of\n"
    "the signed manifest.\n")


def html_bytes(events, coverage=None, context=None):
    return b"".join(html_chunks(events, coverage, context))


def html_chunks(events, coverage=None, context=None):
    """The readable report (see report.py); sealed when the context carries the signing key."""
    return report.evidence_chunks(events, coverage, {"limits": LIMITS, "producer": producer(), **(context or {})})


def export_file(store, vault, fmt, options=None):
    """A stable journal prefix as JSONL, CSV, a sealed HTML report, or the signed evidence ZIP.

    options are resolved report options (report.resolved); the case details they carry are
    signed into the manifest and the report seal."""
    if fmt not in ("jsonl", "csv", "html", "zip"):
        raise ValueError("Unsupported export format")
    options = options or report.resolved()
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
            observed, digest = Coverage(), report.Digest()

            def measured(events):
                for event in events:
                    observed.add(event)
                    digest.add(event)
                    yield event
            result = verify_events(measured(snapshot.events()), vault.public_key)
            if retained:
                verify_checkpoint(retained, vault.public_key, result["events"], snapshot.hash_at)
            coverage = observed.result()
            summary = digest.result()
            # Titles recorded in the journal win; current source titles fill the rest.
            summary["titles"] = {**{t["chat_id"]: t["title"] for t in store.targets() if t.get("title")},
                                 **summary["titles"]}
            context = {"kind": "evidence", "options": options, "report_id": str(uuid.uuid4()), "created_at": utcnow(),
                       "producer": producer(), "limits": LIMITS, "public_key": vault.public_key,
                       "fingerprint": result["fingerprint"], "event_count": result["events"],
                       "head_hash": result["head_hash"], "digest": summary, "anchors": [], "files": {},
                       "account": store.get_setting("account", None), "archive": fmt == "zip", "sign": vault.sign}

            def chunks(format):
                events = snapshot.events()
                return {"jsonl": lambda: (canonical(e) + b"\n" for e in events),
                        "csv": lambda: csv_chunks(events),
                        "html": lambda: html_chunks(events, coverage, context)}[format]()

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

                for format, name in (("jsonl", "events.jsonl"), ("csv", "events.csv")):
                    write_member(name, chunks(format))
                write_member("coverage.json", [json.dumps(coverage, ensure_ascii=False, indent=1).encode("utf-8")])
                write_member("verify.py", [Path(__file__).with_name("verify.py").read_bytes()])
                for event in snapshot.events():
                    digest = event["payload"].get("media_sha256") if event["kind"] in ("media.saved", "actor.avatar_saved") else None
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
                    if proof.suffix in (".tsr", ".ots"):
                        query = proof.with_suffix(".tsq")
                        context["anchors"].append(report.describe_anchor(
                            source.name, source.read_bytes(), proof.name, proof.read_bytes(),
                            query.read_bytes() if proof.suffix == ".tsr" and query.is_file() else None))
                # The readable kit: custody record, sealed report, README and SHA256SUMS, in that order.
                context["events_sha256"] = hashes["events.jsonl"]
                write_member("custody.json", [json.dumps(report.custody(context), ensure_ascii=False,
                                                         indent=1).encode("utf-8")])
                context["files"] = dict(hashes)
                write_member("report.html", chunks("html"))
                listed = {**hashes, **dict.fromkeys(("README.txt", "SHA256SUMS", "manifest.json", "manifest.sig"), "")}
                write_member("README.txt", [report.readme(context, listed, "\n".join(LIMITS) + README)])
                write_member("SHA256SUMS", [report.sha256sums(hashes)])
                manifest = {"format": "tgwitness-evidence-v1", "created_at": context["created_at"],
                            "public_key": vault.public_key, "fingerprint": result["fingerprint"],
                            "event_count": result["events"], "head_hash": result["head_hash"],
                            "scope": "Complete stable journal prefix from sequence 1, including operational events",
                            "producer": producer(), "limitations": LIMITS, "case": report.case_of(options),
                            "report": {"id": context["report_id"], "file": "report.html",
                                       "language": options["language"], "sealed": True, "custody": "custody.json"},
                            "files": hashes}
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
