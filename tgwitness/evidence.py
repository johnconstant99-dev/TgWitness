import csv
import functools
import hashlib
import io
import json
import os
import re
import tempfile
import uuid
import zipfile
from pathlib import Path

from . import __version__
from . import indicators
from . import pdf_report
from . import report
from . import tuning
from . import viewer
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
    return {"software": "TgWitness", "version": __version__, "project": "PhishDestroy",
            "homepage": "https://phishdestroy.io", "source": "https://github.com/phishdestroy/TgWitness", **build()}


@functools.lru_cache(maxsize=1)
def build():
    from .provenance import SOURCE_POLICY, source_files, source_tree_sha256
    found = {"source_policy": SOURCE_POLICY, "source_tree_sha256": source_tree_sha256(source_files())}
    commit = os.environ.get("TGWITNESS_COMMIT") or checkout_commit(Path(__file__).resolve().parents[1])
    if isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit.strip()):
        found["commit"] = commit.strip()
    return found


def checkout_commit(root):
    try:
        git = root / ".git"
        if git.is_file():
            git = (root / git.read_text(encoding="utf-8").split(":", 1)[1].strip()).resolve()
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref: "):
            return head
        ref, common = head[5:], git
        if (git / "commondir").is_file():
            common = (git / (git / "commondir").read_text(encoding="utf-8").strip()).resolve()
        for base in (git, common):
            if (base / ref).is_file():
                return (base / ref).read_text(encoding="utf-8").strip()
        for line in (common / "packed-refs").read_text(encoding="utf-8").splitlines():
            if line.endswith(" " + ref):
                return line.split()[0]
    except (OSError, IndexError):
        return None
    return None


def checkpoint(store, vault):
    from . import board
    with store.snapshot() as snapshot:
        head = snapshot.head
        statement = {"format": "tgwitness-checkpoint-v1", "created_at": utcnow(),
                     "public_key": vault.public_key, "event_count": head["seq"] if head else 0,
                     "head_hash": head["hash"] if head else ZERO}
        annotations = board.head(snapshot.connection)
        if annotations["seq"]:
            statement["annotations_head"] = annotations
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
    "\n\nAdditional verification options\n"
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
    "the signed manifest.\n")


def html_chunks(events, coverage=None, context=None):
    return report.evidence_chunks(events, coverage, {"limits": LIMITS, "producer": producer(), **(context or {})})


COVERAGE_RANGES = 100_000


class BundleSizeLimit(ValueError):
    """The archive hit its configured uncompressed byte ceiling."""


def export_file(store, vault, fmt, options=None, *, include_board=True, compact=False, output_stream=None,
                max_uncompressed_bytes=None):
    if fmt not in ("jsonl", "csv", "html", "json", "pdf", "zip"):
        raise ValueError("Unsupported export format")
    if compact and fmt != "zip":
        raise ValueError("Compact packaging requires ZIP")
    if output_stream is not None and fmt != "zip":
        raise ValueError("External export streams require ZIP")
    if fmt == "pdf" and not pdf_report.available():
        raise pdf_report.MissingFont("PDF reports need fpdf2 on the server: pip install fpdf2 uharfbuzz")
    options = options or report.resolved()
    directory = store.root / "temporary-exports"
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.resolve().parent != store.root.resolve():
        raise ValueError("Temporary export directory must belong to this profile")
    path = None
    if output_stream is None:
        temp = tempfile.NamedTemporaryFile(prefix="tgwitness-export-", suffix="." + fmt, dir=directory, delete=False)
        path = Path(temp.name)
        temp.close()
    try:
        retained = store.retained_checkpoint()
        with store.snapshot() as snapshot:
            from . import board
            board_export = board.export_state(snapshot.connection, vault) if include_board and board.head(snapshot.connection)["seq"] else None
            from .gap_analysis import settings as gap_settings
            observed, digest = Coverage(gap_settings(store)), report.Digest()
            journal_bytes = hashlib.sha256()

            def measured(events):
                for event in events:
                    observed.add(event)
                    if not compact:
                        digest.add(event)
                    journal_bytes.update(canonical(event) + b"\n")
                    yield event
            result = verify_events(measured(snapshot.events()), vault.public_key)
            if retained:
                verify_checkpoint(retained, vault.public_key, result["events"], snapshot.hash_at)
            coverage = observed.result(COVERAGE_RANGES)
            if not compact:
                digest.hash_images(store.root / "media")
            summary = digest.result()
            summary["titles"] = {**{t["chat_id"]: t["title"] for t in store.targets() if t.get("title")},
                                 **summary["titles"]}
            context = {"kind": "evidence", "options": options, "report_id": str(uuid.uuid4()), "created_at": utcnow(),
                       "producer": producer(), "limits": LIMITS, "public_key": vault.public_key,
                       "fingerprint": result["fingerprint"], "event_count": result["events"],
                       "head_hash": result["head_hash"], "events_sha256": journal_bytes.hexdigest(),
                       "digest": summary, "anchors": [], "files": {},
                       "account": store.get_setting("account", None), "archive": fmt == "zip", "sign": vault.sign,
                       "events_again": snapshot.events, "journal_verified": True}
            if board_export:
                from . import board_report
                context["case_board"] = board_report.material(snapshot.connection, board_export["statement"], options)
            selection = report.report_selection.Selection.model_validate(options.get("selection") or {})
            report_events = snapshot.events
            if not compact and selection.enabled and fmt in ("html", "json", "pdf", "zip"):
                selected_event = report.report_selection.compile_selection(selection)
                def report_events():
                    return (event for event in snapshot.events() if selected_event(event))

                selected_digest = report.Digest()
                for event in report_events():
                    selected_digest.add(event)
                selected_digest.hash_images(store.root / "media")
                selected_summary = selected_digest.result()
                selected_summary["titles"] = {chat: summary["titles"].get(chat, "")
                                               for chat in selected_summary["chats"]}
                context["report_digest"] = selected_summary
                context["events_again"] = report_events
                context["source_events"] = snapshot.events
            if not compact and (selection.enabled or selection.id_gaps) and fmt in ("html", "json", "pdf", "zip"):
                selected = report.report_selection.analyze(snapshot, selection, preview_limit=0, scratch_root=directory)
                context["selection"] = {key: selected[key] for key in ("selection", "source", "counts", "id_gaps")}

            def chunks(format):
                events = snapshot.events()
                return {"jsonl": lambda: (canonical(e) + b"\n" for e in events),
                        "csv": lambda: csv_chunks(events),
                        "html": lambda: html_chunks(report_events(), coverage, context)}[format]()

            if fmt == "json":
                path.write_bytes(report.report_json(report_events, coverage, context))
                return path
            if fmt == "pdf":
                data = report.report_data(report_events, coverage, context)
                path.write_bytes(pdf_report.report_pdf(data, context, vault, report_events()))
                return path
            if fmt != "zip":
                with path.open("wb") as out:
                    for chunk in chunks(fmt):
                        out.write(chunk)
                return path

            hashes, total, limit = {}, 0, tuning.value(store, "export_max_gib") * 1024**3
            if max_uncompressed_bytes is not None:
                if type(max_uncompressed_bytes) is not int or not 8 * 1024**2 <= max_uncompressed_bytes <= 1024 * 1024**3:
                    raise ValueError("Invalid uncompressed archive limit")
                limit = max_uncompressed_bytes
            with zipfile.ZipFile(output_stream if output_stream is not None else path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                def write_member(name, values):
                    nonlocal total
                    digest = hashlib.sha256()
                    entry = zipfile.ZipInfo(name)
                    entry.compress_type = zipfile.ZIP_STORED if name.startswith("media/") or name.endswith(".zip") else zipfile.ZIP_DEFLATED
                    with archive.open(entry, "w", force_zip64=True) as outgoing:
                        for chunk in values:
                            total += len(chunk)
                            if total > limit - 4 * 1024**2:
                                raise BundleSizeLimit("Bundle exceeds the uncompressed size limit set in Parameters")
                            outgoing.write(chunk)
                            digest.update(chunk)
                    hashes[name] = digest.hexdigest()
                    return digest.hexdigest()

                for format, name in (("jsonl", "events.jsonl"), ("csv", "events.csv")):
                    if compact and format == "csv":
                        continue
                    write_member(name, chunks(format))
                write_member("coverage.json", [json.dumps(coverage, ensure_ascii=False, indent=1).encode("utf-8")])
                if board_export:
                    write_member("annotations.jsonl", (canonical(row) + b"\n" for row in board.records(snapshot.connection)))
                    write_member("case-board.json", [canonical(board_export)])
                    for identifier, item in board.export_slices(snapshot.connection, board_export["statement"]["state"]):
                        write_member("board/slices/" + identifier + ".json", [canonical(item)])
                if not compact:
                    if analytics := report.report_material(context).get("analytics"):
                        write_member("analytics.json", [canonical(analytics)])
                write_member("verify.py", [Path(__file__).with_name("verify.py").read_bytes()])
                if not compact:
                    write_indicators(write_member, (context.get("report_digest") or summary).get("indicators"), context)
                for event in snapshot.events():
                    if event["kind"] == "sealed.account_export":
                        item = event["payload"]
                        job = item.get("job_id", "")
                        if not re.fullmatch(r"[a-f0-9]{32}", job) or item.get("file") != "account-export.zip" or item["file"] in hashes:
                            raise ValueError("Invalid or duplicate sealed account export")
                        source = store.root / "account-exports" / job / "export.zip"
                        if source.is_symlink() or source.resolve().parent != (store.root / "account-exports" / job).resolve():
                            raise ValueError("Invalid sealed account export path")
                        with source.open("rb") as incoming:
                            calculated = write_member(item["file"], iter(lambda: incoming.read(1024 * 1024), b""))
                        if calculated != item["sha256"] or source.stat().st_size != item["bytes"]:
                            raise ValueError("Sealed account export changed before packaging")
                    if event["kind"] == "media.hashed":
                        data = canonical(event["payload"]["server_hashes"])
                        name = "hashes/" + hashlib.sha256(data).hexdigest() + ".json"
                        if name not in hashes:
                            write_member(name, [data])
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
                            query.read_bytes() if proof.suffix == ".tsr" and query.is_file() else None,
                            public_key=vault.public_key, event_count=result["events"], hash_at=snapshot.hash_at))
                context["events_sha256"] = hashes["events.jsonl"]
                write_member("custody.json", [json.dumps(report.custody(context), ensure_ascii=False,
                                                         indent=1).encode("utf-8")])
                if not compact and options.get("timeline"):
                    context["viewer"] = write_viewer(write_member, "journal",
                        (viewer.journal_item(event, options.get("raw_records", True)) for event in report_events()),
                        None, (context.get("report_digest") or summary).get("indicators"), options)
                context["files"] = dict(hashes)
                if compact:
                    data = {}
                    packaging = {"mode": "compact", "full_journal": True, "preserved_media_omitted": False,
                        "meaning": "Formatted reports, CSV and viewer duplicates are omitted to reduce packaging size. "
                                   "All signed journal events, file-hash manifests and preserved media remain included. "
                                   "Collection gaps and unavailable attachments remain recorded in the journal."}
                    write_member("PACKAGING.json", [canonical(packaging)])
                    write_member("index.html", [compact_index(result["events"])])
                else:
                    data = report.report_data(report_events, coverage, context)
                    write_member("report.json", [report.sealed_json(data, context)])
                    write_pdf(write_member, "report.pdf", lambda: pdf_report.report_pdf(
                        data, context, vault, report_events()))
                    context["files"] = dict(hashes)
                    write_member("report.html", chunks("html"))
                listed = {**hashes, **dict.fromkeys(("README.txt", "SHA256SUMS", "manifest.json", "manifest.sig"), "")}
                readme = (("TgWitness compact evidence archive\n\n" + packaging["meaning"] + "\n\n"
                           + "Open index.html. Verify evidence.zip using verify.py from an independently trusted checkout.\n"
                           + "\n".join(LIMITS) + README).encode() if compact else
                          report.readme(context, listed, "\n".join(LIMITS) + README))
                write_member("README.txt", [readme])
                write_member("SHA256SUMS", [report.sha256sums(hashes)])
                manifest = {"format": "tgwitness-evidence-v1", "created_at": context["created_at"],
                            "public_key": vault.public_key, "fingerprint": result["fingerprint"],
                            "event_count": result["events"], "head_hash": result["head_hash"],
                            "scope": "Complete stable journal prefix from sequence 1, including operational events",
                            "producer": producer(), "limitations": LIMITS, "case": report.case_of(options),
                            "report": {} if compact else report_entry(context, options), "files": hashes,
                            "case_assessment": data.get("case_assessment", {})}
                if compact:
                    manifest["packaging"] = packaging
                if board_export:
                    manifest["annotations_head"] = board_export["statement"]["state"]["annotations_head"]
                manifest_bytes = canonical(manifest)
                if total + len(manifest_bytes) + 88 > limit:
                    raise BundleSizeLimit("Manifest pushes bundle above the verification size limit")
                archive.writestr("manifest.json", manifest_bytes)
                archive.writestr("manifest.sig", vault.sign(manifest_bytes))
        return path
    except BaseException:
        if path is not None:
            path.unlink(missing_ok=True)
        raise


def compact_index(events):
    return ("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; base-uri 'none'; form-action 'none'\">"
            "<title>Compact evidence archive</title><body><main><h1>Compact evidence archive</h1>"
            "<p>Formatted reports and duplicate views were omitted to reduce archive size. "
            "All " + str(events) + " signed journal records, preserved files and server file hashes are included.</p>"
            "<p>Collection may still be partial. Review coverage and the final journal events.</p>"
            "<ul><li><a download href=\"events.jsonl\">Signed journal (JSONL)</a></li>"
            "<li><a download href=\"coverage.json\">Collection coverage</a></li>"
            "<li><a download href=\"PACKAGING.json\">Packaging details</a></li>"
            "<li><a href=\"README.txt\">Verification instructions</a></li></ul>"
            "<p>The manifest signs the archive members. Use verification tools from an independently trusted checkout.</p>"
            "</main></body></html>").encode()


def write_indicators(write_member, found, context):
    for name, data in indicators.files(found or {"items": []}, {**context, "case": report.case_of(context["options"])}):
        write_member(name, [data])


def write_viewer(write_member, kind, items, people, found, options=None):
    writer = viewer.Writer(write_member, kind, chunk_size=(options or {}).get("part_size", viewer.CHUNK))
    for item in items:
        writer.add(item)
    return writer.descriptor(people, found)


def write_pdf(write_member, name, render):
    if not pdf_report.available():
        return False
    try:
        data = render()
    except pdf_report.MissingFont:
        return False
    write_member(name, [data])
    return True


def report_entry(context, options, file="report.html"):
    entry = {"id": context["report_id"], "file": file, "language": options["language"], "sealed": True,
             "design": report.report_design.normalized(options.get("design")),
             "custody": "custody.json", "presentation": {k: options.get(k, v) for k, v in report.report_analytics.Presentation().model_dump().items()}}
    if context.get("selection"):
        entry["selection"] = context["selection"]["selection"]
        entry["selected_records"] = context["selection"]["counts"]["selected_records"]
    if "report.json" in context.get("files", {}):
        entry["json"] = "report.json"
    for pdf in ("report.pdf", "chat.pdf"):
        if pdf in context.get("files", {}):
            entry["pdf"] = pdf
    if context.get("parts"):
        entry["parts"] = [{k: part[k] for k in ("file", "from", "to", "count")} for part in context["parts"]]
    return entry


def encrypt_export(path, fmt, password, inner_name=None):
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
    directory = root / "temporary-exports"
    if directory.is_symlink() or not directory.is_dir() or directory.resolve().parent != root.resolve():
        return
    for item in directory.glob("tgwitness-export-*"):
        if item.is_file() and not item.is_symlink() and item.suffix in (".zip", ".jsonl", ".csv", ".html", ".json"):
            item.unlink()
