import base64
import hashlib
import html
import json
import secrets
import tempfile
import uuid
import zipfile
from pathlib import Path

from . import documentation
from .store import canonical

MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
SIGNATURES = ((b"\x89PNG\r\n\x1a\n", "image/png", "png"), (b"\xff\xd8\xff", "image/jpeg", "jpg"),
              (b"GIF8", "image/gif", "gif"), (b"%PDF", "application/pdf", "pdf"))
MEANINGS = (
    ("key", "Signature (Ed25519)",
     "The workspace key signed this statement. Compare the fingerprint with one obtained independently, for example "
     "directly from the investigator. Without that comparison the signature only shows that the package is internally "
     "consistent."),
    ("shield", "Statement SHA-256",
     "A fingerprint of the signed statement. The workspace journal recorded it when the document was fixed, so a later "
     "copy can be compared with it."),
    ("list", "Journal record hashes",
     "Every step cites the journal record it describes by SHA-256. The full signed journal of the workspace confirms "
     "each record."),
    ("lock", "Sealed records",
     "Content hidden for a stated reason is encrypted inside the statement. A key holder can open it and confirm that "
     "it matches the cited record hash."),
    ("image", "Screenshots and files",
     "Stored under their SHA-256 and listed in manifest-sha256.txt. A changed file no longer matches its name or the "
     "list."),
    ("alert", "What binds this record to outside time",
     "A signature binds these bytes to the collector key. Times come from computer clocks and Telegram servers; "
     "a verified timestamp bound to the recorded data fixes them against an outside source."),
)
COMMANDS = (
    ("Check the signature and content",
     "Needs TgWitness. Replace FINGERPRINT with the fingerprint you obtained independently.",
     "python -m tgwitness.documentation_verify data/documentation.json --fingerprint FINGERPRINT"),
    ("Check that no file changed", "Any BagIt tool works.", "bagit.py --validate ."),
    ("Read the RFC 3161 timestamp reply", "Displays the reply without verifying its signature, trust chain or checkpoint binding.",
     "openssl ts -reply -in data/timestamps/FILE.tsr -text"),
    ("Check the OpenTimestamps proof", "Use the OpenTimestamps client and compare its verified digest with the checkpoint.",
     "ots verify data/timestamps/FILE.ots"),
)
STYLE = (
    "*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--fg);font:15px/1.6 " + documentation.FONT
    + ";-webkit-font-smoothing:antialiased}main{max-width:940px;margin:0 auto;padding:44px 28px 64px}"
    ".mono,pre{font-family:" + documentation.MONO + ";font-size:.88em;overflow-wrap:anywhere}"
    ".icon{width:18px;height:18px;flex:none;vertical-align:-3px}.icon.s{width:14px;height:14px}"
    ".brand{display:flex;gap:8px;align-items:center;font-size:12px;font-weight:700;letter-spacing:.12em;"
    "text-transform:uppercase;color:var(--accent)}h1{font-size:32px;line-height:1.15;letter-spacing:-.02em;"
    "margin:10px 0 22px}h2{display:flex;gap:10px;align-items:center;font-size:20px;letter-spacing:-.01em;margin:40px 0 6px}"
    "h2 .icon{color:var(--accent);width:22px;height:22px}.lead{color:var(--muted);font-size:13.5px;margin:0 0 14px}"
    ".pass{display:flex;gap:18px;align-items:center;padding:22px 24px;border-radius:18px;"
    "background:linear-gradient(135deg,var(--ok-soft),var(--surface));border:1px solid var(--ok-line);"
    "box-shadow:var(--shadow)}.pass .badge{width:54px;height:54px;border-radius:50%;background:var(--ok);color:#fff;"
    "display:grid;place-items:center;flex:none}.pass .badge .icon{width:30px;height:30px}"
    ".pass b{display:block;font-size:17px;color:var(--ok)}.pass span{font-size:13.5px;color:var(--muted)}"
    ".grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:18px}"
    ".fact{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:14px 16px;"
    "box-shadow:var(--shadow)}.fact.wide{grid-column:1/-1}.fact .name{display:flex;gap:8px;align-items:center;"
    "font-size:11.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);"
    "margin-bottom:6px}.fact .name .icon{color:var(--accent)}.fact.ok .name .icon{color:var(--ok)}"
    ".fact .value{font-size:14px;overflow-wrap:anywhere}.fact .mono{background:var(--surface-2);border:1px solid var(--line);"
    "border-radius:6px;padding:1px 6px}"
    ".mean{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.meaning{display:flex;gap:12px;"
    "background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:14px 16px}"
    ".meaning>.icon{color:var(--accent);margin-top:2px}.meaning b{display:block;font-size:14px;margin-bottom:3px}"
    ".meaning p{margin:0;font-size:13.5px;color:var(--muted)}.meaning.warn{background:var(--warn-soft);"
    "border-color:var(--warn-line)}.meaning.warn>.icon,.meaning.warn b{color:var(--warn)}"
    ".steps{list-style:none;margin:0;padding:0;display:grid;gap:12px;counter-reset:step}.steps li{"
    "counter-increment:step;display:grid;grid-template-columns:34px 1fr;gap:12px;background:var(--surface);"
    "border:1px solid var(--line);border-radius:14px;padding:14px 16px}.steps li:before{content:counter(step);"
    "width:34px;height:34px;border-radius:10px;background:var(--accent-soft);color:var(--accent);display:grid;"
    "place-items:center;font-weight:800}.steps b{display:block;font-size:14.5px}.steps p{margin:2px 0 8px;"
    "font-size:13px;color:var(--muted)}pre{margin:0;padding:10px 12px;border-radius:10px;background:#0f172a;"
    "color:#e2e8f0;white-space:pre-wrap;user-select:all}"
    ".caution{display:flex;gap:10px;align-items:flex-start;margin-top:18px;padding:12px 16px;border-radius:12px;"
    "background:var(--amber-soft);border:1px solid var(--amber-line);color:var(--amber);font-weight:600;font-size:14px}"
    "footer{margin-top:40px;padding-top:14px;border-top:1px solid var(--line);font-size:12px;color:var(--ref)}"
    "@media(max-width:760px){.grid,.mean{grid-template-columns:1fr}main{padding:24px 16px}}"
    "@media print{body{background:#fff}.pass,.fact{box-shadow:none}.fact,.meaning,.steps li{break-inside:avoid}"
    "*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}")


def kind(data):
    return next(((mime, suffix) for magic, mime, suffix in SIGNATURES if data.startswith(magic)),
                ("application/octet-stream", "bin"))


def referenced(model):
    found = []
    for block in model["blocks"]:
        step = block.get("step") or {}
        if block["type"] == "step" and not step.get("hidden"):
            found.extend(item["sha256"] for item in step.get("files") or [] if isinstance(item.get("sha256"), str))
    return list(dict.fromkeys(found))


def collect_files(model, supplied, media_root):
    files, total = {}, 0
    for sha256 in referenced(model):
        data = supplied.get(sha256)
        if data is None and media_root is not None:
            path = Path(media_root) / sha256
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_FILE:
                data = path.read_bytes()
        if data is None or hashlib.sha256(data).hexdigest() != sha256 or total + len(data) > MAX_TOTAL:
            continue
        total += len(data)
        files[sha256] = data
    return files


def marked(text, *values):
    shown = html.escape(text, quote=True)
    for value in values:
        if value:
            shown = shown.replace(html.escape(str(value)), '<span class="mono">' + html.escape(str(value)) + "</span>")
    return shown


COURT_FILES = (
    ("court/certification.html", "Certification of authenticity (template to complete and sign)"),
    ("court/exhibits.html", "Exhibit index"), ("court/request-annex.html", "Annex for official requests"))


def verification_html(result, fixed, say, stamps=None, documents=()):
    e, icon = documentation.e, documentation.icon
    head = result.get("journal_head") or {}
    receipts = sorted(name.split("/", 1)[1] for name in stamps or {} if name.endswith((".tsr", ".ots")))
    facts = (
        ("key", say("Signature"), marked(say("Valid for the workspace key with fingerprint {fingerprint}.",
                                             fingerprint=result["fingerprint"]), result["fingerprint"]), "ok wide"),
        ("check", say("Document content"), marked(say("Matches the signed statement.")), "ok"),
        ("list", say("Contents"), marked(say("{steps} steps, {notes} notes, {conclusions} conclusions.",
                                             steps=result["steps"], notes=result["notes"],
                                             conclusions=result["conclusions"])), ""),
        ("shield", say("Statement SHA-256"), marked(fixed["statement_sha256"], fixed["statement_sha256"]) + " · "
         + marked(say("Recorded in journal record #{seq} when the document was fixed.", seq=fixed["event_seq"])), "wide"),
        ("book", say("Journal head at fixing"), marked(say("Record #{seq}, SHA-256 {hash}", seq=head.get("seq"),
                                                           hash=head.get("hash")), head.get("hash")), "wide"),
        ("lock", say("Hidden records"), marked(say("{n} sealed; open them with keys handed over separately.",
                                                   n=len(result["still_sealed"]))), ""),
        ("timer", say("Timestamp receipts (not verified)"),
         marked(say("Included files: {files}. Their signatures, timestamp chains and binding to this document "
                    "have not been verified.", files=", ".join(receipts)), *receipts)
         if receipts else marked(say("No timestamp receipts are included.")), "wide"),
    )
    return ('<!doctype html><html lang="' + e(getattr(say, "language", "en")) + '"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
            "<title>" + e(say("How to check this package")) + "</title><style>:root{color-scheme:light;"
            + documentation.PALETTES["light"] + "}" + STYLE + '</style><main><div class="brand">' + icon("shield")
            + "TgWitness · " + e(say("Case package")) + "</div><h1>" + e(say("How to check this package")) + "</h1>"
            '<div class="pass"><div class="badge">' + icon("check") + "</div><div><b>"
            + e(say("Checked when the package was prepared: the signature and content are valid.")) + "</b><span>"
            + e(say("Repeat the check yourself with the steps below before relying on it.")) + '</span></div></div>'
            '<div class="grid">' + "".join('<div class="fact ' + style + '"'
                                           + (' data-check="timestamps" data-status="'
                                              + ("unverified" if receipts else "absent") + '"' if name == "timer" else "")
                                           + '><div class="name">' + icon(name, "icon s")
                                           + e(label) + '</div><div class="value">' + value + "</div></div>"
                                           for name, label, value, style in facts) + "</div>"
            "<h2>" + icon("help") + e(say("What each check means")) + '</h2><div class="mean">'
            + "".join('<div class="meaning' + (" warn" if name == "alert" else "") + '">' + icon(name) + "<div><b>"
                      + e(say(title)) + "</b><p>" + e(say(text)) + "</p></div></div>" for name, title, text in MEANINGS)
            + "</div><h2>" + icon("search") + e(say("Repeat the check yourself")) + '</h2><p class="lead">'
            + e(say("Run these commands in the package folder.")) + '</p><ol class="steps">'
            + "".join("<li><div><b>" + e(say(title)) + "</b><p>" + e(say(hint)) + "</p><pre>" + e(command) + "</pre></div></li>"
                      for title, hint, command in COMMANDS) + '</ol><div class="caution">' + icon("alert")
            + "<span>" + e(say("Obtain the fingerprint independently; do not copy it from this package.")) + "</span></div>"
            + ("<h2>" + icon("book") + e(say("Documents for court")) + '</h2><ol class="steps">'
               + "".join('<li><div><b><a href="' + e(path) + '">' + e(say(title)) + '</a></b><p class="mono">data/' + e(path)
                         + "</p></div></li>" for path, title in documents) + "</ol>" if documents else "")
            + "<footer>TgWitness · " + e(say("Statement SHA-256")) + " " + e(fixed["statement_sha256"])
            + "</footer></main></html>")


def readme(say, title):
    files = (
        say("data/report.html — the readable account of what the investigator did, with screenshots and times."),
        say("data/presentation.html — the same record as slides; print it to get a PDF with one slide per page."),
        say("data/verification.html — what was checked, what each check means and how to repeat it."),
        say("data/documentation.json — the signed original that the checks use."),
        say("data/files/ — screenshots and files named by their SHA-256."),
        say("data/indicators.csv, data/indicators.stix.json — wallets, links, domains and accounts found in the messages."),
        say("data/timestamps/ — collected checkpoint and receipt files, not cryptographically verified by the package builder."),
        say("data/video/ — subtitles with step captions and notes for the screen recording; open them in a video player "
            "next to the recorder's signed video export."),
        say("data/court/ — certification of authenticity to complete and sign, exhibit index, annex for official requests."))
    return "\n".join((
        title, "=" * min(len(title), 72), "",
        say("This folder is a BagIt bag (RFC 8493). Any BagIt tool can check that no file changed, for example: "
            "bagit.py --validate FOLDER"),
        "", *("  * " + line for line in files),
        "", say("Hidden content is not in these files. Keys to it are handed over separately."), ""))


def timestamps(checkpoints, after_seq):
    if checkpoints is None or not Path(checkpoints).is_dir():
        return {}
    anchors = Path(checkpoints) / "anchors"
    for source in sorted(Path(checkpoints).glob("checkpoint-*.json")):
        try:
            count = int(source.stem.rsplit("-", 1)[1])
        except ValueError:
            continue
        proofs = sorted(anchors.glob(source.stem + ".*")) if anchors.is_dir() else []
        if count >= after_seq and any(p.suffix in (".tsr", ".ots") for p in proofs):
            return {"timestamps/" + path.name: path.read_bytes() for path in [source, *proofs]
                    if path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_FILE}
    return {}


def passphrase():
    raw = base64.b32encode(secrets.token_bytes(20)).decode("ascii")
    return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))


def bag(name, payload, title, say, fixed, now):
    data = {"data/" + key: value for key, value in payload.items()}
    manifest = "".join(hashlib.sha256(value).hexdigest() + "  " + key + "\n" for key, value in sorted(data.items()))
    tags = {"bagit.txt": b"BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\n",
            "bag-info.txt": ("Bag-Software-Agent: TgWitness\nBagging-Date: " + now[:10]
                             + "\nExternal-Identifier: " + fixed["statement_sha256"]
                             + "\nExternal-Description: " + " ".join(title.split())[:200]
                             + "\nPayload-Oxum: " + str(sum(len(v) for v in data.values())) + "." + str(len(data))
                             + "\n").encode("utf-8"),
            "manifest-sha256.txt": manifest.encode("utf-8"),
            "README.txt": readme(say, title).encode("utf-8")}
    tags["tagmanifest-sha256.txt"] = "".join(hashlib.sha256(value).hexdigest() + "  " + key + "\n"
                                             for key, value in sorted(tags.items())).encode("utf-8")
    return {name + "/" + key: value for key, value in {**tags, **data}.items()}


def build(session, say, supplied, media_root, directory=None, checkpoints=None, password=None):
    from .documentation_verify import verify
    fixed = session.get("fixed")
    if not fixed:
        raise ValueError("Fix the document before preparing a case package.")
    if password is not None and len(password) < 20:
        raise ValueError("Use a passphrase of at least 20 characters, or let TgWitness generate one.")
    model, signed = fixed["model"], fixed["signed"]
    exported = canonical({"document": model, "signed": signed})
    result = verify(json.loads(exported))
    files = collect_files(model, supplied, media_root)
    stamps = timestamps(checkpoints, fixed["event_seq"])
    images = {sha256: "data:" + kind(data)[0] + ";base64," + base64.b64encode(data).decode("ascii")
              for sha256, data in files.items() if kind(data)[0].startswith("image/")}
    payload = {"documentation.json": exported,
               "report.html": documentation.render_html(model, say, fixed, images,
                                                        documentation.appearance_of(session)).encode("utf-8"),
               "presentation.html": documentation.render_slides(model, say, fixed, images,
                                                                documentation.appearance_of(session)).encode("utf-8"),
               "verification.html": verification_html(result, fixed, say, stamps).encode("utf-8"), **stamps}
    for sha256, data in files.items():
        payload["files/" + sha256 + "." + kind(data)[1]] = data
    for index, _ in enumerate(model.get("recordings") or [], 1):
        for fmt in ("vtt", "srt"):
            text = documentation.subtitles(model, say, documentation.appearance_of(session), fmt, index)
            if text.strip() not in ("", "WEBVTT"):
                payload["video/recording-" + str(index) + "." + fmt] = text.encode("utf-8")
    items = documentation.indicator_items(model)
    if items:
        from .indicators import csv_bytes, stix_bundle
        context = {"created_at": fixed["at"], "fingerprint": result["fingerprint"],
                   "report_id": str(uuid.UUID(fixed["statement_sha256"][:32])), "case": {"title": session["title"]}}
        payload["indicators.csv"] = csv_bytes(items)
        payload["indicators.stix.json"] = json.dumps(stix_bundle(items, context), ensure_ascii=False,
                                                     indent=2).encode("utf-8")
    from . import court
    listed = court.exhibits(model, payload)
    payload["court/exhibits.csv"] = court.exhibits_csv(listed)
    payload["court/exhibits.html"] = court.exhibits_html(listed, session["title"], say).encode("utf-8")
    request = court.annex(model)
    payload["court/request-annex.json"] = json.dumps(request, ensure_ascii=False, indent=2).encode("utf-8")
    payload["court/request-annex.csv"] = court.annex_csv(request)
    payload["court/request-annex.html"] = court.annex_html(request, session["title"], say).encode("utf-8")
    from . import undercover
    activity = undercover.record(model)
    documents = COURT_FILES
    if activity["chats"] or activity["personas"] or activity["authorisations"]:
        payload["court/undercover-record.json"] = json.dumps(activity, ensure_ascii=False, indent=2).encode("utf-8")
        payload["court/undercover-record.html"] = undercover.render_html(activity, session["title"], say).encode("utf-8")
        documents = COURT_FILES + (("court/undercover-record.html", "Undercover activity record"),)
    payload["verification.html"] = verification_html(result, fixed, say, stamps, documents).encode("utf-8")
    hashes = {"data/" + name: hashlib.sha256(value).hexdigest() for name, value in payload.items()}
    receipts = sorted(name.split("/", 1)[1] for name in stamps if name.endswith((".tsr", ".ots")))
    payload["court/certification.html"] = court.certification_html(session, model, fixed, result["fingerprint"], hashes, say,
                                                                   receipts).encode("utf-8")
    entries = bag("tgwitness-case-" + session["id"][:8], payload, session["title"], say, fixed, fixed["at"])
    handle = tempfile.NamedTemporaryFile(prefix="tgwitness-case-", suffix=".zip", delete=False, dir=directory)
    handle.close()
    path = Path(handle.name)
    try:
        if password is None:
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
                for name, data in entries.items():
                    archive.writestr(name, data)
        else:
            import pyzipper
            with pyzipper.AESZipFile(path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as archive:
                archive.setpassword(password.encode("utf-8"))
                archive.setencryption(pyzipper.WZ_AES, nbits=256)
                for name, data in entries.items():
                    archive.writestr(name, data)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path
