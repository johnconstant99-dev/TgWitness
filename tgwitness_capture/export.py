import base64
import hashlib
import html
import os
import tempfile
import zipfile
from pathlib import Path

from .format import FORMAT, canonical, check_events, digest, seal, utcnow
from .journal import sync_directory


def report(events, observer_id, key_fingerprint):
    rows = []
    for event in events:
        links = []
        for artifact in event["artifacts"]:
            path = "objects/" + artifact["sha256"]
            label = html.escape(artifact["role"])
            if artifact["media_type"] == "image/png":
                links.append(f'<a href="{path}" download="{event["seq"]}.png"><img loading="lazy" src="{path}" alt="{label}"></a>')
            links.append(f'<a href="{path}" download>{label} · {artifact["size"]} bytes · {artifact["sha256"]}</a>')
        details = html.escape(canonical(event).decode())
        rows.append(f'<article><h2>#{event["seq"]} {html.escape(event["kind"])}</h2>'
                    f'<time>{html.escape(event["observed_at"])}</time>'
                    f'<pre>{html.escape(canonical(event["payload"]).decode())}</pre>'
                    + "".join(links) + f'<details><summary>Signed event</summary><pre>{details}</pre></details></article>')
    script = "document.querySelector('input').addEventListener('input',e=>{const q=e.target.value.toLowerCase();document.querySelectorAll('article').forEach(n=>n.hidden=!n.textContent.toLowerCase().includes(q))});"
    script_hash = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    return (f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
            f'<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src \'self\' file:; '
            f'style-src \'unsafe-inline\'; script-src \'sha256-{script_hash}\'; base-uri \'none\'; form-action \'none\'">'
            '<title>Independent capture report</title><style>body{font:16px system-ui;max-width:1100px;margin:32px auto;padding:0 20px;background:#f5f7fa;color:#16243a}'
            'article{padding:20px;background:white;border:1px solid #cdd6e2;border-radius:12px;margin:18px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}'
            'a{display:block;overflow-wrap:anywhere;margin:10px 0}img{max-width:100%;max-height:600px}input{padding:12px;width:90%}time{color:#536274}</style>'
            '<h1>Independent capture report</h1>'
            f'<p>Observer: {html.escape(observer_id)}<br>Key SHA-256: {key_fingerprint}</p>'
            '<p>This is a view of recorded observations, not a continuous reconstruction. Check the ZIP with a trusted verifier and independently retained key fingerprint/checkpoint. '
            'Signatures establish integrity, not the truth of the source. Clock values are local unless independently anchored.</p>'
            '<label>Find events <input type="search" placeholder="URL, event, time"></label>'
            + "".join(rows) + f'<script>{script}</script></html>').encode()


def export_zip(journal, destination):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise ValueError("Export destination already exists")
    with journal.lock:
        events = journal.events()
        head = check_events(events, journal.public_key, journal.observer_id)
        files = {"events.jsonl": b"".join(canonical(event) + b"\n" for event in events),
                 "report.html": report(events, journal.observer_id, journal.fingerprint)}
        artifacts = {}
        for event in events:
            for artifact in event["artifacts"]:
                previous = artifacts.setdefault(artifact["sha256"], artifact["size"])
                if previous != artifact["size"]:
                    raise ValueError("Inconsistent artifact size")
        manifest_files = {name: {"sha256": digest(raw), "size": len(raw)} for name, raw in files.items()}
        fd, temporary = tempfile.mkstemp(dir=destination.parent, suffix=".part")
        try:
            with os.fdopen(fd, "w+b") as output:
                with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                    for name, raw in files.items():
                        archive.writestr(name, raw)
                    for value, size in artifacts.items():
                        name = "objects/" + value
                        hasher = hashlib.sha256()
                        actual = 0
                        with (journal.objects / value).open("rb") as source, archive.open(name, "w", force_zip64=True) as target:
                            while chunk := source.read(1024 * 1024):
                                hasher.update(chunk)
                                actual += len(chunk)
                                target.write(chunk)
                        if hasher.hexdigest() != value or actual != size:
                            raise ValueError("Artifact changed before export")
                        manifest_files[name] = {"sha256": value, "size": size}
                    manifest = {"format": FORMAT, "observer_id": journal.observer_id,
                                "public_key": journal.public_key, "created_at": utcnow(),
                                "seq": len(events), "head_hash": head, "files": manifest_files}
                    archive.writestr("manifest.json", canonical(manifest))
                    archive.writestr("manifest.sig", seal(journal.key, "manifest", manifest))
                output.flush()
                os.fsync(output.fileno())
            # Verification reads the bytes just written, not the source objects.
            from .verify import verify_zip
            verify_zip(temporary, journal.fingerprint)
            os.replace(temporary, destination)
            sync_directory(destination.parent)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        journal.append("export.created", {"export_id": destination.name,
                       "manifest_sha256": digest(canonical(manifest)), "exported_seq": len(events), "exported_head": head})
        return manifest
