import html
import json
import math
import re
from datetime import datetime

PATH = "docs/validation/"
LANGUAGES = ("en", "ru")
STATIC = {f"validation/{name}": f"website/validation/{name}"
          for name in ("validation.css", "validation.js", "snapshot.json", "performance.svg")}
STATIC.update({f"validation/audit/{name}": f"website/validation/audit/{name}"
               for name in ("REPORT.md", "MEASUREMENTS.csv", "PROOF.json", "VERIFY.py", "SHA256SUMS.txt")})


def number(value):
    return f"{value:,}".replace(",", "\u202f") if isinstance(value, int) else f"{value:.3f}"


def validate(data):
    if data["format"] != "tgwitness-validation-snapshot-v1" or data["measurement_authority"] != "operator":
        raise ValueError("Unsupported validation snapshot")
    if not re.fullmatch(r"[0-9a-f]{40}", data["source_revision"]):
        raise ValueError("Snapshot must name an exact source revision")
    checked = datetime.fromisoformat(data["checked_at"].replace("Z", "+00:00"))
    if checked.utcoffset() is None:
        raise ValueError("Snapshot date must include a time zone")
    ids = [server["id"] for server in data["servers"]]
    if len(ids) != len(set(ids)) or any(not re.fullmatch(r"[A-Z]", name) for name in ids):
        raise ValueError("Server labels must be unique letters")
    counts = [*data["tests"].values(), *data["suites"].values(), *data["integrity"].values()]
    counts += [server[key] for server in data["servers"] for key in ("journals", "events", "checkpoints", "nested_vms")]
    if any(type(value) is not int or value < 0 for value in counts):
        raise ValueError("Counts must be nonnegative integers")
    if data["integrity"]["journals_passed"] > sum(server["journals"] for server in data["servers"]):
        raise ValueError("Passing journals exceed inspected journals")
    measured = set()
    for run in data["benchmarks"]:
        if run["server"] not in ids or run["server"] in measured:
            raise ValueError("Benchmark must identify one inspected server")
        measured.add(run["server"])
        start, end = (datetime.fromisoformat(run[key].replace("Z", "+00:00"))
                      for key in ("started_at", "finished_at"))
        if not start <= end <= checked:
            raise ValueError("Benchmark falls outside the snapshot")
        if type(run["records"]) is not int or run["records"] <= 0:
            raise ValueError("Benchmark requires recorded data")
        if (run["archive_verified"] is not True or run["key_pinned"] is not True
                or run["attachments"] is not False or run["accounts"] != 2
                or run["reused_records"] != 0 or run["duplicate_ids"] != 0 or run["route"] != "WARP"):
            raise ValueError("Benchmark does not support the published method and integrity claims")
        for phase in ("acquisition", "end_to_end"):
            seconds, rate = run[phase + "_seconds"], run[phase + "_records_per_second"]
            if (not math.isfinite(seconds) or seconds <= 0 or not math.isfinite(rate)
                    or abs(run["records"] / seconds - rate) > 0.002):
                raise ValueError("Benchmark rate does not match its count and duration")
        if run["end_to_end_seconds"] < run["acquisition_seconds"]:
            raise ValueError("Export interval cannot be shorter than collection")
        if not re.fullmatch(r"[0-9a-f]{64}", run["archive_sha256"]):
            raise ValueError("Benchmark archive hash is missing")
    for source in data["provenance"]:
        if not re.fullmatch(r"[0-9a-f]{64}", source["sha256"]):
            raise ValueError("Source receipt hash is missing")
    return data


def content(read_public, render, values, lang):
    data = validate(json.loads(read_public("website/validation/snapshot.json")))
    words = json.loads(read_public("website/validation/texts.json"))[lang]
    esc = lambda value: html.escape(str(value), quote=True)
    message_count = sum(run["records"] for run in data["benchmarks"])
    peak_rate = max((run["acquisition_records_per_second"] for run in data["benchmarks"]), default=0)
    counts = (message_count, peak_rate, len(data["benchmarks"]), len(data["servers"]))
    stats = ''.join(f'<div><strong>{number(count)}</strong><span>{esc(words[key])}</span></div>'
                    for key, count in zip(("messages_exported", "peak_rate", "benchmarks", "servers"), counts))
    servers = []
    bars = []
    rows = []
    run_cards = []
    maximum = max((run["acquisition_records_per_second"] for run in data["benchmarks"]), default=1)
    for server in data["servers"]:
        label = esc(words["server"] + " " + server["id"])
        servers.append(
            f'<section class="v-server"><div class="v-server-top"><span class="v-server-id">{esc(server["id"])}</span>'
            f'<span class="v-chip"><span aria-hidden="true">✓</span> {esc(words["inspected"])}</span></div>'
            f'<h3>{label}</h3><p class="v-role">{esc(words[server["scope"]])}</p>'
            f'<p class="v-spec">{server["cpu"]} vCPU · {server["memory_gib"]} GiB · {esc(server["os"])}</p>'
            f'<dl>{"".join(f"<div><dt>{esc(words[key])}</dt><dd>{number(server[key])}</dd></div>" for key in ("journals", "events", "checkpoints"))}</dl>'
            f'<p class="v-server-note">{esc(words[server["scope"] + "_scope"])}</p></section>')
        run = next((r for r in data["benchmarks"] if r["server"] == server["id"]), None)
        if run is None:
            bars.append(f'<div class="v-bar-row v-unmeasured"><span>{label}</span><div class="v-bar-track">'
                        f'<span>{esc(words["unmeasured"])}</span></div><span aria-label="{esc(words["unmeasured"])}">—</span></div>')
            continue
        rate = run["acquisition_records_per_second"]
        run_cards.append(
            f'<article class="v-run-card"><div class="v-run-label">{label}<span>{esc(run["route"])} · {run["accounts"]} {esc(words["accounts"])}</span></div>'
            f'<div class="v-run-messages"><strong>{number(run["records"])}</strong><span>{esc(words["messages_exported"])}</span></div>'
            f'<div class="v-run-rate"><strong>{rate:.3f}</strong><span>{esc(words["rate"])}</span></div>'
            f'<dl><div><dt>{esc(words["acquisition"])}</dt><dd>{number(run["acquisition_seconds"])} {esc(words["seconds"])}</dd></div>'
            f'<div><dt>{esc(words["end_to_end"])}</dt><dd>{number(run["end_to_end_seconds"])} {esc(words["seconds"])}</dd></div></dl></article>')
        bars.append(
            f'<div class="v-bar-row"><span>{label}</span><div class="v-bar-track" aria-hidden="true">'
            f'<span class="v-bar" data-bar="{esc(server["id"])}" style="width:{rate / maximum * 100:.3f}%"></span></div>'
            f'<strong><span data-rate="{esc(server["id"])}" data-acquisition="{rate:.3f}" '
            f'data-end-to-end="{run["end_to_end_records_per_second"]:.3f}">{rate:.3f}</span> '
            f'<small>{esc(words["rate"])}</small></strong></div>')
        rows.append(
            f'<tr><th scope="row">{label}</th><td>{number(run["records"])}</td>'
            f'<td>{number(run["acquisition_seconds"])} {esc(words["seconds"])}<br><strong>{rate:.3f} {esc(words["rate"])}</strong></td>'
            f'<td>{number(run["end_to_end_seconds"])} {esc(words["seconds"])}<br><strong>{run["end_to_end_records_per_second"]:.3f} {esc(words["rate"])}</strong></td></tr>'
            f'<tr class="v-hash-row"><td colspan="4"><time datetime="{esc(run["started_at"])}">{esc(run["started_at"])}</time>'
            f' → <time datetime="{esc(run["finished_at"])}">{esc(run["finished_at"])}</time><br>SHA-256 <code>{esc(run["archive_sha256"])}</code></td></tr>')
    tests = ''.join(f'<div class="v-test v-{key}"><strong>{number(data["tests"][key])}</strong><span>{esc(words[key])}</span></div>'
                    for key in ("passed", "failed", "skipped"))
    suites = ''.join(f'<li><span>{esc(words[key])}</span><strong>{number(count)} <small>{esc(words["suite_passed"])}</small></strong></li>'
                     for key, count in data["suites"].items())
    limits = ''.join(f'<li><span class="v-limit-index">{index:02d}</span><div><h3>{esc(words[key])}</h3><p>{esc(words[key + "_text"])}</p></div></li>'
                     for index, key in enumerate(data["limits"], 1))
    provenance = ''.join(f'<li><span>{esc(source["name"])}</span><code>{esc(source["sha256"])}</code></li>'
                         for source in data["provenance"])
    context = {key.upper(): esc(value) for key, value in words.items() if isinstance(value, str)}
    context.update(values)
    context.update({"HEADLINE": words["headline"].format(messages=number(message_count)), "RUN_CARDS": ''.join(run_cards), "REVISION_LABEL": esc(words["revision"]), "DATE": esc(data["checked_at"].replace("T", " ").replace("Z", " UTC")),
                    "DATETIME": esc(data["checked_at"]), "REVISION": esc(data["source_revision"]),
                    "SHORT_REVISION": esc(data["source_revision"][:8]), "RELEASE_ID": esc(data["release_id"]),
                    "STATS": stats, "SERVERS": ''.join(servers), "BARS": ''.join(bars), "ROWS": ''.join(rows),
                    "TESTS": tests, "SUITES": suites, "LIMITS": limits, "PROVENANCE_ROWS": provenance,
                    "METHOD_STEPS": ''.join(f'<li>{esc(step)}</li>' for step in words["method_steps"])})
    return render(read_public("website/validation/page.html").decode("utf-8"), context)
