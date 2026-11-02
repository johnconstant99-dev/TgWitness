from html import escape
from datetime import datetime
import re

FORMAT = "tgwitness-case-assessment-v1"
TITLE = "Basis of trust and limitations"
OVERVIEW = "Evidence at a glance"
INTRO = ("This assessment describes this copy. Checks performed by the exporter must be repeated independently. "
         "A valid signature does not establish the truth of a message or guarantee acceptance in court.")
STANDALONE = "This is a standalone report. Obtain the signed ZIP to verify the authoritative records and supporting proofs."
STATUSES = {"checked_locally": "Checked during export", "recorded": "Recorded; review required",
            "not_included": "Not included in this copy", "not_checked": "Not independently checked",
            "incomplete": "Incomplete or unavailable"}
LABELS = {"records": "Records", "first": "First record", "last": "Last record", "fingerprint": "Signing key fingerprint (SHA-256)",
          "gaps": "Gaps", "periods": "Continuous observation periods", "unobserved": "Message numbers not observed",
          "verified_stamps": "Validated timestamp receipts", "other_stamps": "Other timestamp receipts",
          "anchored_through": "Timestamp covers through record", "unanchored_tail": "Records after that checkpoint",
          "timestamp": "Timestamp", "messages": "Messages", "tasks_done": "Tasks completed", "tasks_total": "Tasks planned",
          "failures": "Failures and gaps", "unchanged": "Unchanged records", "minimised": "Minimized records", "left_out": "Omitted records",
          "drand": "Recorded drand rounds", "starts": "Recorded process starts", "tdx": "Process starts carrying a TDX quote",
          "operator_fields": "Case fields supplied by the operator", "complete": "Completed within selected scope"}
RESULTS = {
    "integrity": "Checked {n} signed journal records; the key still needs independent confirmation.",
    "integrity_unknown": "Independent verification of this copy is still required.",
    "time": "Validated time bound through record #{n}; {tail} later records are outside that bound.",
    "time_unknown": "No independently validated time bound is included in this copy.",
    "coverage": "Recorded gaps: {gaps}. Message numbers not observed: {missing}.",
    "witness": "Recorded drand rounds: {drand}; starts carrying TDX: {tdx}. Independent validation is not supplied.",
    "custody": "Operator declarations supplied: {n}. Identity and custody still need confirmation.",
    "meaning": "Source authenticity, authorship and meaning require corroboration.",
    "complete": "Acquisition completed within the selected scope: {done} of {total} tasks.",
    "partial": "Acquisition is incomplete or its completion cannot be established from this copy.",
    "sharing": "This is a transformed selection; original completeness cannot be inferred.",
    "chat": "History snapshot: earlier edits and deletions are not reconstructed.",
}

CSS = """
.case-assessment .assessment-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin-top:20px}
.assessment-item{border:1px solid #8894a455;border-radius:12px;padding:18px;min-width:0;break-inside:avoid}
.assessment-item h3{margin:0 0 8px;font-size:16px}.assessment-state{font-size:12px;font-weight:600}
.assessment-item p{line-height:1.6;overflow-wrap:anywhere}.assessment-item dl{font-size:12px;display:grid;grid-template-columns:1fr 1fr;gap:6px 12px}
.assessment-item dt,.assessment-item dd{margin:0;overflow-wrap:anywhere}.assessment-item dd{font-family:monospace}
.assessment-review{padding:12px;border-inline-start:3px solid #697d99;margin-top:14px}
@media(max-width:760px){.case-assessment .assessment-grid{grid-template-columns:1fr}}
@media print{.case-assessment .assessment-grid{display:block}.assessment-item{margin-bottom:10px}}
"""


def row(key, status, title, basis, limit, verify, facts=None, references=()):
    return dict(id=key, status=status, title=title, basis=basis, limitation=limit,
                verification=verify, facts=facts or {}, references=list(references))


def result(item, key, **values):
    item["result"] = {"text": RESULTS[key], "values": values}


def verified_stamp(anchor, count):
    try:
        stamp = datetime.fromisoformat(anchor["time"].replace("Z", "+00:00"))
    except (KeyError, AttributeError, TypeError, ValueError):
        return False
    return (anchor.get("kind") == "rfc3161" and anchor.get("checkpoint_bound") is True
            and isinstance(anchor.get("signed"), dict)
            and isinstance(anchor["signed"].get("root_sha256"), str)
            and bool(re.fullmatch(r"[0-9a-f]{64}", anchor["signed"]["root_sha256"])) and stamp.tzinfo is not None
            and type(anchor.get("event_count")) is int and 0 <= anchor["event_count"] <= count)


def common(kind, reference, fingerprint, rows, operator_fields=0, *, archive=False):
    rows.extend([
        row("custody", "recorded" if operator_fields else "incomplete", "Operator and custody",
            "Case details and handover notes are statements supplied by the operator; their inclusion in a signed report preserves those statements.",
            "Signing does not verify the operator's identity, qualifications, lawful authority or an undocumented transfer of custody.",
            "Record who acquired, held and transferred the original ZIP. Preserve its hash, the trusted key fingerprint and independent checkpoint copies separately.",
            {"operator_fields": operator_fields}, ("manifest.json",)),
        row("meaning", "not_checked", "Source and interpretation",
            "The collector records data visible to a Telegram account. The report identifies observations and their selected scope.",
            "Telegram does not sign these records. An account ID is not proof of a person's identity; a message is not proof that its contents are true. Data fabricated before signing can still have valid signatures.",
            "Corroborate disputed content, authorship and collection conditions with independent material. Cite the archive, file and record reference for each claim."),
    ])
    result(rows[-2], "custody", n=operator_fields)
    result(rows[-1], "meaning")
    return {"format": FORMAT, "kind": kind, "reference": reference, "fingerprint": fingerprint,
            "assessment_author": "exporter", "independent_review": "not_performed",
            "supporting_files_included": archive, "checks": rows}


def journal(context, coverage):
    digest, handover = context.get("digest") or {}, context.get("handover")
    count = context.get("event_count") or 0
    anchors = context.get("anchors") or []
    stamps = [a for a in anchors if verified_stamp(a, count)]
    latest = max(stamps, key=lambda a: (a["event_count"], a["time"])) if stamps else None
    counts = (handover or {}).get("counts") or {}
    rows = [row("integrity", "checked_locally" if context.get("journal_verified") is True else "not_checked",
        "Integrity and substitution",
        "The journal chain and record signatures are checked against the exporter's key before packaging. The manifest and report seals bind the files in this copy." if context.get("journal_verified") is True else
        "No export-time journal verification result accompanies this report. Verify the authoritative records before relying on this copy.",
        "A matching key supplied only inside the same archive is not an independent trust anchor. Someone controlling the signing key can construct another valid journal; signatures alone cannot detect that substitution.",
        "Use verify.py from a trusted checkout with --fingerprint and a fingerprint obtained separately. Compare a previously retained checkpoint or an independent witness archive.",
        {"records": count, "first": digest.get("first"), "last": digest.get("last"), "fingerprint": context.get("fingerprint")},
        ("records.jsonl" if handover else "events.jsonl", "manifest.json", "manifest.sig"))]
    facts = {"verified_stamps": len(stamps), "other_stamps": len(anchors) - len(stamps)}
    if latest:
        facts.update(anchored_through=latest["event_count"], timestamp=latest["time"], unanchored_tail=count-latest["event_count"])
    rows.append(row("time", "checked_locally" if latest else "not_included" if not anchors else "incomplete",
        "Independent time bounds",
        "A validated timestamp binds a signed checkpoint to this journal prefix and a certificate chain trusted by this exporter. The counts below separate validated receipts from other files.",
        "A timestamp gives an upper bound for the checkpoint's existence, not the message's sending time. Later records are outside that bound. An OTS receipt or an unvalidated TSA reply is not a confirmed time bound.",
        "Recheck checkpoint inclusion, timestamp imprint, signature and certificate trust using the original receipt. Use --tsa-ca with an independently trusted TSA root; verify OTS against Bitcoin separately.",
        facts, tuple(a["file"] for a in stamps if a.get("file"))))
    coverage = coverage or {}
    rows.append(row("coverage", "recorded" if coverage else "incomplete", "Scope and missing material",
        "Observation periods and interruptions are derived from recorded collector activity. A minimized extract lists how many records were kept, changed or omitted.",
        "No recorded gap does not mean complete delivery. Missing message numbers do not prove deletion. Earlier deletions, inaccessible messages and activity outside the chosen scope may never have been observed.",
        "Compare coverage.json and the selection in manifest.json with the period and chats relevant to the case. Explain each material gap before drawing conclusions from absence.",
        {"gaps": len(coverage.get("gaps") or []), "periods": len(coverage.get("continuous") or []),
         "unobserved": sum(c.get("not_observed", 0) for c in coverage.get("unobserved_ids") or []),
         **{k: counts[k] for k in ("unchanged", "minimised", "left_out") if k in counts}}, ("coverage.json", "manifest.json")))
    signals = digest.get("trust_signals") or {}
    rows.append(row("witness", "not_checked", "Witnesses and collection environment",
        "The counts below describe records included in this copy. A drand entry or a TDX quote is evidence to verify, not a configuration-based assurance badge.",
        "This export has not independently compared a witness journal or established the collector's operating environment. A drand round alone supplies no upper time bound. A TDX label alone does not verify measurements, freshness or key custody.",
        "Compare an independently retained witness ZIP using --witness. Confirm beacon rounds using --check-drand. For TDX, check the quote, challenge, Intel trust chain, measurements and exact deployed source with the assurance verifier.",
        {k: signals.get(k, 0) for k in ("drand", "starts", "tdx")}, ("records.jsonl" if handover else "events.jsonl",)))
    result(rows[0], "integrity" if context.get("journal_verified") is True else "integrity_unknown", n=count)
    result(rows[1], "time" if latest else "time_unknown", n=latest["event_count"] if latest else 0,
           tail=count-latest["event_count"] if latest else 0)
    result(rows[2], "coverage", gaps=rows[2]["facts"]["gaps"], missing=rows[2]["facts"]["unobserved"])
    result(rows[3], "witness", drand=signals.get("drand", 0), tdx=signals.get("tdx", 0))
    options = context.get("options") or {}
    return common("handover" if handover else "evidence", context.get("report_id"), context.get("fingerprint"), rows,
                  sum(bool(options.get(k)) for k in ("case_title", "case_id", "examiner", "organization", "notes")),
                  archive=context.get("archive") is True)


def snapshot(context, kind="account", meta=None):
    meta = meta or {}
    sharing = kind == "sharing"
    chat = kind in ("chat", "account_chat")
    counts, coverage = context.get("counts") or {}, context.get("coverage") or {}
    complete = (context.get("complete_within_scope") is True and coverage.get("inventory_complete") is True
                and type(coverage.get("failures")) is int and coverage["failures"] == 0
                and type(coverage.get("tasks_total")) is int and coverage.get("tasks_done") == coverage["tasks_total"])
    rows = [row("integrity", "not_checked", "Integrity and substitution",
        "The signed manifest binds the authoritative data files and readable report to the key named in this copy.",
        "This is an exporter's signature, not Telegram's signature. Trusting a key from the same ZIP cannot exclude wholesale replacement or fabrication before signing.",
        "Verify the original ZIP with a trusted copy of verify.py and --fingerprint from a separate trusted channel. Keep the verification result with the unchanged ZIP.",
        {"fingerprint": context.get("fingerprint")}, ("manifest.json", "manifest.sig")),
        row("scope", "recorded" if sharing or chat or complete else "incomplete", "Scope and missing material",
            "This sharing copy is a separately signed derivative with selected or transformed content." if sharing else
            "This is a history acquisition within the selected scope. Completion counts describe acquisition tasks, not everything that ever existed on Telegram.",
            "A signed derivative does not by itself prove correct derivation from the original. Names, text and context may have been changed or omitted." if sharing else
            "History is not an atomic snapshot. Earlier versions, earlier deletions, inaccessible content and changes during collection may be absent.",
            "Review the public selection and transformations. If authorized, compare the derivative against the separately retained original." if sharing else
            "Review filters, limits, task failures and message-ID coverage against the specific period and conversations needed for the case.",
            {"messages": meta.get("message_count", counts.get("messages")), **({} if sharing or chat else
             {"complete": complete, **{k: coverage[k] for k in ("tasks_done", "tasks_total", "failures") if k in coverage}})},
            ("messages.jsonl", "manifest.json") if sharing else ("chat.json", "message-ids.json") if kind == "chat" else ("inventory.json", "manifest.json")),
        row("time", "not_included", "Independent time bounds",
            "This copy contains capture or export times recorded by the collector.",
            "The snapshot workflow does not provide independent timestamp or witness verification for these messages. A recorded time is not a trusted upper bound.",
            "Preserve independent receipts for the original archive hash when available. Do not describe collector clock values as independently certified times."),
    ]
    options = context.get("options") or {}
    result(rows[0], "integrity_unknown")
    result(rows[1], "sharing" if sharing else "chat" if chat else "complete" if complete else "partial",
           **({"done":coverage.get("tasks_done"), "total":coverage.get("tasks_total")} if complete and not sharing and not chat else {}))
    result(rows[2], "time_unknown")
    return common(kind, context.get("archive_reference") or context.get("report_id"), context.get("fingerprint"), rows,
                  0 if sharing else sum(bool(options.get(k)) for k in ("case_title", "case_id", "examiner", "organization", "notes")),
                  archive=context.get("archive") is True)


def fact_text(value, say):
    return say("Yes" if value else "No") if isinstance(value, bool) else str(value) if value is not None else say("Not recorded")


def html(data, say):
    e = lambda value: escape(str(value), quote=True)
    parts = ['<section class="card panel case-assessment" id="case-assessment"><h2>' + e(say(TITLE)) + '</h2><p>' + e(say(INTRO)) + '</p>']
    if not data.get("supporting_files_included"):
        parts.append('<p class="assessment-review">' + e(say(STANDALONE)) + '</p>')
    parts.append('<ol class="assessment-overview" aria-label="' + e(say(OVERVIEW)) + '">')
    for number, item in enumerate(data["checks"], 1):
        parts.append('<li data-status="' + e(item["status"]) + '"><a href="#assessment-' + e(item["id"]) + '">'
                     '<span class="assessment-index">' + f'{number:02d}' + '</span><strong>' + e(say(item["title"]))
                     + '</strong><span class="assessment-state">' + e(say(STATUSES[item["status"]])) + '</span></a></li>')
    parts.append('</ol>')
    parts.append('<div class="assessment-grid">')
    for number, item in enumerate(data["checks"], 1):
        conclusion = item["result"]
        parts.append('<article class="assessment-item" id="assessment-' + e(item["id"]) + '" data-status="' + e(item["status"]) + '" data-assessment="' + e(item["id"]) + '"><div class="assessment-heading"><span class="assessment-index">'
                     + f'{number:02d}' + '</span><h3>' + e(say(item["title"])) + '</h3></div><div class="assessment-state">' + e(say(STATUSES[item["status"]]))
                     + '</div><p class="assessment-result">' + e(say(conclusion["text"], **conclusion["values"])) + '</p><p class="assessment-basis">' + e(say(item["basis"])) + '</p><dl>')
        parts.extend('<dt>' + e(say(LABELS.get(k, k))) + '</dt><dd dir="auto">' + e(fact_text(v, say)) + '</dd>' for k, v in item["facts"].items())
        parts.append('</dl><p class="assessment-limit"><strong>' + e(say("Limits of this conclusion")) + '</strong>' + e(say(item["limitation"])) + '</p><p class="assessment-review"><strong>' + e(say("Independent review")) + '</strong>' + e(say(item["verification"])) + '</p>')
        if item["references"]:
            parts.append('<p class="assessment-references">' + e(say("Evidence references")) + ': ' + e(', '.join(item["references"])) + '</p>')
        parts.append('</article>')
    return ''.join(parts) + '</div></section>'


def pdf(lay, data):
    say = lay.say
    lay.section(say(TITLE), say(INTRO))
    if not data.get("supporting_files_included"):
        lay.callout(say(STANDALONE))
    lay.assessment_overview(data)
    lay.pdf.add_page()
    for number, item in enumerate(data["checks"], 1):
        lay.assessment_card(number, item)


def text_keys():
    examples = [journal({}, {}), snapshot({}), snapshot({}, "sharing"), snapshot({}, "chat"), journal({"journal_verified": True}, {})]
    return list(dict.fromkeys([TITLE, INTRO, OVERVIEW, "Limits of this conclusion", "Independent review", "Evidence references", "Not recorded",
                              *STATUSES.values(), *LABELS.values(),
                              *(r[k] for data in examples for r in data["checks"] for k in ("title", "basis", "limitation", "verification")), *RESULTS.values(), STANDALONE]))
