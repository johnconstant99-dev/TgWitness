
import base64
import hashlib
import html
import json
import re
from pathlib import Path

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import __version__, tsa_roots
from .anchor import timestamp_request
from .cloud_report import COVERAGE_TITLE, SCOPE_TITLE
from .store import canonical, utcnow
from .verify import fingerprint, read_pdf_seal, timestamp_reply_summary, timestamp_signature, timestamp_token

TIME_STAMPS = (tsa_roots.QUALIFIED_TSA, "https://freetsa.org/tsr")
SEAL_FORMAT = "tgwitness-verification-seal-v1"
STATUS = {"pass": "PASS", "review": "REVIEW", "unavailable": "UNAVAILABLE", "fail": "FAIL", "incomplete": "INCOMPLETE"}
TRUST_CHAIN = (
    ("tdx_quote", "Intel SGX Root CA", "Intel's root, pinned in the verifier; the platform's PCK certificate chains "
                                       "to it, and Intel's signed TCB data rate the platform"),
    ("tdx_binding", "Intel TDX quote", "signed by the CPU's quoting enclave over SHA-512 of the collector's "
                                       "statement and this request's random challenge"),
    ("tdx_os", "Firmware, kernel, initrd, command line", "MRTD and RTMR0-2 equal what the published dstack OS image "
                                                         "and QEMU's ACPI tables for this VM give"),
    ("tdx_compose_hash", "App-compose", "RTMR3, replayed from dstack's event log, measures the compose the collector "
                                        "reports"),
    ("tdx_compose", "TgWitness commit", "the compose is byte for byte the one the commit's own code builds: source "
                                        "pinned by hash, images by digest, nothing else runs"),
    ("tdx_identity", "This CVM", "the deployed application and instance, with keys from the KMS"),
    ("fingerprint", "Collector key", "created inside the CVM; the key that signs the evidence journal"),
)
COMPARISON = (
    ("The host or provider staff can read the collector's memory", "yes", "yes", "no: encrypted by the CPU"),
    ("Proof of which code runs", "none", "the collector's own report", "Intel-signed measurement"),
    ("Proof of the operating system", "none", "the collector's own report", "measured, equal to the published image"),
    ("A changed compose or extra code", "not seen", "seen in installer hashes the collector reports",
     "seen in RTMR3 and the provider's revisions"),
    ("The signing key can be copied out", "by root", "by root on the server", "only by code the measurement shows"),
)


class SealError(ValueError):
    pass


def esc(value):
    return html.escape(str(value if value is not None else "—"))


def short(value, size=16):
    text = str(value or "")
    return text if len(text) <= size else text[:size] + "…"


def common_name(name):
    found = re.search(r"(?:^|,)CN=([^,]+)", str(name or ""))
    organisation = re.search(r"(?:^|,)O=([^,]+)", str(name or ""))
    if not found:
        return str(name or "")
    return found.group(1) + (" (" + organisation.group(1) + ")" if organisation and organisation.group(1) not in
                             found.group(1) else "")


def readable(timestamp):
    found = re.match(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})", str(timestamp or ""))
    return found.group(1) + " " + found.group(2) + " UTC" if found else str(timestamp or "—")


def checks(report):
    return {c["check"]: c for c in report.get("checks") or []}


def time_stamp(data, url, session=None):
    query = timestamp_request(data)
    response = (session or requests).post(url, data=query, timeout=30, headers={
        "Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply"})
    if response.status_code != 200:
        raise SealError(url + " answered HTTP " + str(response.status_code))
    return query, response.content


def described(reply, digest, query, *, include_reference=False):
    summary = timestamp_reply_summary(reply, digest, query)
    signed = timestamp_signature(reply, tsa_roots.trusted_roots(), include_reference=include_reference)
    signer = next(x509.load_der_x509_certificate(c) for c in timestamp_token(reply)["certificates"]
                  if hashlib.sha256(c).hexdigest() == signed["signer_sha256"])
    return {"time": summary["time"], **signed, "qualified": tsa_roots.qualified(signer)}


def service(url):
    return re.sub(r"[^a-z0-9]+", "-", url.split("//", 1)[-1].lower()).strip("-")[:40]


def seal(base, vault=None, tsas=TIME_STAMPS, session=None, stamp=None):
    base = Path(base)
    data = base.with_suffix(".json").read_bytes()
    digest = hashlib.sha256(data).digest()
    stamps = []
    for url in tsas:
        try:
            query, reply = (stamp or time_stamp)(data, url, session)
            info = described(reply, digest, query)
        except (requests.RequestException, ValueError, StopIteration) as exc:
            stamps.append({"tsa": url, "error": type(exc).__name__ + ": " + str(exc)[:200]})
            continue
        name = base.name + "." + service(url)
        base.with_name(name + ".tsq").write_bytes(query)
        base.with_name(name + ".tsr").write_bytes(reply)
        stamps.append({"tsa": url, "query": name + ".tsq", "reply": name + ".tsr",
                       "reply_sha256": hashlib.sha256(reply).hexdigest(), **info})
    statement = {"format": SEAL_FORMAT, "report": base.with_suffix(".json").name, "report_sha256": digest.hex(),
                 "sealed_at": utcnow(), "verifier": {"software": "TgWitness", "version": __version__},
                 "time_stamps": [s for s in stamps if "error" not in s]}
    sealed = {"statement": statement, "failed_time_stamps": [s for s in stamps if "error" in s]}
    if vault is not None:
        statement["public_key"] = vault.public_key
        sealed.update(signature=vault.sign(canonical(statement)), fingerprint=fingerprint(vault.public_key))
    base.with_suffix(".seal.json").write_text(json.dumps(sealed, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return sealed


def check(base, expected_fingerprint=None):
    base = Path(base)
    data = base.with_suffix(".json").read_bytes()
    sealed = json.loads(base.with_suffix(".seal.json").read_text(encoding="utf-8"))
    statement, found = sealed["statement"], []
    if statement.get("format") != SEAL_FORMAT:
        raise SealError("not a TgWitness verification seal")
    if statement["report_sha256"] != hashlib.sha256(data).hexdigest():
        raise SealError(base.with_suffix(".json").name + " is not the sealed report: its SHA-256 differs")
    found.append(("report", "SHA-256 " + statement["report_sha256"]))
    if sealed.get("signature"):
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(statement["public_key"], validate=True)).verify(
                base64.b64decode(sealed["signature"], validate=True), canonical(statement))
        except (InvalidSignature, ValueError, KeyError):
            raise SealError("the verifier's signature over the seal is invalid") from None
        key = fingerprint(statement["public_key"])
        if expected_fingerprint and key != expected_fingerprint.lower():
            raise SealError("the seal is signed by verifier key " + key + ", not the expected one")
        found.append(("verifier", "signature valid, key " + key + (" (as expected)" if expected_fingerprint else
                                                                    "; compare it with the verifier's published key")))
    else:
        found.append(("verifier", "not signed by a verifier key"))
    for stamp in statement.get("time_stamps") or []:
        reply = base.with_name(stamp["reply"]).read_bytes()
        query = base.with_name(stamp["query"]).read_bytes()
        if hashlib.sha256(reply).hexdigest() != stamp["reply_sha256"]:
            raise SealError(stamp["reply"] + " is not the time stamp the seal names")
        info = described(reply, bytes.fromhex(statement["report_sha256"]), query, include_reference=True)
        found.append(("time stamp", readable(info["time"]) + " by " + common_name(info["signer"]) + ", root "
                      + common_name(info["root"])
                      + ("; qualified eIDAS time stamp, " + info["qualified"]["service"] + " granted on the "
                         + info["qualified"]["trusted_list"]["territory"] + " trusted list since "
                         + info["qualified"]["since"] if info["qualified"] else "")))
        found.append(("certificate reference", info["certificate_reference"]))
        found.extend(("time stamp warning", warning) for warning in info["warnings"])
    pdf = base.with_suffix(".pdf")
    if pdf.exists() and sealed.get("signature"):
        content, pdf_seal, info = read_pdf_seal(pdf.read_bytes())
        signed = pdf_seal["statement"]
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(signed["public_key"], validate=True)).verify(
                base64.b64decode(pdf_seal["signature"], validate=True), canonical(signed))
        except (InvalidSignature, ValueError, KeyError):
            raise SealError("the PDF's seal is not signed by its key") from None
        if signed.get("content_sha256") != content or signed.get("report_sha256") != statement["report_sha256"]:
            raise SealError(pdf.name + " is not a signed rendering of the sealed report")
        if signed["public_key"] != statement["public_key"]:
            raise SealError(pdf.name + " is signed by another verifier key")
        found.append(("pdf", pdf.name + " signed by the same verifier key, document certificate "
                      + info["certificate_sha256"][:16] + "…, covering the whole file"))
    return found


CSS = """
:root{--ink:#0f172a;--muted:#5b6475;--line:#e3e7ee;--paper:#ffffff;--tint:#f5f7fb;--gold:#b58a2e;--ok:#11795b;
--okbg:#e7f6f0;--warn:#a15c07;--warnbg:#fdf3e2;--bad:#b42318;--badbg:#fdecea;--gray:#556070;--graybg:#eef1f5}
*{box-sizing:border-box}body{margin:0;background:#e9edf3;color:var(--ink);font:14px/1.55 "Segoe UI",Inter,
system-ui,-apple-system,Arial,sans-serif}.page{max-width:1080px;margin:28px auto;background:var(--paper);
box-shadow:0 18px 60px rgba(15,23,42,.14);border-radius:14px;overflow:hidden}
header{background:linear-gradient(135deg,#0b1222 0%,#16233f 60%,#1d2f55 100%);color:#fff;padding:34px 44px 30px;
position:relative}header .brand{letter-spacing:.32em;font-weight:700;font-size:12px;opacity:.85}
header h1{font-size:30px;margin:14px 0 4px;font-weight:700}header .sub{opacity:.82;font-size:15px}
header .rule{position:absolute;left:44px;bottom:0;width:64px;height:4px;background:var(--gold)}
.verdict{display:inline-block;margin-top:18px;padding:7px 16px;border-radius:999px;font-weight:700;
letter-spacing:.08em;font-size:13px}.v-pass{background:#1f9d6f}.v-review{background:#c27a12}.v-fail{background:#c0352b}
.v-incomplete{background:#5a6474}.meta{margin-top:14px;font-size:12px;opacity:.78}
main{padding:30px 44px 40px}section{margin:0 0 30px;break-inside:avoid-page}
h2{font-size:18px;margin:0 0 4px;display:flex;gap:12px;align-items:baseline}h2 .n{color:var(--gold);
font-size:13px;font-weight:700;letter-spacing:.1em}.lead{color:var(--muted);margin:0 0 14px}
.summary{font-size:17px;line-height:1.6;padding:18px 22px;border-left:4px solid var(--gold);background:var(--tint);
border-radius:0 10px 10px 0}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.card{border:1px solid var(--line);border-radius:10px;padding:13px 15px;background:#fff}
.card .k{font-size:11px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted)}
.card .v{font-weight:650;margin-top:3px;word-break:break-all}.mono{font-family:"Cascadia Mono",Consolas,
"SFMono-Regular",Menlo,monospace;font-size:12px}table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
border-bottom:2px solid var(--line);padding:8px 10px}td{border-bottom:1px solid var(--line);padding:9px 10px;
vertical-align:top}td.mono{word-break:break-all}.pill{display:inline-block;border-radius:999px;padding:2px 10px;
font-size:11px;font-weight:700;letter-spacing:.06em}.s-pass{background:var(--okbg);color:var(--ok)}
.s-review{background:var(--warnbg);color:var(--warn)}.s-fail{background:var(--badbg);color:var(--bad)}
.s-unavailable,.s-incomplete{background:var(--graybg);color:var(--gray)}
.chain{position:relative;margin-left:8px}.step{display:grid;grid-template-columns:34px 1fr;gap:14px;
padding:0 0 14px;position:relative}.step:before{content:"";position:absolute;left:16px;top:30px;bottom:0;width:2px;
background:var(--line)}.step:last-child:before{display:none}.dot{width:34px;height:34px;border-radius:50%;
display:flex;align-items:center;justify-content:center;font-weight:800;font-size:15px;color:#fff}
.d-pass{background:#1f9d6f}.d-review{background:#c27a12}.d-fail{background:#c0352b}.d-unavailable{background:#8a93a3}
.step .t{font-weight:650}.step .d{color:var(--muted);font-size:13px}.compare td:last-child{font-weight:650;
color:var(--ok)}.compare th:last-child{color:var(--ok)}.two{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.list{margin:0;padding-left:18px}.list li{margin:0 0 6px}.yes h3{color:var(--ok)}.no h3{color:var(--bad)}
h3{font-size:14px;margin:0 0 8px}.seal{border:1px solid #e2d3ad;background:linear-gradient(180deg,#fffaf0,#fff);
border-radius:12px;padding:16px 18px;margin-bottom:12px}.seal .q{display:inline-block;background:#173a8a;color:#fff;
font-size:11px;font-weight:700;border-radius:6px;padding:2px 8px;margin-left:8px}
pre{background:#0f172a;color:#dbe4f3;padding:14px 16px;border-radius:10px;overflow:auto;font-size:12px}
details summary{cursor:pointer;color:var(--muted)}footer{border-top:1px solid var(--line);padding:18px 44px;
color:var(--muted);font-size:12px}
@media print{body{background:#fff}.page{box-shadow:none;margin:0;border-radius:0;max-width:none}
header{-webkit-print-color-adjust:exact;print-color-adjust:exact}.pill,.dot,.verdict{-webkit-print-color-adjust:exact;
print-color-adjust:exact}details{display:none}@page{size:A4;margin:12mm}}
@media(max-width:760px){.cards,.two{grid-template-columns:1fr}header,main,footer{padding-left:20px;padding-right:20px}}
"""


def verdict_text(report):
    found = checks(report)
    attestation = report.get("attestation") or {}
    statement = (report.get("collector_statement") or {}).get("statement") or {}
    os_image = attestation.get("os_image") or {}
    intel = attestation.get("intel") or {}
    commit = (report.get("deployment") or {}).get("commit")
    parts = []
    if found.get("tdx_quote", {}).get("status") in ("pass", "review"):
        parts.append("The collector answered from a genuine Intel TDX confidential VM" + (
            ", rated " + intel["status"] + " by Intel" if intel.get("status") else ""))
    if found.get("tdx_compose", {}).get("status") == "pass":
        parts.append("it runs TgWitness commit " + short(commit, 12) + " and nothing else")
    if found.get("tdx_os", {}).get("status") == "pass":
        parts.append("its firmware, kernel and command line are the published " + str(os_image.get("image")))
    if statement.get("fingerprint"):
        parts.append("its evidence is signed by key " + short(statement["fingerprint"], 16) + ", made inside the CVM")
    text = "; ".join(parts) + "." if parts else "The attestation did not verify."
    worst = report.get("result")
    if worst in ("review", "incomplete"):
        text += " Some checks need review or were unavailable; they are listed below."
    if worst == "fail":
        text += " At least one check failed; do not rely on this deployment before reading why."
    return text


def html_report(report, sealed=None):
    found, attestation = checks(report), report.get("attestation") or {}
    deployment, server = report.get("deployment") or {}, report.get("server") or {}
    statement = (report.get("collector_statement") or {}).get("statement") or {}
    quote, intel, os_image = attestation.get("quote") or {}, attestation.get("intel") or {}, attestation.get("os_image") or {}
    result = report.get("result", "incomplete")
    out = ["<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,"
           "initial-scale=1'><title>TgWitness attestation certificate · ", esc(deployment.get("name")),
           "</title><style>", CSS, "</style></head><body><div class=page><header><div class=brand>TG / WITNESS</div>"
           "<h1>Hardware attestation certificate</h1><div class=sub>", esc(report.get("provider_title")),
           " · Intel TDX confidential virtual machine · deployment ", esc(deployment.get("name")), "</div>",
           "<div class='verdict v-", esc(result if result in ("pass", "review", "fail") else "incomplete"), "'>",
           esc(STATUS.get(result, result.upper())), "</div><div class=meta>Checked ", esc(readable(report.get("generated_at"))),
           " by ", esc((report.get("verifier") or {}).get("software")), " ", esc((report.get("verifier") or {}).get("version")),
           (" · report SHA-256 " + esc(short(sealed["statement"]["report_sha256"], 32)) if sealed else ""),
           "</div><div class=rule></div></header><main>"]
    out += ["<section><h2><span class=n>01</span>Verdict</h2><p class=summary>", esc(verdict_text(report)), "</p></section>"]
    cards = [("Collector key", statement.get("fingerprint")), ("TgWitness commit", deployment.get("commit")),
             ("Intel TCB", (intel.get("status") or "—") + (" · FMSPC " + intel["fmspc"] if intel.get("fmspc") else "")),
             ("OS image", os_image.get("image") or "not compared"), ("VM", os_image.get("machine") or "—"),
             ("CVM", str(server.get("id") or "—") + (" · " + str(server.get("location")) if server.get("location") else "")),
             ("App ID", (attestation.get("identity") or {}).get("app_id")),
             ("Instance", (attestation.get("identity") or {}).get("instance_id")),
             ("Compose hash", (attestation.get("identity") or {}).get("compose_hash"))]
    out.append("<section><h2><span class=n>02</span>At a glance</h2><div class=cards>")
    out += ["<div class=card><div class=k>" + esc(k) + "</div><div class='v mono'>" + esc(v) + "</div></div>" for k, v in cards]
    out.append("</div></section>")
    out.append("<section><h2><span class=n>03</span>Chain of trust</h2><p class=lead>Each link is checked by this "
               "verifier itself, from Intel's root to the key that signs the evidence.</p><div class=chain>")
    for check, title, detail in TRUST_CHAIN:
        status = found.get(check, {}).get("status", "unavailable")
        mark = {"pass": "✓", "review": "!", "fail": "✕"}.get(status, "·")
        out.append("<div class=step><div class='dot d-" + esc(status) + "'>" + mark + "</div><div><div class=t>"
                   + esc(title) + " <span class='pill s-" + esc(status) + "'>" + esc(STATUS.get(status, status)) + "</span></div>"
                   + "<div class=d>" + esc(detail) + "</div><div class='d mono'>"
                   + esc(found.get(check, {}).get("detail", "")[:600]) + "</div></div></div>")
    out.append("</div></section>")
    out.append("<section><h2><span class=n>04</span>What makes this deployment different</h2><p class=lead>The same "
               "collector, three ways of running it.</p><table class=compare><tr><th></th><th>Ordinary server</th>"
               "<th>High-assurance server</th><th>This deployment: Intel TDX</th></tr>")
    out += ["<tr><td>" + "</td><td>".join(esc(c) for c in row) + "</td></tr>" for row in COMPARISON]
    out.append("</table></section>")
    registers = [("MRTD", "firmware", quote.get("mrtd"), os_image.get("mrtd")),
                 ("RTMR0", "firmware configuration, memory, ACPI tables", quote.get("rtmr0"), os_image.get("rtmr0")),
                 ("RTMR1", "kernel", quote.get("rtmr1"), os_image.get("rtmr1")),
                 ("RTMR2", "command line and initrd", quote.get("rtmr2"), os_image.get("rtmr2")),
                 ("RTMR3", "app-compose and dstack events", quote.get("rtmr3"), None)]
    out.append("<section><h2><span class=n>05</span>Measurements</h2><p class=lead>Registers the CPU signed in the "
               "quote, against the values computed from the published image.</p><table><tr><th>Register</th>"
               "<th>Measures</th><th>In the quote</th><th>Computed</th></tr>")
    for name, what, quoted, computed in registers:
        match = "—" if computed is None else ("<span class='pill s-pass'>EQUAL</span>" if computed == quoted
                                              else "<span class='pill s-fail'>DIFFERENT</span>")
        out.append("<tr><td><b>" + name + "</b></td><td>" + esc(what) + "</td><td class=mono>" + esc(quoted) + "</td><td>"
                   + match + "</td></tr>")
    out.append("</table>")
    if os_image.get("cmdline"):
        out.append("<p class=lead style='margin-top:10px'>Measured command line: <span class=mono>"
                   + esc(os_image["cmdline"]) + "</span></p>")
    out.append("</section>")
    out.append("<section><h2><span class=n>06</span>Certified by</h2><p class=lead>Who vouches for each part, and how "
               "this verifier checked them.</p><table><tr><th>Statement</th><th>Vouched for by</th><th>Checked</th></tr>")
    certified = [("The machine is a genuine Intel TDX platform at the TCB level shown", "Intel, through the SGX Root "
                  "CA and its signed TCB Info and revocation lists", found.get("tdx_quote", {}).get("status")),
                 ("The OS is the published dstack image", "Dstack-TEE's published release, matched by measurement",
                  found.get("tdx_os", {}).get("status")),
                 ("The code is the TgWitness commit", "the commit's source on GitHub, rebuilt by this verifier",
                  found.get("tdx_compose", {}).get("status")),
                 ("The provider did not change the compose", "Phala Cloud's revisions and operations",
                  found.get("provider_actions", {}).get("status")),
                 ("Every collector start was attested", "the evidence journal, each start with its own Intel quote",
                  found.get("journal", {}).get("status"))]
    for text, who, status in certified:
        status = status or "unavailable"
        out.append("<tr><td>" + esc(text) + "</td><td>" + esc(who) + "</td><td><span class='pill s-" + esc(status) + "'>"
                   + esc(STATUS.get(status, status)) + "</span></td></tr>")
    out.append("</table>")
    if attestation.get("certificates"):
        out.append("<h3 style='margin-top:16px'>Intel certificate chain in the quote</h3><table><tr><th>Subject</th>"
                   "<th>Valid</th><th>SHA-256</th></tr>")
        for c in attestation["certificates"]:
            out.append("<tr><td>" + esc(common_name(c["subject"])) + (" <span class='pill s-pass'>"
                       "PINNED ROOT</span>" if c.get("pinned_root") else "") + "</td><td>" + esc(c["not_before"][:10])
                       + " – " + esc(c["not_after"][:10]) + "</td><td class=mono>" + esc(c["sha256"]) + "</td></tr>")
        out.append("</table>")
    out.append("</section>")
    out.append("<section><h2><span class=n>07</span>Seals of this report</h2>")
    if sealed:
        st = sealed["statement"]
        for stamp in st.get("time_stamps") or []:
            q = stamp.get("qualified")
            out.append("<div class=seal><b>RFC 3161 time stamp</b>" + ("<span class=q>eIDAS QUALIFIED</span>" if q else "")
                       + "<div class=mono>" + esc(readable(stamp["time"])) + " · " + esc(stamp["tsa"]) + "</div><div>"
                       "Signed by " + esc(common_name(stamp["signer"])) + "; chain to " + esc(common_name(stamp["root"]))
                       + "</div>")
            if q:
                out.append("<div>Qualified electronic time stamp (eIDAS Regulation (EU) No 910/2014, art. 41–42) from "
                           + esc(q["provider"]) + ", service " + esc(q["service"]) + ": status <b>" + esc(q["status"])
                           + "</b> since " + esc(q["since"][:10]) + " on the " + esc(q["trusted_list"]["territory"])
                           + " trusted list (" + esc(q["trusted_list"]["url"]) + ", issued "
                           + esc(q["trusted_list"]["issued"][:10]) + "). It is presumed accurate as to date and time, "
                           "and the report's integrity since then is presumed, in every EU member state.</div>")
            out.append("</div>")
        if sealed.get("fingerprint"):
            out.append("<div class=seal><b>Verifier signature</b><div>Ed25519 over the seal statement, which names the "
                       "report's SHA-256 and every time stamp.</div><div class=mono>key " + esc(sealed["fingerprint"])
                       + "</div></div>")
        out.append("<p class=lead>Report SHA-256 <span class=mono>" + esc(st["report_sha256"]) + "</span>. Check the seal: "
                   "<span class=mono>python -m tgwitness.cloud check-report --report " + esc(st["report"]) + "</span></p>")
    else:
        out.append("<p class=lead>This report is not sealed.</p>")
    out.append("</section>")
    out.append("<section><h2><span class=n>08</span>All checks</h2><table><tr><th>Result</th><th>Check</th><th>Detail</th>"
               "<th>Source</th></tr>")
    for c in report.get("checks") or []:
        out.append("<tr><td><span class='pill s-" + esc(c["status"]) + "'>" + esc(STATUS.get(c["status"], c["status"]))
                   + "</span></td><td><b>" + esc(c["title"]) + "</b><div class='mono' style='color:#8a93a3'>"
                   + esc(c["check"]) + "</div></td><td>" + esc(c["detail"]) + "</td><td>" + esc(c["source"]) + "</td></tr>")
    out.append("</table></section>")
    if report.get("provider_actions"):
        out.append("<section><h2><span class=n>09</span>Provider log</h2><table><tr><th>Action</th><th>Started</th>"
                   "<th>Actor</th><th>Assessment</th></tr>")
        for a in report["provider_actions"]:
            out.append("<tr><td>" + esc(a.get("command")) + " <span class=mono>" + esc(short(a.get("id"), 20)) + "</span></td><td>"
                       + esc(a.get("started")) + "</td><td>" + esc(a.get("actor")) + "</td><td><span class='pill s-"
                       + esc(a.get("assessment")) + "'>" + esc(STATUS.get(a.get("assessment"), a.get("assessment")))
                       + "</span> " + esc(a.get("meaning")) + "</td></tr>")
        out.append("</table></section>")
    out.append("<section><h2><span class=n>10</span>" + COVERAGE_TITLE + "</h2><div class=two>"
               "<div class=yes><h3>Establishes</h3><ul class=list>")
    out += ["<li>" + esc(t) + "</li>" for t in report.get("establishes") or []]
    out.append("</ul></div><div class=no><h3>" + SCOPE_TITLE + "</h3><ul class=list>")
    out += ["<li>" + esc(t) + "</li>" for t in report.get("does_not_establish") or []]
    out.append("</ul></div></div></section>")
    out.append("<section><h2><span class=n>11</span>Repeat the verification</h2><pre>python -m tgwitness.cloud verify "
               "--record deployment.json --provider-token-file READ_ONLY_KEY \\\n    --fingerprint "
               + esc(report.get("fingerprint")) + " --cloud-init docker-compose.yaml \\\n    --source CHECKOUT_OF_COMMIT "
               "--evidence tgwitness-evidence.zip --report verification.md</pre>"
               "<details><summary>Full JSON report</summary><pre>" + esc(json.dumps(report, indent=2, ensure_ascii=False))
               + "</pre></details></section>")
    out.append("</main><footer>TgWitness attestation certificate · PhishDestroy · https://github.com/phishdestroy/TgWitness"
               " · This page is a rendering of the sealed JSON report; the JSON and its seal are authoritative.</footer>"
               "</div></body></html>\n")
    return "".join(out)


def pdf_report(report, sealed=None, vault=None):
    from . import pdf_report as pdf_module
    from .pdf_report import BAD, GOLD, MUTED, OK, Layout, Mono
    from .report import Words
    say = Words("en")
    deployment = report.get("deployment") or {}
    found, attestation = checks(report), report.get("attestation") or {}
    quote, intel, os_image = attestation.get("quote") or {}, attestation.get("intel") or {}, attestation.get("os_image") or {}
    statement = (report.get("collector_statement") or {}).get("statement") or {}
    pdf = pdf_module.document(say, "Attestation certificate · " + str(deployment.get("name")) + " · "
                              + readable(report.get("generated_at")))
    lay = Layout(pdf, say)
    result = report.get("result", "incomplete")
    seal_note = ("Sealed: " + ", ".join(readable(s["time"]) + " " + ("qualified eIDAS time stamp" if s.get("qualified")
                                                                      else "RFC 3161 time stamp")
                                        for s in sealed["statement"]["time_stamps"])
                 + ("; verifier key " + sealed["fingerprint"][:16] + "…" if sealed.get("fingerprint") else "")
                 if sealed else "Not sealed")
    lay.title_block("Hardware attestation certificate · " + str(report.get("provider_title")),
                    "TgWitness on an Intel TDX confidential VM: " + STATUS.get(result, result.upper()),
                    [("Deployment", deployment.get("name")), ("Checked", readable(report.get("generated_at"))),
                     ("Commit", short(deployment.get("commit"), 20)), ("Collector key", short(statement.get("fingerprint"), 24)),
                     ("OS image", os_image.get("image")), ("Intel TCB", intel.get("status"))], seal_note,
                    kind="Attestation certificate")
    lay.section("Verdict")
    lay.text(verdict_text(report), size=11, height=5.6)
    lay.gap(2)
    lay.section("Chain of trust", "Each link is checked by the verifier itself, from Intel's root to the key that "
                                  "signs the evidence.")
    lay.grid(["", "Link", "Checked"], [[STATUS.get(found.get(c, {}).get("status", "unavailable"), "—"), t + ": " + d,
                                        found.get(c, {}).get("detail", "")[:300]] for c, t, d in TRUST_CHAIN], widths=(16, 52, 62))
    lay.section("What makes this deployment different")
    lay.grid(["", "Ordinary server", "High-assurance server", "Intel TDX (this)"], [list(r) for r in COMPARISON],
             widths=(40, 24, 30, 36))
    lay.section("Measurements", "Registers the CPU signed, against values computed from the published image.")
    rows = []
    for name, key in (("MRTD", "mrtd"), ("RTMR0", "rtmr0"), ("RTMR1", "rtmr1"), ("RTMR2", "rtmr2"), ("RTMR3", "rtmr3")):
        computed = os_image.get(key)
        rows.append([name, Mono(quote.get(key) or "—"), "—" if computed is None else "equal" if computed == quote.get(key)
                     else "DIFFERENT"])
    lay.grid(["Register", "In the quote", "Computed"], rows, widths=(16, 94, 20))
    lay.section("Certified by")
    lay.grid(["Statement", "Vouched for by", "Checked"], [
        ["Genuine Intel TDX platform, TCB " + str(intel.get("status")), "Intel SGX Root CA, TCB Info, revocation lists",
         STATUS.get(found.get("tdx_quote", {}).get("status"), "—")],
        ["OS is the published " + str(os_image.get("image")), "Dstack-TEE release, matched by measurement",
         STATUS.get(found.get("tdx_os", {}).get("status"), "—")],
        ["Code is the TgWitness commit", "commit source on GitHub, rebuilt here",
         STATUS.get(found.get("tdx_compose", {}).get("status"), "—")],
        ["Provider did not change the compose", "Phala Cloud revisions and operations",
         STATUS.get(found.get("provider_actions", {}).get("status"), "—")]], widths=(52, 54, 24))
    if attestation.get("certificates"):
        lay.heading("Intel certificate chain in the quote")
        lay.grid(["Subject", "Valid", "SHA-256"], [[common_name(c["subject"])
                                                    + (" (pinned root)" if c.get("pinned_root") else ""),
                                                    c["not_before"][:10] + " – " + c["not_after"][:10], Mono(c["sha256"])]
                                                   for c in attestation["certificates"]], widths=(44, 30, 56))
    lay.section("Seals of this report")
    if sealed:
        st = sealed["statement"]
        for stamp in st.get("time_stamps") or []:
            q = stamp.get("qualified")
            lay.kv([("Time stamp", readable(stamp["time"]) + (" — qualified eIDAS time stamp" if q else " — RFC 3161")),
                    ("Authority", stamp["tsa"]), ("Signed by", common_name(stamp["signer"])),
                    ("Root", common_name(stamp["root"])),
                    ("Trusted list", q and (q["provider"] + ", " + q["service"] + ": " + q["status"] + " since "
                                            + q["since"][:10] + " on the " + q["trusted_list"]["territory"]
                                            + " trusted list issued " + q["trusted_list"]["issued"][:10]))])
        if sealed.get("fingerprint"):
            lay.kv([("Verifier key", Mono(sealed["fingerprint"]))])
        lay.kv([("Report SHA-256", Mono(st["report_sha256"]))])
        lay.callout("A qualified electronic time stamp is presumed, in every EU member state, accurate as to its date "
                    "and time and to the integrity of the data it covers (Regulation (EU) No 910/2014, article 41).", GOLD)
        lay.qr(["TgWitness verification seal", "report " + st["report"], "sha256 " + st["report_sha256"]])
    else:
        lay.text("This report is not sealed.", color=MUTED)
    lay.section("All checks")
    lay.grid(["Result", "Check", "Detail"], [[STATUS.get(c["status"], c["status"]), c["title"], c["detail"][:500]]
                                             for c in report.get("checks") or []], widths=(18, 42, 70))
    lay.section(COVERAGE_TITLE)
    lay.text("Establishes", size=9, style="B", color=OK)
    lay.bullets(report.get("establishes") or [], size=8.4)
    lay.text(SCOPE_TITLE, size=9, style="B", color=BAD)
    lay.bullets(report.get("does_not_establish") or [], size=8.4)
    lay.section("Repeat the verification")
    lay.command("python -m tgwitness.cloud verify --record deployment.json --provider-token-file READ_ONLY_KEY "
                "--fingerprint " + str(report.get("fingerprint")) + " --cloud-init docker-compose.yaml --source "
                "CHECKOUT_OF_COMMIT --evidence tgwitness-evidence.zip --report verification.md")
    if sealed:
        lay.command("python -m tgwitness.cloud check-report --report " + sealed["statement"]["report"])
    if vault is None:
        return bytes(pdf.output())
    unsigned = pdf_module.add_signature_field(pdf, say)
    statement = {"format": "tgwitness-verification-pdf-v1", "public_key": vault.public_key,
                 "report_sha256": sealed["statement"]["report_sha256"] if sealed else None,
                 "deployment_id": deployment.get("deployment_id"), "result": result}
    return pdf_module.sealed_pdf(unsigned, vault, statement)


def write(report, markdown, base, vault=None, tsas=TIME_STAMPS, session=None):
    base = Path(base)
    base.with_suffix(".md").write_bytes(markdown.encode())
    base.with_suffix(".json").write_bytes(json.dumps(report, indent=2, ensure_ascii=False).encode())
    sealed = seal(base, vault, tsas, session)
    base.with_suffix(".html").write_text(html_report(report, sealed), encoding="utf-8")
    base.with_suffix(".pdf").write_bytes(pdf_report(report, sealed, vault))
    return sealed
