"""Versioned preparation guidance, separate from the evidence verification results."""
from copy import deepcopy
from functools import lru_cache
from hashlib import sha256
from html import escape
import json
from pathlib import Path
from typing import Literal
import unicodedata

from pydantic import BaseModel, ConfigDict, field_validator

CATALOG = Path(__file__).with_name("jurisdictions.json")
TITLE = "Jurisdiction guidance"
NOTICE = ("Research draft for preparation, not a finding of admissibility or a complete filing checklist. "
          "Confirm the court, applicable law, collection authority, disclosure duties and required formalities "
          "with a qualified local practitioner. Selecting this profile does not verify evidence or change any trust assessment.")
LOCAL_NOTICE = "Local-language summary; not a certified translation of the law or evidence."
PROCEDURES = {"civil": "Civil / commercial", "criminal": "Criminal"}

# These are explanations of possible safeguards, never assertions that they were used.
METHODS = [
    {"id": "signing", "name": "Collector signature", "helps": "Detect changes to signed bytes when the trusted key is known independently.",
     "retain": "Original signed ZIP, verification output, separately retained key fingerprint and checkpoints.",
     "limit": "An operator holding the key can sign fabricated records or a replacement journal. Zero independent witnesses leaves that risk open."},
    {"id": "time", "name": "Independent timestamps", "helps": "Bound when a particular checkpoint or archive hash already existed.",
     "retain": "Original receipt, exact checkpoint binding and verification against independent trust roots; confirmed Bitcoin proof for OTS.",
     "limit": "Does not certify message sending time, authorship or truth. An unverified receipt or later unanchored records do not acquire that bound."},
    {"id": "storage", "name": "Encrypted storage with retention", "helps": "Preserve separately held copies and restrict deletion during an enforced retention period.",
     "retain": "Object versions, retention mode and dates, access policy, custody and independent retrieval checks. Keep decryption keys available to the authorized recipient.",
     "limit": "Encryption protects confidentiality, not immutability. S3 compatibility or versioning alone is not Object Lock. Governance bypass and shared administrator control weaken independence."},
    {"id": "witness", "name": "Independent witness", "helps": "Compare independently held observations or signed checkpoints and explain gaps and disagreements.",
     "retain": "Witness identity or independently trusted key, scope, signed records, challenge responses and explicit coverage gaps.",
     "limit": "A second signature under the same control is not independence. Closed-source daily scoring is a proposed service, not a verified capability in this report. A silent witness cannot attest to its own outage."},
    {"id": "tee", "name": "Attested collection (TEE / Phala)", "helps": "Support claims about a measured execution environment within a stated threat model.",
     "retain": "Verifiable quote, fresh challenge, certificate chain, measurements, deployed code or reproducible build mapping, key binding and output hashes.",
     "limit": "A provider label or quote presence is insufficient. Attestation does not establish Telegram authorship, accurate outside inputs or legal admissibility; provider and hardware trust remain."},
    {"id": "visual", "name": "Browser capture, screenshots and video", "helps": "Show visible context and the steps a person or capture process observed.",
     "retain": "Original media and metadata, capture method and environment, source identifiers, session timing, hashes and links to the corresponding structured records.",
     "limit": "Visual recordings can be incomplete or manipulated and do not replace source data. A TEE recording binds only what the attested process actually captured and signed."},
    {"id": "human", "name": "Human witness, expert or notary", "helps": "Explain collection, identity and custody, answer challenges and complete route-specific certifications or formalities.",
     "retain": "Who did what and when, qualifications, signed declaration or applicable certificate, custody transfers and the exact material examined.",
     "limit": "Professional status alone does not authenticate unseen data. Separate provider-account ownership can reduce operator control; it does not prove the provider cannot access a host or hypervisor."},
]


@lru_cache(maxsize=1)
def _catalog():
    raw = CATALOG.read_bytes()
    value = json.loads(raw)
    value["sha256"] = sha256(raw).hexdigest()
    return value


def catalog():
    return deepcopy(_catalog())


class Options(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jurisdiction: str = ""
    procedure: Literal["civil", "criminal"] = "civil"
    include_in_report: bool = True
    local_note: bool = False
    include_methods: bool = False

    @field_validator("jurisdiction")
    @classmethod
    def known_jurisdiction(cls, value):
        if value and value not in {p["code"] for p in _catalog()["profiles"]}:
            raise ValueError("Choose a jurisdiction from the supplied catalog.")
        return value


def package_review(assessment):
    """Turn the existing export assessment into tasks, without inferring assurances."""
    if assessment is None:
        return None
    items = []
    for check in assessment.get("checks", []):
        key, status = check["id"], check["status"]
        facts = check.get("facts", {})
        action = check["verification"]
        if key == "integrity":
            action = ("Give the recipient the original ZIP and a signing-key fingerprint obtained through a separate trusted channel. "
                      "Run the independent verifier and compare any previously retained checkpoint. A successful local check does not settle key ownership.")
        elif key == "time" and status != "checked_locally":
            if facts.get("other_stamps", 0):
                action = ("Validate the existing receipts against the exact checkpoint and independent trust roots. "
                          "If no receipt validates, obtain and retain a timestamp for the current archive hash. A new timestamp cannot backdate earlier observations.")
            else:
                action = ("Obtain and retain an independent timestamp for the current archive hash. "
                          "For ongoing collection, configure checkpoint timestamps and check their receipts. A timestamp obtained now cannot establish an earlier time bound.")
        elif key == "time" and facts.get("unanchored_tail", 0):
            action = ("Retain and independently verify the existing receipt. Timestamp a new checkpoint covering the later records; "
                      "until then, report those records separately from the timestamped prefix.")
        elif key == "coverage" and (facts.get("gaps", 0) or facts.get("unobserved", 0)):
            action = ("Identify which recorded gaps overlap the relevant events and explain them in the examination notes. "
                      "Label any later recovery as a separate acquisition. Changing settings now cannot restore continuous observation of the past.")
        elif key == "witness":
            if facts.get("tdx", 0) or facts.get("drand", 0):
                action = ("Independently verify the included beacon rounds or TDX quotes and their binding to the captured output. "
                          "Compare a separately held witness archive where available; record unresolved checks explicitly.")
            else:
                action = ("Retain the current signed checkpoint outside the collector under separate control. "
                          "For future collection, configure an independent witness if needed and preserve its results. A witness added now does not certify earlier collection.")
        elif key == "custody" and not facts.get("operator_fields", 0):
            action = ("Identify the collector and document the acquisition method, dates and every transfer of the original ZIP. "
                      "Complete the applicable case details and examination notes, then preserve the new export and its hash.")
        result = check.get("result") or {}
        items.append({"check": key, "title": check["title"], "status": status,
                      "finding": result.get("text", "Not assessed").format(**result.get("values", {})),
                      "action": action, "references": list(check.get("references", []))})
    return {"basis": "Derived from this copy's export assessment. Configuration choices are not verification results. These tasks do not certify court admissibility.",
            "supporting_files_included": assessment.get("supporting_files_included") is True,
            "items": items}


def build(options=None, *, assessment=None):
    choice = Options.model_validate(options or {})
    if not choice.jurisdiction or not choice.include_in_report:
        return None
    data = _catalog()
    profile = next(p for p in data["profiles"] if p["code"] == choice.jurisdiction)
    criminal = choice.procedure == "criminal"
    return {
        "format": "tgwitness-jurisdiction-guidance-v1", "language": "en",
        "catalog_version": data["version"], "catalog_sha256": data["sha256"],
        "research_date": profile["reviewed_on"],
        "status": profile["criminal_status"] if criminal else "research_draft",
        "jurisdiction": profile["code"], "name": profile["name"], "scope": profile["scope"],
        "procedure": choice.procedure, "notice": NOTICE,
        "package_review": package_review(assessment),
        "law": profile["criminal_law"] if criminal else profile["law"],
        "basis": profile["criminal"] if criminal else profile["basis"],
        # Civil formalities must not be presented as a criminal checklist.
        "preparation": profile["criminal"] if criminal else profile["prepare"],
        "tasks": [] if criminal else list(profile["tasks"]),
        "human": ("Ask a local criminal-procedure practitioner which witness, expert, certificate or official collection procedure is required. "
                  "Civil filing routes must not be assumed to apply.") if criminal else profile["human"],
        "sources": deepcopy(profile["criminal_sources"] if criminal else profile["sources"]),
        "local_summary": {"language": profile["language"], "notice": LOCAL_NOTICE,
                          "text": profile["local_criminal"] if criminal else profile["local"]} if choice.local_note else None,
        "safeguards": deepcopy(METHODS) if choice.include_methods else [],
    }


def attach(assessment, options):
    guidance = build((options or {}).get("jurisdiction_guidance"), assessment=assessment)
    if guidance:
        assessment["jurisdiction_guidance"] = guidance
    return assessment


def html(data):
    if not data:
        return ""
    e = lambda value: escape(str(value), quote=True)
    parts = ['<section class="card panel case-assessment" id="jurisdiction-guidance" lang="en" dir="ltr">',
             '<h2>' + TITLE + '</h2><h3>' + e(data["name"]) + ' · ' + e(PROCEDURES[data["procedure"]]) + '</h3>',
             '<p class="assessment-review">' + e(data["notice"]) + '</p>']
    if review := data.get("package_review"):
        parts.append('<h3>What this copy needs next</h3><p>' + e(review["basis"]) + '</p>')
        if not review["supporting_files_included"]:
            parts.append('<p><strong>Get the original signed ZIP before verification. This standalone report does not contain the supporting proof files.</strong></p>')
        parts.append('<div class="scroll"><table><thead><tr><th scope="col">Check</th><th scope="col">This copy</th><th scope="col">Next step</th></tr></thead><tbody>')
        for item in review["items"]:
            parts.append('<tr><th scope="row"><a href="#assessment-' + e(item["check"]) + '">' + e(item["title"])
                         + '</a></th><td>' + e(item["finding"]) + '</td><td>' + e(item["action"]) + '</td></tr>')
        parts.append('</tbody></table></div>')
    else:
        parts.append('<p>Export adds findings and next steps for the actual copy. This design preview does not verify the journal or supporting proofs.</p>')
    parts.extend(['<p>' + e(data["scope"]) + '</p><p class="hint">Research date: ' + e(data["research_date"])
             + ' · ' + e(data["status"].replace('_', ' ')) + ' · Catalog ' + e(data["catalog_version"]) + '</p>',
             '<h3>Legal basis</h3><p><strong>' + e(data["law"]) + '</strong></p><p>' + e(data["basis"]) + '</p>'])
    if data["preparation"] != data["basis"]:
        parts.append('<h3>Preparation</h3><p>' + e(data["preparation"]) + '</p>')
    if data["tasks"]:
        parts.append('<ul>' + ''.join('<li>' + e(task) + '</li>' for task in data["tasks"]) + '</ul>')
    parts.append('<h3>Human involvement</h3><p>' + e(data["human"]) + '</p><h3>Legal sources</h3><ul>')
    for source in data["sources"]:
        parts.append('<li><a rel="noopener noreferrer" href="' + e(source["url"]) + '">' + e(source["title"]) + '</a></li>')
    parts.append('</ul>')
    if local := data.get("local_summary"):
        direction = "rtl" if local["language"] in ("ar", "fa", "ur") else "ltr"
        parts.append('<h3>Local-language summary</h3><p>' + e(local["notice"]) + '</p><p lang="'
                     + e(local["language"]) + '" dir="' + direction + '">' + e(local["text"]) + '</p>')
    if data.get("safeguards"):
        parts.append('<h3>Collection safeguards</h3><p>Possible measures to discuss and document. Inclusion here does not mean a measure was used or verified.</p><div class="assessment-grid">')
        for method in data["safeguards"]:
            parts.append('<article class="assessment-item"><h3>' + e(method["name"]) + '</h3><p>' + e(method["helps"])
                         + '</p><p><strong>Retain: </strong>' + e(method["retain"]) + '</p><p class="assessment-limit"><strong>Limits: </strong>' + e(method["limit"]) + '</p></article>')
        parts.append('</div>')
    return ''.join(parts) + '</section>'


def pdf(lay, data):
    if not data:
        return
    lay.section(TITLE, data["name"] + " · " + PROCEDURES[data["procedure"]])
    lay.callout(data["notice"])
    if review := data.get("package_review"):
        lay.heading("What this copy needs next")
        lay.text(review["basis"])
        if not review["supporting_files_included"]:
            lay.text("Get the original signed ZIP before verification. This standalone report does not contain the supporting proof files.", style="B")
        lay.grid(["Check", "This copy", "Next step"],
                 [(item["title"], item["finding"], item["action"]) for item in review["items"]], (18, 30, 52))
    lay.text(data["scope"])
    lay.text("Research date: " + data["research_date"] + " · " + data["status"].replace('_', ' ') + " · Catalog " + data["catalog_version"])
    lay.heading("Legal basis")
    lay.text(data["law"], style="B")
    lay.text(data["basis"])
    if data["preparation"] != data["basis"]:
        lay.heading("Preparation")
        lay.text(data["preparation"])
    lay.bullets(data["tasks"])
    lay.heading("Human involvement")
    lay.text(data["human"])
    lay.heading("Legal sources")
    for source in data["sources"]:
        lay.text(source["title"])
        lay.text(source["url"], size=7.5)
    if local := data.get("local_summary"):
        lay.heading("Local-language summary")
        lay.text(local["notice"])
        # Do not silently drop an optional summary's script in an English PDF.
        glyphs = set().union(*(font.cmap for font in lay.pdf.fonts.values() if hasattr(font, "cmap")))
        if any(ord(char) not in glyphs for char in local["text"]
               if not char.isspace() and unicodedata.category(char) != "Cf"):
            from .pdf_report import MissingFont
            raise MissingFont("The local-language summary needs additional PDF fonts. Install a font for this language or disable the local summary.")
        lay.text(local["text"], align="R" if local["language"] in ("ar", "fa", "ur") else "L")
    if data.get("safeguards"):
        lay.heading("Collection safeguards")
        lay.text("Possible measures to discuss and document. Inclusion here does not mean a measure was used or verified.")
        for method in data["safeguards"]:
            lay.heading(method["name"])
            lay.text(method["helps"])
            lay.text("Retain: " + method["retain"])
            lay.text("Limits: " + method["limit"])
