[TgWitness](../README.md) / [Documentation](README.md) · [Investigation](INVESTIGATION.md)

![Investigation](assets/presentation/chapter-investigate.svg)

# Jurisdiction guidance in Report Studio

Open **Exports → Build report → Jurisdiction guidance · optional**. Select the
intended court's jurisdiction and procedure, review the source links, then save
report settings. The Guidance tab previews the appendix using the current draft.
Previewing or changing the country does not save it. Existing report designs,
themes, language settings, scope filters and examination notes continue to apply.

The catalog covers 25 jurisdictions: Australia, Brazil, Canada, mainland China,
England and Wales, France, Germany, India, Indonesia, Iran, Italy, Malaysia,
Mexico, Pakistan, the Philippines, Portugal, Russia, Saudi Arabia, Singapore,
Spain, Turkey, Ukraine, the UAE, the United States and Vietnam. Scope notes
identify limits such as federal/state differences; a country is not a substitute
for identifying the actual court. This is a coverage set, not a market ranking.

## Defaults and configuration

The nested `jurisdiction_guidance` object is accepted by `ReportOptions` and
account/sharing `report_presentation`:

```json
{
  "jurisdiction_guidance": {
    "jurisdiction": "",
    "procedure": "civil",
    "include_in_report": true,
    "local_note": false,
    "include_methods": false
  }
}
```

| Choice | Behavior |
| --- | --- |
| Empty jurisdiction | No appendix. Never inferred from IP address, interface language or provider location. |
| Jurisdiction code, e.g. `BR`, `US`, `IN`, `GB-EW` | Uses that catalog entry. Unknown codes are rejected. |
| `civil` / `criminal` | Selects the corresponding basis, sources and local summary. Civil preparation tasks are not reused as criminal formalities. |
| `include_in_report: false` | Keeps the selection in saved settings while omitting the appendix. |
| `local_note: true` | Adds a native-language summary. It is not a certified translation. A PDF needs fonts for its script; missing glyphs produce an explicit error. |
| `include_methods: true` | Adds explanations of signatures, timestamps, retained storage, witnesses, TEE, visual capture and human involvement. These are possible measures, not claims that they were used. |

`GET /api/report-guidance` supplies the versioned catalog to authenticated users
with view access. `POST /api/report-options` uses the existing export permission.
Save the complete report-options object when changing these choices, as with
other report settings. These controls configure the report, not the collector,
cloud account, retention policy or witness service.

Use **Examination notes** to identify the specific court, applicable regional
rules, certification route, questions and professional review. For an unlisted
jurisdiction or a special procedure, leave the catalog selection empty and use
those notes; do not choose a neighboring country as a legal proxy.

## Reports and isolation

| Output | Guidance selection |
| --- | --- |
| Journal and handover HTML, PDF, JSON and signed manifests | Saved workspace report options, or explicit options for that export. |
| Single-chat report | Its report options. |
| Account report and its chat reports | Explicit `report_presentation`, or saved workspace presentation when the API caller omits it. |
| Minimized sharing copy | No implicit inheritance. An API caller can explicitly select a public profile in the derivative's `report_presentation`. |
| Standalone Case Board note export | Outside this report-options flow. Use the evidence or account report for this appendix. |

Reusable layout profiles exclude the jurisdiction object, just as they exclude
case names, findings and filters. A new workspace starts with no jurisdiction.
The existing unsigned-preview and lock/workspace guards also cover these fields.

The appendix is carried in `case_assessment.jurisdiction_guidance`, with the
catalog version and SHA-256, research date, scope, sources and research status.
HTML, PDF and structured report data render that same object. Existing signatures
bind the appendix to the delivered copy. The cryptographic assessment's checks
are not upgraded or hidden by selecting a jurisdiction or a safeguard explanation.

The appendix starts with **What this copy needs next**, derived from the actual
export assessment: the observed result and the next verification or documentation
step for each check. For example, an absent timestamp, an unvalidated receipt and
a timestamp covering only a prefix produce different instructions. Recorded gaps
lead to an explanation of the affected period, not a claim that a setting can
repair past collection. Included TDX quotes still require independent validation.
The design preview does not invent these findings; they are added during export.
This task list is software guidance, not an assessment of legal admissibility.

## Research status and trust limits

Catalog version `2026-11-06.1` is a **research draft**, not a jurisdiction-specific
legal opinion, exhaustive minimum filing checklist or promise of acceptance.
Iran's criminal route is expressly marked `needs_local_review`. All routes require
checking current law and the actual court, acquisition authority, disclosure,
authentication, hearsay where applicable, translation and formalities. The
catalog records source links; it does not archive or continuously monitor statutes.
English guidance and native summaries need professional review before relying
on them for a particular filing.

Selecting a safeguard adds an explanation of its benefit, what to retain and its
limits. A collector signature is not a Telegram signature. No independent witness
leaves operator-key substitution risk open. Provider ownership separation reduces
some operator powers without proving that a hosting provider cannot access the
host. The proposed closed-source daily witness is described as a proposal, not an
implemented verification result.

Retention must be established for the actual object versions and permissions;
encryption, an S3 endpoint or versioning alone is insufficient. See
[AWS Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html).
TEE claims require verification of the relevant deployment and output bindings;
the framework's scope is documented by [dstack](https://github.com/Dstack-TEE/dstack).
Video supplies visible context, not proof that every input or scene is authentic.

## Validation

`python -m pytest tools/test_jurisdiction_guidance.py tools/test_case_assessment.py tools/test_report_profiles.py -q`

Tests cover defaults, input rejection, every civil/criminal catalog branch,
unchanged trust checks, workspace and permission boundaries, sharing defaults,
layout exclusion, all eight HTML/PDF designs, manifest/JSON agreement and
signature failure after altering the guidance text. Browser review uses synthetic
records, both themes, narrow and desktop viewports, keyboard navigation, saved
versus draft choices and procedure switching.
