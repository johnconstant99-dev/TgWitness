# Case reports: basis of trust and limitations

[Русский](ru/CASE_REPORTS.md)

Each report explains what supports its claims, where the support ends, and how a
recipient can check it. It describes the exported material, not the quality of a
configuration or the likely outcome of a court case.

The **Basis of trust and limitations** section appears in journal, handover, chat,
account and sharing reports. Journal and handover PDFs use the same assessment as
their signed `report.json`. ZIP manifests carry `case_assessment` in the signed
manifest. Existing signatures and authoritative records are not rewritten.

## Document formats and reading order

### Report studio

Open **Exports → Configure and preview**. Work through **Data → Contents → Preview**:

1. Use the whole workspace or choose chats, authors, inclusive UTC observation
   dates and event types. Load the catalog to search chats and authors, or enter
   their Telegram IDs. Author filters match recorded sender IDs; a deletion
   notice without a sender does not match an author filter.
2. Choose charts, participant labels, the transcript and your written findings.
3. Build the preview. It shows actual counts, activity, participants, sample
   records, saved changes and missing message-number ranges. Changing a choice
   marks the preview out of date. Save before downloading HTML, signed PDF,
   signed JSON or the evidence ZIP.

The data preview counts the complete stable journal prefix, not an initial sample.
Only displayed sample rows and long lists are bounded; their omitted counts are
shown. A later export takes a fresh stable snapshot, so ongoing collection may
increase the figures. Scope, counts and source identity are included in the
signed report. Opening or previewing the form does not save it.

**This is a report selection, not a minimized handover.** Charts and the transcript
use the selected records. Integrity, custody and coverage describe the full source
journal. The evidence ZIP still contains its original records and attachments.
Use [a minimized handover](EVIDENCE.md) when a recipient must receive only
the permitted data.

### Read edits, deletions and missing IDs

An edit shows the saved **Before** and **After** text and highlights the changed
words. A deletion shows the last version saved before the notice. If no earlier
content was captured, the report says so. When you select only edits or deletions,
the preceding versions remain available as explicitly labelled context outside
the filters. Unrelated messages are not added to these histories.

**Unobserved message IDs** are gaps between known numbers in the chosen chats and
date-derived ID span. Every known source record is checked before declaring a
number unobserved: filtering out another author, an event type or a date cannot
create a false gap. Neighboring saved messages are labelled as context. A missing
number does not establish that a message existed or was deleted; deletion notices
and unsuccessful rechecks remain separate event types.

### Choose a layout

Open **Exports → Build report**. Choose one of three independent visual designs:
**Case dossier**, **Intelligence brief** or **Editorial review**. Then choose the
contents: **Case dossier** (detailed), **Briefing** (an overview), **Activity review**
(charts without the transcript), or **Custom report**. A content preset keeps your
chosen design, case details and written analysis. Individual changes select Custom.

Select activity over time, the UTC weekday/hour heatmap, participant rankings, chat
rankings and record composition. Choose 5–30 ranked groups and neutral participant
aliases or account IDs. Unknown senders and the remaining participants are separate
rows. Aliases affect charts only; source records still contain their identities.

The optional **Examination notes** contain the question, method, findings and
conclusion written by the report's author. Cite source files and record numbers.
The signature preserves these statements; it does not mean an independent expert
has reviewed them. Private examination notes and full-journal charts are excluded
from minimized journal handovers.

The design preview updates from the unsaved draft using production cover, examination and
chart components, limited to matches within the first 50,000 source records. The data preview below
calculates the complete selection. It is explicitly
unsigned and does not persist edits. Cover and Charts buttons switch its section.
This is not a complete PDF preview. **Save report settings** applies the choices to
future exports; existing signed files are immutable. PDF uses the chosen palette,
its own A4 layout and the same selected aggregates as HTML and signed JSON.

Trust assessment, coverage limitations and verification instructions stay present.
Hiding charts or the readable transcript does not remove authoritative source rows
from the ZIP. Disabled chart series are omitted from the analytical JSON; use a
minimized export to restrict disclosure of source records.

Data-selection filters apply to journal reports; account and sharing exports retain
their own acquisition and disclosure scope.

Shared design/chart preferences are frozen into new chat/account exports and account
sharing previews. Account/sharing language and privacy settings remain independent;
private case and examination notes are not copied into these exports. Account and
sharing reports remain HTML protected by their signed archive manifest. Journal,
minimized journal handover and single-chat kits also provide signed PDFs.

### What the charts count

Journal activity and heatmaps count new, historical, recovered, edited, deleted and
missing-on-recheck **observations**, by collector observation time in UTC. Heartbeats
and attachment receipts are excluded. Participant rankings count only new, historical
and recovered message observations: a sender is not declared to be the editor or
deleter. Repeated observations can describe the same Telegram message.

Journal analytics retain counts by kind, first/last record references and the source
`events.jsonl` SHA-256. Figures include exact values in HTML and PDF. Daily buckets
switch to months beyond 366 recorded days; graphs combine these into at most 36
equal-width intervals. More than 100,000 distinct identifiers or 1,200 months marks
the affected chart unavailable, while exact overall counts remain available.

Snapshot and account-sharing charts count only included non-service message rows,
using their recorded message time. Sharing aggregates are calculated after redaction
and filtering. These charts use at most 90 equal-width UTC date intervals and retain
up to 10,000 grouping values; excess counts are explicitly declared and reconciled.
The last interval may be shorter. Unknown or naive dates do not enter time charts.

An empty interval means no included observations, not verified inactivity. Activity
is not online presence or identification of a real person. Consult coverage for gaps.
Unknown senders are not treated as a verified common identity. There is no trust score.

When included, `analytics.json` is protected by the archive's signed file hashes.
Journal `report.json` embeds the same selected aggregate. Signature verification
detects changed bytes; it does not independently certify the calculation method.
Recompute journal aggregates with `report_analytics.Analytics` and `selected`, or
snapshot aggregates with `snapshot_analytics.collect` and `project`.

Build the three designs from fictional activity, without Telegram or external services:

```sh
python tools/build_report_studio_example.py --output test-results/new-studio-example
```

Use a new directory for each run. English is the default; `--language` also accepts
`ru` and `de`. To exercise all four content presets, use
`python tools/build_dossier_example.py --templates --language en --output test-results/new-presets`.

![Fictional HTML dossier](assets/reports/dossier-en.png)

The HTML opens with a case cover and key figures. The numbered evidence map links
to each finding, its supporting facts, limits and independent review. Searchable
records and stable record references remain available in the offline viewer.
The design adapts to narrow screens, both themes and browsers without JavaScript.

The signed PDF has a dedicated A4 cover, report reference and QR, an executive
summary, an evidence map, numbered findings and document bookmarks. Its page
headers and footers identify the report. A QR identifies the material; it is not
an independent verification result. Browser printouts are separate from this
cryptographically signed PDF.

The observation timeline places recorded observation periods and interruptions
on the same UTC axis. Empty space is not inferred coverage; the detailed tables
retain the exact intervals. The ZIP contains the readable reports, signed JSON,
source records and verification instructions.

Generate a fresh, fictional English/Russian/German dossier with the development
environment installed:

```sh
python tools/build_dossier_example.py --output test-results/my-new-dossier
```

Each language directory contains `report.html`, `report.pdf`, `report.json` and
`dossier.zip`. Existing sample directories are never overwritten. No Telegram
account, external timestamp service or network connection is used to create it.

![First three pages of the fictional signed PDF](assets/reports/dossier-pdf.png)

## Reading a concrete case

For a journal of 1,200 entries with a validated timestamp at entry 1,000, the
report identifies 200 later entries outside that timestamp's bound. This is an
upper bound on the existence of a checkpoint, not proof of each message's send
time. If three other timestamp files fail validation or cannot be validated,
they are counted separately and cannot supply a positive conclusion.

A usable timestamp must satisfy all of these checks: its imprint matches the
checkpoint, its signature chains to a trusted TSA root at the stamped time, and
the checkpoint's signature, key, count and head match the exact journal prefix.
Merely parsing a timestamp or having an OTS receipt is insufficient. The reader
must independently choose the trusted TSA root and repeat verification. OTS needs
its own Bitcoin confirmation check.

| Report status | Meaning |
| --- | --- |
| Checked during export | The exporter performed the stated check; independent repetition is still needed. |
| Recorded; review required | The underlying observation or operator statement is recorded; it is not independent confirmation. |
| Not included in this copy | The copy has no supporting artifact for this claim. It does not say none exists elsewhere. |
| Not independently checked | The report does not supply an independent verification result. |
| Incomplete or unavailable | Material or a required check is missing, incomplete or unsuccessful. |

There is no aggregate trust percentage. Zero recorded interruptions does not
prove complete Telegram delivery. A valid signature does not establish the real
identity of an account holder, the truth of message contents or legal admissibility.

## What a strong configuration must preserve

1. Before relying on collection, retain the collector's key fingerprint through
   a separate trusted channel. A key contained only in the supplied ZIP does not
   protect against substitution of the whole ZIP and key.
2. Retain independently timestamped checkpoints and, where used, a witness
   journal outside the collector's administrative control. Compare them against
   the exported journal. A person controlling the signing key can otherwise
   produce another mathematically valid journal.
3. Record acquisition scope, gaps, filters, limits and changes in collection.
   Explain missing periods relevant to the actual claim. Do not interpret absent
   message IDs as proof of deletion.
4. Preserve original ZIPs and their hashes. Record each holder, transfer, date
   and purpose. Operator names and case notes are signed declarations, not
   identity or qualification checks.
5. For confidential VMs, preserve and independently verify the quote, challenge,
   Intel certificate chain, measurements, exact source and key-handling conditions.
   A TDX setting or a quote's presence alone is not a successful attestation.

These measures detect particular substitutions and changes under stated trust
assumptions. They do not turn Telegram data into Telegram-signed statements and
cannot make fabricated input before signing universally detectable.

## Recipient review

Use a trusted checkout's verifier and an independently obtained fingerprint:

```sh
python verify.py evidence.zip --fingerprint TRUSTED_SHA256
python verify.py evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca tsa-root.pem
python verify.py evidence.zip --fingerprint TRUSTED_SHA256 --witness witness.zip --witness-fingerprint WITNESS_SHA256 --require-witness
python verify.py evidence.zip --fingerprint TRUSTED_SHA256 --check-drand
```

The witness ZIP must come from an independently trusted source; preserve its key
and provenance too. Retain the commands, tool version, outputs, reviewed input
hashes and unresolved questions. Beacon verification is a separate online check;
the report renderer never contacts a service merely to display a report.

For a dispute over a particular message, cite the archive reference, authoritative
file and record reference, then describe the relevant time bound, coverage gaps,
selection and corroborating material. A sharing copy is a separate derivative:
its signature protects that copy but does not by itself prove faithful derivation.
Private filters and identity mappings do not enter its public assessment.

The report's editable PDF view is protected by its signatures. Verification of
the signed PDF detects changes to covered bytes; a screenshot or printout does
not carry those signatures. Keep the original digital file and verification result.
