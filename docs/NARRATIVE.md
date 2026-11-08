[TgWitness](../README.md) / [Documentation](README.md) · [Investigation](INVESTIGATION.md)

![Investigation](assets/presentation/chapter-investigate.svg)

# Evidence narratives

`python -m tgwitness.narrative` produces a source-linked account from a **verified full evidence ZIP**. It first authenticates the archive, then creates PDF, HTML, JSON and four SVG diagrams. It never takes a supplied verdict JSON as proof. A failed signature, inconsistent manifest or contradictory witness evidence stops generation.

```sh
python -m tgwitness.narrative evidence.zip --lang de --jurisdiction DE --out narrative-de/
python -m tgwitness.narrative evidence.zip --lang ru --fingerprint COLLECTOR_FP --witness witness.zip --witness-fingerprint WITNESS_FP --check-drand --check-bitcoin --out narrative-ru/
```

Obtain fingerprints independently. An unpinned package can be described, but its missing pin is visible as a limitation. Instructions in the report use `TRUSTED_COLLECTOR_FP` and `TRUSTED_WITNESS_FP`; they never turn an embedded key into an independent trust decision. `--tsa-ca ROOT.pem` enables the existing RFC 3161 root check. External checks use the verifier's existing trust model; see [FOR-THE-RECORD.md](FOR-THE-RECORD.md).

The destination must be empty. Generation stages all outputs before publishing them into that directory. It does not overwrite another report, contact Telegram, submit timestamps, send mail or publish anything. Network checks run only when requested. The input ZIP remains unchanged. The output is a derived report, not a new independently witnessed evidence package.

## Saved configuration profiles

Use an explicit local JSON file to save presentation choices and verification requirements. See the [example configuration](examples/narrative.json) and [Russian instructions](ru/NARRATIVE.md).

```sh
python -m tgwitness.narrative --write-config narrative-config.json
python -m tgwitness.narrative --config narrative-config.json --profile ru-html --print-config
python -m tgwitness.narrative evidence.zip --config narrative-config.json --profile ru-html --out narrative-ru/
python -m tgwitness.narrative evidence.zip --config narrative-config.json --profile de-proof --fingerprint COLLECTOR_FP --witness witness.zip --witness-fingerprint WITNESS_FP --out narrative-de/
```

Precedence is built-in defaults → file `defaults` → named `profiles` entry → explicit CLI options. Only the file named by `--config` is loaded; configuration inside an evidence archive is never executed or applied. Relative witness and TSA CA paths in the file resolve from that file's directory; CLI paths resolve from the invocation directory. `--write-config` refuses to replace an existing file. `--print-config` shows effective settings without opening an evidence package or making network requests.

| Setting | CLI | Default / meaning |
|---|---|---|
| `lang`, `jurisdiction` | `--lang`, `--jurisdiction` | `en`, no jurisdiction; `--jurisdiction none` clears a profile's jurisdiction |
| `outputs` | `--outputs html json svg` | `pdf html json svg`; at least one of PDF, HTML or JSON is required |
| `diagrams` | `--diagrams timeline flow ladder files` | All four; `--diagrams none` omits drawings when SVG output is not selected |
| `max_records` | `--max-records` | 100000 per journal, allowed 1–1000000; overflow stops without truncating the report |
| `scene_max_records` | `--scene-max-records` | 2000, allowed 1–10000; caps grouped records before adding restart cross-references |
| `fingerprint`, `witness`, `witness_fingerprint`, `tsa_ca` | Existing flags with hyphenated names | Independently supplied trust inputs; fingerprints must be lowercase SHA-256 hex |
| `check_drand`, `check_bitcoin` | `--check-drand`, `--check-bitcoin` | `false`; the corresponding `--no-check-…` option overrides a profile's `true` |
| `require_tier` | `--require-tier` | `self_attested`; requirements do not create proofs or enable network requests implicitly |
| `require_pinned_signer` | `--require-pinned-signer` / `--no-require-pinned-signer` | `false`; if required, an independently pinned collector or a verified matching pinned witness must be supplied |

The `de-proof` example requests external checks and requires `witness_anchored` plus a trusted pin. It will refuse an archive that lacks these proofs. Merely specifying a witness fingerprint without a matching witness archive does not satisfy the pin requirement. JSON-only output avoids PDF font requirements. Diagram choices do not remove the textual assurance ladder, limitations or event references. Formats and languages do not change the machine scene model; changing scene size changes grouping only. A gap scene also cites the next recorded restart, even if that extra cross-reference exceeds the grouping cap.

Every successful run also writes **`narrative-run.json`**: effective presentation/check settings, their SHA-256, input package hashes, optional TSA CA hash, pin status and attained tier. Local witness and CA paths are omitted. This is an unsigned run receipt, not an external attestation. It accompanies even PDF-only or HTML-only output. The settings hash describes the public settings object; input-file hashes are separate fields.

Exit codes: **0** generated successfully; **1** package verification, record-limit or rendering failure; **2** invalid configuration or unmet pin/tier requirements. Unknown fields, duplicate JSON keys, invalid types and configurations over 64 KiB are rejected. There are no settings to skip signature verification, suppress limitations, raise a verdict or mark translations reviewed. Saved profiles and CLI settings do not change the signed input archive.

Configuration tests cover precedence and paths, selective output, intact limitations/references without diagrams, bounded grouping, record overflow, invalid settings, archive tampering and CLI exit codes. Signed collector/witness fixtures test a required `witness_anchored` profile with confirmed, absent and mismatched commitments; external network responses in those tests are synthetic.

## Reading the report

Read the introduction, chronology, assurance checks, limitations and verification commands in that order. Jurisdiction terms are optional. The appendix identifies every cited record by journal, sequence number and full SHA-256. The source package SHA-256 appears at the front. Collector and witness sequence numbers have separate namespaces.

A recorded claim is described as a recorded claim. A document event containing `signature_claimed: qualified` and `signature_objects: 0` does **not** become a finding that the PDF is unsigned, forged or legally invalid. The renderer does not independently inspect PDF signatures, validate QES or DKIM, or reconstruct an earlier receipt date. External anchor files receive credit only when the verifier actually checks them. A pending OTS submission remains unconfirmed.

Counts describe event kinds. New messages, edits, deletion notices and absence on recheck remain distinct. Counts do not establish continuous coverage. Unknown events retain their source references and an interpretation limitation. Dates in scenes come from signed event metadata, not an authenticated wall clock. Bitcoin dates are block-header dates, not exact receipt times.

The HTML timeline has keyboard-focusable and hoverable event references. Every SVG has a title and description. The PDF uses selectable text and the same drawing geometry; it does not depend on a browser or an SVG conversion service. Japanese PDF generation uses the project's existing CJK font discovery; a suitable installed font is required. No new package dependency was added.

## Templates and jurisdictions

There are 25 complete phrase catalogs and matching glossaries. Supported languages: en, de, fr, es, it, pt, nl, pl, cs, sk, uk, ru, ro, bg, hu, el, sv, da, fi, no, lt, lv, et, tr, ja. `no` uses Bokmål wording. `pt` uses the generic CLDR Portuguese cardinal rule. Templates support the bounded ICU **plural subset** used in these catalogs, including nested placeholders and exact-number branches; this is not a general implementation of every ICU formatter. Cardinal rules follow [Unicode CLDR](https://www.unicode.org/cldr/charts/48/supplemental/language_plural_rules.html).

The checker compares keys and placeholders, renders plural cases, checks phrase lengths and applies any supplied forbidden-word lists. Every language, including English and German, is visibly marked **machine-assisted, not reviewed**. Passing mechanical tests is not legal or native-language review.

Jurisdiction catalogs contain terminology and official source references checked on 2026-11-06. They cover DE, AT, CH, UK, IE, FR, ES, IT, PL, CZ, UA, NL, BE and US-federal. `UK` is explicitly scoped to **England and Wales civil proceedings**; it does not represent Scotland or Northern Ireland. CH currently supplies electronic-signature terminology, not a complete Swiss procedure guide. Missing local terms remain null. A regional data-protection authority is not guessed. GDPR access periods are not encoded as a universal 30-day deadline; [EDPB guidance](https://www.edpb.europa.eu/system/files/2023-04/edpb_guidelines_202201_data_subject_rights_access_v2_en.pdf) distinguishes the applicable one-month rule. An OTS proof is not automatically classified as a qualified timestamp under eIDAS.

Changing jurisdiction affects only the jurisdiction section and its source references. Changing language does not change the machine scene model. The section is a reference table, not a legal opinion or a procedural checklist.

## Release requirements still outstanding

The T7 forbidden-word lists and T13 custody/spec schema have not been supplied. Existing `custody.*` events receive source-linked generic descriptions; compatibility with an absent schema is not asserted. The narrative glossary is ready for reuse, but a shared T7/T14 interface cannot be tested without those specifications.

Release validation remains incomplete until T7 and T13 integration and native legal review of en/de/fr/uk/ru are documented. No human read-aloud test or ten-minute comprehension study has been performed. The feature is a review draft, not a release-complete implementation of those dependencies.

The requested sample includes six distinct scene kinds and collection on both sides of an interruption. Preserving that catalog produces seven chronological scenes, not five. The golden fixture records this explicitly instead of merging unrelated events to force an arbitrary count. Recorded stop/start pairs extend the gap scene to the next recorded start; their dates remain computer-clock claims, not independently proved downtime.

Tests cover the golden model, all 25 PDF/HTML outputs, unchanged scene counts across languages, plural edge cases, exact record references, independent DE/AT/CH sections, escaped markup, unverified claims, and the pre-existing signed legacy archive. Output narratives preserve hashes and mask contacts with the handover detectors; they are not a general anonymisation service for arbitrary names embedded in filenames or payload strings.
