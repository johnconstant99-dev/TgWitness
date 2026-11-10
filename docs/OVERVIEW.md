# TgWitness: start, scale and evidence

TgWitness is an open-source Telegram exporter and investigation workspace. Install
it with one command, connect an account, choose the chats and export a signed
archive. It also supports temporary collection on GitHub Actions and continuing
investigations with saved edits, deletion observations, search and reports.

## Start with the task you have

| Your task | Shortest path | What you receive |
| --- | --- | --- |
| Save a conversation or account | Install, connect an account, select the export scope | A signed archive with the selected history, collection outcomes and verification material |
| Collect on a temporary runner | Use GitHub Actions capture, authorize a fresh session and choose the scope | An encrypted archive with GitHub workflow provenance |
| Follow changes over time | Keep observation running for selected chats | Saved versions, deletion notices, attachments and recorded coverage |
| Investigate and share findings | Search the archive, use Case Board and configure a report or sharing copy | Source-linked findings and a verifiable handoff suited to the recipient |

### One-command installation

The installer includes Python and dependencies. A source checkout, Docker, an AI
provider and an independent witness are optional choices, not setup prerequisites.

Linux / macOS:

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

Windows, in PowerShell or Command Prompt:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

Open the panel, connect your Telegram account and select the collection scope.
Installation does not start collection by itself. The [installation guide](INSTALLATION.md)
explains local access, servers, updates and checking the downloaded build.

For a temporary runner, follow [GitHub Actions capture](SEALED-ACTIONS.md). That
workflow needs a GitHub fork, authorization and an archive password. The capture
page explains those steps and the session time budget before the run. Download
and retain the resulting archive and its verification material.

## More settings when the task needs them

A single-chat export needs an account and a selected scope. Continuing observation,
multiple accounts, proxies, attachment policies, report design, reviewer access,
external timestamps and off-site storage serve different investigation and
handoff requirements. Configure those features when they are relevant.

Scope, permissions and minimized sharing copies help operators choose what to
collect and disclose. Jurisdiction guidance and report settings record the
selected procedure and preparation steps. See [account export](ACCOUNT-EXPORT.md), [access](ACCESS.md) and
[report configuration](CASE_REPORTS.md).

The application runs on the chosen computer or server. Basic collection does not
require a GPU or an LLM. Optional OCR, transcription and AI analysis have their
own resource requirements. Size a deployment for message rate, attachments,
retained history and concurrent accounts.

## Preserve the record, whoever it helps

The purpose is to preserve observed material, context and changes regardless of
whose position they support. Evidence may challenge the collector's own account
of events. Keep source observations, missing coverage and analytical conclusions
identifiable so another person can assess the same material.

The logic is: account-visible observation → signed journal → export → recipient
verification. Saved edits add versions. Deletion observations retain previously
captured content. Coverage records expose known interruptions. Reports and AI
analysis refer back to saved sources; an interpretation does not become a source
observation merely because it appears in a signed report.

| Verification check | What a recipient can establish |
| --- | --- |
| File hashes, signatures and journal chain | The supplied records and files agree with the expected key and journal boundary |
| A separately retained checkpoint or witness | The archive agrees with a previously retained journal state |
| A verified external timestamp | The referenced bytes existed by the timestamp under the stated trust assumptions |
| GitHub capture attestation | The archive matches the approved workflow, collector revision and recorded digest |
| Intel TDX attestation | The quote, platform status, expected OS/application measurements, freshness and collector identity pass their configured checks |

In attested acquisition, the approved collector's authenticated Telegram connection
and output are bound to the checked execution environment. The archive retains the
captured content and context; reports and analysis refer back to those records.
Use the mode-specific verification steps and trusted inputs in
[the trust guide](TRUST.md) and [evidence format](EVIDENCE.md).

## Published scale and measured performance

The following results describe different workloads and dates. Counts are not
interchangeable: a journal event is not necessarily a unique Telegram message.

| Date | Workload | Published result | What was measured |
| --- | --- | --- | --- |
| 1 November 2026 | Running server, ten workspace databases | 1,610,818 journal records; 900,232 new-message events, 80,683 edit events and 400,536 deletion events | Read-only inventory of the stored journals |
| 5 November 2026 | Search over 1,000,000 synthetic messages in 200 chats | Index built in 71 seconds; per-query median search times of 9–190 ms | Local search benchmark |
| 6 November 2026 | Two fresh real Telegram exports | 27,030 and 29,299 messages; 56,329 across both runs | Two accounts per run through WARP, text and metadata, no attachment downloads |
| 6 November 2026 | The same two exports, including preparation and packaging | 127.713 and 141.781 messages/second | Measured complete-export rates; both archives verified against pinned keys |

The [verification record](VERIFICATION.md) gives the server inventory, live
collection checks and search measurement. [Export performance](https://phishdestroy.github.io/TgWitness/docs/validation/)
publishes the two real runs, hardware, durations, archive hashes and signed
measurement files, each with its recorded revision and conditions.

The [public-history qualification](EXPORT-BENCHMARK-2026-11-06.md) also records
**48 verified archives with 3,598,381 records** across a 50-source input list and
40 account workspaces. Its eight-account Source A acquired **768,007 history
records in 1,117.082 seconds**, including waits: **687.512 records/second**, with
attachment downloads disabled. The complete attempt, including validation, took
1,574.920 seconds. These measurements describe that workload, alongside the
smaller fresh-export examples above.

### Testing history and duration

TgWitness has been developed and tested for about six months. The collector, the
signed journal and the verifier came first; the web panel and the add-on modules
were built on them later. This repository was created new on 29 October 2026 for
publication and began with the existing code, so its age is not the project's age
([limits and objections](LIMITS-AND-OBJECTIONS.md#the-project-is-only-two-weeks-old)).
The cumulative exercised workload is on the order of 100 million, including earlier
runs, failures, fixes and repeated validation. The dated public measurements
document selected runs with their own revisions, methods and results.

## Read capability status precisely

Assess each workflow against its implementation, published build and recorded
tests. The source is currently labelled preview. That release label coexists
with working collection, exports, independent verification and published scale
measurements. A preview feature and a validated workflow can exist in the same
application; describe the specific feature and evidence behind an assessment.

Use [current capabilities](STATUS.md), [features and limits](PRODUCT.md),
[verification](VERIFICATION.md) and [the changelog](CHANGELOG.md) together.
Record the tested revision when citing a result. The 6 November measurement
snapshot also retains failed and skipped tests; those are not passes.

## Readable by people and AI tools

The website provides a concise `llms.txt`, a complete English handbook in
`llms-full.txt` and `llms-full.md`, and Markdown editions of its pages. These are
documentation formats, not an AI requirement for running TgWitness.

Optional [MCP](MCP.md) and [command-line access](CLI.md) let authorized tools read
selected saved records. Message content remains untrusted input. Summaries should
cite sources, distinguish observed facts from inference and preserve uncertainty.
Full-text search, OCR and AI output do not change the original signed observations.
