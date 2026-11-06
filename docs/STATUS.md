# Current capabilities and qualification

Source version: **0.9.1 preview**. Reviewed 5 November 2026.

The source tree, published downloads and live qualification are separate states.
The latest published package at this review is [0.9.0 preview](https://github.com/phishdestroy/TgWitness/releases/tag/v0.9.0),
from `51fedc1be07788b2f261499a98e061118b396a36`. Features subsequently merged into
`main` require a build from that source or a later release. Check
[Releases](https://github.com/phishdestroy/TgWitness/releases) for newer packages.

## Capability record

| Workflow | Implemented in this source | Recorded validation | Remaining qualification |
| --- | --- | --- | --- |
| Live observation | Delivered messages, versions, deletion notices, media, rechecks, explicit gaps | Earlier real-account tests and a multi-workspace inventory in [Verification](VERIFICATION.md) | Complete role/failure matrix and atomic lossless live update replay |
| Full history | Standard/Takeout, signed resumable cursors, shared cooldown, concurrent media, Recent Actions and saved-version comparison | Synthetic failure tests and browser acceptance in [Backfill](BACKFILL.md) | Controlled real-account Standard/Takeout, approval, admin rights, long waits and throughput |
| Account/chat exports | Separate archives, selection, resumable account export and explicit multi-account chat export | Automated acquisition, file-integrity, recovery and browser checks | New revisions require their own live acceptance; results from pending branches do not qualify main |
| Evidence and handover | Journal signatures, file manifests, retained checkpoints, standalone verification, reports and minimized copies | Signature/tampering tests, smaller verified live journal and report checks | Independent security review, deployment-specific custody and forensic certification |
| Search and investigation | Full-text preview, Case Board, source-linked notes, reports and optional analysis | Browser checks and [one-million-message synthetic search benchmark](SEARCH.md#benchmark) | Sustained combined ingestion, search, media and export load on intended hardware |
| Independent witness | Separate keys, signed heads, freshness challenges and offline receipts | Synthetic rollback/fork/freshness checks and retained witness observations | Independent operator custody and prolonged failure/availability qualification |
| Trusted Live | Official Desktop/Web, guarded video, native JSON, continuity view and optional provider observations | Linux container checks; [CPU Ubuntu and WARP integration](VERIFICATION.md#trusted-live-cpu-ubuntu-and-warp--5-november-2026) | Real account login/export/hybrid/logout, native attachment preservation, local drand BLS verification and attested Trusted Live image |
| Phala high assurance | TDX verification, measured source/deployment and provider checks | [Real Phala deployments and external timestamp verification](VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) | Telegram collection on the qualified CVM and additional OS/deployment combinations |

Implemented does not mean qualified for every account or deployment. Full history
requires pausing live observation on that account. Its atomic message/cursor commit
does not establish atomic live MTProto replay. [Compare collection methods](COLLECTION-MODES.md)
before choosing a workflow.

## Checks and release decisions

The [main check run for b231dd64](https://github.com/phishdestroy/TgWitness/actions/runs/42128532175)
passed installation, functional browser, media-container and Docker/Compose jobs,
but two browser-UX checks failed. Subsequent local investigation reproduced a
preview-readiness race and a short synthetic-ID collision in report metadata.
The relevant checks now hold responses deliberately and use unambiguous privacy
markers. Consult the [checks for the candidate commit](https://github.com/phishdestroy/TgWitness/actions)
for acceptance; an older passing run does not qualify a newer tree.

CodeQL, dependency advisory checks and container image scans are separate gates.
A skipped image scan is not a passing image scan. Earlier findings remain in their
dated audit reports; they must not be presented as measurements of an unscanned
current image.

Before publishing a stable release, run the complete platform/security checks and
[controlled live acceptance](internal/LIVE_ACCEPTANCE.md), build all artifacts from
the tested revision, verify their hashes/provenance and record every limitation.
See [release readiness](internal/READINESS.md) for the acceptance checklist.
