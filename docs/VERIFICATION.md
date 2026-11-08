[TgWitness](../README.md) / [Documentation](README.md) · [Evidence and verification](EVIDENCE.md)

![Evidence & verification](assets/presentation/chapter-evidence.svg)

# TgWitness verification

**Updated 8 November 2026.** Results are tied to the revision, environment and
workload recorded for each run. [Current capabilities](STATUS.md) describes the
available workflows; this page records what has actually been checked.

These are selected validation results from the
[development history](OVERVIEW.md#testing-history-and-duration). Engineering tests,
live acquisition, fault injection, recovery checks and artifact verification each
have their stated scope; external certification is a separate status.

On 8 November, the published installer at `b35f8e18f3d1` was inspected without
executing or installing it: wheel and dependency-lock SHA-256 and RSA signatures
passed, and the wheel contained the Secret Chat backend, interface, API routes,
collector hooks and optional dependency declaration. See the
[package check](PSEUDO-SECRET.md#package-availability).
[CI for that revision](https://github.com/phishdestroy/TgWitness/actions/runs/42446658989)
and the [installer run](https://github.com/phishdestroy/TgWitness/actions/runs/42446659252)
completed successfully. Older audit reports retain the findings for their original
snapshots; current implementation and qualification are recorded separately.

[Performance graphs](https://phishdestroy.github.io/TgWitness/docs/validation/) ·
[Signed English audit](../website/validation/audit/REPORT.md) ·
[Downloadable measurements](../website/validation/audit/MEASUREMENTS.csv)

| Latest evidence | Result | Scope |
| --- | --- | --- |
| Release audit · 6 Nov | 1,461 core tests passed; 37 platform skips | Source `92e539af40d8`; open findings retained |
| Fresh exports · 6 Nov | 127.713 and 141.781 records/s, complete cycle | Two accounts per server; text and metadata through WARP |
| Retained archives · 6 Nov | 48 archives; 3,598,381 records verified | Existing archives checked against pinned workspace keys |
| Trusted Live · 5 Nov | Guarded CPU recording and WARP checks | Official Desktop login and native export remain unqualified |
| Phala / Intel TDX · 4 Nov | All 16 verifier checks passed on later runs | Historical deployment; no Telegram account on the CVM |

<details>
<summary>On this page</summary>

- [Release audit and fresh exports · 6 November 2026](#release-audit-and-fresh-exports--6-november-2026)
- [Trusted Live CPU Ubuntu and WARP · 5 November 2026](#trusted-live-cpu-ubuntu-and-warp--5-november-2026)
- [Live Phala Cloud deployment · 4 November 2026](#live-phala-cloud-deployment--4-november-2026)
- [Live server journal inventory · 1 November 2026](#live-server-journal-inventory--1-november-2026)
- [Recent offline and fault-injection checks · 1 November 2026](#recent-offline-and-fault-injection-checks--1-november-2026)
- [Live Telegram test, whole account · 29 October 2026](#live-telegram-test-whole-account--29-october-2026)
- [Password-protected export opened with libarchive · 29 October 2026](#password-protected-export-opened-with-libarchive--29-october-2026)
- [Live Telegram test · 27 to 29 October 2026](#live-telegram-test--27-to-29-october-2026)
- [Synthetic local capacity measurement](#synthetic-local-capacity-measurement)
- [Full-text search on one million messages · 5 November 2026](#full-text-search-on-one-million-messages--5-november-2026)
- [Qualification status](#qualification-status)

</details>

## Release audit and fresh exports · 6 November 2026

The audit used v0.9.1 at source
`92e539af40d8368d198ff5e040f1d876f2c1310e`, release
`92e539af40d8-83e41104669e`. Installed-package smoke checks passed on three
servers. The signed report retains the state observed at that time.

[![Acquisition and complete export rates for two fresh workloads](../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/docs/validation/)

| Workload | Records | Acquisition | Complete cycle | Complete-cycle rate |
| --- | ---: | ---: | ---: | ---: |
| Server A · two accounts | 27,030 | 189.043 s | 211.647 s | 127.713 records/s |
| Server B · two accounts | 29,299 | 182.513 s | 206.650 s | 141.781 records/s |

Both exports began without resume, excluded attachments and avatars, and ended
with zero duplicate or reused records. The complete cycle includes preparation,
acquisition, selection, packaging and archive verification. Server A also ran a
protected-chat read check. Four FloodWait events on A and three on B were
respected.

| Check | Result | Qualification |
| --- | --- | --- |
| Core pytest | 1,461 passed | 37 platform skips |
| Browser / browser UX / evidence / site | 102 / 66 / 15 / 9 passed | These programs overlap other tests; counts are not additive |
| Capture addon | 124 passed | Three Official Web checks blocked by the required Chromium sandbox |
| API authorization | 269 routes; 538 requests passed | Missing credentials and revoked access |
| Retained archives | 48 of 48 verified | 3,598,381 records; pinned workspace keys |
| Live fleet read checks | 24 of 40 profiles passed | 16 WARP routes failed qualification; those profiles were not connected |

The [signed report](../website/validation/audit/REPORT.md) records all open
findings, including three defects in an unpublished secret-chat snapshot absent
from the audited main build. The earlier
[public-history qualification](EXPORT-BENCHMARK-2026-11-06.md) used a different
revision and workload; its rates must not be combined with this comparison.

Verify the original report using the
[pinned key and verifier](../website/validation/audit/README.md#verify-the-original-files).
Its signature protects the retained report from alteration. The report identifies
the tested revision, workload, environment and verification results for that run.

## Trusted Live CPU Ubuntu and WARP · 5 November 2026

The retained integration run used a CPU-only Ubuntu 24.04.5 guest (4 vCPU, 8 GiB)
under QEMU inside a RunPod CPU host. The collector used `14e642a5`; verification used
`02072461`. The final fixes merged in [PR #114](https://github.com/phishdestroy/TgWitness/pull/114)
as `755f78f6`, whose tree matched the tested PR head. This was not a TEE.

- A real WARP Connector reported healthy; proxied HTTPS reported WARP and Gateway
  enabled. Three probes saw the same egress address.
- Disconnecting WARP made the proxied request fail. Direct gateway-service HTTPS
  was rejected. In the recorder namespace, direct IPv4/IPv6, external DNS and
  Docker's embedded UDP resolver were blocked.
- A scoped read-only provider token could read health/connections and could not
  read the connector enrollment token. Signed provider observations included
  explicit unavailable samples. The witness ran on the operator's host, so this
  demonstrates recording and retention, not independent third-party custody.
- Official Desktop reached its unauthenticated welcome screen. Guarded keyboard
  input was rejected during capture. Three H.264 display segments decoded and
  their clock overlay was inspected. The 18-event preflight archive verified
  against the pinned recorder key and retained checkpoint.
- The final capture tests passed 114 cases on Windows and Linux CI, with real
  Chromium/FFmpeg. Five anchor tests and dependency advisory checks passed.

An initial 2 vCPU/4 GiB startup timed out under concurrent image-build load and
stopped through the guard; it is not counted as success. Manual test-account
login, native chat export, real hybrid comparison and Telegram-side logout remain
pending. No supplied Telethon session was imported. Attachments, automatic OCR,
local drand BLS verification and Trusted Live TDX attestation were not qualified.

## Live Phala Cloud deployment · 4 November 2026

**Historical result:** later deployments passed all 16 verifier checks,
including Intel TDX and the quick tunnel. Restart evidence, signed address
discovery and report timestamps were checked separately. Each test CVM was
removed after its run.

| Setup | Recorded value |
| --- | --- |
| Provider | Phala Cloud · `tdx.small` · US-WEST-1 |
| Deployment | `--provider phala --quick-tunnel`; initially empty workspace |
| Initial collector | `df7d860c` · v0.8.1 |
| Collector with all fixes | `53a0f7e9` |
| Production guest | `dstack-0.5.12`; SSH access disabled |
| External services | ntfy.sh, GitHub and Intel PCS |
| Observed cost | Seven CVMs, about 1.9 US cents together; historical test pricing |

The sequence below separates initial failures, fixes and completed checks.
No Telegram account was connected to these CVMs.

<details>
<summary>Deployments 1–2 · provider differences and regression checks</summary>

The first two deployments found five differences from the simulated Phala Cloud.
Private Phala regressions reproduce each difference and fail without its fix:

| On Phala Cloud | Before the fix | Fix |
| --- | --- | --- |
| `compose_file.name` is required | HTTP 422, nothing created | The compose carries the CVM name |
| Unless given an empty one, Phala adds its own pre-launch script to the measured app-compose (v0.0.20: Docker login, `docker compose pull`, root password, SSH keys from `user_config`) | `tdx_compose` fails: code outside the published compose | The app-compose sets `pre_launch_script` to `""`; Phala then leaves it out |
| Without `image` Phala picks `dstack-dev-0.5.12`, the development build, with SSH access enabled | `server_state` fails. The quote alone passed on this image; only the provider record and `tdx_os` show it | The deployment asks for the production build of Phala's current release, `dstack-0.5.12` |
| With the dstack gateway off, the CVM details never get an `instance_id` | Deploy waits 30 minutes and fails | The instance ID is read from the CVM state |
| Restarts, stops and starts are CVM operations, not application revisions | `provider_actions` did not list restarts | The operations are read as well |

</details>

<details>
<summary>Deployment 3 · attestation, access checks and restart evidence</summary>

- The CVM ran `dstack-0.5.12` with SSH access off. The collector posted its signed address about
  1.5 minutes after creation. Deploy then passed `tdx_binding`, `tdx_quote` (Intel TCB
  UpToDate, quote v4, FMSPC `20a06f000000`, not in debug mode, not migratable, collateral
  fetched from Intel), `tdx_compose_hash`, `tdx_compose` (byte for byte) and `tdx_identity` (KMS keys).
- The panel at its trycloudflare.com address answered 401 without a token or with a wrong one,
  and 200 with the panel token.
- `verify` with `--source` set to GitHub's archive of the commit and the fingerprint passed
  separately: server, `server_state`, firewall (no gateway, no public endpoint), provider log,
  statement, fingerprint, source hash, boot and the five `tdx_*` checks passed. Cloudflare and
  `tdx_os` were unavailable, so the result was INCOMPLETE.
- Two restarts through Phala's API: each time the CVM was back in under two minutes with the
  same collector key, a new signed address, and the old one answering 530. `verify` reported
  the new boot and both restarts as REVIEW. With `--evidence` it confirmed the journal
  signatures and three starts, each with its own Intel TDX quote from the same CVM.
- `destroy` removed only that CVM. The workspace was then empty, and the panel address stopped
  answering.
- The panel wizard's price check read `tdx.small` at $0.058 an hour. A wrong key got a plain
  "did not accept the API key" message.

</details>

<details>
<summary>Follow-up fixes · signed address discovery and OS measurements</summary>

- Without the address key, `verify` followed the newest well-formed post on the address topic,
  which is printed in the published compose. One forged post sent it to a host that does not
  exist, and `statement` failed: a forger could not pass as the collector, but could block
  third-party verification, for up to 12 hours with a forged future timestamp. The collector now
  also posts its address signed with its own key, `verify` accepts only such posts when the
  collector makes them, and posts are ordered by ntfy.sh's receive time.
  A private cloud-wizard regression replays the forged posts. A CVM
  runs this only from a commit that contains it, so this run's collector did not sign its address
  yet and `verify` said so.
- `tdx_os` could not run without `dstack-mr`, whose current version has `measure-os` rather than
  the `measure --json` the documentation named. The verifier now computes MRTD and RTMR0-2 itself
  from the published image and the VM's shape, ACPI tables included.

</details>

<details>
<summary>Deployment 4 · all 16 checks, report seals and restart verification</summary>

- Deploy downloaded the published `dstack-0.5.12` once, matched it to the OS image hash the CVM
  reported, and `tdx_os` passed: MRTD, RTMR0, RTMR1 and RTMR2 equal the values computed for QEMU
  8.2.2, 1 vCPU and 2 GiB. The same computation gave a different RTMR0 for a claimed 4 GiB, 2 vCPUs,
  QEMU 9.2.1 or a second network card, and failed for a changed kernel, firmware or command line
  and for the development image.
- `verify` passed every one of its 16 checks, the quick tunnel's connector included, so the result
  was PASS. It wrote the HTML and PDF certificate, sealed with a qualified eIDAS time stamp from
  the Belgian government's time-stamping unit TSU 202301 (status granted on Belgium's trusted
  list), a FreeTSA time stamp and the verifier's signature; `check-report` confirmed all of them
  and the PDF's signature.
- After a restart, `verify --evidence` confirmed two starts, each quoted inside the CVM and each
  booted from the published `dstack-0.5.12`; the restart and the new boot were REVIEW.
- `destroy` left the workspace empty.

</details>

<details>
<summary>Deployment 5 · collector-signed discovery and forged-post rejection</summary>

The collector ran from commit `53a0f7e9`, which includes the fixes above.

- The collector posted its address signed with its own key, next to the operator's HMAC post.
  Two forged posts were then added to the topic, one with a zeroed HMAC and one signed by another
  Ed25519 key, both claiming a time in the year 2096. `verify` took the address signed by the
  collector key and passed all 16 checks; the seal again carried the qualified Belgian time stamp,
  FreeTSA's and the verifier's signature, and `check-report` confirmed them.
- After a restart the collector posted the new address signed: `verify` found it at once, the
  operator's **Find the current address** 27 seconds later from the HMAC post, and both ignored
  the forged posts. `verify --evidence` confirmed two starts booted from `dstack-0.5.12`.
- Deploy printed what Phala bills the CVM, disk included: $0.06078 an hour.

</details>

### Panel wizard and remaining scope

The panel wizard ran against Phala Cloud twice, once through its job API and once through the
browser with a real Chromium: the price check, creation with the commit under **Advanced**, all six
attestation checks passed, the server list showing the billed price (44.37 USD a month), **Find
the current address**, the measured compose download, and deletion. The browser saw no page errors.
Each time the workspace was empty afterwards.

Not covered: a Cloudflare domain on Phala, a Telegram account on the CVM, and the `dstack-0.6.1`
image. The wizard's price before creation is Phala's compute price only, as its API names the disk
price only for an existing CVM; the server list shows the billed price after creation.
All prices in this section were observed on 4 November 2026.

## Live server journal inventory · 1 November 2026

At approximately 19:15 UTC, sequential read-only SQLite `query_only` queries counted
events in ten workspace databases on a running server. Collection continued during
the queries, so this is not an atomic snapshot across workspaces.

| Observed across the ten workspace databases | Count |
| --- | ---: |
| Workspaces with at least one `message.new` event | 8 |
| Journal records, including operational events | 1,610,818 |
| `message.new` events | 900,232 |
| `message.edited` events | 80,683 |
| `message.deleted` events | 400,536 |
| `message.recovered` events | 53,403 |
| `message.snapshot` events | 2,183 |
| `media.saved` events | 50,418 |
| `media.failed` events | 5,575 |
| `coverage.gap` events | 11 |
| Database bytes, excluding WAL files and media | 7,909,003,264 |

These are **event counts**, not unique messages, people or media files. The same
message can appear in more than one workspace, and an edit or deletion can produce
another journal event. `media.failed` counts historical failure events, not the
current media queue. The queries did **not** newly verify signatures and the full
hash chain of all 1,610,818 records, measure delivery or throughput, or establish
that every Telegram event was captured. No message content, account or chat IDs,
workspace labels, credentials or private files are published here.

At this review, the separately configured public monitor covered three sources:
one capture response was OK and two reported `no_response`. That monitor is
not a ten-workspace health summary. `no_response` means the observer obtained no
response at that check; message delivery is assessed from the journal. The smaller
29 October test below has its own explicit signature and hash-chain verification.

## Recent offline and fault-injection checks · 1 November 2026

These checks use fictional data and local files; they add regression evidence for
the current source, not another live Telegram delivery measurement:

| Check | What it exercised |
| --- | --- |
| Source archive | Two builds with identical source bytes but changed file times produced the same ZIP and checksum. Exact archived bytes and file hashes matched; private test files stayed out. A simulated write failure left the previous archive and checksum intact. |
| Account export recovery | A simulated disk error on the second ZIP member left no published or partial ZIP. Resume kept every signed receipt byte-identical, produced an independently verifiable archive using the expected signing fingerprint, and retained the synthetic coverage gap as a partial result. Scale assertions guard against repeated task and receipt scans as histories grow. |
| Minimized disclosure privacy | Synthetic Unicode names and aliases, nested metadata, unknown senders and media fields were checked in all three identity modes and with text omission. A masking-limit failure did not silently weaken redaction; the original signed account export stayed unchanged. |
| Linux media decoder and OCR | A [Linux Docker CI check](https://github.com/phishdestroy/TgWitness/actions/runs/41341200341/job/124951395192) at commit `5a9e0814` passed generated Ogg/Opus, MP3, M4A, MP4 with video, WAV and FLAC inputs; forged-duration and secondary-file-reference controls; and 48 mutated parser fixtures (34 rejected, 14 decoded within bounds). Real Tesseract OCR ran with original bytes unchanged. The decoder and OCR ran in network-isolated containers without a Whisper model. |

The checks run in the [pull-request](../.github/workflows/pr-check.yml) and
[full Checks](../.github/workflows/checks.yml) workflows.
They test these failure boundaries, not every possible storage failure or whether
a disclosure is automatically safe to publish. The media check does not measure
speech recognition accuracy or Telegram delivery. Review each derivative before sharing.

## Live Telegram test, whole account · 29 October 2026

The same account kept running after the test below. On 29 October at 12:10 UTC its scope
was switched to the whole account (channels, groups, private chats and bots); the panel asked
for confirmation and the signed journal recorded it. By 17:59 UTC the journal held:

| Recorded, 27 October 21:36 to 29 October 17:59 UTC | Count |
| --- | ---: |
| Journal records | 9,968 |
| New messages | 5,308 |
| of them after the switch to the whole account | 3,878 |
| Deletions | 784 |
| of them deleted after TgWitness had saved the message | 596 |
| Edits | 41 |
| Messages added by rechecks | 2,273 |
| Messages a recheck could no longer find | 18 |
| Messages saved by history snapshots | 242 |
| Saved attachments | 247 |
| Collector starts | 19 |
| Telegram FloodWait pauses | 26 |

- The panel's **Verify** check confirmed the signatures and hash chain of all 9,968 records.
- Messages came from 2 groups or channels and 3 private chats and bots. One message button was
  pressed from **Chats**; the request and Telegram's answer are in the journal.
- New chats were added when the collector rescanned the account at a restart. Saving the
  earlier messages of new chats was off (`history = 0`), so it is not covered here.

Not covered: reactions, membership changes, people profiles, sending messages, joining by
invitation, proxies, notifications, the witness bot and several accounts at once. Public files
contain only counts.

## Password-protected export opened with libarchive · 29 October 2026

An archive written by the export encryption code (WinZip AES-256, the format 7-Zip and WinRAR
read) was opened with Windows `tar` (bsdtar 3.6.2, libarchive). With the right password the
extracted file matched the original SHA-256; a wrong password was refused with "Incorrect
passphrase". 7-Zip and WinRAR themselves were not run.

## Live Telegram test · 27 to 29 October 2026

One real Telegram account, signed in through the built-in API pair pool, recorded one
supergroup from **27 October 21:36 UTC to 29 October 05:15 UTC**. The collector was
started 12 times in that period.

| Recorded | Count |
| --- | ---: |
| Journal records, including heartbeats and service records | 2,385 |
| New messages | 1,291 |
| Deletions | 472 |
| of them deleted after TgWitness had saved the text | 347 |
| Edits | 12 |
| Messages missed while stopped, added by the recheck | 12 |
| Saved attachments | 17 |
| Attachments not downloaded (downloads off, or no file to download) | 14 |
| Telegram FloodWait pauses, 3 seconds each, during rechecks | 8 |

- The signatures and the hash chain of all 2,385 records verify against the journal's
  public key.
- After a restart the collector resumes from the saved update state (`pts`) and Telethon
  catches up; the recheck then adds messages that are still missing.
- On every FloodWait the collector waited the requested time and continued.
- The account stayed signed in, and the same session reconnected on 29 October.

Not covered by this test: several accounts at once, administrator roles, proxies, outages
longer than a few hours and the full [live acceptance procedure](internal/LIVE_ACCEPTANCE.md).
Public files contain only these counts: no account or chat identifiers, messages or
credentials.

## Synthetic local capacity measurement

Private synthetic capacity run: 10,000 events across 100 chats.

| Metric | Observed |
| --- | --- |
| Input | 10,000 synthetic message events across 100 synthetic selected sources |
| Message text | 400 characters; no media or network |
| Ingestion | 53.273 seconds; 187.7 events/second |
| Handler latency | p50 4.162 ms; p95 7.784 ms; maximum 129.118 ms |
| ZIP export | 19.868 seconds with tracemalloc enabled |
| Peak traced Python export allocations | 0.51 MiB; not process RSS |
| ZIP size | 4,610,962 bytes |
| Independent verification | All 10,000 events verified |

This measures the local serial recording/export path on this Windows host; live
delivery, concurrent accounts, Telegram throttling and media are measured in the live
runs above. The measurement predates the final offline timestamp tooling, which leaves
the measured message path unchanged.

## Full-text search on one million messages · 5 November 2026

Command: `python tools/bench_fulltext.py --messages 1000000 --work <empty directory>`

A deterministic signed journal of 1,000,000 synthetic messages in 200 chats (Russian
word forms, Ukrainian, English, Chinese, Japanese, links and handles) was indexed in
71 seconds; the index took 58 MiB beside a 1.50 GiB journal. Best-match
searches took 9 to 190 ms (median), against 2.4 to 3.2 seconds for the previous substring
search. Full results, hardware and limits: [Full-text search](SEARCH.md#benchmark).
Private compatibility tests also verify a frozen signed archive made before full-text
search with the current verifier, and a current archive with the frozen archive's
own `verify.py`.

<a name="remaining-qualification"></a>

## Qualification status

The retained live journal establishes real collection, edits, deletion notices, attachments,
rechecks and rate-limit handling. Docker/Compose and installation checks are recorded in
CI; the real Phala deployment and external timestamp verification are described above.
Saved MTProto state and catch-up are implemented. The newer backfill commits messages and
cursors atomically and preserves available Recent Actions, with synthetic coverage today.

Further controlled runs for role visibility, reaction actors, prolonged FloodWait,
account bans, network and process interruption recovery, mobile QR confirmation,
sustained high load and long-term archival follow the
[live acceptance](internal/LIVE_ACCEPTANCE.md) matrix. Independent security review and
forensic certification are external steps.

The [public audit directory](../website/validation/audit/README.md) contains only
the signed report and aggregate measurements. Detailed operational receipts,
raw captures and account material remain private. Application screenshots in
`docs/assets/` use fictional demonstration data.
