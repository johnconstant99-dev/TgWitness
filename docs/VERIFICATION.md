# TgWitness verification · updated 2026-11-04

## Live Phala Cloud deployment · 4 November 2026

`--provider phala --quick-tunnel` ran against real **Phala Cloud** (`tdx.small`, region
US-WEST-1) with a Phala Cloud API key of an empty workspace, real ntfy.sh, GitHub and Intel PCS.
The CVM installed commit `df7d860c` (v0.8.1); deploy, verify and destroy ran from the command
line with the fixes below. Seven CVMs cost about 1.9 US cents together.

The first two deployments found five differences from the simulated Phala Cloud.
[`tools/check_phala.py`](../tools/check_phala.py) now reproduces each, and fails without its fix:

| On Phala Cloud | Before the fix | Fix |
| --- | --- | --- |
| `compose_file.name` is required | HTTP 422, nothing created | The compose carries the CVM name |
| Unless given an empty one, Phala adds its own pre-launch script to the measured app-compose (v0.0.20: Docker login, `docker compose pull`, root password, SSH keys from `user_config`) | `tdx_compose` fails: code outside the published compose | The app-compose sets `pre_launch_script` to `""`; Phala then leaves it out |
| Without `image` Phala picks `dstack-dev-0.5.12`, the development build, with SSH access enabled | `server_state` fails. The quote alone passed on this image; only the provider record and `tdx_os` show it | The deployment asks for the production build of Phala's current release, `dstack-0.5.12` |
| With the dstack gateway off, the CVM details never get an `instance_id` | Deploy waits 30 minutes and fails | The instance ID is read from the CVM state |
| Restarts, stops and starts are CVM operations, not application revisions | `provider_actions` did not list restarts | The operations are read as well |

The third deployment:

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

Two further findings, fixed afterwards:

- Without the address key, `verify` followed the newest well-formed post on the address topic,
  which is printed in the published compose. One forged post sent it to a host that does not
  exist, and `statement` failed: a forger could not pass as the collector, but could block
  third-party verification, for up to 12 hours with a forged future timestamp. The collector now
  also posts its address signed with its own key, `verify` accepts only such posts when the
  collector makes them, and posts are ordered by ntfy.sh's receive time.
  [`tools/check_cloud_wizard.py`](../tools/check_cloud_wizard.py) replays the forged posts. A CVM
  runs this only from a commit that contains it, so this run's collector did not sign its address
  yet and `verify` said so.
- `tdx_os` could not run without `dstack-mr`, whose current version has `measure-os` rather than
  the `measure --json` the documentation named. The verifier now computes MRTD and RTMR0-2 itself
  from the published image and the VM's shape, ACPI tables included.

The fourth deployment, with these:

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

The fifth deployment ran the collector from commit `53a0f7e9`, which has all of the above:

- The collector posted its address signed with its own key, next to the operator's HMAC post.
  Two forged posts were then added to the topic, one with a zeroed HMAC and one signed by another
  Ed25519 key, both claiming a time in the year 2096. `verify` took the address signed by the
  collector key and passed all 16 checks; the seal again carried the qualified Belgian time stamp,
  FreeTSA's and the verifier's signature, and `check-report` confirmed them.
- After a restart the collector posted the new address signed: `verify` found it at once, the
  operator's **Find the current address** 27 seconds later from the HMAC post, and both ignored
  the forged posts. `verify --evidence` confirmed two starts booted from `dstack-0.5.12`.
- Deploy printed what Phala bills the CVM, disk included: $0.06078 an hour.

The panel wizard ran against Phala Cloud twice, once through its job API and once through the
browser with a real Chromium: the price check, creation with the commit under **Advanced**, all six
attestation checks passed, the server list showing the billed price (44.37 USD a month), **Find
the current address**, the measured compose download, and deletion. The browser saw no page errors.
Each time the workspace was empty afterwards.

Not covered: a Cloudflare domain on Phala, a Telegram account on the CVM, and the `dstack-0.6.1`
image. The wizard's price before creation is Phala's compute price only, as its API names the disk
price only for an existing CVM; the server list shows the billed price after creation.

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
not a ten-workspace health summary. `no_response` means the observer could not
obtain a response at that check; it does not establish message loss. The smaller
29 October test below has its own explicit signature and hash-chain verification.

## Recent offline and fault-injection checks · 1 November 2026

These checks use fictional data and local files; they add regression evidence for
the current source, not another live Telegram delivery measurement:

| Check | What it exercised |
| --- | --- |
| [Source archive](../tools/check_source_archive.py) | Two builds with identical source bytes but changed file times produced the same ZIP and checksum. Exact archived bytes and file hashes matched; private test files stayed out. A simulated write failure left the previous archive and checksum intact. |
| [Account export recovery](../tools/check_account_export_recovery.py) | A simulated disk error on the second ZIP member left no published or partial ZIP. Resume kept every signed receipt byte-identical, produced an independently verifiable archive using the expected signing fingerprint, and retained the synthetic coverage gap as a partial result. Scale assertions guard against repeated task and receipt scans as histories grow. |
| [Minimized disclosure privacy](../tools/check_disclosure_privacy.py) | Synthetic Unicode names and aliases, nested metadata, unknown senders and media fields were checked in all three identity modes and with text omission. A masking-limit failure did not silently weaken redaction; the original signed account export stayed unchanged. |
| [Linux media decoder and OCR](../tools/check_media_worker.py) | A [Linux Docker CI check](https://github.com/phishdestroy/TgWitness/actions/runs/41341200341/job/124951395192) at commit `5a9e0814` passed generated Ogg/Opus, MP3, M4A, MP4 with video, WAV and FLAC inputs; forged-duration and secondary-file-reference controls; and 48 mutated parser fixtures (34 rejected, 14 decoded within bounds). Real Tesseract OCR ran with original bytes unchanged. The decoder and OCR ran in network-isolated containers without a Whisper model. |

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

Command: `python tools/check_capacity.py --events 10000 --chats 100`

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

This measures the local serial recording/export path on this Windows host. It does
not measure MTProto delivery, concurrent accounts, Telegram throttling, media, a
long-running workload, or a guaranteed number of real chats. The measurement predates
the final offline timestamp tooling, which does not change the measured message path.

## Full-text search on one million messages · 5 November 2026

Command: `python tools/bench_fulltext.py --messages 1000000 --work <empty directory>`

A deterministic signed journal of 1,000,000 synthetic messages in 200 chats (Russian
word forms, Ukrainian, English, Chinese, Japanese, links and handles) was indexed in
71 seconds; the index took 58 MiB beside a 1.50 GiB journal. Best-match
searches took 9 to 190 ms (median), against 2.4 to 3.2 seconds for the previous substring
search. Full results, hardware and limits: [Full-text search](SEARCH.md#benchmark).
`tools/test_fulltext.py` also verifies a signed archive made before full-text search
(`tools/fixtures/evidence-before-fulltext.zip`) with the current verifier, and a current
archive with that archive's own `verify.py`.

## Remaining qualification

The retained live journal establishes real collection, edits, deletion notices, attachments,
rechecks and rate-limit handling. It does not establish exhaustive delivery or a controlled
matrix of role visibility, reaction actors, prolonged FloodWait, account bans and
network/process interruption recovery. QR-token issuance remains distinct from completed
mobile QR confirmation.

Docker build/run, Linux/macOS installation, sustained high load, independent security
review, a real independent TSA response, certificate revocation/archival validation and
forensic certification remain outside the recorded qualification. Saved MTProto state
and catch-up are implemented; atomic durable replay remains unestablished. Admin-log
collection, extra reactor lists and priority short polling remain separate features.
See [live acceptance](internal/LIVE_ACCEPTANCE.md) for the controlled qualification matrix.

Local detailed receipts and screenshots are under test-results/ (Git-ignored).
The public screenshot in docs/assets/ contains only fictional demonstration data.
