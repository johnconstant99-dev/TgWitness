# TgWitness verification · updated 2026-11-01

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
