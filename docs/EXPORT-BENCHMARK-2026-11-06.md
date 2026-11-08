[TgWitness](../README.md) / [Documentation](README.md) · [Evidence and verification](EVIDENCE.md)

![Evidence & verification](assets/presentation/chapter-evidence.svg)

# Public-history export qualification: 6 November 2026

The first 50 unique public usernames in a fixed input list were tested on two
new servers with 40 separate account workspaces. Forty-eight sources produced
verified archives containing **3,598,381 records**; two usernames could not be
resolved and were not replaced. The input list's SHA-256 was
`c26ce4a6ba429f8d16012285b85191cde4d6a5c57089028df7cecf742f87137d`.

The base was `c88f7d407257247fab499bef6321306c357159e9`, with local candidates
`73719b52d6fcdaa7` and `b709aa39be623274`. These results do not describe an updated
published installer. Python was 3.12.16 and Telethon was 1.45.0, layer 229.

## Scope

Each job froze its upper ID and read accessible history without text, sender or
date filters. Attachments and profile photos were disabled in the candidates.
No chats were joined and no messages were sent. Visible participant/admin windows
were recorded separately; hidden or capped lists are not complete membership.

All nonempty acquisitions used regular requests. Takeout initialization required
approval waits; the two empty plans labelled Takeout performed no history reads.
This experiment therefore does not measure sustained Takeout throughput.

The archived records contain 63,761 distinct positive sender IDs, including bots,
and 110 chat sender IDs. Participant observations contain 24,816 distinct visible
member IDs and 190 admin IDs across sources. These are different sets and different
observation times.

## Speed and density

Two jobs without reused history pages illustrate the measured range:
Source labels below are anonymized; the detailed operational records stay outside
the source repository.

| Source | Accounts | Newly acquired history records | History time, including waits | History records/s | Total attempt, including validation |
| --- | ---: | ---: | ---: | ---: | ---: |
| Source A | 8 | 768,007 | 1,117.082 s | 687.512 | 1,574.920 s |
| Source B | 1 | 9,586 | 285.926 s | 33.526 | 556.272 s |

The first archive ultimately contains 768,955 records: numeric-ID rechecks added
948. Across all sources, rechecks added 1,516 records beyond the history pass.
Default rechecks sample gaps; they do not test every absent ID.

Source A had a planned upper ID of 10,800,044, but observed IDs started at
9,830,143. Its density between observed bounds was 79.282%; its fraction of the
whole planned ID range was 7.120%. Source C contained 9,497 records under upper
ID 14,185,675. A last ID is not a count of available messages or confirmed deletions.

This was an operational qualification with fixes, interruptions and retries,
not a controlled fleet-scaling comparison. Thirty-nine accounts made recorded
history calls. Fixed lead assignments left some later jobs waiting for a busy
account. Learned bulk delays also carried over between jobs and request types.
Do not extrapolate the eight-account rate to forty continuously busy accounts.
Resumed pages are excluded from current-attempt history throughput.

## Verification and limits

- All 48 ZIPs verified against separately pinned workspace keys, with no duplicate
  IDs or unfinished ranges in completed results.
- Ten small archives matched complete independent GetHistory ID traversals.
- Of 4,508 sampled later reads, 4,471 matched all compared core fields: full text,
  author, date, reply, edit time and media type. Later diagnostics for 36 differences
  found only photo `file_reference`/`access_hash` changes within reply metadata.
  Original byte-level differences remain retained. The remaining record
  was saved successfully but was not returned on the final
  ID recheck. That later result was a Telegram response rather than a parser
  exception; the saved record keeps the message as observed.
- File references can expire and be refreshed by fetching their source again;
  see [Telegram's documentation](https://core.telegram.org/api/file-references).
  Media bytes were not compared.
- Four deliberate pause/resume checks retained signed pages. Active working data
  used local disk; completed ZIPs were copied and hash-checked on persistent storage.
  This does not promise zero-loss recovery if the active container disk disappears.
- Final offline backup checks verified 51,285 file hashes and 42 workspace journals
  across both hosts. All 48 archive hashes matched signed completion records;
  the 40 imported authorizations were unchanged against the initial snapshots.
  These checks did not open Telegram connections.
- No matching native Telegram Desktop export was available among the inspected
  local exports. The independent API checks are not a Desktop-export comparison.
- Sequential final checks found all 40 accounts authorized, with matching account
  identities and no frozen, restricted or deleted flags in the inspected API
  responses. All clients disconnected after checking. This records their observed
  condition at that time.

Recorded backoffs, including pilots and interrupted runs, comprised 690 events
with requested waits from 3 to 31 seconds. Full deadlines were retained. Saved
client-counter snapshots covered 47,416 calls and 688 flood errors; two earlier
backoffs are outside those counter snapshots, so these totals must not be divided
into an error rate. They are client calls, not SDK-internal wire attempts.

## Corrections and remaining work

The pilot exposed unpaced message-ID rechecks, a profile-photo request despite
disabled attachments, and excessive empty ranges in sparse regular-mode exports.
The candidate paces ID/participant reads, honors media settings for chat photos,
and applies bounded density planning to both transports. Existing signed plans
keep their original ranges; explicitly replanned jobs retain the earlier attempt.
The early baseline did fetch photo bytes before the media fix.

Eleven pre-export connection timeouts were retained across attempts and retried
after disconnection. Limiting simultaneous connection starts reduced the initial
burst but did not eliminate timeouts. All readable sources eventually completed.
The harness's raw end-to-end rate overcounted reused messages on resumed jobs;
the derived report excludes that field and separates current-attempt and whole-job
durations. Production history timers already exclude reused pages.

Relevant regression tests: **116 passed**. The portable full suite reported
**1,102 passed, 57 warnings, 253 subtests passed**; Ruff passed. The Wolfi-only
installer fixture failed on Windows with `AssertionError: unexpectedly None : dirname`
and was excluded from the portable run; it was not qualified in its intended image.

Takeout throughput, complete large-archive second passes, method-specific learned
delays, queue utilization and full crash recovery during acquisition remain separate
qualification work. The detailed operational artifacts are `FULL50-RESULTS.csv`,
`FULL50-DENSITY.csv`, `FULL50-COMPLETENESS.md`, per-host results and dated measurements.
Raw chat data and account credentials are not included in the source repository.
