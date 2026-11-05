# Resumable API backfill

Use **Sources → Full history** on an idle account. Choose Standard API or Takeout,
one to five attachment workers, Recent Actions collection and saved-version comparison.
Start, pause, resume and end controls remain in the existing history card. API callers
can POST these options to `/api/history/start`:

```json
{"transport":"standard","media_workers":2,"admin_log":true,"compare_saved":true}
```

The source list, account and options are signed at creation. Options cannot be changed
on resume. Media continues to follow the workspace's attachment policy; a subsequent
policy change may exclude queued files and produces separate receipts. The existing
**Messages first** preference defers downloads until text acquisition ends.

This mode uses the authenticated MTProto client. It is separate from official-client
[Trusted Live](TRUSTED-LIVE.md), and is not an assurance that Telegram will never limit
or restrict an account. It uses the workspace's selected network route.

## Requests, limits and recovery

History reads use descending exclusive cursors with pages of at most 100 returned
messages, retaining `MessageEmpty` as an unavailable observation. The last committed ID is the next offset, without subtraction. An empty
successful read ends a range; an error never means end of history. Every range fixes
its upper ID on its first successful read. SDK methods may make additional RPCs,
all subject to the same serialized account request lane.

Bulk history, dialog, admin-log and file requests start with one-second spacing.
Twenty consecutive successes reduce it by 20%, with a 0.5-second floor. FloodWait
increases spacing by 0.5, 2 or 5 seconds, up to 10 seconds, and persists an account-wide
cooldown of the server's wait plus a one-second margin. Text and media share that
cooldown. This is a local pacing policy, not a published Telegram rate entitlement.

Transient history requests retry five times with exponential backoff; exhaustion
pauses the run. FloodWait does not spend that retry budget. Cancellation interrupts
waits and preserves committed work. Authorization loss pauses the acquisition;
resumption never silently switches accounts. Independent account workspaces can run
separately, and the existing distributed-export workflow remains available for explicit
multi-account exports. History does not redistribute a banned account's cursor.

The highest message ID is not a message-count estimate. No automatic takeout threshold,
proxy rotation or zero-delay speed guarantee is used. Secret Chats and messages not
available to the selected account are outside this acquisition.

## Takeout

Takeout reuses the account export transport and encrypted Takeout state. It checks the
connected account before initialization, selects the required chat/media flags, records
Telegram's split ranges and the ranges in which each selected dialog appears, and resets
offsets only when moving to another recorded range. Resume validates the range inventory.
Changes require a new acquisition instead of guessing a replacement cursor.

Telegram's requested approval delay is displayed and retained. Resume is explicit;
there is no blocking console prompt or fallback to the ordinary transport. An expired
Takeout ID is cleared without deleting Telegram login credentials. History, attachment
downloads and file-reference refreshes use the matching Takeout wrapper. Recent Actions
uses the ordinary authenticated read API and is labeled separately.

Pause retains the Takeout session. Completion finalizes it after media workers drain;
the success flag is set only if text/admin reads and requested media have no reported
failure or pending work. Ending an unfinished run closes Takeout without the success
flag and preserves observations. No claim is made about a fixed maximum approval delay,
unlimited export volume or immunity from FloodWait.

Paused Takeout attachments stay assigned to that acquisition; ordinary observation
workers cannot silently download them through the standard API. Pending files caused
by disabled sources or media settings pause Takeout completion until those settings
are restored. Ending the run explicitly marks its remaining Takeout files as skipped.

## Durable observations and media

Each message observation, original media descriptor, routing index and cursor commitment
are written in one SQLite transaction. Each cursor commitment is an individually signed
`history.cursor` journal event. Resume verifies the journal and retained checkpoint,
then compares each source with its latest signed cursor. Unrelated journal events can
advance the workspace head without invalidating a source cursor. Older runs reconstruct
their unsigned cursor from signed observations before continuing. Disposable routing
and admin-log deduplication indexes are rebuilt from the journal.

Media workers run concurrently with text acquisition while network calls remain
serialized per account. Files stream to temporary paths, are hashed incrementally and
atomically moved to content-addressed storage. Completed, skipped, retrying and failed
attachments append new events. Signed message records are never rewritten to add a
hash. A refreshed file reference must still describe the original attachment.

Backfill messages retain the existing `message.snapshot` / `history_acquisition` journal
format and include `acquisition.source="backfill"`, `source_mode` and the Takeout range,
if present. `observed_at` is acquisition time; `payload.sent_at` and `edited_at` describe
the provider's message dates. They are not interchangeable timestamps.

## Recent Actions and version comparison

When selected, Recent Actions is paginated before and after each source's history read.
Delete/edit actions retain their provider event IDs, reported dates, actor and old/new
content as `history.admin_log.observed`. Attachments of historical versions use
`message.admin_log` records so an old version does not replace the current chat view.
The second pass collects newer actions; signed per-pass cursors and provider IDs prevent
repeating committed observations after a pause.

No admin access produces an explicit `unavailable` result and an incomplete overall
result, not an empty successful log. Private chats and basic groups are not applicable.
The report records the returned interval, counts and outcomes. Recent Actions has a
limited moving window: beginning/end passes do not guarantee coverage during a very
long acquisition or pause, nor recovery of every deletion within a nominal 48 hours.

`history.content.changed` links two signed observations when normalized content differs.
It does not invent a live edit event, editor or edit time. A message absent from a later
read, a jump in IDs or a time gap does not by itself prove deletion. Signed server-action
observations and inferred content differences remain distinct.

## Verification and limits

Save the signed progress report and Export evidence. The standalone verifier checks
the journal, message counts, fixed source/account/options plan and latest cursor
commitments against the report's journal prefix. Attachment outcomes are separate from
text completion. Preserve a workspace backup to resume; an evidence ZIP is not a session
or acquisition-state backup.

Signatures prove integrity relative to the collector's trusted key and retained external
commitments, not Telegram authorship, legal admissibility or exhaustive delivery.
Backfill is a series of observations of available state, not an atomic historical
snapshot. It cannot reconstruct unobserved past versions or expired content. Existing
external witness/checkpoint mechanisms retain their documented trust limits.

Automated coverage uses synthetic accounts and clients: atomic interruption, tampered
cursors, legacy recovery, slow media, account-wide cooldown, Takeout delay/expiry/ranges,
admin permissions and deduplication, independent report verification, and browser
pause/reload/resume. These tests do not certify real-account behavior or throughput.

Protocol references: [Telegram Takeout](https://core.telegram.org/api/takeout),
[Recent Actions](https://core.telegram.org/api/recent-actions), and
[Telethon client pagination and Takeout](https://docs.telethon.dev/en/stable/modules/client.html).
