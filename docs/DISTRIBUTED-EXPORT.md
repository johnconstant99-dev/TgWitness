# Distributed chat export

Absent-number rechecks count gaps as intervals, without allocating every missing
number in memory. Default sampling stays bounded; an explicit full recheck reads
successive batches and can be cancelled. Unchecked numbers remain visible in the
result and are not treated as proof of deletion.

Open a chat and choose **Export chat**. Select idle account workspaces that already have access to the source. Every account keeps its configured connection. This feature does not change WARP or choose an exit IP.

## History acquisition

With **Download media** off, distributed acquisition also skips downloading the
chat's profile photo. Its available photo ID and other profile metadata remain
in the export. Photo retrieval requires both the export's media option and the
workspace's media/avatar settings. Message-ID rechecks share account pacing with
history reads; any server-requested wait still applies to every caller.

**Regular session** preserves the existing acquisition path. **Telegram Takeout session** is an opt-in path for public channels and supergroups. It opens an export session for each participating account, uses the last Telegram split range for this public-only scope, and reads history without Telethon's additional iterator delay. Telegram's own FloodWait remains fully enforced. The current implementation still has one outgoing RPC per account; choosing Takeout does not increase same-account concurrency.

The initial source/date boundaries are measured with regular requests and frozen in the signed plan. Takeout reads those planned ranges. Profiles, admin logs, optional context and attachment retrieval continue to use regular requests; the archive identifies that scope. The Takeout flags request the selected chat type without contacts or file export. Private chats and private groups remain available through the regular path or [account export](ACCOUNT-EXPORT.md).

If Telegram requires export approval, the job pauses and shows the returned deadline. Approve in Telegram or wait, then resume explicitly. There is no automatic regular-speed fallback. Pause/cancel retain the private Takeout handle for a resumable job; they do not log out the account or revoke an authorization. Resume validates the account, handle and split range. An expired handle pauses the job; a subsequent resume creates a new generation. A changed split range requires a new export rather than mixing incompatible pagination.

Takeout handles stay in the encrypted vault. Chunk receipts identify transport and generation without the handle. The signed archive records generation open/reuse/close times and any finalization error. History finalization occurs after selection and its network work, before packaging; a packaging retry can reuse the signed chunks. Old plans retain their original transport and chunk sizes.

## Exclusive account ownership

One account runs one acquisition task. Monitoring, History, account export and chat export are mutually exclusive. Starting an export never pauses monitoring automatically. Deselect a busy account or explicitly pause its current task first. Reservations are acquired before Telegram requests and released on completion, failure or pause. Separate accounts may work concurrently; RPCs within one account are serialized. Full server-requested FloodWait deadlines are persisted and respected before subsequent requests, including after restart. This cannot guarantee Telegram will never rate-limit an account.

## Selection

- All available history, rolling 7/30 days, previous calendar month, or custom bounds. UI dates use the browser time zone and become fixed UTC bounds `[from, until)` at launch.
- Messages exactly at **From**, including several messages in the same second, are included. Telegram can return the date-offset message itself, so acquisition reads slightly before the lower boundary and applies the precise period locally. **Until** remains exclusive.
- Offline message-language detection using Lingua. Short, uncertain and mixed-language messages have a separate include/exclude option. Detector version and decisions accompany evaluated selected messages; confidence is a heuristic, not proof of language.
- **Messages that are replies** selects direct replies. **Messages that received a reply** selects originals with an observed direct incoming reply. Relationships are built before language/text filtering, so a Russian answer can qualify an English original. Merely posting into a forum topic does not count as a direct reply.
- Replies can be sought within the selected period or through the acquisition start. The latter can require scanning later history too.
- Bounded parent/reply context with a separate message cap. Context may fall outside the filters and is marked `selection.role=context`. Missing parents retain a reason; linked discussions outside the chosen source are not traversed. Context expands over acquired history and fetches missing same-source parents; it does not discover every reply outside the scanned period.
- Literal text phrase; sender-ID filtering through the API. Optional attachments are fetched after selection under each account's capture policy. A changed message is not silently substituted during attachment retrieval.

## Chunking and continuation

For a supergroup/channel, preflight resolves the source separately for every account and fixes visible date/ID boundaries. The shared queue assigns non-overlapping chunks to eligible accounts. Both regular and Takeout acquisition start from 2,000 numeric IDs per chunk and can widen that to at most 100,000 IDs using the densest participating account's available whole-history count estimate. This reduces empty requests in sparse histories; it excludes no IDs from the signed plan and does not change RPC pacing. Counts are a planning estimate, not a selected-period count or a deletion finding. An ID range is not a message count. Ordinary groups and private chats use one account because IDs cannot be merged across accounts in the same way.

`distributed-exports/<job-id>/` retains a signed immutable plan, signed chunk receipts, acquired JSONL chunks, rebuildable SQLite indexes and the resulting ZIP. New plans use `tgwitness-distributed-pages-v1` checkpoints inside each chunk. At most 100 decoded messages are buffered before a checkpoint; a 4 MiB target also flushes smaller batches (an individual record can be up to 64 MiB). These are local record batches, not raw Telegram RPC responses. Each receipt binds the plan hash, chat, account/signing key, ID range, before/after cursor, byte interval, data hash, local acquisition times, transport generation and previous receipt hash.

Data is flushed and synced before its receipt is atomically written and synced. Only then does the durable cursor advance. Pause drains an in-flight write before releasing the account. Resume verifies every retained checkpoint before connecting, ignores unsigned trailing bytes, and truncates that tail before continuing from the last committed cursor. Up to 99 buffered messages, or the current unsigned write, may need to be read again. Committed pages are retained unchanged. A partially acquired range stays with its original account; another account cannot silently finish that range. Empty terminal receipts identify iterator exhaustion for that observer, not universal absence. An expired Takeout can resume in a new generation, recorded separately in subsequent receipts.

Once a range is complete, its chunk receipt binds the final checkpoint head. Resume checks signatures, hashes, ranges, ordering, account identity and retained progress before reusing it. Old plans without `checkpoint_format` keep the original whole-chunk recovery path; they are not silently migrated. Paused jobs can be reopened from **Saved exports** in the export dialog. Several jobs can run concurrently when they use separate accounts. Each job keeps its own workers, checkpoints and timings; an account reserved by one job cannot join another until it is released.

Inspect a **paused or failed** new-format working directory without the app, SQLite index or vault:

```bash
python tgwitness/verify.py /path/to/distributed-exports/JOB_ID --fingerprint RETAINED_FINGERPRINT --json
```

This read-only check reports committed messages/pages, completed ranges and unsigned tail bytes. Pin the lead fingerprint independently. Like any local receipt chain, removal of its tail and all corresponding local progress cannot be detected without a separately retained receipt head. The verifier establishes local integrity, not Telegram signatures or an atomic snapshot.

Intermediate chunks include messages needed to evaluate filters, including rejected messages. Filters limit the final archive. A paused, cancelled or failed job retains those chunks and checkpoint receipts for recovery. After the ZIP passes verification, the app removes chunks, receipts, temporary media and indexes. The job directory retains `export.zip`, the signed `job.json` plan and `status.json`; use the ZIP verifier for completed jobs. The configured free-space reserve is checked before new chunks and each checkpoint.

Wider ranges still reduce requests across sparse histories. New checkpoints bound interrupted-range rereading independently of that width. Cross-account overlap coverage checks remain separate future work. Signing and syncing more often costs local I/O; checkpointing improves recovery, not the speed of a successful uninterrupted network read.

Plans created before the inclusive-start fix retain their original signed ID ranges on resume. Start a new date-filtered export to recover any message excluded at **From** by an older plan.

## Result and limits

### Performance measurements

The export panel and status API report elapsed time for the **current start or resume** using a monotonic clock. Preparation includes connection, boundary checks, saved-chunk verification and chat metadata. Acquisition measures the concurrent workers together, including Telegram waits, chunk writes and receipt signing. Selection and attachment retrieval, then packaging and verification, have separate timers. Pausing or finishing freezes the measurements; resuming starts a new measurement and excludes previously committed messages from its throughput numerator.

Acquisition throughput is newly committed messages divided by acquisition wall time. New jobs update at page commits, including progress inside an unfinished range; old jobs update at chunk commits. It is an average, not an instantaneous network rate. It does not include selection, attachments or ZIP/PDF creation. The signed job status retains these measurements; a successful run also records them in `chat_export.completed`. Jobs created before this feature have no performance record until resumed. Remaining message count is unknown, so the panel does not invent an ETA from numeric ID ranges. Compare runs with identical fixed scope, attachment settings and account access; more accounts do not guarantee linear speedup.

Large-list discovery has a different request mix from history acquisition. See the [exporter source comparison and limits](EXPORT-LIMITS.md) before extrapolating a small history benchmark to thousands of new sources.

A [50-source live qualification](EXPORT-BENCHMARK-2026-11-06.md) on 2026-11-06
produced 48 verified archives with 3,598,381 records. One eight-account regular-mode
job acquired 768,007 history records in 1,117.082 seconds; its complete attempt took
1,574.920 seconds. Rechecks added records that the history pass did not return.
The run also exposed sparse-range overhead, connection timeouts and slower later
jobs after learned pacing increased. It did not establish sustained Takeout speed
or linear scaling across forty accounts; see the qualification's scope and checks.

A bounded live pilot on 2026-11-06 UTC compared one and two accounts over the same approximately 4,000-ID ranges in two public supergroups. Acquisition of 3,313 messages took 33.672 s and 16.969 s; acquisition of 3,691 took 37.750 s and 19.188 s. All four ZIPs verified. ID sets matched between runs; differences in three reply-media headers were limited to access hashes and file references. These are small, sequential runs without attachments or Takeout, on a 32-logical-CPU Windows host; they do not establish sustained throughput for ten accounts or thousands of sources. Only authors and a bounded visible participant sample were collected, not complete membership.

### Archive

The ZIP uses the existing independently verifiable chat-export format with per-account signed parts, selected messages, context labels, selection settings and acquisition scope. `chat.json` is authoritative. HTML and PDF distinguish omitted-by-selection message numbers from evidence of deletion. The app verifies the ZIP before marking it ready; downloads remain available afterwards.

The manifest identifies the checkpoint format and count used locally. Unselected checkpoint data and its receipts are not added to a filtered ZIP. Archive verification continues to check the selected messages and their account signatures; local checkpoint verification is the separate directory check above. Old ZIPs remain supported.

Coverage means accessible ranges actually read, not all historical messages. Accounts can have different access; distributed or resumed acquisition is not an atomic snapshot. No actor, deletion reason, ban or moderator identity is inferred from a missing ID or online status. More accounts do not guarantee linear speedup.

API: `POST /api/multi-export/start` accepts `chat_id`, `lead`, `profiles`, `selection`, and `transport` (`regular`, the default, or `takeout`); `GET /api/multi-export/jobs` lists visible saved jobs. Per-job routes support polling, `pause`, `resume`, `cancel` and `download`. Access to every participating workspace/source is checked.
