# Distributed chat export

Open a chat and choose **Export chat**. Select idle account workspaces that already have access to the source. Every account keeps its configured connection. This feature does not change WARP or choose an exit IP.

## Exclusive account ownership

One account runs one acquisition task. Monitoring, History, account export and chat export are mutually exclusive. Starting an export never pauses monitoring automatically. Deselect a busy account or explicitly pause its current task first. Reservations are acquired before Telegram requests and released on completion, failure or pause. Separate accounts may work concurrently; RPCs within one account are serialized. Full server-requested FloodWait deadlines are persisted and respected before subsequent requests, including after restart. This cannot guarantee Telegram will never rate-limit an account.

## Selection

- All available history, rolling 7/30 days, previous calendar month, or custom bounds. UI dates use the browser time zone and become fixed UTC bounds `[from, until)` at launch.
- Offline message-language detection using Lingua. Short, uncertain and mixed-language messages have a separate include/exclude option. Detector version and decisions accompany evaluated selected messages; confidence is a heuristic, not proof of language.
- **Messages that are replies** selects direct replies. **Messages that received a reply** selects originals with an observed direct incoming reply. Relationships are built before language/text filtering, so a Russian answer can qualify an English original. Merely posting into a forum topic does not count as a direct reply.
- Replies can be sought within the selected period or through the acquisition start. The latter can require scanning later history too.
- Bounded parent/reply context with a separate message cap. Context may fall outside the filters and is marked `selection.role=context`. Missing parents retain a reason; linked discussions outside the chosen source are not traversed. Context expands over acquired history and fetches missing same-source parents; it does not discover every reply outside the scanned period.
- Literal text phrase; sender-ID filtering through the API. Optional attachments are fetched after selection under each account's capture policy. A changed message is not silently substituted during attachment retrieval.

## Chunking and continuation

For a supergroup/channel, preflight resolves the source separately for every account and fixes visible date/ID boundaries. The shared queue assigns non-overlapping chunks of up to 2,000 numeric IDs to eligible accounts. An ID range is not a message count: Telegram can omit IDs. Ordinary groups and private chats use one account because IDs cannot be merged across accounts in the same way.

`distributed-exports/<job-id>/` retains a signed immutable plan, signed chunk receipts, acquired JSONL chunks, rebuildable SQLite indexes and the resulting ZIP. Receipts include the fetching account's signing key, range, count, hash and commit time. Pause preserves committed chunks; an interrupted chunk is fetched again. Resume checks signatures, hashes, ranges, ordering and account identity before reusing chunks. Paused jobs can be reopened from **Saved exports** in the export dialog. One distributed job runs at a time in this coordinator.

Intermediate chunks include messages needed to evaluate filters, including rejected messages. Filters limit the final archive; rejected messages can remain in local storage. The configured free-space reserve is checked before new chunks. Completed job directories are not deleted automatically.

## Result and limits

The ZIP uses the existing independently verifiable chat-export format with per-account signed parts, selected messages, context labels, selection settings and acquisition scope. `chat.json` is authoritative. HTML and PDF distinguish omitted-by-selection message numbers from evidence of deletion. The app verifies the ZIP before marking it ready; downloads remain available afterwards.

Coverage means accessible ranges actually read, not all historical messages. Accounts can have different access; distributed or resumed acquisition is not an atomic snapshot. No actor, deletion reason, ban or moderator identity is inferred from a missing ID or online status. More accounts do not guarantee linear speedup.

API: `POST /api/multi-export/start` accepts `chat_id`, `lead`, `profiles`, and `selection`; `GET /api/multi-export/jobs` lists visible saved jobs. Per-job routes support polling, `pause`, `resume`, `cancel` and `download`. Access to every participating workspace/source is checked.
