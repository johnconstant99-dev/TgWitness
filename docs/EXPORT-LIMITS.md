# Export pacing and Telegram limits

Reviewed on 6 November 2026 UTC. This compares implementation paths, not advertised
throughput. Source inspection and synthetic tests do not establish a safe Telegram
quota. Exact limits depend on the request and account circumstances; Telethon's
[error documentation](https://docs.telethon.dev/en/stable/concepts/errors.html#avoiding-limits)
does not provide a universal request rate.

## Different workloads need separate measurements

Resolving thousands of previously unknown usernames is different from reading
thousands of pages from one known chat. Measure `contacts.resolveUsername`,
`messages.getHistory`, participant requests and Takeout initialization separately.
Access hashes belong to the account that obtained them. A stored peer can reduce
repeat resolution, but another account must obtain its own access information.
Username reassignment also means a cached username is not proof of its current owner.

Telethon's [`get_entity` implementation](https://github.com/LonamiWebs/Telethon/blob/v1/telethon/client/users.py)
explicitly warns about repeated username resolution (roughly 50 usernames in a
short period in its observations). This is not a published hourly quota. Calling
`get_entity(username)` forces a fresh lookup; `get_input_entity` can use an existing
account-local cache. The first pass over unknown usernames still needs resolution.

Takeout uses Telegram's [export API](https://core.telegram.org/api/takeout), with
explicit scope flags and wrapped requests. It can require an approval delay.
It is not an exemption from every limit and does not grant access to hidden members.
The absence of forwarding protection does not prove Takeout eligibility. JSON is
an output format; writing JSON itself does not make API acquisition faster.

## Reviewed implementations

| Tool and pinned source | Actual behavior | Applicable lesson and limits |
| --- | --- | --- |
| [tg-chat-dump `b496a89`](https://github.com/renkagod/tg-chat-dump/tree/b496a89d154076c55e5abd707370ad88c44cbeb7), MIT | `accounts.py` sets Telethon's flood sleep threshold to 24 hours. `fetch.py` runs three workers per account by default and sets `wait_time=0`. It reuses Takeout across chats. `store.py` commits rows and cursor together every 100 messages; ID tasks are up to 5,000 IDs. | Page-level checkpoints reduce restart work. Zero iterator delay and three workers are performance choices, not rate-limit protection. After Takeout approval delay, ordinary acquisition is allowed and initialization can be tried again on a later dump. Do not copy that behavior as a safety guarantee. |
| [tg-archive `b8f3feb`](https://github.com/knadh/tg-archive/blob/b8f3febaad1180cd581bed0ff07d582d012e8c0b/tgarchive/sync.py), MIT | Incremental SQLite sync, default batches of 2,000 messages, five seconds between batches. Takeout uses zero iterator wait. `_fetch_messages()` logs an escaping FloodWait but returns no messages or retry state. | Useful incremental acquisition pattern. The escaping error path returns `None`; its caller then iterates it. It is not a robust long-wait implementation. |
| [tdl `70c561c`](https://github.com/iyear/tdl/tree/70c561c0a6d44d8d7fffdea14988fc4104bc56d2), AGPL-3.0 | `app/chat/export.go` pages history by 100. Default middleware includes gotd's [`SimpleWaiter` v0.20.0](https://github.com/gotd/contrib/blob/v0.20.0/middleware/floodwait/simple_waiter.go), which waits for the returned duration and retries until cancellation by default. Participant export skips filters requiring admin permission. | Separate permission failures from rate limits. File-download threads do not establish message-export concurrency. The chat-export path calls the ordinary API; the reviewed Takeout pool is used by the file downloader. |
| [Telegram Desktop `6d7e0ab`](https://github.com/telegramdesktop/tdesktop/blob/6d7e0ab348cb2a5520776de442e215833f4573c0/Telegram/SourceFiles/export/export_api_wrap.cpp), GPL-3.0 | Export history uses pages of 100 and advances its cursor after handling a slice. It obtains Telegram split ranges; public-only exports can use the final range. | Follow the supported export procedure and avoid unnecessary ranges. The slice size is not a published requests-per-second allowance. |

No source code from these projects was incorporated for this review.

### Prevention and retry implementations

Five additional checkouts were inspected at the commits below. They distinguish
preventing bursts, responding to a server wait and reducing repeated work. These
are different controls; increasing a library's automatic sleep threshold only
changes how an already received wait is handled.

| Tool and pinned source | Actual behavior | Applicable lesson and limits |
| --- | --- | --- |
| [gotd/contrib `2ae3c55`](https://github.com/gotd/contrib/blob/2ae3c554730a955ed6cd10b358f8466e29b5e770/middleware/ratelimit/ratelimit.go), MIT | A token bucket reserves capacity before invoking a request; the caller supplies the rate and burst size. Its separate [FloodWait scheduler](https://github.com/gotd/contrib/blob/2ae3c554730a955ed6cd10b358f8466e29b5e770/middleware/floodwait/scheduler.go) delays queued requests of the affected type. | Use admission control before sending, in addition to recovery after failure. There is no universal safe rate in this implementation. The scheduler keys on the request constructor; TgWitness must retain the inner method and Takeout wrapper distinction. |
| [mtcute `8def99b`](https://github.com/mtcute/mtcute/blob/8def99b4f5c831cdbc55527e3096a80c790e1409/packages/core/src/network/middlewares/flood-waiter.ts), MIT | Caches method-specific deadlines in memory. A cached wait exceeding the caller's threshold returns a local error without sending another request. Cancellation is supported. SLOWMODE_WAIT is excluded from the method-wide cache. | Avoid repeated calls while a known deadline is active. Its cache is not durable, and the default ignores the last two seconds of a cached wait; do not replace TgWitness's persisted full deadline with that behavior. |
| [Telegram-Archive `18b629b`](https://github.com/GeiserX/Telegram-Archive/blob/18b629b6c7d31cb1217b2275487a160e79b0a461/telegram_archive/telegram_backup.py), GPL-3.0 | `_resweep_pace()` spaces reaction-refresh requests across chat boundaries. `_register_resweep_flood()` parks progress until the requested wait plus two seconds; the third flood defers the rest of that run. | Keep pacing state across chats and bound automatic recovery. These controls govern reaction refresh, not a measured history-export quota. Preserve unfinished cursors so deferral does not permanently starve later chats. |
| [telegram-migrator `ad01288`](https://github.com/warl0ckwraith/telegram-migrator/blob/ad012889302de4be7ce8d90b3ef879aa8a8852e9/src/transfer_engine.py), MIT | `AdaptiveThrottle` reduces the batch and increases delay after a flood; it only starts increasing throughput after eight stable batches. | Feedback-driven pacing is useful. This class governs forwarding/copying messages; its numerical presets are not evidence of safe read limits. |
| [tg-export `e8ed303`](https://github.com/deathmaz/tg-export/blob/e8ed30306b8f46cb9521121567b0ed0b62e33b8a/src/tg_export/fetcher.py), MIT | `wait_time` is selected from the requested mode before opening Takeout. `_takeout_or_client()` falls back to the ordinary client on TakeoutInitDelayError without changing that selection. | A reproduced fallback can use the ordinary client with `wait_time=0`. Select pacing from the actual transport, not just the requested flag. TgWitness's distributed Takeout mode already pauses for approval instead of silently falling back. |

The reviewed gotd waiter also clamps parsed wait durations to fourteen days in
[`flood.go`](https://github.com/gotd/contrib/blob/2ae3c554730a955ed6cd10b358f8466e29b5e770/middleware/floodwait/flood.go).
Do not shorten a server-requested deadline when adapting an implementation. A
maximum *automatic* wait should stop or defer the job when exceeded, not authorize
an early retry. No code from these five projects was incorporated into TgWitness.

Offline probes executed the named Python definitions with fixture clocks and
clients: spacing across chats, third-flood deferral, adaptive batch reduction and
the Takeout fallback above. Telegram-Archive requires Python 3.14; only its two
unchanged, compatible methods were exercised on Python 3.12. These were not full
upstream test suites or live Telegram measurements. The Go and TypeScript paths
were inspected, not executed.

Desktop's [MTProto error handler](https://github.com/telegramdesktop/tdesktop/blob/6d7e0ab348cb2a5520776de442e215833f4573c0/Telegram/SourceFiles/mtproto/mtp_instance.cpp)
also parses FloodWait and schedules the affected request after the returned number
of seconds (plus a small timer margin). Official export does not mean zero waits.

## TgWitness behavior and measured limits

[Account export](ACCOUNT-EXPORT.md) supports Takeout and durable page receipts.
[Distributed chat export](DISTRIBUTED-EXPORT.md#history-acquisition) now has an
opt-in Takeout history path for public channels and supergroups. New plans for
either transport can widen 2,000-ID chunks up to 100,000 numeric IDs in sparse
histories without excluding any IDs. Existing signed plans keep their original
chunk sizes. Transport and generation accompany signed receipts.
This path has offline protocol/recovery tests and browser checks; sustained
Takeout throughput has not been measured. Regular-mode observations are recorded
in the [50-source qualification](EXPORT-BENCHMARK-2026-11-06.md). New distributed plans retain signed
checkpoints of up to 100 decoded messages inside a chunk, with observer-bound
recovery and standalone verification. These local batches differ from account
export's API-page receipts; older distributed plans retain chunk-only recovery.

The shared client serializes RPC calls and persists the complete server-requested
deadline before another call, including after reconnect. It now records method,
wrappers, wait duration, effective deadline and per-method client-call counts in
`telegram.backoff`. Connection details show the method and deadline while paused.
Arguments and exception text are omitted. Counters begin with the client instance;
they are not wire-level attempts and do not expose retries inside Telethon.
The existing event kind and signed export format remain unchanged.

`AccountPacer` covers history, dialogs, admin logs, message-ID rechecks and
participant pages, including Takeout-wrapped requests. It starts with a one-second
interval, decreases it after twenty successful bulk calls to a floor of half a
second, and increases it after FloodWait, capped at ten seconds. These are local
policy values, not Telegram quotas. The learned delay is persisted per account;
the next-send timer belongs to the client instance. Full server deadlines remain
authoritative, including FLOOD_PREMIUM_WAIT.

The earlier source probe concerned the pre-integration branch: its serial queue
alone did not add pacing. The current bulk pacer still does not cover unknown
username discovery, and does not give ordinary and
Takeout history separate budgets. The existing profile guard rejects adding the same Telegram account
to another workspace; that guard was also exercised and must not be duplicated.
It does not coordinate independent installations on separate servers.

A 50-source benchmark pilot exposed a 31-second `channels.getMessages` FloodWait
while rechecking missing IDs. Those calls previously shared the account's server
cooldown but bypassed the local bulk interval. ID rechecks and participant pages
now use that interval too. This prevents that unpaced burst; it does not establish
a flood-free quota. The completed qualification retained 690 backoff events across
pilots and interrupted runs, with requested waits of 3–31 seconds. Both history
and ID rechecks triggered waits. These observations do not establish a universal
quota; the qualification identifies the source revisions and counter coverage.

The next pacing change should:

1. Keep a scheduler per account with separate budgets for discovery, ordinary
   history, Takeout history and participants. Resolve Takeout wrappers before
   classification. Preserve the existing full account cooldown on FloodWait.
2. Retain scheduling state across chats and client recreation. On multiple servers,
   assign an account to one active worker or coordinate its lease and deadline;
   an additional authorization of the same account is not independent capacity.
3. Decrease the affected workload's rate after a wait, with bounded, gradual
   recovery. Defer long or repeated waits with durable progress. Do not retry an
   unchanged workload immediately at its previous speed after the deadline.
4. Reuse account-local peers and verified page checkpoints. Distinguish resolving
   a known ID from observing the current owner of a username. Avoid repeated
   full-profile lookups when a cached input peer is sufficient.
5. Expose time spent acquiring, pacing, waiting for Telegram and committing data.
   Calibrate rates with bounded live batches; advertise no unmeasured quota.

These extensions to the bulk scheduler are recommendations, not implemented behavior. Durable
checkpoints already avoid reacquiring committed pages after interruption. Overlap
of network reads and bounded local processing can improve throughput without
increasing request concurrency; that overlap is also not implemented yet.

The bounded [one/two-account history pilot](DISTRIBUTED-EXPORT.md#performance-measurements)
does not measure sustained discovery. A separate live inventory of 4,408 public
links, with three-second gaps between top-level operations, was paused after 388
completed results: 380 accessible sources and eight unavailable. Their reported
available-message counts totaled 34,409,815; their last IDs totaled 169,711,686.
Neither sum establishes deletions or completeness of the unprocessed list.
Both workers received FloodWait (logged waits of 9,803 and 70,390 seconds).
The old log omitted the failed method: attributing these waits to username
resolution or history would be speculation. Both clients disconnected; saved
results remain resumable.

The local inventory harness now stops scheduling on the first observed FloodWait
(another account may already have a request in flight), retains the full deadline,
and refuses a new pilot if either account still has a persisted wait. It limits a
pilot to 20 new sources per account and spaces source-resolution operations by at
least ten seconds, with at least three seconds between top-level operations.
These are conservative local pilot settings, not Telegram quotas or production
defaults. The harness remains outside the repository; no new live run has validated
these settings. Existing signed receipts are reused without refetching their sources.

Before scaling, measure discovery, history and participant acquisition independently
on bounded batches after all waits expire. Report committed messages, elapsed time
including waits, requests by method, inaccessible sources and partial membership.
For sparse numeric ID ranges, compare cursor-based history with fixed-ID chunking:
empty chunks can add requests without yielding messages. Keep this comparison
separate from evidence of deletion. No 10/50/100-account scaling guarantee follows
from the current pilot.

## Counts and ID boundaries

Keep server-reported counts, observed unique messages and numeric ID spans separate.
Telegram's [channel history response](https://core.telegram.org/constructor/messages.channelMessages)
can mark results `inexact`. A pagination offset does not establish a count for a
selected date range. In the reviewed tg-chat-dump code, `id_bounds` narrows dates
but retains the total from the initial history response. Telethon's history
`get_messages(limit=0)` obtains the total using a raw request with `limit=1`.

Matching counts do not prove that no messages were deleted before observation.
If IDs 6 through 10 disappear before a first observation, a visible history of
IDs 1 through 5 can have server count, acquired count and ID span all equal to five.
Different account totals also need measurement times, filters, response precision
and access conditions before a visibility difference can be established.

Record the account binding, chat, observation time, transport and exact selection
scope with any count comparison. Count observed service messages separately;
subtracting an estimated service-message ratio cannot yield an exact deletion
count. Describe unexplained missing IDs as absence within the measured scope.
The collector's signature protects the recorded observation against later changes;
it does not turn the count into a publicly verifiable Telegram signature.
