# TgWitness product and collection model

Design reference: 26 October 2026. The primary use case is private Telegram groups
and channels accessible to the connected accounts. This document separates
implemented behavior, platform boundaries and future work. A target architecture
item is not a claim that the feature already exists.

## Standalone application

TgWitness has its own installation, data directory, and release lifecycle. The bundled
web interface handles setup and review; exported records can be used independently.

The operator connects their accounts, chooses sources visible to each, and obtains
a saved observation journal. The panel exposes content, saved changes, observation
provenance and known gaps. Another investigator can verify the exported material.

Four distinct states matter: account authorization, access to a source, a working
collector, and the extent to which delivery completeness is established. None of
the first three automatically proves the fourth. A quiet group is not necessarily
a failed collector.

## Optional extras

Everyday setup is account → sources → observation. **Extras** is a separate destination
with two cards: a Telegram witness bot and planned
GitHub build verification. Each states its availability and requirements before showing
settings. Choosing a card opens instructions; it does not enroll or start a service.

Bot setup has three steps: create read-only access, choose publication settings, and
launch on the witness host. Network and publication options, existing connections and
verification commands are disclosed on demand. Downloaded configuration is distinct
from a running witness. Switching extras retains the draft; account changes and locking
clear the temporary token and form. The built-in guide includes launch instructions.
GitHub remains a marked plan, with no credential form or pretend connection state.

## Protocol and private sources

**MTProto is Telegram's protocol; Telethon is the Python library TgWitness uses to
speak MTProto.** They are not alternative connection methods. Collection uses MTProto;
the optional witness publishes signed checks through the Bot API.

Each workspace has its own authorized client and account update stream. TgWitness
selects observations from configured sources and makes separate explicit requests
for functions such as history snapshots and media downloads.

A private source needs no public username. Telegram peer type and numeric ID are
the identifiers; titles and usernames can change. Access depends on existing
membership and permissions. TgWitness does not automatically join sources or bypass
join approval. An access hash from another account is not a universal access token.

The collection model must account for pre-join hidden history, participant/admin
roles, session revocation, removal or changed permissions, group-to-supergroup
migration, topics/forums, linked discussions, channel identities and unavailable
attachments. Not every combination has been qualified live.

Source visibility is checked at collector start. Missing a source from the bounded
dialog result means **access unconfirmed**, not proven removal. One unavailable
source does not prevent observing other accessible sources. Never put invitation
links or real sessions in public fixtures.

## Multiple accounts

The panel supports any number of **workspaces**, each with its own:

- Authorization, encrypted vault and connection route.
- SQLite journal and Ed25519 signing identity.
- Selected sources, media queue and capture settings.
- Observation state, errors, checkpoints and exports.

Switching the displayed workspace does not stop another collector. Duplicate account
authorization across workspaces is rejected. A journal already bound to one Telegram
account cannot be reassigned to another; reconnecting the same account is allowed.
This preserves account identity and the relevant message-ID scope.

There is no fixed number and no measured throughput guarantee. Workspaces share a
Python process and event loop. Separate account workers remain future work. For
current process isolation, use separate installations, ports and data directories.

Assign each account sources it can access. Different accounts may observe the same
group, but their observations remain separate and retain their origin. Two accounts
on one operator-controlled machine are not two independent witnesses. Exports are
per workspace; a merged case package or global Telegram timeline is not implemented.

## Capture and attribution

Sources provides per-account switches for new messages, edits, deletions, reactions
and membership. Presets retain either all categories or messages/edits/deletions.
The policy applies to the workspace's selected groups, survives restart, and is signed
with before/after changes. Defaults preserve all categories. Turning a category off
does not remove old records; turning it back on does not reconstruct missed events.
Operational records, other group service events and explicit history snapshots are
separate. Captured Telegram objects may retain embedded metadata regardless of the
separate-update switches. There are no per-group category overrides yet.

| Material | Captured now | Boundary |
| --- | --- | --- |
| Message | Text, peer/message IDs, sender metadata, replies and original update envelope | No publicly verifiable Telegram signature for the message |
| Edit | New observed version and any previously saved versions | Intermediate edits during downtime can be lost; sender is not necessarily editor |
| Deletion | Notification and prior captured content, if any | Usually no deleter or precise action time |
| Unscoped deletion | Original account-level notice without guessing the peer | Strict correlation with previously saved account-scoped IDs is future work |
| Reaction | Delivered counters and visible recent identities | A complete available reactor list requires separate queries; channels may hide identities |
| Membership | Service messages and delivered participant updates | Visibility depends on role and chat type; missing events do not establish absence |
| Admin actions | Only relevant delivered updates | Separate admin-log polling is not implemented |
| Attachment | Original version descriptor, downloaded bytes/SHA-256 and attempt outcomes | A vanished file may be unrecoverable; the latest version is not substituted |
| History | Explicit snapshot of current visible messages | Does not reconstruct all edits or deleted content |
| Collector process | Start/stop, heartbeat, errors, settings, scope and program receipt | Self-report, not independent process attestation |

An action is attributed to a person only if the source actually supplies that actor.
Otherwise the interface reports the missing attribution. Usernames and names are
observed attributes, not proof of real-world identity.

## Capacity and Telegram limits

There is no universal number of chats that can be monitored with guaranteed quality.
Capacity depends on peak events per second, attachment volume and sizes, additional
RPCs, active accounts, disk latency/free space, network conditions, Telegram limits,
acceptable lag and queue depth.

Telegram distinguishes passive delivery from active short polling. Its update
documentation describes additional `updates.getChannelDifference` calls for open
channels/supergroups and recommends at most **ten simultaneously short-polled
sources**. This is not a limit of ten selected groups or a completeness guarantee.

| Mode | Purpose | Status |
| --- | --- | --- |
| Standard observation | Record delivered updates from selected sources | Implemented |
| Priority observation | Additional difference checks for a bounded source set | Not implemented as a user mode |

Arbitrary high-frequency polling, ignoring FloodWait or assuming linear capacity
from extra accounts is not a valid sizing model. Default limits are the
first 1,000 listed dialogs, up to 500 messages per history snapshot,
1–2,000 MiB per collected file by type, and 4 GiB uncompressed signed ZIP content; each
is changed per workspace under **Parameters**. Exports have no fixed event-count cap.
Browser fallback is bounded to 128 MiB by default; the streaming CLI has a configurable
transfer limit, 5 GiB by default.

`tools/check_capacity.py` measures local synthetic ingestion and export. Its results
are not Telegram delivery measurements or a guaranteed real-chat count. See
[VERIFICATION.md](VERIFICATION.md) for the measured version and workload.

## Reliability and recovery

Implemented behavior includes SQLite WAL/synchronous transactions; atomic message
and media-job writes; persistent jobs and retry delays; original-version descriptors;
bounded retries; persisted media FloodWait; media downloads outside the text event's
network wait; stable-prefix exports while later writes continue; atomic settings and
audit records; preservation of working authorization after failed replacement login;
isolation of a damaged additional workspace; explicit reconnect attempts; distinct
authorization-loss reporting; and wall-clock change detection using a monotonic clock.

Account and channel pts/qts/seq are saved and resumed after a restart, and observed chats
are rechecked periodically; see [evidence format](EVIDENCE.md#durable-collection-and-process-receipts-02). Saving the position
periodically is not an atomic, lossless acknowledgement of journal acceptance.

Every process start records the previous head and offline boundary. Current history
is not treated as gap repair. Telegram's difference retention is finite;
`differenceTooLong` cannot reconstruct all vanished content. Irrecoverable gaps must
remain explicit even if a later history snapshot succeeds.

## Evidence model

Each event records a sequence, local UTC observation time, source time when supplied,
kind, source, actor when supplied, original payload, previous hash and signature.
Message observations also retain collector account/run context.

The signed process receipt contains a random run ID; TgWitness/Python/OS/dependency
versions; source-file SHA-256 values and aggregate fingerprint; initial account,
scope and settings; UTC/monotonic readings; and the preceding journal head.
Settings changes, start/stop and errors enter the same journal. Checkpoints are
retained at startup, every five minutes while observing (changeable), and on orderly stop.
A retained local checkpoint can detect rollback to an earlier journal prefix.

| Mechanism | What it establishes |
| --- | --- |
| File SHA-256 | Bytes match a known digest |
| Event hash chain | Record ordering/linkage relative to a known boundary |
| Ed25519 | Signature under a particular key |
| Independently retained checkpoint | Later material agrees with the retained boundary |
| Program-file measurement | Collector self-report about measured files |
| Valid independent TSA response | Existence of particular bytes by the TSA time under explicit trust assumptions |

RFC 3161 request preparation and OpenSSL response verification are implemented.
Automatic submission is not. A request or local signature carrying the machine's
time is not an independent timestamp. See [TIMESTAMP.md](TIMESTAMP.md).

An operator controlling the collector and signing key can fabricate new signed
observations. The signatures do not establish Telegram origin, truth or automatic
legal admissibility. Stronger custody requires independent checkpoint/time storage,
key access controls, transfer records and verification from trusted software.

## Export, deployment and handoff

A signed ZIP contains original JSONL, CSV, HTML, preserved attachments, hashes, a
signed manifest and a convenience verifier. It covers one workspace and a fixed full
journal prefix. Panel search filters do not silently remove records. Secret keys,
tokens and Telegram sessions are excluded; original observations can still contain
personal information and Telegram metadata.

Retain the ZIP digest, trusted fingerprint, checkpoint, process receipt and handoff
record separately. Use a verifier from a trusted installation, rather than trusting
executable code solely because it appears in the examined ZIP.

The browser interface ships locally without Node.js, CDNs or external fonts. One
operator token controls the installation. Remote access needs HTTPS or an SSH tunnel.
Native Python and container definitions are supplied, with service examples under
[deploy/](../deploy/README.md); executed platform checks are listed separately.

The default workspace uses the data root; additional workspaces use `profiles/<id>/`.
Backup requires a stopped process and the complete data/key set. Evidence ZIPs are
not application backups. Secrets can use an external master key for a new data
directory; journal/media encryption is provided by the operator's disk/volume.
See [CONNECTION-SECURITY.md](CONNECTION-SECURITY.md) and [OPERATIONS.md](OPERATIONS.md).

## Stable release criteria

Before a stable release, qualify:

1. Real private groups, supergroups, forums and channels with member/admin roles and
   hidden/visible history, including login/2FA, revocation and access loss.
2. Controlled edits, deletions, reactions, membership and media against known actions.
3. Process/host crashes, disk failures/full disk, expired file references, FloodWait,
   network loss, corrupted files and database rollback.
4. Sustained multi-account use with measured lag, queues, memory and disk, including
   quiet and noisy sources together.
5. Interruption between MTProto state advancement and journal acceptance.
6. Clean installation on the intended OS/container matrix and verified backup restore.
7. Independent review of security, signatures and attribution/evidence claims.

Admin-log polling, additional reactor lists, priority polling, separate workers,
application-wide encryption and user roles remain future work. Version 0.6 supports
the bounded single-account TData and account-file import described in [ACCOUNTS.md](ACCOUNTS.md).
Review Telegram API terms before publication. Research references and platform
findings are in [RESEARCH.md](internal/RESEARCH.md).
