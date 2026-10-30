# How collection works

TgWitness records what a connected Telegram account observes. The journal preserves
those observations, their sequence, and the context supplied with them. It does
not infer unseen actions from a missing message or from an account being connected.

## From login to a journal

```mermaid
flowchart TD
    A[Authorize a user account] --> B[Select accessible groups and channels]
    B --> C[Save event and attachment settings]
    C --> D[Start observation]
    D --> E[Receive updates from the active client]
    E --> F[Apply source and event policy]
    F --> G[Append a signed observation]
    G --> H[Review or export the journal]
    G --> I[Process any queued attachment]
    I --> J[Append the download outcome]
```

Authorization, access to a source, a running collector, and complete delivery are
different questions. A successful login does not grant access to every group.
A connected transport does not establish that every relevant update arrived.

## Observation scope: chosen chats, a folder or the whole account

Sources → **Observation scope** decides which chats a workspace records.

| Mode | Records | New chats |
| --- | --- | --- |
| Chosen chats (default) | Only the chats you add by hand | Never added automatically |
| Telegram folder | Chats in one of the account's folders: chats included by name, plus the folder's categories (contacts, non-contacts, groups, channels, bots), minus its excluded chats and, if the folder says so, archived chats | Matching chats are added as soon as they become active; chats you add to the folder in Telegram are picked up within an hour |
| Whole account | Every chat the account sees | Every new chat, group, private chat or bot is added the moment its first update arrives |

- **Source types** (channels, groups, private chats, bots) narrow the folder and
  whole-account modes. Chosen chats can be of any type, including private chats and bots.
- **Excluded chats** are never recorded, in any mode. In folder and whole-account modes,
  *Exclude* and *Remove* on a source put it on this list, so the scope does not add it again.
  Choosing the chat again by hand (in Sources or from Chats) takes it off the list. The list
  holds up to 5,000 chats; past that, *Remove* is refused and the chat can be paused instead.
- **Own actions** (on by default): messages this account sends, its edits and its
  reply-keyboard button presses. Turned off, outgoing messages and edits are skipped.
- Switching to a folder or the whole account asks for confirmation: these modes record
  private chats and messages of third parties and belong on a dedicated account only.
  The confirmation and every scope change are signed `scope.changed` records.
- Chats added by the scope appear as sources marked *auto*, recorded as `scope.applied`
  (at start and hourly) or `source.discovered` (a new chat while observing). Switching back
  to chosen chats pauses every automatically added source.

What these modes cannot do:

- **Secret chats** are end-to-end encrypted between two devices and never reach
  TgWitness, in any mode.
- **Nothing is recorded while TgWitness is not running.** After a restart it asks Telegram
  for missed updates and rechecks chats, but Telegram does not return everything after long
  outages. Reports and `verify.py` show such periods as gaps (see [coverage](EVIDENCE.md#coverage-continuity-gaps-and-unobserved-ids)).
- Only the first 1,000 dialogs are listed at start (the limit is under **Parameters**); older
  chats are added when they next become active. The earlier history of an added chat is not fetched — take a history
  snapshot or a full chat export when you need it.
- Folder conditions that change all the time (muted, read) are not applied: such chats
  stay observed.
- **Inline (callback) bot buttons** pressed in another app are invisible to a second
  session; the bot's reply or edit is recorded. Reply-keyboard presses arrive as outgoing
  messages and are labeled `button_press`.
- More chats mean more requests. Telegram restricts accounts for volume it considers
  excessive, which is one more reason to use dedicated accounts.

## Scope and event selection

Each workspace has its own sources. TgWitness does not join groups, accept
invitations, or enumerate every member automatically. Sources must already be
accessible to the account. At startup, the collector checks selected sources
against the account's visible dialogs; the first 1,000 dialogs are inspected unless
**Parameters → Chats read from the account's list** says otherwise.
An absent source is marked **access unconfirmed**, not assumed to have removed you.

| Setting | Collects | Effect when disabled |
| --- | --- | --- |
| New messages | Ordinary delivered messages | Later edits/deletions may have no earlier captured text to compare. |
| Edits | Delivered edited message versions | Intermediate changes are not reconstructed later. |
| Deletions | Scoped deletion notices and unscoped account-level notices | Deletion notices are not added to the journal. |
| Reactions | Delivered reaction snapshots | Separate reaction updates are not added. |
| Membership | Delivered membership service messages and participant updates | Those membership observations are not added. |

Settings apply to all selected sources in the workspace. Save the form to apply
changes; changes are recorded with signed before/after values. Disabling a category
does not remove earlier records. Re-enabling it does not backfill missed updates.

Operational records and other group service events remain separate from these
switches. Membership service messages can create message records when membership
is enabled even if ordinary new-message capture is disabled. Captured Telegram
objects retain embedded metadata; a switch is not a redaction rule.

**Deletions in private chats and ordinary groups** arrive as message IDs without a chat.
These chats share one account-wide message ID sequence, so when a message with that ID was
saved earlier, its chat is known: the deletion is recorded in that chat with
`chat_resolution` explaining how. IDs never saved stay an **unscoped deletion** with an
explicit unknown source; the collector does not guess. Telegram never says who deleted a
message; when the deleted message was sent by this account, the record says so
(`deleted_message_was_outgoing`) without naming a deleter.

## Own actions

Messages sent by the observed account are labeled `outgoing`. An edit of an outgoing
message notes that in private chats and groups only its author can edit it, while channel
posts can be edited by other admins. When an outgoing message repeats the text of a button
from the newest saved reply keyboard in that chat, it carries `button_press` with a link to
the keyboard's record.

Excluding own actions also applies to background rechecks and automatic new-chat history.
Skipped outgoing messages advance the recheck position so they cannot block later incoming
messages. Explicit panel actions and manually requested history snapshots remain recorded.

## Investigation mode: joining teams and talking to bots

**Sources → Observation scope → Investigation mode** prepares the scope for a dedicated
account that joins team chats, starts bots and writes to them: the whole account, every
source type, own actions, and for every chat or bot that appears its profile and its latest
200 visible messages. Review the form and press **Save scope**; the switch to the whole
account asks for the usual confirmation.

- **Buttons.** Buttons under a message are kept with it and shown in **Chats**: links, web
  apps, login links, texts to copy, callback data, inline queries, requests for a phone
  number or location. Links are shown as text and never opened by the panel. When a bot
  changes only the buttons (a new payment link), that is a new version of the message, both
  from live updates and from rechecks.
- **New chats and bots.** In folder and whole-account modes, **When a new chat or bot
  appears** saves, right after it appears:
  - its profile as a `source.profile` record: bot description and commands, the about text
    of a user, group or channel, members, linked chat and invite link when Telegram returns
    one;
  - its latest visible messages (up to 1,000) as a history snapshot marked `new_chat`: the
    earlier messages of a team chat just joined, or what a bot said before observation
    noticed the chat. Messages already saved live are not repeated.

  Chats already in the list when the mode is switched on are added without snapshots.
  A FloodWait pauses this work and it resumes afterwards; failures are recorded and live
  recording of the chat continues.
- **Profiles on request.** **Chats → Profile → Save profile now** saves the current profile
  of any source; the newest one is shown above the messages.
- **Not visible.** Inline (callback) buttons pressed in another Telegram app, the popup or
  link a bot answers such a press with, and invite links used in another app do not reach
  TgWitness. What the bot sends or edits afterwards is recorded.

### Act from the panel

**Chats** now includes a mini-client using the selected workspace's Telegram account:

- Write a plain-text message or choose **Reply** under a saved message. The returned outgoing
  message is recorded even when the scope excludes outgoing updates.
- Press **Press button** under a current callback or text button. The server fetches the
  message again and refuses the action if the keyboard differs from the saved version.
  Callback receipts retain Telegram's popup text, alert flag and URL; the answer is also shown
  below the conversation. URLs remain selectable text and are not opened automatically.
- Expand **Open Telegram link**, enter `@username`, a public `https://t.me/name` link,
  `https://t.me/+invite` / `joinchat/invite`, or a bot link with `?start=parameter`, and press
  **Save preview**. The original link and Telegram's preview are signed before joining.
  **Join / open and observe** then joins the group/channel or opens the user/bot, adds the
  chat as an enabled source, and sends `/start` to a bot, including its start parameter.
  A join request awaiting administrator approval is recorded as pending, not as membership.

Turn on **Start observation** to capture incoming replies live. Panel actions work while
observation is paused, but only their direct responses are then guaranteed to be saved.
Newly added sources use the configured profile/history intake when observation is running.
When a source is paused, enable it in **Sources** before sending or pressing its buttons.

`interaction.preview`, `interaction.requested` and `interaction.result` are ordinary signed
journal events included in evidence exports. Requests identify the account, message/button
or preview record and whether observation was running. Receipts distinguish success,
rejection, approval pending and an unknown outcome. An interrupted request may have reached
Telegram: check the chat before starting a new action. Reusing a request ID retrieves its
saved receipt without repeating the action, including after restart. The panel retains the
ID after an ambiguous response for the same action during the current page session.
It also retains that ID when refreshing the view fails after a successful action: the receipt
stays visible, and clicking again retrieves it. Callback and join RPCs have one application
attempt; retryable reads keep their configured retry policy. Switching chats immediately
clears the draft and reply target and disables sending until the new conversation loads.

This mini-client handles text and callback buttons. Web apps, login/phone/location requests,
payments, inline queries and attachments still require a Telegram client; their saved button
metadata remains visible. The new controls use English text.

## Recheck tiers

Rechecks ask Telegram again for missed messages, edits and messages it no longer returns.
Sources marked with a star are **priority** sources, rechecked every 15 minutes by default;
all other sources every 6 hours. Chosen chats start as priority sources, chats added by a
folder or the whole account as regular ones. At most 30 sources are rechecked per pass and
the rest wait for the next minute; after a reconnect, priority sources go first. Both
intervals are set under Sources → Recording settings → Recheck (0 turns a tier off) and are
recorded as `recheck.changed`.

Missed messages are fetched upward from where the previous pass stopped, at most
**Parameters → new messages per recheck** (1,000 by default) per pass. After a long stop the
recheck therefore fills the whole gap, even when live messages newer than the gap were saved
first. A chat that is still catching up is rechecked again on the next minute instead of
waiting for its tier interval; `recheck.completed` shows `continues_after` until it is done.

Comparisons include message text, entities, keyboards (including removal), and attachment
content/identity. Changing file access hashes or file references alone does not create an
edit, nor does what Telegram fills in on its own: a link preview loading, story views, paid
media unlocked by this account, an invoice's receipt. Each saved version in Chats links to its full journal record, including media metadata.

## Message history and attribution

Suppose the collector observes “Meeting at 10:00,” later sees “Meeting at 11:00,”
and then receives a deletion notice. It appends three distinct observations. The
original text remains, the edit is a separate version, and the notice records that
a deletion was observed.

If collection began after the first version disappeared, that text is unavailable.
If several edits occurred while the process was offline, only subsequently observed
versions can be saved. A deletion notice cannot recover content never captured.

The message sender is not automatically the editor. Telegram usually does not
supply the person who deleted a message or the exact deletion time. Unknown actors
stay unknown. Reaction snapshots and participant updates contain only the counts
and identities Telegram makes visible to the account.

Sequence numbers express observation order. The collector's UTC timestamp is its
local clock; a Telegram source timestamp is stored separately when supplied.
Neither is an independent trusted timestamp.

## History snapshots

A snapshot requests the latest visible messages from an enabled source, up to
500 per request. Results are labeled as history observations. They can overlap
with live capture, and repeated observations are kept as separate records.

Snapshots follow the attachment policy but remain separate from live-event switches.
They do not reconstruct deleted messages or missed intermediate versions. You can
request one while paused; any attachments it queues wait until observation starts
and the download worker runs.

## Attachment handling

Attachment download is on by default and pauses below 1 GiB of free disk. The collector commits the
message observation and download job together. The job retains the original media
descriptor and size policy, so a later edited attachment is not silently substituted.

Downloads run after message capture. A completed download creates a `media.saved`
record with its SHA-256 and byte count. Skipped, failed, retried, and interrupted
work has separate outcomes. A queued job is not proof that the file was preserved.
The completed file must also match the byte count in the original observed attachment
descriptor. A short or unexpectedly long response is not recorded as preserved media.

Limits are set **per type**: photos, videos, GIFs and animations, round video messages,
voice messages, music and audio, stickers, and files. Each type can be turned off and has
its own size limit from 1 to 2,000 MiB; new workspaces start with 20 MiB for photos,
100 MiB for videos, 50 MiB for files, audio and round videos, 20 MiB for voice and GIFs and
5 MiB for stickers. *Maximum file size* sets every type at once. Policies saved before
per-type limits keep their single limit for every type. A type turned off produces a
`media.skipped` record; unknown-size or oversized files are not downloaded. Large files get
download time for at least 256 KiB/s. Jobs survive restart, but expired references, lost
access, or deleted files can still prevent recovery. Existing jobs retain the policy saved
with them.

## Pause, lock, disconnect, and restart

| Action or condition | Effect |
| --- | --- |
| Switch workspace | Changes the panel view; other collectors keep their state. |
| Lock the panel or close a tab | Leaves the server and observation running. |
| Pause observation | Stops that collector and preserves queued attachment work. |
| Disable a source | Stops future scoped capture; queued media jobs for it wait while it is disabled. |
| Remove a source | Forgets it as a source and deletes its people profiles; records already saved stay in the append-only journal. Its attachments still waiting are recorded as failed (`source_removed`). In folder and whole-account modes it is also excluded. |
| Change the connection route | Requires a pause, closes old clients, and cancels unfinished login. |
| Stop the Python process | Stops all workspaces; no observations are made while it is offline. |
| Restart after active observation | Attempts to resume the saved scope using the saved session. A manual pause clears that intent. |

The collector records detected disconnects, retries, errors, starts/stops, and
heartbeats. Short interruptions can be missed by periodic connectivity checks.
After a restart, missed updates are requested from the saved update position and
observed chats are rechecked periodically; see [evidence format](EVIDENCE.md#durable-collection-and-process-receipts-02). A snapshot provides context;
it does not prove that a gap was repaired.

## Account isolation and verification

Each workspace has its own journal, authorization, signing key, policy, and queue.
Only its active client can contribute live observations. Rejected, pending,
superseded, and connection-test clients cannot write live updates into its journal.
Different accounts can observe the same group, but their journals remain separate.

Each event includes the previous hash and an Ed25519 signature. Exports cover the
whole workspace journal through a fixed sequence number. Panel filters do not filter
the export; collection may continue beyond its boundary while it is being prepared.

**Verify journal** checks the event chain and signatures through the displayed
boundary. Its result is cleared when the workspace changes, and the panel identifies
new records added after the check. ZIP export also verifies collected media.

A valid signature establishes integrity relative to the trusted key, not Telegram
origin or truthful content. Retain fingerprints and checkpoints independently. See
the [evidence model](EVIDENCE.md), [daily operations](OPERATIONS.md), and
[live acceptance procedure](internal/LIVE_ACCEPTANCE.md) for trust and delivery requirements.
