[TgWitness](../README.md) / [Documentation](README.md) · [Getting started](QUICKSTART.md)

![Getting started](assets/presentation/chapter-start.svg)

# Panel guide

[First setup and settings](SETTINGS.md) · [Accounts](ACCOUNTS.md) · [Export and verify](EVIDENCE.md) · [Case reports](CASE_REPORTS.md)

What each screen does, what it writes to the signed journal and where the detailed
guide is. The panel shows one workspace at a time: one Telegram account with its own
sources, journal and signing key. The account selector in the top bar switches
workspaces. The address carries the workspace (`?ws=…`); while the address, the
selector and the loaded account disagree, actions stay blocked.

Use [Compare collection methods](COLLECTION-MODES.md) to choose between live
observation, full history, fresh account/chat exports and saved-record handover.
The Exports page includes the same comparison above its download controls.

<details>
<summary>On this page</summary>

- [Find your way](#find-your-way)
- [Start here](#start-here)
- [Chats](#chats)
- [Journal](#journal)
- [Sources](#sources)
- [Exports](#exports)
- [Settings, accounts and connection](#settings-accounts-and-connection)
- [Extras](#extras)
- [Protection modes](#protection-modes)
- [More tools](#more-tools)

</details>

## Find your way

The sidebar keeps six daily sections together: **Home**, **Chats**, **Journal**,
**Exports**, **Accounts** and **Settings**. Sections that your access does not permit
are omitted. **More tools** contains investigation and administration tools.
Open **Appearance** at the bottom of the sidebar to change the language, theme,
time zone or interface level:

| Level | Sections in the sidebar |
| --- | --- |
| Simple | The daily sections |
| Standard | Also Case Board, Sources, Access and Documentation under More tools |
| Expert | Also System map, Network topology, Extras, Ask the archive, Parameters, Account, System log and Integrations under More tools |

Section names stay the same at every level. A level only hides sections. A hidden feature keeps working, and the server checks
every permission on its own. Level, language, theme and time zone are saved per
operator and workspace; see [settings](SETTINGS.md).

Use **Go to a section** at the top of the sidebar (Ctrl+K, or ⌘K on a Mac) to find
a chat, a parameter or a journal record by `#number`. Arrow keys move, Enter opens,
Esc closes.

The top bar has:

- **Notifications**: problems and chat changes worked out from the journal.
  **Mark all as read** clears the counter and **Notification rules** opens the rules.
  Delivery to Telegram, Discord or email is set up in
  [Extras → Notifications](#notifications).
- A collection-status menu with the start/pause control, connection settings and
  health diagnostics for Telegram, event intake, sources and the attachment queue.
  On a narrow screen, open it with the activity icon.
- **Lock**: closes the panel in this browser. Collection keeps running on the server.

The version and protection mode are under **Appearance**; see [protection modes](#protection-modes).
An installation with saved sources and journal records opens **Chats** after sign-in.
An explicit link still opens its requested screen.

The demo workspace contains fictional messages and never connects to Telegram.
Actions that would change a real workspace are refused there.

[System map](SYSTEM-MAP.md) shows this installation's account routes, proxy state,
socket endpoints, encrypted vaults, evidence services and observed network requests.
Select an account to inspect its path. Available but disabled services stay visible.

## Start here

Choose a task. **Export my account** downloads what the account can read now.
**Follow an investigation** records new messages, observed edits and deletion notices
from the chats you choose. While observation is paused, Chats, Journal and Sources
show the setup card: connect the account, choose sources, start observation.
With the goal **Evidence for a case**, or in the Witnessed, Case preparation,
GitHub-verified or Mossad [protection mode](#protection-modes), starting observation
first reads Telegram's session list. If other sessions are signed in, the panel names
their number and offers **Start anyway** or **Open Sessions of this account**. Other
goals and modes start without that question.
The goal question stays on this page until you
answer or skip it. A new workspace opens the [first setup](SETTINGS.md) instead.

## Chats

Saved conversations, read-only by default.

- Search the list by name or ID. **Choose** adds or removes watched chats.
  **Open Telegram link** takes a username or invite link and saves a preview to the
  journal. **Join / open and observe** then joins the chat and adds it to your sources;
  opening a bot sends it `/start`.
- The chat header counts messages **deleted, text kept**, **deleted before saving**
  and **not found on recheck**. The chat list and notifications use the same
  definitions. A deleted message is red and keeps its saved text; an edited message
  keeps every saved version. Each deletion says what is known: when it was seen, that
  Telegram does not report who deleted it, or that only the notice arrived.
- **Load history** brings the last 100, 250 or 500 messages into this view and the
  journal. Find it in **Chat actions**, alongside recording settings, read-only and
  secret-masking controls. The menu closes with Escape or a click outside it.
  To load every enabled source, use [Sources → Full history](#sources).
- **Export chat** downloads the whole visible history as a signed `chat.json` and
  `chat.html`. Several connected accounts can share the work: each downloads its own
  range of message numbers and signs its part, and the account that starts the
  export signs the archive. See [export one chat](wiki/Chat-Export.md).
- **People** lists everyone with saved messages in this chat. People profiles are off
  by default because they are personal data about third parties. When they are on for
  a chat, a profile shows name and username history, Telegram flags, avatar hashes, activity,
  who replies to whom, other observed chats, and mentioned wallets, phones, usernames
  and links. Every fact points to its record. **Export profiles** saves a signed file,
  optionally in a password ZIP; turning profiles off deletes the profile file. See
  [people profiles](EVIDENCE.md#people-profiles).
- **Save profile now** records a snapshot of the chat or bot profile: description,
  members, invite link, bot commands.

### Read-only, sending and secrets

Two switches above the messages protect the account and the reader:

- **Read-only** is on when a chat opens. Turn it off to send messages or press bot
  buttons. Each action asks **Send as @account?** or **Press this bot button as
  @account?**, tells you that chat members see it and that it goes into the signed
  journal. **Do not ask again for 10 minutes in this chat** skips the question for a
  while. Sending is off for the **Evidence for a case** goal, in the panel and in the API.
- **Mask secrets** hides what looks like a password, a login code, an API key or
  hash, a bot token, a session string, a private key, a JWT or a payment card number
  (card numbers are checked with the Luhn sum). **Show** reveals one value; the reveal is
  recorded in the journal. Turning masking off for this browser is recorded too.
  Only the display changes: the original records and every export keep the full text.

## Journal

Every record the workspace has signed, newest first.

- **Overview** counts observed messages, recorded edits, deletion notices and
  selected sources.
- **Event timeline** filters by event type (all, edits, deletions, reactions,
  membership, coverage), by text and by source. **Load earlier events** pages back.
- Open a record to see its details, hash and payload. **Link to this record** is an
  address that opens the same record. Possible secrets are masked in this preview;
  exports keep the original.
- The journal is append-only: nothing in the panel edits or deletes a record. Check it
  with **Exports → Verify journal** or `python -m tgwitness.verify`; see
  [export and verify](EVIDENCE.md).

## Sources

Which conversations this workspace records, and what it keeps from them. Changes
apply to future activity; saved records stay.

**Refresh chat list** reads the account's chats and folders. It does not download messages.

### Scope

- **What this account records**: **Chosen chats** (only the chats you add),
  **Telegram folder** (one of the account's folders, including chats added to it
  later) or **Whole account** (every chat, and every new chat, group, private chat or
  bot as it appears). **Investigation mode** is for a dedicated account: it records
  everything the account sees, its own messages and button presses, and saves each new
  chat's profile and earlier visible messages straight away. The
  [dedicated account guide](https://phishdestroy.github.io/TgWitness/docs/dedicated-account/)
  explains why never to use your main account.
- **Source types** limit folder and whole-account modes to channels, groups, private
  chats and bots. **Own actions** adds the account's own messages, edits and
  reply-keyboard presses.
- **When a new chat or bot appears**: save its profile and up to the chosen number of
  its latest visible messages.

[Pseudo-secret](PSEUDO-SECRET.md) is the included Secret Chat interface, enabled
per account after installing the optional protocol dependency. Cloud observation
and history use their own settings. Nothing is recorded while TgWitness is
not running; after a restart it catches up only what Telegram still returns, and the
report shows the gap. Chats beyond the chat list limit (1,000 dialogs unless changed in
Parameters) are added when they next become active. Inline bot buttons pressed in
another app are invisible; the bot's reply is recorded.

### Chats in scope

Filter by status (**Enabled**, **Paused**, **Priority**, **Excluded**, **Unconfirmed
access**, **Ignored**) and type, then act on a selection: enable, pause, mark or remove
priority, exclude from scope or remove. The status badge only shows the state; actions
are in each row's menu with a line on what they do. Pausing and excluding ask for
confirmation, also in bulk. Removing a source asks for its name and deletes its people
profiles; its saved records stay in the journal.

A source the account's chat list does not show is **receiving updates, not in the chat
list** while records keep arriving, otherwise **access unconfirmed**. **Available
chats** adds chats with **Add selected** or **Add all matching**.

### Full history

Loads the available history of every enabled source into Chats and the journal.
Progress survives a restart; attachments follow your media settings. See
[source history](HISTORY.md).

### Recording

- **Choose which changes to preserve**: new messages, edits, deletion notices,
  visible reactions, joins and leaves. A preset changes the form;
  **Save recording settings** applies it. Turning a category back on does not recover
  missed events.
- **Preserve media when available**: download attachments up to a size per file, set
  per type from 1 to 2,000 MiB, and limit video length in seconds (0 means no limit).
  Every download attempt gets a recorded outcome.
- **Recheck**: priority chats every few minutes, other chats rarely, so the account
  stays clear of Telegram's FloodWait limits. 0 turns a group off. Mark priority chats
  with the star in the list; chats per pass and the pause between chats are in
  Parameters. See [collection](COLLECTION.md).

## Exports

**Downloads** prepares files; **Build report** chooses how reports look.

| What | Use it for | Guide |
| --- | --- | --- |
| Account export | A fresh snapshot of what the account can read now | [Account export](ACCOUNT-EXPORT.md) |
| Sharing copy | A minimized derivative of a finished account export | [Disclosure](ACCOUNT-EXPORT.md#prepare-a-disclosure-for-a-lawyer-or-another-recipient) |
| Signed ZIP | Journal, report, attachments and verification tools at a fixed journal boundary | [Export and verify](EVIDENCE.md) |
| HTML, PDF, JSON report | A sealed readable report | [Case reports](CASE_REPORTS.md) |
| JSONL, CSV | Original records with signatures; a formula-safe spreadsheet | [Export and verify](EVIDENCE.md) |
| Handover extract | Only the chats, period and people a recipient needs | [Evidence](EVIDENCE.md#investigation-handoff) |
| Chat export | One chat as signed `chat.json` and `chat.html` | [Export one chat](wiki/Chat-Export.md) |

- **Encrypt the downloads above with a password** (12 characters or more) saves an
  AES-256 ZIP that 7-Zip or WinRAR opens. The signed file inside is unchanged. The
  password is not stored.
- When the session key of this workspace was imported, the account export and chat
  export dialogs say so in one line: copies of that key can exist outside Telegram's
  session list. The same line offers **Create an independent authorization**, which
  opens the sign-in page with that option selected. See
  [accounts](ACCOUNTS.md#create-an-independent-authorization).
- A chat export that fails or is cancelled keeps the range it saved. **Capture or export
  one chat** then offers **Resume export** and **Start over**; see
  [export one chat](wiki/Chat-Export.md).
- **Prepared exports** keeps up to 20 files within 2 GiB, plus the latest one, for
  repeat downloads, each with its SHA-256 for the recipient to compare.
- When the browser refuses its save dialog, the panel falls back to an ordinary download.
- **Your signing identity** shows the key fingerprint. **Save checkpoint** and
  **Download signed run receipt** give you records to keep outside the collector.
  **Prepare timestamp request** builds an RFC 3161 request without contacting any service.

## Settings, accounts and connection

- **Settings**: goal, connection, what to record and the interface. See
  [first setup and settings](SETTINGS.md).
- **Accounts**: every workspace with its state, sources, events and attachment queue.
  Filter by **Needs attention**, **Collecting**, **Offline or paused** or **Not
  connected**, pause or resume a selection, import account files in bulk and manage
  groups. See [accounts](ACCOUNTS.md).
- **Account**: sign-in and the connection route of this account. Direct, a WireGuard
  profile, your own proxy, the public MTProto pool or WARP; prepare and check a route,
  then apply it to this account, a group or all accounts. See
  [connection and proxies](CONNECTION-SECURITY.md) and [proxies](wiki/Proxies.md).
  **Account security → Sessions of this account** lists Telegram's sessions, ends one
  or all of them, and — for a key created in this workspace — offers **Make this the
  only session when Telegram allows it**, which repeats that action after the 24 hours
  Telegram requires and shows the two-step password it sets once. See
  [account security](ACCOUNTS.md#create-an-independent-authorization).
  **Account security → Witness probe** uses a second workspace to check that this
  session receives updates live; see [witness probe](ACCOUNTS.md#witness-probe).

## Extras

Optional: an account and sources are enough to start collecting. Only the option you
choose opens its settings, and nothing is connected automatically. The
**Protection level** card at the top shows the [protection mode](#protection-modes).

| Card | What it adds | Guide |
| --- | --- | --- |
| Storage & disk space | Backups, moving older files to your cloud, an evidence copy that cannot be deleted | [Storage](STORAGE.md) |
| Goal & protection level | Suggested settings for your goal and two scales | [below](#goal-and-protection-level) |
| Notifications | Problems, changed messages and a daily summary; your own control bot | [below](#notifications) |
| Evidence & backups | Timestamps, more witnesses and an encrypted off-site copy | [below](#evidence-and-backups) |
| Server 24/7 | A cloud server without SSH, created and deleted from the panel | [High assurance](HIGH-ASSURANCE.md#from-the-panel) |
| Independent witness | Signed checks posted to your Telegram channel or Discord | [Witness](WITNESS.md) |
| Code check | Compares the running program with a public GitHub commit | [below](#code-check) |

### Goal and protection level

Four questions:

1. **What is it for?** A personal record, an investigation, or evidence for a case.
2. **How much will you observe?** A few chats (up to about 50), many chats (up to about
   500) or whole accounts. This sets the chat list limit to 1,000, 3,000 or 20,000.
3. **Photos and files?** Text only, photos and short media (photos 20 MB, videos
   100 MB), or everything (videos and documents up to 1 GB each). Everything with whole
   accounts also keeps 4 GiB of disk free.
4. **Where will it run?** This computer, or a server that is always on.

The suggestion lists independent timestamps, drand and Telegram's device list, each
with a line on what it adds. Timestamps start every 60, 30 or 10 minutes for a personal
record, an investigation or evidence; drand and the device list need timestamps.
**Apply** changes only these, the attachment policy and the two parameters above. Each
change is a journal record, plus `setup.applied`. Notifications, an off-site copy, a
server, Gateway DNS, the code check and a witness are offered as next steps with their
own forms.

Two scales are computed from what is set, not from the goal:

| Scale | Points |
| --- | --- |
| Credibility | Signed journal 1, timestamps 3, drand 1, device list 1, code check that matches 1, witness polling 1, attested server 2, Gateway DNS log 1 |
| Reliability | Always-on server 3, off-site copy 3, Object Lock 1, problem notifications 1 |

80% or more reads **maximum**, 50% **high**, 25% **moderate**, below that **basic**.
Reliability currently counts an always-on server from the answer to question 4,
before any server is checked.

### Notifications

Notifications go through Apprise to Telegram, Discord, Slack, ntfy, email, Matrix and
100+ other services. Pick a service, fill in one or two fields and send a test, or
paste Apprise addresses directly.

- **Problems**: disk almost full, account signed out, collection, copy or timestamp
  errors, a new session signed in to the account with the device, application and
  country Telegram lists, a login code or new sign-in that Telegram reports during
  observation, and another session after **Make this the only session**. On a sealed
  server, an opened SSH port or a login is a problem too.
- **Changes**: deleted, edited and missing messages in observed chats, grouped into
  one notification per check (every minute unless changed in Parameters).
- **Completed tasks**: history, exports and storage copies.
- **Watchlist hits**: matches from watchlists set to send an alert.
- **Daily summary** at the chosen hour, server time.

Notifications carry chat names and counts. Message excerpts are off by default; with
them on, message text leaves this machine.

**Your operator bot** is a bot of your own from @BotFather that answers `/status` and
`/stats`, and optionally `/pause`, `/resume` and `/copy`. Only the listed chat and
Telegram user IDs can use it; conversation text stays in the workspace. Use a separate
bot if another application already receives its commands. See
[notifications](wiki/Notifications.md) and [operator bot](STORAGE.md#operator-bot-and-completion-notices).

### Evidence and backups

- **Independent timestamps** send only the SHA-256 of each signed checkpoint to RFC 3161
  authorities and OpenTimestamps calendars, every 5 to 1,440 minutes. A recipient needs
  such third-party time for the minimum for evidence. **Anchor now**
  runs a pass. See [timestamps](TIMESTAMP.md).
- **More witnesses**, each off until chosen: the newest drand round, Telegram's list of
  signed-in devices without IP addresses, and Cloudflare Gateway's log of the server's
  DNS queries. See [optional records](EVIDENCE.md#optional-records-in-evidence-mode-drand-and-telegram-devices).
- **Encrypted backup** copies the journal, files, checkpoints and chat exports to
  S3-compatible storage (Wasabi, Amazon S3, Backblaze B2, Cloudflare R2, MinIO).
  Everything is encrypted on this machine first. **Download encryption key** and keep it
  apart: without it the copy cannot be read. Object Lock in Governance or Compliance mode
  keeps objects from deletion for a set number of days. See [off-site copy](wiki/Off-site-Copy.md).

### Code check

Checks whether the installed program matches a published version.

1. Enter a GitHub repository (the official one is filled in) and a tag, branch or commit.
2. **Check now** asks GitHub's API, through this workspace's route for outside requests,
   for that commit's file list. It compares the git blob ID of every measured program
   file with the commit. A Windows checkout with converted line endings still matches.
3. The result lists changed, extra and missing files (up to 50 of each) and is saved as
   a `source.checked` journal record.

The result counts as current only while the running program files are unchanged:
check again after an update. No token is needed and only public repositories work;
chats and credentials are not uploaded. A match identifies the code on disk. It is not
hardware attestation; for that, see [Phala Cloud](HIGH-ASSURANCE.md#confidential-vm-on-phala-cloud-intel-tdx).

## Protection modes

The switcher next to the version number shows the chosen mode and how many of the 18
protection layers are active, for example `🟠 Witnessed 9/18`. **Change mode** in
**Extras → Protection level** opens the choice. A mode describes a target and lists what
is still missing; recording, signing and saved settings are the same in every mode.

| Mode | For | Adds |
| --- | --- | --- |
| 🟢 Easy | Watching a chat and keeping a copy | Chats, the journal and chat exports; signing runs in the background |
| 🟡 Signed | Reports to a platform, a host or an abuse desk | Signed archive, journal check, checkpoints, handover extract |
| 🟠 Witnessed | Cases where someone may claim the record was changed | An independent witness posting signed journal heads |
| 🔴 Court-ready | Evidence for a lawyer, the police or a court | Timestamps, an encrypted off-site copy, case details in reports |
| 🟣 GitHub-verified | Records whose software anyone must be able to check | Code check and GitHub Actions capture |
| ⚫ Mossad | High-stakes cases against a well-funded adversary | A sealed 24/7 server, a hidden IP address, all 18 layers |

The layers: every record signed and chained; a signed run receipt; attachments saved
with SHA-256; signed checkpoints; rechecks; problem alerts; read-only witness access; a
witness checking on schedule; RFC 3161 timestamps; OpenTimestamps proofs; a verified
latest timestamp; an encrypted off-site copy; case details in reports; a matching code
check; Telegram never seeing this machine's IP; outside requests through a proxy; Object
Lock on the copy; a sealed server with provider records. A layer that is off has
**Set up**, which opens its form. Choosing a lower mode asks for confirmation and
deletes nothing.

## More tools

<p lang="en" translate="no"><strong>Extras → Independent capture</strong>: connect a
separate browser or AyuGram recorder, pin its signing key, select capture options,
start/pause, take snapshots and download verified signed archives. Each recorder has
its own manual login, route, journal and key. Both connections start disabled.
See the English <a href="OPTIONAL-CAPTURE.md">Independent capture guide</a>.</p>

- **Ask the archive**: search saved observations, review the sources, then decide
  whether to send them to an AI model. See [archive analysis](ANALYSIS.md) and
  [local OCR and transcription](MEDIA-ANALYSIS.md).
- **Parameters**: limits and pace of collection, rechecks, downloads, profiles,
  notifications and exports. Search by name, show **Only changed** values and prepare
  defaults as a draft with **Restore defaults…**. **Save parameters** applies the values
  from their next use, and each change is a journal record.
- **Access**: separate tokens for reviewers, analysts and operators, limited to chosen
  workspaces, chats and rights. See [access](ACCESS.md).
- **System log**: what this process did since it started (connections, proxy changes,
  sign-ins, refusals, settings changes) with IP addresses hidden. **Follow new lines**
  keeps the newest line in view. Messages stay in the journal only.
- **Integrations**: the AI provider, [read-only MCP](MCP.md) connections and
  [signed webhooks](WEBHOOKS.md).
- **Case Board**: private team notes, bookmarks and slices next to the evidence. See
  [Case Board](CASE-BOARD.md).
- **Documentation**: the [investigation mode](INVESTIGATION-MODE.md) drawer. While a
  documented session is recording, it moves to the main sidebar.
- **GitHub Actions capture** in Exports: one chat captured from your fork. See
  [sealed capture](SEALED-ACTIONS.md).
