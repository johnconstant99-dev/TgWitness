# Complete project guide

[Project home](../README.md) · [GitHub Wiki](https://github.com/phishdestroy/TgWitness/wiki)

<picture>
  <source media="(max-width: 640px)" srcset="assets/presentation/mobile.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="assets/presentation/tgwitness-investigation-static.svg">
  <img src="assets/presentation/tgwitness-investigation-animated.svg" width="1200" alt="TgWitness — follow the trail, preserve the evidence. Illustrated investigation sources, preserved records and a signed handoff.">
</picture>

<p align="center">
  <strong>Your Telegram observation workspace.</strong><br>
  Captured conversations. Preserved changes. Independently verifiable exports.<br>
  On your own computer or server. With your own accounts.
</p>

<p align="center">
  <a href="CHANGELOG.md">v0.7.0</a> &nbsp; · &nbsp;
  <a href="QUICKSTART.md">Python 3.11+</a> &nbsp; · &nbsp;
  <a href="../LICENSE">MIT license</a>
</p>

<p align="center">
  <a href="#quick-start"><img src="assets/presentation/button-start.svg" alt="Quick start" height="40"></a>
  <a href="wiki/Home.md"><img src="assets/presentation/button-wiki.svg" alt="Read the wiki" height="40"></a>
  <a href="README.md"><img src="assets/presentation/button-docs.svg" alt="Documentation" height="40"></a>
  <a href="#repository-map"><img src="assets/presentation/button-source.svg" alt="Repository map" height="40"></a>
</p>
<p align="center"><a href="#screenshots">Take a look at the workspace</a> · <a href="../.github/CONTRIBUTING.md">Contribute</a></p>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/chats-dark.png">
  <img src="assets/chats.png" width="1200" alt="TgWitness Chats: captured conversations with edited and deleted messages, shown with fictional demo data.">
</picture>
<p align="center"><sub>The conversation, its changes, and the record behind it. Light and dark themes. Fictional demo data.</sub></p>

## Features

<table>
<tr>
<td width="50%" valign="top"><h3>Conversations with a history</h3><p>Read saved messages in context. Compare captured edits. Keep content after a deletion notice.</p></td>
<td width="50%" valign="top"><h3>Your scope, your workspace</h3><p>Observe selected chats, a folder, or the whole account. Separate accounts keep separate journals and settings.</p></td>
</tr>
<tr>
<td valign="top"><h3>A handoff you can verify</h3><p>Signed records, preserved attachments, an offline report and a standalone verifier. Optional password protection.</p></td>
<td valign="top"><h3>Follow the connections</h3><p>Search across saved conversations. Review cited timelines, people profiles and file connections within a workspace.</p></td>
</tr>
<tr>
<td valign="top"><h3>A workspace for daily use</h3><p>Light and dark themes, 25 interface languages, keyboard navigation and actions directly from Chats.</p></td>
<td valign="top"><h3>Go further when you need to</h3><p>Add a witness, external timestamps, notifications. Each has its own setup guide.</p></td>
</tr>
</table>

<details>
<summary>Explore all capabilities and their current limits</summary>

- **Your connection route.** Under **Account → Proxy settings**, choose from bundled public
  MTProxy lists, refresh them from their sources, or paste your own Telegram proxy link.
  Manual SOCKS5/HTTP/MTProxy and an operator catalog remain available. The public lists are
  downloaded and filtered, but no account has been connected through a listed server yet.
  [How public lists work](CONNECTION-SECURITY.md#public-proxies-supplied-by-your-installation).

- **A journal of what your accounts actually see.** New messages, edits, deletion notices,
  reactions, membership events and coverage gaps from the groups and channels you select.
- **Chosen chats, a Telegram folder or the whole account.** Pick the types to record —
  channels, groups, private chats, bots — and new chats are added the moment they appear.
  Exclusions, own outgoing messages and edits, deletions in private chats matched to their
  chat, priority rechecks and attachment limits per type ([collection](COLLECTION.md#observation-scope-chosen-chats-a-folder-or-the-whole-account)).
- **Investigation mode.** One button prepares a dedicated account that joins teams and talks
  to bots: everything it sees and sends is recorded, buttons under bot messages (links, web
  apps, texts to copy) are kept and button-only edits become new versions, and every new chat
  or bot gets its profile (description, commands, members) and earlier visible messages saved
  at once ([investigation mode](COLLECTION.md#investigation-mode-joining-teams-and-talking-to-bots)).
  The panel's **Dedicated account guide** (`/dedicated-account.html`) explains why the main
  account must not be used, why TgWitness works through public app hash/app ID pairs and why
  an API pair does not itself grant access to your account (with links to Telegram's documentation), and
  lists ways to create an extra account.
- **Act directly from Chats.** Send messages and replies, press bot callback/text buttons,
  or preview a Telegram invitation and join. The selected account performs the action;
  requests, invitation previews and bot popup/URL responses enter its signed journal
  ([panel mini-client](COLLECTION.md#act-from-the-panel)).
- **Coverage you can state.** Reports and the verifier say "continuously observed from X to
  Y", list gaps with their reason and message IDs that were never observed — never
  presenting them as deleted.
- **People profiles, opt-in per chat.** Name and username history, Telegram flags, avatar
  SHA-256 and pHash, activity, who replies to whom and mentioned wallets, phones, usernames
  and links — built only from saved records, every fact pointing to its journal record,
  exported as a separate signed file ([evidence model](EVIDENCE.md#people-profiles)).
- **Independent witness.** A separate process with its own key and bot fetches the signed
  journal head, posts it to a Telegram channel and reports when the collector does not
  answer; the verifier checks exports against it. Interval, timeout, which checks are posted
  and the wording of posts are options or a JSON config file ([witness](WITNESS.md)).
  Tested against a local Bot API server, not yet with a real bot and channel.
- **Collection settings in the panel.** Limits and pace of collection,
  rechecks, downloads, people profiles, notifications and exports are on the **Parameters**
  page with their ranges and defaults; every change is recorded in the signed journal
  ([settings and parameters](#settings-and-parameters)).
- **Edits and deletions in context.** Every edit is a separate version shown next to the previous
  one; a deletion notice never erases content that was already captured.
- **Signed, verifiable exports.** Each event is hash-chained (SHA-256) and signed (Ed25519). The
  signed ZIP bundles JSONL, CSV, an offline HTML report, preserved media and a standalone verifier.
- **Password-protected exports.** Optionally put any export into a WinZip AES-256 ZIP, the
  format 7-Zip and WinRAR read; the signed contents inside stay unchanged. A test archive opened
  byte-for-byte in libarchive (Windows `tar`) and a wrong password was refused
  ([evidence model](EVIDENCE.md#investigation-handoff)).
- **Notifications.** Problems (low disk space, a signed-out account, collector, copy or timestamp
  errors), changes in observed chats and a daily summary, sent through [Apprise](https://github.com/caronc/apprise)
  to Matrix, Telegram, Discord, Slack, ntfy, email and many other services — without message
  text unless you turn on excerpts — and listed in the panel. Delivery is tested against a
  local endpoint; the services themselves have not been tested yet.
- **25 interface languages.** The panel and documentation share the same language selection,
  including German, French, Italian, Japanese, Korean, Hebrew and both Chinese scripts.
  Translations are prepared with DeepL; the bundled guides also retain their separate Amharic
  translation. Telegram content and journal records are always shown exactly as saved.
- **Light and dark theme.** Follows the system setting by default; the choice is remembered per browser.
- **Keyboard-friendly navigation.** Press **Ctrl+K** (Mac: **⌘K**) or select **Go to…** to
  find a section. Use the arrow keys and Enter to open it; Escape closes the menu.
- **Multiple accounts.** Any number of isolated workspaces, each with its own Telegram session,
  journal, signing key, proxy route and capture policy.
- **Flexible sign-in.** Phone + code + 2FA, QR code, Telethon/Pyrogram `.session`, Telegram Desktop
  TData ZIP, Telethon StringSession, or a full Auth Key with its DC ID. **Sign out of Telegram** on
  the Account page ends the session in Telegram and forgets it; the journal and keys stay.
- **Per-account proxies.** SOCKS5 and HTTP CONNECT, tested against local test proxies, and
  experimental MTProxy, not yet tested with a real server. A failed proxy never silently falls
  back to a direct connection.
- **Private by design.** Runs on your computer or server. Bundled web UI, no Node.js, no hosted
  service, no telemetry. Sessions, API credentials and proxy secrets live in an encrypted vault.
- **Easy to run.** Double-click on Windows, one script on Linux/macOS, or Docker Compose with
  optional automatic HTTPS. So far only the Windows launchers have been run; see
  [what has been tested](#what-has-been-tested).

</details>

## Quick start

**Start with the demo.** Explore fictional conversations without connecting a Telegram account.

| Windows | Linux / macOS |
| --- | --- |
| Double-click **`scripts\Demo.cmd`** | Run **`sh start.sh --demo`** |

From a source checkout, Python 3.11+ is required; the launcher prepares the environment
and installs pinned dependencies on first use. Open **http://127.0.0.1:8787**.
The demo is separate from your real workspaces.

**Ready to connect?** Stop the demo and run **`Start.cmd`** on Windows or **`sh start.sh`**
on Linux/macOS. Open the panel, paste the token from `data/live/panel-token.txt`,
then [connect a dedicated account](#connect-a-telegram-account).

For portable builds and Docker, follow the [installation guide](QUICKSTART.md#install-and-start).
Portable downloads become available when a release is published.
[Tested environments and current limits](#what-has-been-tested).


![Section divider](assets/presentation/divider.svg)

## Screenshots

| Compare captured edits | Choose what to observe |
| --- | --- |
| [![Compare two observed versions of a message](assets/detail.png)](assets/detail.png) | [![Selected chats and capture policy](assets/sources.png)](assets/sources.png) |
| **Prepare a signed handoff** | **Review the observation journal** |
| [![Signed export options](assets/exports.png)](assets/exports.png) | [![Observation journal in the dark theme](assets/workspace-dark.png)](assets/workspace-dark.png) |

All screenshots use fictional demonstration data. Open any image for the full-size view.

## How it works

Each observed change adds a record. The previous hash links it to the journal; a signature lets the recipient check its integrity against a trusted key.

![Observe: choose sources. Preserve: retain captured versions and attachments. Verify: export a signed record and check it against a trusted key.](assets/presentation/evidence-chain-animated.svg)

1. **Observe** the sources your Telegram account can access.
2. **Preserve** delivered events in a signed, append-only journal, with captured versions and coverage gaps.
3. **Verify** an export independently, using a key fingerprint you retained outside the collector.

A signature establishes integrity relative to a trusted key. It does **not** prove
Telegram origin, complete capture, or that the operator told the truth.
[Understand the evidence model →](HOW-IT-WORKS.md)

<details>
<summary>What each observation preserves</summary>

Each workspace belongs to one Telegram account. The collector accepts updates from that account's
client, applies the saved capture policy and appends observations to an append-only journal.

| Observation | What is preserved | Boundary |
| --- | --- | --- |
| New message | Text, sender ID, reply reference, metadata, observation time | Only updates delivered for selected sources |
| Edit | A separate content version | Intermediate versions missed while offline cannot be recovered |
| Deletion | Message ID plus everything captured earlier | Telegram usually omits who deleted and when |
| Reactions | Counts and recent identities when supplied | A snapshot, not a complete change log |
| Membership | Service messages and participant updates | Not every join/leave is guaranteed to arrive |
| Attachment | Optional content-addressed file with SHA-256 | Files can vanish before download; outcomes are recorded |
| Coverage | Starts, stops, disconnects, heartbeats, policy changes | Liveness is not proof of complete capture |
| History snapshot | Latest visible messages, up to 500 unless raised in **Parameters**, explicitly labeled | Cannot reconstruct missed edits or deletions |

Read [how collection works](COLLECTION.md) for policies, attachment queues and restarts.

</details>


![Section divider](assets/presentation/divider.svg)

## Connect a Telegram account

> [!WARNING]
> **Use a dedicated account you can afford to lose.** Telegram can restrict or permanently
> ban accounts. We strongly advise against connecting personal or valuable accounts,
> or creating API credentials on them. [Read the account guide](ACCOUNTS.md).

Sign in by phone, QR code or a supported session file. Choose your sources, save the
capture policy and press **Start observation**. Keep the collector running;
**Pause observation** stops collection, while **Lock** only closes browser access.

<details>
<summary>Sign-in formats and the built-in API pool</summary>

Sign in by phone, QR code or an existing session — no API ID or hash needed.

**Why a built-in API pool?** Creating your own API ID on [my.telegram.org](https://my.telegram.org)
is known to get accounts restricted, and Telegram does not publish clear limits — many
researchers have lost their main accounts this way. Telegram's own
[Obtaining API ID](https://core.telegram.org/api/obtaining_api_id) page says accounts using
unofficial API clients are automatically put under observation and sends wrongly banned users to
recover@telegram.org. TgWitness therefore ships public API pairs
already used by other open-source clients, so you never have to create one. If you have your
own API ID, enter it under **API ID + Hash** and it will be used instead.

When no pair is entered, imported or already saved in the workspace, TgWitness picks one of the
50 pairs in the pool and moves on to the next if Telegram refuses one. The pair that signed in
stays with that account. A pair identifies the application; you still authorize your Telegram
account separately. The panel access token opens TgWitness and is separate from Telegram login.

| What you have | How to use it |
| --- | --- |
| Phone number with access to the account | **Phone** tab: code from Telegram, then 2FA password if enabled |
| An already signed-in Telegram app | **QR code** tab: Settings → Devices → Link Desktop Device |
| Telethon (schema 7/8) or Pyrogram (schema 2/3) `.session` | **Files** tab |
| `name.session` + `name.json` pair | **Files** tab, select both; the JSON supplies API ID/hash |
| Telegram Desktop `tdata` folder | ZIP only `key_datas` and `D877F783D5D3EF8Cs`, then **Files**; local passcode if set |
| Telethon StringSession, `.txt` or `.tgwitness-session` | **Files** tab or *Passcode or session text* |
| Account JSON with a session or Auth Key | **Files** tab |
| Full Auth Key (512 hex chars) + DC ID | **Auth key** tab; optional User ID is checked against Telegram |

Not supported: TDLib storage, Pyrogram session strings, bot tokens, multi-account TData and bulk
account lists. Files are converted in memory on your server and checked with Telegram before they
are saved. The [accounts guide](ACCOUNTS.md) explains every format step by step: how to get
API credentials, how to recognise a file, JSON fields, limits and error messages.

After sign-in, open **Sources** (your chats load automatically), add the groups you need, choose what to capture
(for example *Messages, edits & deletions*) and start observation. Keep the process running:
**Pause observation** stops collection, **Lock** only closes browser access.

</details>

## Evidence and verification

Use the **signed ZIP** for a handoff: it contains original records, preserved media,
coverage information, an offline report and the verifier. Keep a trusted key
fingerprint and checkpoint separately. [Export and verify step by step →](wiki/Exports-and-Verification.md)

<details>
<summary>Export formats, verification commands and trust boundaries</summary>

| Export | Contents | Integrity |
| --- | --- | --- |
| **Signed ZIP** | JSONL, CSV, HTML report, coverage, media, manifest, verifier | Signed events plus a signed manifest of every file, naming the producer. Use this for handoff. |
| JSONL | Original records with hashes and signatures | Per-event Ed25519 signatures and hash chain |
| CSV / HTML | Spreadsheet-safe table / offline readable report | Covered only inside the signed ZIP |
| Checkpoint JSON | Journal length and head hash | Separately signed; keep it outside the collector |
| Run receipt JSON | Code hashes, dependency versions, scope, settings | Separately signed process statement |
| People profiles JSON | One chat's profiles with record references | Signed statement; record hashes checked against the ZIP |
| Witness journal ZIP | Heads the witness fetched, answers missed, channel posts | Signed by the witness's own key |

Filters affect browsing only; exports always contain the complete journal up to a fixed sequence
number. Verify an archive with a trusted copy of the verifier and an independently retained key
fingerprint and checkpoint:

```sh
python -m pip install cryptography
python tgwitness/verify.py tgwitness-evidence.zip --fingerprint TRUSTED_PUBLIC_KEY_SHA256 --checkpoint tgwitness-checkpoint.json
# with an independent witness and its channel (Telegram Desktop export)
python tgwitness/verify.py tgwitness-evidence.zip --fingerprint TRUSTED_PUBLIC_KEY_SHA256 \
    --witness witness.zip --witness-fingerprint WITNESS_SHA256 --channel result.json
```

The verifier prints the signed producer, continuous observation periods, gaps and message
IDs that were never observed, and fails if the journal differs from any head the witness saw.

Signatures provide tamper evidence relative to a trusted signing key. They do **not** prove
Telegram origin, truthful content or trusted time, and they do not protect against an operator who
controls the collector and its key. For trusted time, evidence mode (off by default) timestamps
checkpoints with RFC 3161 authorities and OpenTimestamps calendars, or the panel prepares an
offline RFC 3161 request ([timestamp procedure](TIMESTAMP.md)). Both are tested against
local test servers, not yet against the public services. See the [evidence model](EVIDENCE.md)
and the [investigation handoff](EVIDENCE.md#investigation-handoff) checklist.

</details>


![Section divider](assets/presentation/divider.svg)

## Deployment

Run locally, or use the supplied Docker, HTTPS and service templates.
[Server setup](DEPLOYMENT.md) · [Backup and recovery](wiki/Backup-and-Recovery.md) · [Connection settings](CONNECTION-SECURITY.md)

<details>
<summary>Deployment commands and environment variables</summary>

> [!NOTE]
> The Docker, Caddy (HTTPS), systemd and launchd setups below are prepared and their files
> pass syntax checks, but none of them has been run yet. The Windows portable package and the
> source launch on Windows have.

**Local or single server with Docker:**

```sh
docker compose up -d --build --wait
docker compose exec tgwitness cat /data/panel-token.txt
```

The container runs as a non-root user with a read-only filesystem, publishes only to
`127.0.0.1:8787` and keeps all data in a named volume.

**Public server with automatic HTTPS (Caddy):** copy `deploy/env.example` to `.env`, set
`TGWITNESS_DOMAIN`, point DNS at the server, open TCP 80/443 and run

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml up -d --build --wait
```

**Windows without installing anything:** the portable ZIP attached to each release contains the
official embedded Python runtime and all dependencies. Data stays in its `data` folder; to update,
extract the new version and copy that folder across.

**Without Docker:** systemd, Windows logon task and launchd templates are in [deploy/](../deploy/README.md).
Updates, backups, alternate ports and GHCR images (once the release workflow publishes them)
are covered in [deployment](DEPLOYMENT.md).

### Command line

```text
python start.py [--demo] [--setup-only] [--check [--json]] [--host HOST] [--port PORT] [--data-dir DIR]
```

| Task | Command (from the project environment) |
| --- | --- |
| Readiness check without starting | `python start.py --check` |
| Convert a Telethon SQLite session offline | `python -m tgwitness.sessions account.session --out account.tgwitness-session` |
| Stream a large export to disk | `python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip` |
| Verify an exported archive | `python tgwitness/verify.py tgwitness-evidence.zip --fingerprint SHA256` |
| Verify an archive above 4 GiB | `python tgwitness/verify.py big-evidence.zip --fingerprint SHA256 --max-gib 16` |
| Run an independent witness from a config file | `python -m tgwitness.witness run --config witness.json` |

Auxiliary `python -m tgwitness…` commands must run inside `.venv` (`.venv\Scripts\python.exe` on
Windows, `.venv/bin/python` elsewhere).

| Variable | Purpose |
| --- | --- |
| `TGWITNESS_HOST`, `TGWITNESS_PORT` | Listen address and port (default `127.0.0.1:8787`) |
| `TGWITNESS_DATA` | Data directory (default `data/live`) |
| `TGWITNESS_TOKEN` | Fixed panel token instead of the generated one (at least 24 characters) |
| `TGWITNESS_VAULT_KEY_FILE` | External vault master key for new installations |
| `TGWITNESS_DOMAIN`, `TGWITNESS_IMAGE` | Docker HTTPS hostname and published image (see `deploy/env.example`) |
| `TGWITNESS_WITNESS_*` | Independent witness: collector, tokens, channel, `_INTERVAL`, `_TIMEOUT`, `_POST` (all, changes, problems), `_TITLE`, `_CONFIG` ([witness](WITNESS.md#options)) |

</details>

<details>
<summary>Collection settings and parameters</summary>

## Settings and parameters

Everything is changed in the panel, per workspace, without editing code or configuration
files. Each change of scope, policy or parameter is recorded in the signed journal with the
values before and after, and every observation start names the values in force.

| Where | What you set |
| --- | --- |
| **Sources** | Scope (chosen chats, a Telegram folder, the whole account), source types, exclusions, own actions, which changes to keep, attachment types and size per type (1–2,000 MiB), recheck interval for priority and other chats (any number of minutes, 0 = off), history snapshots, notifications |
| **Exports** | Password-protected downloads, evidence mode (interval, timestamp authorities and calendars), off-site S3 copy (interval, Object Lock retention and mode) |
| **Witness** | Read-only witness tokens; the witness's own options are shown with ready-made commands |
| **Parameters** | Chat list size and refresh, heartbeat and checkpoint intervals, startup buffer, how rechecks spread requests (first delay, chats per pass, pause, messages recovered and re-requested), disk reserve, download timeout, speed and retries, what people profiles look for, including your own regular expressions, notification size and pace, snapshot, ZIP and browser-download limits, panel action timeout, Telegram client timeouts and retries |

Values on **Parameters** show their range and default; changed ones are marked and can be
restored one by one or all at once. They apply from their next use; Telegram client timeouts
and retries from the next connection. A ZIP limit above 4 GiB needs `verify.py --max-gib N`
when the archive is verified ([operations](OPERATIONS.md#panel-layout)).

</details>


![Section divider](assets/presentation/divider.svg)

## Security and project status

The panel listens on localhost by default. Sessions, credentials and signing keys
use an encrypted vault; local messages and attachments require disk encryption
if you need protection at rest. [Security model](CONNECTION-SECURITY.md) · [Report a vulnerability](../.github/SECURITY.md)

This is a pre-release project. Review the [verification record](VERIFICATION.md)
and [open audit findings](internal/RECHECK-2026-10-29.md) before distributing a build.
Executed checks and remaining qualification work are recorded explicitly.

<details>
<summary>What has actually been tested</summary>

### What has been tested

TgWitness **0.6.1** runs on Windows 11 with Python 3.12. Status on 29 October 2026:

| Area | How it was tested |
| --- | --- |
| Messages, edits, deletions, attachments, rechecks after restarts, FloodWait pauses | Done with **a real Telegram account**, 27–29 October 2026: 9,968 signed records, every signature and the hash chain verified ([live test](VERIFICATION.md#live-telegram-test-whole-account--29-october-2026)) |
| Observing the whole account, and history snapshots | Done with **a real account** on 29 October 2026: messages from 2 groups or channels and 3 private chats and bots |
| Pressing a message button from **Chats** | Done once with **a real account** |
| Sign-in with Telethon/Pyrogram session files and Telegram Desktop TData | Done with **one real account** |
| Phone, QR code and Auth Key sign-in, signing out, new chats joining the scope with their earlier messages, sending messages, joining by invitation, reactions, membership, people profiles, several accounts at once, exports and the verifier | Automated tests with synthetic Telegram clients |
| SOCKS5/HTTP proxies, witness bot, notifications, S3 copy, RFC 3161 and OpenTimestamps | Automated tests against local test servers |
| Public MTProxy lists | Downloaded and filtered (118 servers on 29 October); no connection through them yet |
| MTProxy, Docker, HTTPS with Caddy, Linux, macOS, Python 3.11 and 3.13, CI and release workflows, long outages, independent security review | **Not tested yet** |

Details: [verification record](VERIFICATION.md), [release status](internal/RELEASE.md)
and [readiness](internal/READINESS.md).

</details>

<details>
<summary>Deployment and data-protection details</summary>

- The panel listens on localhost by default. For remote access use the HTTPS Compose profile or an
  SSH tunnel; never expose plain HTTP.
- Telegram sessions, API credentials, proxy credentials and the signing key are stored in a
  Fernet-encrypted vault. By default its key sits in the same data directory; set
  `TGWITNESS_VAULT_KEY_FILE` for an external master key. Local message content and media are
  **not** encrypted by TgWitness; keep the data directory on an encrypted disk or volume.
  Signed ZIP exports can optionally be password-encrypted.
- Data files, sessions, tokens, keys and exports are excluded from git and Docker builds.
- Report vulnerabilities privately as described in [SECURITY.md](../.github/SECURITY.md).

</details>

<details>
<summary>Responsibility and data protection (GDPR)</summary>

## Responsibility and data protection (GDPR)

TgWitness is a tool. Whoever runs it decides what is collected, why and for how long, and is
responsible for it — under the EU/UK GDPR usually as the *controller* of that personal data.
Telegram messages contain personal data of people who never agreed to be recorded: names,
usernames, IDs, photos, phone numbers, opinions. This section is not legal advice; check the
law that applies to you and Telegram's terms.

- **Have a lawful basis and a purpose.** Fraud prevention, network and information security
  and the defence of legal claims are commonly relied on as legitimate interests
  (GDPR Art. 6(1)(f), Recitals 47 and 49; Art. 9(2)(f) for legal claims). Write the purpose
  down per case. Public authorities work under their own legal bases.
- **Collect as little as the purpose needs.** Start with chosen chats. Folder and whole-account
  modes record private chats and third parties' messages: use them only on dedicated
  accounts; the panel asks for confirmation and the signed journal records it. Turn off event
  types, attachment types and own actions you do not need, and exclude chats.
- **People profiles are profiling.** They are off by default and switched on per chat. Use
  them for a specific investigation, do not base automated decisions about people on them
  (Art. 22), and switch them off or remove the chat when done — that deletes them. Systematic
  monitoring of many people usually calls for a data protection impact assessment (Art. 35).
- **Keep it secure.** Sessions, credentials and keys are in an encrypted vault; put the data
  directory on an encrypted disk, give exports a password (AES-256 ZIP), keep the panel behind
  HTTPS, and give a witness only its read-only token. Notifications carry no message text
  unless you turn on excerpts, which sends text to the notification service.
- **Retention and erasure.** The journal is append-only so that its integrity can be proven;
  single records cannot be removed without breaking the signature chain. Plan retention per
  workspace and delete an added workspace (Accounts → Delete) when the purpose ends. The main
  workspace cannot be deleted from the panel: sign out of Telegram on the Account page, stop
  TgWitness and remove its data directory. Off-site copies under S3 Object Lock cannot be deleted before their
  retention date — choose the period accordingly. The right to erasure has exceptions, for
  example for the establishment or defence of legal claims (Art. 17(3)(e)).
- **Requests from the people recorded.** Chat exports and profile files make it possible to
  find what is held about a person (Art. 15).
- **Nothing is sent to the authors.** TgWitness has no telemetry and no hosted service; data
  leaves your machine only through the routes you configure (Telegram, timestamp services,
  S3 copy, notifications, witness).

</details>


![Section divider](assets/presentation/divider.svg)

## Development

Improvements to collection, verification, accessibility and documentation are welcome.
Read the [contribution guide](../.github/CONTRIBUTING.md) and use fictional data in examples and reports.

<details>
<summary>Development setup and checks</summary>

```sh
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\Activate.ps1
python -m pip install -c deploy/constraints.txt -e ".[dev]"
python -m pytest -q                                    # unit and integration tests
python -m playwright install chromium
python tools/check_browser.py                          # end-to-end UI acceptance
python tools/check_account_browser.py                  # sign-in flows
python tools/capture_screenshots.py --docs             # refresh README images
python tools/build_portable.py                         # Windows portable ZIP (Windows + Python 3.12)
python tools/build_source.py                          # source ZIP with SHA-256 manifest
python tools/build_site.py                             # static project site in dist/site
python tools/check_site.py                             # website browser acceptance
```

The automated test suite uses synthetic Telegram objects and never connects real accounts;
the live test is described above. CI is configured to run the test matrix on
Windows, Linux and macOS with Python 3.11–3.13, the browser checks, source packaging, the Windows
portable build and a Docker build. The release workflow is set up to attach the source ZIP, wheel,
Windows portable ZIP and multi-architecture GHCR image to a published GitHub Release. Neither
workflow has run yet. Read [CONTRIBUTING.md](../.github/CONTRIBUTING.md) before opening a pull request.

</details>

## Documentation

| Start using it | Understand it | Work on it |
| --- | --- | --- |
| [Quick start](QUICKSTART.md) | [How it works](HOW-IT-WORKS.md) | [Contributing](../.github/CONTRIBUTING.md) |
| [Project wiki](wiki/Home.md) | [Evidence and trust](EVIDENCE.md) | [Architecture](ARCHITECTURE.md) |
| [Investigations](INVESTIGATION.md) | [Collection and coverage](COLLECTION.md) | [Changelog](CHANGELOG.md) |
| [Troubleshooting](wiki/Troubleshooting.md) | [Independent witness](wiki/Independent-Witness.md) | [Website and publishing](internal/PUBLISHING.md) |

[Browse every guide →](README.md) &nbsp; · &nbsp; [Get help →](../.github/SUPPORT.md)

<details>
<summary>Read the project overview in your language</summary>

**English** · [Русский](ru/README.md) · [Українська](uk/README.md) · [Español](es/README.md) · [Português (Brasil)](pt/README.md) · [Türkçe](tr/README.md) · [العربية](ar/README.md) · [فارسی](fa/README.md) · [اردو](ur/README.md) · [हिन्दी](hi/README.md) · [Bahasa Indonesia](id/README.md) · [Tiếng Việt](vi/README.md) · [简体中文](zh/README.md)

</details>


![Section divider](assets/presentation/divider.svg)

## License

[MIT License](../LICENSE). Our
[position on Taylor Wessing](TAYLOR-WESSING-EXCLUSION.md) is a statement, not a licence condition.


## Repository map

| Inside the project | What you will find |
| --- | --- |
| [Application](../tgwitness/README.md) | Collectors, journals, evidence exports and the panel |
| [Documentation](README.md) · [Wiki](wiki/Home.md) | Setup, investigations, operations and verification |
| [Tests](../tests/README.md) | Synthetic regression checks and qualification entry points |
| [Tools](../tools/README.md) | Local builds, browser checks, screenshots and packaging |
| [Deployment](../deploy/README.md) | Service templates and HTTPS configuration |
| [Website](../website/README.md) | Public pages, practical guides and language catalogues |
| [GitHub configuration](../.github/AUTOMATION.md) | Automation, issue forms and dependency updates |
