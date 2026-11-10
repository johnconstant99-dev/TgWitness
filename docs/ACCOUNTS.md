[TgWitness](../README.md) / [Documentation](README.md) · [Getting started](QUICKSTART.md)

![Getting started](assets/presentation/chapter-start.svg)

# Accounts and session formats

TgWitness signs in as a **Telegram user account** (not a bot) over MTProto, using
Telethon. Each account lives in its own **workspace** (called a *workspace* in the
API and command-line tools) with its own session, sources, journal and signing key.

Session files, session strings and Auth Keys are **account authorizations**: whoever
holds one can act as that account. They do not contain message history.

> [!WARNING]
> **Use dedicated accounts.** Telegram restricts and can permanently ban accounts for
> request volumes it considers excessive, whatever the client or purpose, and documents
> those limits only in part. Connect accounts prepared for observation rather than
> personal or otherwise valuable ones, and create an API ID / API hash on a dedicated
> account.

- [At a glance](#at-a-glance)
- [Before you start: API ID and API hash](#before-you-start-api-id-and-api-hash)
- [Phone number](#phone-number) · [QR code](#qr-code) · [Auth Key + DC ID](#auth-key--dc-id)
- [Account files](#account-files): [Telethon .session](#telethon-session) ·
  [Pyrogram .session](#pyrogram-session) · [Session + JSON pair](#session--json-pair) ·
  [TData](#telegram-desktop-tdata) · [StringSession](#telethon-stringsession) ·
  [Auth key and DC in one line](#auth-key-and-dc-in-one-line) · [Account JSON](#account-json)
- [Identify what you have](#identify-what-you-have) · [Unsupported formats](#unsupported-formats)
- [Multiple accounts](#multiple-accounts) · [Keeping account files safe](#keeping-account-files-safe) ·
  [Troubleshooting](#troubleshooting)

## At a glance

| What you have | Tab in **Add account** | You will also need |
| --- | --- | --- |
| The phone number and access to its login codes | **Phone** | 2FA password if enabled |
| Telegram open on another device | **QR code** | 2FA password if enabled |
| A `.session` file (Telethon or Pyrogram) | **Files** | Optional companion JSON for app settings |
| `.session` + `.json` with the same name | **Files** (select both) | Usually nothing else |
| A Telegram Desktop `tdata` folder | **Files** (as a ZIP) | The Desktop local passcode if one is set |
| A Telethon StringSession (text, `.txt`, `.tgwitness-session`) | **Files** | No separate API pair required |
| An auth key and DC as one line, `<512 hex>:<1–5>` | **Files** (paste or a text file) | No separate API pair required |
| A `.json` with a session or Auth Key | **Files** | No separate API pair required |
| An Auth Key (512 hex characters) and its DC number | **Auth key** | Optional User ID |

TgWitness recognises files by their **contents**, not their names. Renaming a file
never converts it.

## Before you start: API ID and API hash

You can sign in without creating a Telegram API application. When no pair is entered,
imported or already saved in the workspace, TgWitness picks a pair from its built-in pool of
50 public API pairs (`tgwitness/api_pool.py`), preferring Telegram Desktop for a fresh
login and retaining a saved pair first; remaining candidates are shuffled. If Telegram refuses a pair
(`API_ID_INVALID`, `API_ID_PUBLISHED_FLOOD`, `UPDATE_APP_TO_LOGIN`), the next one is tried,
up to eight per sign-in; refused pairs are skipped until restart. The pair that signed in is
saved with the account and reused for it. An **API ID** and **API hash** identify the application to Telegram; they
do not authorize an account by themselves.

Missing connection fields use a deterministic device/OS pair from the bundled
[opentele2 2.0.0 catalogs](https://github.com/DedInc/opentele2/tree/7e973bc71cd7a714ad13ac703c0895a90d36a735):
Desktop `2040`, Android `6`, Android X `21724`, iOS `10840`, macOS `2834`, and Web `2496`.
Android's source-build ID `4` also uses the Android catalog, as identified in
[Telegram Android's BuildVars](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/java/org/telegram/messenger/BuildVars.java).
Web defaults to A; an imported `K` app-version suffix or `macos` language pack selects
K, and version `0.7.0` selects Webogram. Unknown application IDs keep Telethon's host
defaults. Imported fields always win, including an older app version and an empty
language pack. The catalog never changes the API ID/hash. Its version snapshot is
reviewed explicitly, not fetched during login. A saved profile stays stable after updates.

`account.getAuthorizations` reports Telegram's saved authorization metadata; it is
not an echo of each new `initConnection`. Compare it with the actual sent profile.
Connecting an existing authorization does not validate its companion API hash:
`initConnection` sends the API ID, while the hash is used by login requests.

After a new phone or QR authorization, TgWitness requests config, nearest DC,
online status, languages (when the language pack is nonempty), app updates and
terms-of-service updates, with 0.3–1.5 seconds between requests. Updating status
briefly marks the account online. This sequence runs once at login completion,
not on imports, reconnects or restarts. The authorization is saved first; a failed
request stops the sequence without retrying or discarding the login. Results are
recorded as `account.initialized`, with error names rather than response bodies.
Telegram's own policies decide account restrictions.

For `tdesktop`, a missing `tz_offset` uses the server's local UTC offset, rounded
to 900 seconds using the [opentele2 algorithm](https://github.com/DedInc/opentele2/blob/7e973bc71cd7a714ad13ac703c0895a90d36a735/crates/opentele2-core/src/fingerprint.rs)
(MIT; license in `tgwitness/client_profiles.LICENSE`). It is refreshed on each
connection so daylight-saving changes are reflected. An imported `tz_offset`
takes precedence on every platform and is kept exactly, including zero. Other
`initConnection.params` entries are retained.
The HTTP sign-in form accepts the numeric timezone returned by file import;
booleans, fractions and offsets outside the supported range are rejected.

Direct, SOCKS5 and HTTP CONNECT routes use Telethon's `ConnectionTcpObfuscated`
(obfuscated abridged MTProto). HTTPS CONNECT retains TLS to the proxy and uses
the same obfuscated transport inside the tunnel. MTProxy retains its required
randomized intermediate transport and secret handling. Route switches apply the
same choices. Obfuscation changes packet framing; it does not hide the account
or its client metadata from Telegram or imply immunity to restrictions.

After connecting an authorized client, TgWitness checks config, nearest DC,
the current authorization, the reviewed layer baseline, languages, app updates
and terms-of-service updates. These diagnostics run once per client instance,
before collection, and are shown under the connection details with their time.
`account.connection_checked` records the result without session hashes, IPs,
tokens or API hashes. They never accept terms or install updates. A request
failure or FloodWait stops subsequent requests; a missing result stays unknown.
Local checks can still report their results while network checks are skipped.

FloodWait diagnostics retain the failed TL method, any Takeout/range wrappers,
the server-requested wait and the effective deadline in `telegram.backoff`.
Connection details show the method and deadline while requests are paused.
The diagnostic includes per-method client-call counters since that client was
created; they count nested peer resolution separately, but do not count packets
or Telethon's internal retry attempts. Current counters are also available as
`collector.rpc_activity` in the status API. No request arguments, usernames, access
hashes or exception text are included. The last diagnostic and full deadline
survive restart. Earlier waits without a method record cannot be attributed
retrospectively. See [export limits](EXPORT-LIMITS.md) for the source review and
the distinction between discovery and history acquisition.

`official_app=True` or `False` is Telegram's current-authorization flag. Neither
value establishes whether the account is restricted, trusted or under observation.
The existing evidence-mode `account.devices` snapshots remain the history of all
signed-in devices; connection diagnostics retain only the current device description.

Before connection, advisory checks compare the API platform, language pack,
device/OS and app-version formats, mobile system locale, and Telethon's actual
schema layer against the reviewed catalog baseline. Warnings appear in the server
log and account status metadata; they never replace imported values or change the
schema layer. A different layer is a signal to review compatibility; the account's
own connection status shows whether it works. Telegram decides restrictions on its
side, whichever client profile is used. Disconnected account status
uses the saved profile instead of generating another device description.

To use your own application instead (the account that registers it is the one at risk; see
[Why a built-in API pool?](PROJECT-GUIDE.md#connect-a-telegram-account)):

1. Open [my.telegram.org](https://my.telegram.org) and sign in with any phone number
   you own. The code arrives in the Telegram app, not by SMS.
2. Choose **API development tools**.
3. Create an application: any title and short name (5–32 letters), platform **Desktop**.
   URL and description can stay empty.
4. Copy **App api_id** (a number) and **App api_hash** (32 hexadecimal characters).

In the panel, open **API ID + Hash** under the sign-in form. You can paste a single
`api_id:api_hash` pair into **API ID** and both fields are filled. One pair can be
used for all of your accounts. After a successful login it is saved, encrypted, in
that workspace only and is never sent back to the browser.

Three different credentials are involved:

| Secret | Opens | Where it lives |
| --- | --- | --- |
| Panel token | The TgWitness web panel | `panel-token.txt` in the data directory, or `TGWITNESS_TOKEN` |
| API ID + hash | Nothing by itself; identifies the app | Built-in pair, imported settings, or your own app at my.telegram.org |
| Account authorization | The Telegram account | Created by phone/QR login or brought in as a session |

If Telegram must be reached through a proxy, set it first under
**Account → Settings → Connection settings → Change connection route**.

## Phone number

1. Open **Account**, tab **Phone**, and enter the number in international format,
   for example `+44 7700 900123`. Spaces and dashes are removed automatically.
2. Press **Continue**. API ID + Hash can stay empty.
3. Enter the code Telegram sends, usually to the Telegram app; Telegram decides whether to send SMS.
4. If the account has two-step verification, enter that password. It is not the panel
   token and not a device passcode.
5. Check the account ID shown after login, then choose sources.

Login codes and the 2FA password are never written to disk.

## QR code

Use this when the account is already signed in on a phone or another computer.

1. Tab **QR code** → **Show QR code**. API ID + Hash can stay empty.
2. On the signed-in device: **Settings → Devices → Link Desktop Device**, scan the code
   and confirm.
3. Enter the 2FA password in TgWitness if Telegram requests it.

The QR image is generated locally. Codes expire; press **Generate another QR code**
to retry. Locking the panel, switching workspace or starting another login cancels
a pending code.

## Auth Key + DC ID

An Auth Key is the raw 256-byte authorization behind every Telegram session, written
as **512 hexadecimal characters**, together with the data-centre number **DC 1–5**.

1. Tab **Auth key**. Paste the complete key; a shortened key containing `…` cannot work.
2. Select the DC ID supplied with the key.
3. Optionally enter the **User ID**. TgWitness then refuses to connect if Telegram reports
   a different account.
4. Press **Connect account**.

An Auth Key (512 characters) is not an API hash (32 characters). The same key can also
be imported as JSON, see [Account JSON](#account-json).

## Account files

Open **Add account → Files** and select up to **four files belonging to one account**,
**8 MiB** in total, then press **Connect account**.

The **Files**, **Auth key** and bulk-import forms show the parallel-session warning
before connecting. By default imported authorizations are reused. Keep the original
client closed while its key is in use here. **Files** and **Auth key** also offer
**Create an independent authorization**, described below. Bulk import still uses
the direct mode. Phone and interactive QR login create separate authorizations.
The warning heading stays visible in the import form; its full explanation opens
automatically when files or a key/session string are supplied. It can be collapsed
after reading, so the file picker and connection controls remain usable on a phone.

- Files are converted **in memory** on your TgWitness server. Uploads are not stored,
  ZIPs are not extracted to disk and no external service is contacted.
- The resulting session is then checked with Telegram. If a file states a user ID,
  it must match the account Telegram reports.
- Files that describe different accounts or different API credentials are rejected
  instead of picking one.
- **Passcode or session text** holds the TData local passcode field, a box for pasting
  a StringSession and **Read files without signing in** (fills the form without
  contacting Telegram).

### Create an independent authorization

Select **Create an independent authorization** before connecting imported files or
an Auth Key. TgWitness connects the imported donor briefly, uses it to approve the
new client's QR login token, and disconnects the donor immediately after approval.
The new client has its own authorization key and a separately selected Desktop
profile. The donor's supplied API credentials and device profile are used only for
the donor connection. No existing authorization is logged out or revoked.

**Keep the donor's original client fully closed during this step.** The initial
connection still uses its copied key, so this mode cannot remove that initial
parallel-use risk. Once the new authorization is connected, the owner can reopen
the original client and use both independently. Interactive **QR code** login lets
the original client approve the login without copying or connecting its key here.

If Telegram requests 2FA, this mode uses `twoFA` from the selected JSON when present,
or asks for the password. A rejected imported password returns to the password form.
Passwords are not saved. The candidate key is saved encrypted in
`independent_login.enc`, including changes during data-centre migration. After an
interruption, select the same donor and this option to resume the saved candidate.
The workspace remains reserved for that account; failed completion does not delete
the new workspace. Keep its data directory and vault key. The final credentials and
`account.authorized` journal record include the import method, input formats and
donor API ID, without the donor key or password.

On 5 November 2026, a dedicated account passed live checks with Telethon, Pyrogram
and TData donors: 2FA completion, distinct new authorization keys, concurrent access
by the donor and new client, and reading a public channel. The Telethon case also
resumed a saved candidate after an interruption at the password step. Each new
authorization completed the six post-login initialization requests, and its signed
journal verified. The original session remained usable in all four supplied formats.

Telegram's [RPC error database](https://core.telegram.org/api/errors.json) associates
`FRESH_CHANGE_ADMINS_FORBIDDEN` with changing admins, `FRESH_CHANGE_PHONE_FORBIDDEN`
with changing the phone number, and `FRESH_RESET_AUTHORISATION_FORBIDDEN` with
revoking other sessions, changing their lifetime or registering a passkey.
`SESSION_TOO_FRESH_*` and `PASSWORD_TOO_FRESH_*` concern ownership transfers and
revenue or gift withdrawals. These are not collection operations; a new login does
not imply a blanket 24-hour reading ban. Export can separately return
`TAKEOUT_INIT_DELAY_*`. TgWitness retains server-requested pauses and does not retry
token acceptance automatically or revoke sessions to work around restrictions.

**Account security → Sessions of this account → End all other sessions** calls `auth.resetAuthorizations` on the
operator's request and records `account.all_other_sessions_terminated` with the session
counts before and after. Telegram accepts it from a session signed in for 24 hours.

**Make this the only session** does the same for a key created by signing in from this
workspace, then turns on a two-step password if the account has none. The panel shows that
password once; TgWitness does not keep it. The journal records `session.exclusive_from`. If
Telegram later lists another session, the journal records `session.exclusive_ended` and the
panel raises an alert. The verifier prints both.

**Make this the only session when Telegram allows it** is the same action on a timer. The
option appears under **Sessions of this account** for a key created in this workspace and is
recorded as `session.exclusive_automatic`. While observing, the collector checks every five
minutes whether 24 hours have passed since the `account.authorized` record of that key —
Telegram answers `FRESH_RESET_AUTHORISATION_FORBIDDEN` before that — and then runs the same
operation once. Success is recorded as `session.exclusive_from`, like the manual button.
A refusal is recorded once as `session.exclusive_postponed` with Telegram's reason, and the
collector retries with a growing delay of up to six hours. Read-only has no effect here:
ending sessions is an account-security action, not a chat action.

A two-step password generated by the automatic run is held in memory only. The panel fetches
it once from `POST /api/account/sessions/only/password`, which clears it, and shows it in the
same dialog as the manual flow when you open **Sessions of this account**. The connection page
notes that a password is waiting. It is never written to disk or to the journal, so a restart
before the operator reads it loses it; the password can then only be changed through
**Two-step password**.

New sessions are also reported while observing: when Telegram's session list gains an entry,
the `account.sessions` record names it under `added` and the panel raises an alert with the
device, application and country from that snapshot.

### Witness probe

**Account security → Witness probe** checks whether another client receives this account's
updates. Add a second workspace signed in with a different Telegram account and its own
session key, create a private group with both accounts, then choose that group as **Probe
chat** and the second workspace as **Witness workspace** and turn the probe on. Both accounts
need **Read-only** off, and the witness workspace must be observing.

While observing, this workspace sends `probe:<n>:<token>` into the group every 60–120 seconds
and records `probe.sent`. The witness answers `ack:<n>:<token>` and records `probe.seen` and
`probe.ack_sent`. An ack that reaches this session as a live update within 20 seconds is
recorded as `probe.acked`. Otherwise the workspace reads the group's recent history. An ack
found there but not delivered live is recorded as `coverage.gap` with reason
`probe_ack_missed_live`: the panel raises an alert and marks event intake as failed until a
later ack arrives live (`connection.restored`, reason `probe_ack_live`). No ack is recorded as
`probe.unanswered`; a connection interruption during the wait or an unreadable history as
`probe.inconclusive`. Read-only, Telegram restrictions and FloodWait pauses are recorded once
as `probe.skipped`.

### Telethon `.session`

| | |
| --- | --- |
| What it is | The SQLite database Telethon-based tools create, for example `my_account.session` |
| Recognised by | Tables `sessions` (with `dc_id`, `server_address`, `port`, `auth_key`) and `version` = 7 or 8 |
| Requirements | Exactly one authorized session row; a closed, complete database |

Close the program that created the file first. If `my_account.session-journal` or
`my_account.session-wal` exists next to it, the database is not finalised: open and
close the original client cleanly. Deleting those sidecar files can leave a broken copy.

### Pyrogram `.session`

| | |
| --- | --- |
| What it is | The SQLite database Pyrogram-based tools create |
| Recognised by | Table `sessions` with `dc_id`, `auth_key`, `test_mode`, `user_id`, `is_bot`; `version` = 2 or 3 |
| Requirements | One authorized **user** session on the production network. Bot and test-DC sessions are rejected |

The stored user ID is checked against Telegram during login.

### Session + JSON pair

Accounts are often distributed as two files with the same name, for example
`447700900123.session` and `447700900123.json`. Select **both** at once.

- From the JSON, TgWitness uses `app_id`/`api_id` and `app_hash`/`api_hash`, so you
  usually do not have to type API credentials.
- The connection profile uses `device_model` (alias `device`), `system_version`
  (alias `sdk`), `app_version`, `lang_code`, `system_lang_code` (alias `system_lang_pack`),
  `lang_pack` and optional `tz_offset` (seconds from UTC, -43200 to 50400).
  Supplied fields take priority over generated defaults and the panel/browser
  language. Conflicting aliases are rejected. The resolved profile is saved in the
  encrypted workspace credentials and reused after restart, including its app version.
- `phone`, proxy settings and device tokens are **ignored**. `twoFA` is read only
  when **Create an independent authorization** is selected; direct import ignores it.
- A JSON without a supported authorization field is only metadata. Add its session
  file or continue with phone or QR login. A JSON containing a supported session or
  Auth Key can authorize on its own; see [Account JSON](#account-json).

### Telegram Desktop (TData)

TData is the `tdata` folder of the Telegram Desktop application (the cross-platform
app from desktop.telegram.org).

| System | Default `tdata` location |
| --- | --- |
| Windows | `%APPDATA%\Telegram Desktop\tdata` (portable Telegram: next to `Telegram.exe`) |
| Linux | `~/.local/share/TelegramDesktop/tdata` |
| macOS | `~/Library/Application Support/Telegram Desktop/tdata` |

To import it:

> **Parallel session warning.** Direct TData import reuses Telegram Desktop's authorization
> key. Do not use that key in Desktop and
> TgWitness simultaneously. Telegram can invalidate the authorization with
> `AUTH_KEY_DUPLICATED`, leaving both copies unusable until a new login.
>
> Fully quit Desktop, including its tray process, and keep that copy closed while
> TgWitness uses the imported session. **Quit, do not log out or revoke the session:**
> revocation also invalidates the imported copy. If you need both clients running,
> select **Create an independent authorization** and keep Desktop closed until the
> new login succeeds, or sign in to TgWitness by phone or QR. A dedicated
> account is recommended, but does not make cloned keys safe to use in parallel.
>
> This also applies to imported `.session` files, StringSession text and Auth Key HEX.
> Other clients with their own independently created authorizations can remain signed in.
> See [Telegram's AUTH_KEY_DUPLICATED documentation](https://core.telegram.org/api/errors#406-not-acceptable).

1. Fully quit Telegram Desktop.
2. Create a ZIP containing **only** these two items from `tdata`:
   - `key_datas`
   - the 16-character file ending in `s` next to it, usually `D877F783D5D3EF8Cs`

   Zipping the whole folder with its media cache usually exceeds the limits
   (512 entries, 32 MiB unpacked).
3. Select the ZIP in **Files**. If Telegram Desktop has a **local passcode**, enter it
   under **Passcode or session text** first. This is not the 2FA password.

Supported: one account per archive, modern `key_datas`/`key_data0`/`key_data1` storage,
local passcode. Not supported: folders with several logged-in accounts, older Desktop
layouts, password-protected ZIPs, and the separate native macOS app "Telegram for macOS".

### Telethon StringSession

A single line of text, usually starting with `1` and about 350 characters long. Load
it as a `.txt` or `.tgwitness-session` file (at most 4 KiB), or paste it under
**Passcode or session text**. Only Telethon strings are accepted; Pyrogram and TDLib
strings use different formats.

### Auth key and DC in one line

Account lists often carry the raw authorization as `<512 hexadecimal characters>:<DC id>`,
for example `a1b2…ef:5`. Paste that line under **Passcode or session text**, load it as a
text file, or put it in the `session` field of an [Account JSON](#account-json). TgWitness
maps DC 1–5 to the same production addresses as the `auth_key` + `dc_id` JSON import and
reports the format as **Auth key HEX and DC**. Any other DC number or key length is rejected.

### Account JSON

One JSON object, at most **64 KiB**, in a file ending in **`.json`**.

| Field (aliases) | Meaning |
| --- | --- |
| `api_id` (`app_id`) | Application ID, a positive number |
| `api_hash` (`app_hash`) | Application hash, 32 hexadecimal characters |
| `string_session` (`session_string`, `session_str`; legacy `session`) | Telethon StringSession text, or `<512 hexadecimal characters>:<DC id>`, not a file name |
| `auth_key` (`auth_key_hex`) + `dc_id` | Complete 512-character Auth Key and DC 1–5 |
| `user_id` (`id`) | Optional; checked against Telegram before the authorization is saved |
| `device_model` (`device`) | Connection device description |
| `system_version` (`sdk`) | Connection OS version |
| `app_version` | Application version sent to Telegram |
| `lang_code`, `system_lang_code` (`system_lang_pack`), `lang_pack` | Client language, system language and client language pack; an empty `lang_pack` is allowed |
| `tz_offset` | Optional UTC offset in seconds, sent in `initConnection.params`; integer or decimal integer string |

If both an alias and the main name are present, they must agree. Explicit Telethon
session fields take priority over a generic `session` blob in another format. If
both contain recognizable Telethon sessions, they must describe the same authorization.
Without an explicit field, `session` must be a valid Telethon StringSession or an auth key
and DC in `<512 hexadecimal characters>:<DC id>` form. Examples:

```json
{ "app_id": 1234567, "app_hash": "0123456789abcdef0123456789abcdef" }
```

```json
{
  "api_id": 1234567,
  "api_hash": "0123456789abcdef0123456789abcdef",
  "auth_key": "REPLACE_WITH_ALL_512_HEXADECIMAL_CHARACTERS",
  "dc_id": 2,
  "user_id": 123456789
}
```

The first example only fills API credentials; sign in by phone or QR, or add a session
file. Bulk lists (a JSON array of accounts) are not accepted.

## Identify what you have

| You see | It is | Use |
| --- | --- | --- |
| `*.session`; opening it in a text editor shows `SQLite format 3` at the top | Telethon or Pyrogram SQLite | **Files** (detected automatically) |
| A `tdata` folder containing `key_datas` | Telegram Desktop TData | ZIP two files, then **Files** |
| One text line starting with `1`, ~350 characters | Telethon StringSession | **Files** |
| One text line `512 characters 0-9a-f`, then `:` and a digit 1–5 | Auth key and DC | **Files**, box **Passcode or session text** |
| `*.json` with `app_id`/`app_hash` | Companion metadata | **Files**, together with its session |
| `*.json` with `auth_key` or `string_session` | Account JSON | **Files** |
| 512 characters `0-9a-f` | Auth Key | **Auth key** |
| 32 characters `0-9a-f` | API hash | **API ID + Hash** |
| `td.binlog` or a `db.sqlite` from a TDLib app | TDLib storage | Not supported |
| `123456789:AA…` | Bot token | Not supported |

## Unsupported formats

| Format | Alternative |
| --- | --- |
| TDLib storage (`td.binlog`) and TDLib exports | Sign in by phone or QR |
| Pyrogram session **strings** | Use the Pyrogram `.session` file, or phone/QR |
| TData with several logged-in accounts | Log out the other accounts in Telegram Desktop, or use each account's own session file |
| Bot tokens | Not supported: TgWitness observes as a user account |
| CSV/JSON lists of many accounts | Import supported session files through **Accounts → Import accounts**, or sign in by phone/QR in separate workspaces |
| Test-DC or bot sessions | Use a production user account |

## Multiple accounts

Press **+** beside the account selector, or open
**Account → Settings → Connection settings → Workspaces**, enter a label and
sign in.

- Any number of workspaces, including the main one. Each has its own session, proxy
  route, sources, capture policy, journal, signing key, checkpoints and exports.
- Switching the displayed workspace does not pause the others.
- A journal stays bound to the account that created it. Signing in as a different
  account requires another workspace, and one account cannot be assigned to two
  workspaces.
- The main panel token controls all workspaces. [Issued access](ACCESS.md) can restrict other people to selected accounts and chats, with separate permissions and session limits.
- **Accounts** renames a workspace and deletes an added one, with its session, journal,
  sources and signing key. The main workspace cannot be deleted from the panel.

### Bulk import and account groups

Use **Accounts → Import accounts** to add several accounts, pair files by basename
and see each login result. Each account gets its own workspace.

A group keeps related accounts together without merging their sessions, keys or
evidence. **Open group** on **Accounts** leads to its page at `/groups/<id>`:

- **Accounts:** each member's connection route, observation and last message, with
  **Start all** and **Pause all**.
- **Needs attention:** accounts that were signed out, are unavailable or have a
  connection, intake, source or media problem; each name leads to its card.
- **Chats several accounts see:** shared sources, the accounts observing them and
  interruptions in the available workspace-observation period (up to seven days). **Export with N accounts**
  splits a channel or supergroup export between them and signs one archive.
- **Export group:** one ZIP with each account's signed export under `accounts/` and
  `manifest.json` listing their SHA-256 and key fingerprints, signed by the main
  workspace in `manifest.signature.json`. Verify each account archive on its own with
  `python -m tgwitness.verify` and that account's trusted fingerprint.

Members share the group's settings; an account can keep its own values.
See [shared settings](SETTINGS.md#account-groups),
[the import and groups guide](wiki/Accounts.md#import-accounts-and-share-settings)
and [the MTProxy pool dashboard](wiki/Proxies.md#pool-dashboard-and-custom-sources).

## Sign out

**Account → Sign out of Telegram** (with observation paused) asks Telegram to end the
session, so it also disappears from the account's **Settings → Devices**, and removes the
session from the workspace vault. The journal, sources, settings and signing key stay, and
the journal records the sign-out. The workspace still belongs to its account: only that
account can connect to it again. If Telegram does not answer, the session is still removed
here and the panel says so; end it in Telegram under **Settings → Devices**.

## Keeping account files safe

- Treat every `.session`, TData ZIP, StringSession, Auth Key and account JSON like a
  password. TgWitness keeps the imported authorization in its encrypted vault; you can
  remove the original files afterwards.
- Do not run the same authorization in two programs at once. Telegram may revoke it
  (`AUTH_KEY_DUPLICATED`), and both copies stop working.
- An expired or revoked session cannot be revived by conversion. Sign in again.

## Troubleshooting

| Message or symptom | What to do |
| --- | --- |
| *Cannot read this session. Close its original client…* | The SQLite file is open or unfinished (`-journal`/`-wal` sidecar). Close the original program cleanly and copy the file again. |
| *Supported Telethon SQLite schemas: 7 and 8* / *Pyrogram … 2 and 3* | A very old or unknown library version created the file. Sign in by phone/QR instead. |
| *Only authorized production user sessions are supported* | The Pyrogram file belongs to a bot or the test network. |
| *TData archive exceeds 512 entries or 32 MiB* | ZIP only `key_datas` and `D877F783D5D3EF8Cs`, not the whole folder. |
| *Cannot decrypt TData. Check the Desktop local passcode* | Enter the Telegram Desktop local passcode under **Passcode or session text**. |
| *Import one TData account at a time* | Telegram Desktop had several accounts; see [Unsupported formats](#unsupported-formats). |
| *Selected files describe different accounts or API credentials* | Select files of one account only. |
| *JSON contains no supported API credentials or authorization* | Check the field names in [Account JSON](#account-json). |
| *API metadata only* | The JSON has no session. Add the `.session` file or use phone/QR. |
| *Auth Key HEX must contain all 512 hexadecimal characters* | The key is truncated or contains `…`. |
| Account ID does not match the imported account | The file's user ID differs from what Telegram reports; the file is for another account. |
| Account already belongs to another workspace | Open that workspace instead of adding the account twice. |
| Connected, but a private group is missing from the chat list in **Sources** | Check membership. The picker inspects the first 1,000 dialogs; raise the limit under **Parameters**. |
| Proxy connection fails | Check the route and IP mode. Automatic MTProxy tries another working entry. Hide the address waits; Direct as a last resort can connect directly after its configured delay. See [routing modes](CONNECTION-SECURITY.md#ip-modes). |

See also: [connection and security](CONNECTION-SECURITY.md) for proxies and encryption,
and [how collection works](COLLECTION.md) for what is captured after sign-in.
