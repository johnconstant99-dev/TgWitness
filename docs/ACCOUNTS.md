# Accounts and session formats

TgWitness signs in as a **Telegram user account** (not a bot) over MTProto, using
Telethon. Each account lives in its own **workspace** (called a *workspace* in the
API and command-line tools) with its own session, sources, journal and signing key.

Session files, session strings and Auth Keys are **account authorizations**: whoever
holds one can act as that account. They do not contain message history.

> [!WARNING]
> **Do not use anything you cannot afford to lose.** We strongly advise against connecting
> personal or otherwise valuable accounts, and against creating an API ID / API hash on an
> account you value. This is not about TgWitness being untested: Telegram restricts and
> permanently bans accounts unpredictably — for request volumes it happens to consider
> excessive, regardless of the client or purpose, with no adequate documentation. Many bans
> are irreversible. Use dedicated accounts. Smooth test runs depend on Telegram, not on the
> software, and guarantee nothing for later.

- [At a glance](#at-a-glance)
- [Before you start: API ID and API hash](#before-you-start-api-id-and-api-hash)
- [Phone number](#phone-number) · [QR code](#qr-code) · [Auth Key + DC ID](#auth-key--dc-id)
- [Account files](#account-files): [Telethon .session](#telethon-session) ·
  [Pyrogram .session](#pyrogram-session) · [Session + JSON pair](#session--json-pair) ·
  [TData](#telegram-desktop-tdata) · [StringSession](#telethon-stringsession) ·
  [Account JSON](#account-json)
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
| A `.json` with a session or Auth Key | **Files** | No separate API pair required |
| An Auth Key (512 hex characters) and its DC number | **Auth key** | Optional User ID |

TgWitness recognises files by their **contents**, not their names. Renaming a file
never converts it.

## Before you start: API ID and API hash

You can sign in without creating a Telegram API application. When no pair is entered,
imported or already saved in the workspace, TgWitness picks a pair from its built-in pool of
50 public API pairs (`tgwitness/api_pool.py`) in random order. If Telegram refuses a pair
(`API_ID_INVALID`, `API_ID_PUBLISHED_FLOOD`, `UPDATE_APP_TO_LOGIN`), the next one is tried,
up to eight per sign-in; refused pairs are skipped until restart. The pair that signed in is
saved with the account and reused for it. An **API ID** and **API hash** identify the application to Telegram; they
do not authorize an account by themselves.

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
3. Enter the code Telegram sends (usually to the Telegram app; SMS is not guaranteed).
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

- Files are converted **in memory** on your TgWitness server. Uploads are not stored,
  ZIPs are not extracted to disk and no external service is contacted.
- The resulting session is then checked with Telegram. If a file states a user ID,
  it must match the account Telegram reports.
- Files that describe different accounts or different API credentials are rejected
  instead of picking one.
- **Passcode or session text** holds the TData local passcode field, a box for pasting
  a StringSession and **Read files without signing in** (fills the form without
  contacting Telegram).

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
- Other fields such as `phone`, `device`, `sdk`, `app_version`, `lang_pack` or a stored
  `twoFA` password are **ignored**. If the account has 2FA, TgWitness asks for it.
- A JSON on its own is only metadata. Without the session file, continue with phone
  or QR login.

### Telegram Desktop (TData)

TData is the `tdata` folder of the Telegram Desktop application (the cross-platform
app from desktop.telegram.org).

| System | Default `tdata` location |
| --- | --- |
| Windows | `%APPDATA%\Telegram Desktop\tdata` (portable Telegram: next to `Telegram.exe`) |
| Linux | `~/.local/share/TelegramDesktop/tdata` |
| macOS | `~/Library/Application Support/Telegram Desktop/tdata` |

To import it:

> **Parallel session warning.** Importing TData reuses Telegram Desktop's authorization
> key; it does not create an independent login. Do not use that key in Desktop and
> TgWitness simultaneously. Telegram can invalidate the authorization with
> `AUTH_KEY_DUPLICATED`, leaving both copies unusable until a new login.
>
> Fully quit Desktop, including its tray process, and keep that copy closed while
> TgWitness uses the imported session. **Quit, do not log out or revoke the session:**
> revocation also invalidates the imported copy. If you need both clients running,
> sign in to TgWitness by phone or QR to create its own authorization. A dedicated
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

### Account JSON

One JSON object, at most **64 KiB**, in a file ending in **`.json`**.

| Field (aliases) | Meaning |
| --- | --- |
| `api_id` (`app_id`) | Application ID, a positive number |
| `api_hash` (`app_hash`) | Application hash, 32 hexadecimal characters |
| `string_session` (`session_string`, `session`) | Telethon StringSession text, not a file name |
| `auth_key` (`auth_key_hex`) + `dc_id` | Complete 512-character Auth Key and DC 1–5 |
| `user_id` (`id`) | Optional; checked against Telegram before the authorization is saved |

If both an alias and the main name are present, they must agree. Examples:

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
| CSV/JSON lists of many accounts | Add one workspace per account |
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
and see each login result. Each account gets its own workspace. Groups can copy
selected settings from a template without merging sessions, keys or evidence.
See [the import and groups guide](wiki/Accounts.md#import-accounts-and-share-settings)
and [the MTProxy pool dashboard](wiki/Proxies.md#pool-dashboard-and-custom-sources).

## Sign out

**Account → Sign out of Telegram** (with observation paused) asks Telegram to end the
session, so it also disappears from the account's **Settings → Devices**, and removes the
session from the workspace vault. The journal, sources, settings and signing key stay, and
the journal records the sign-out. The workspace still belongs to its account: only that
account can connect to it again. If Telegram does not answer, the session is still removed
here and the panel says so; end it in Telegram under **Settings → Devices**.

## Convert a Telethon session offline

The panel imports `.session` files directly. For an offline conversion to a
StringSession file, run from the project folder:

```powershell
.venv\Scripts\python.exe -m tgwitness.sessions account.session --out account.tgwitness-session   # Windows
```

```sh
.venv/bin/python -m tgwitness.sessions account.session --out account.tgwitness-session          # Linux/macOS
```

The converter reads Telethon SQLite only (up to 64 MiB), never modifies the input,
makes no network request and refuses to overwrite an existing output file.

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
| Proxy connection fails | Check the route and IP mode. Automatic MTProxy tries another working entry. Hide IP mode waits; the explicitly selected fallback mode can connect directly after its configured delay. See [routing modes](CONNECTION-SECURITY.md#ip-modes). |

See also: [connection and security](CONNECTION-SECURITY.md) for proxies and encryption,
and [how collection works](COLLECTION.md) for what is captured after sign-in.
