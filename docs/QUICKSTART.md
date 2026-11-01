**English** · [Русский](ru/QUICKSTART.md) · [Українська](uk/QUICKSTART.md) · [Español](es/QUICKSTART.md) · [Português (Brasil)](pt/QUICKSTART.md) · [Türkçe](tr/QUICKSTART.md) · [العربية](ar/QUICKSTART.md) · [فارسی](fa/QUICKSTART.md) · [اردو](ur/QUICKSTART.md) · [हिन्दी](hi/QUICKSTART.md) · [Bahasa Indonesia](id/QUICKSTART.md) · [Tiếng Việt](vi/QUICKSTART.md) · [简体中文](zh/QUICKSTART.md)

# TgWitness quick start

TgWitness is a standalone application for observing Telegram groups and channels
that your accounts can access. It runs locally with its own data directory.

**First visit?** [Explore the demo](#explore-the-interface) before connecting an account.
[Choose a guide](README.md) for proxies, witnesses, exports or server setup.

## Install and start

[GitHub Actions capture (preview)](SEALED-ACTIONS.md)

Choose one method. Portable downloads become available after a release build is published:

| Host | Nothing installed | From source: Python 3.11+ | Docker: Engine/Desktop with Compose 2.20+ |
| --- | --- | --- | --- |
| Windows | Extract `TgWitness-<version>-windows-amd64-portable.zip` from GitHub Releases, double-click `TgWitness.cmd` | Double-click `Start.cmd` | Double-click `scripts\Docker.cmd` |
| Linux / macOS | — | `sh start.sh` | `sh scripts/docker-start.sh` |

For the source methods, [download and extract current `main`](https://github.com/phishdestroy/TgWitness/archive/refs/heads/main.zip)
or clone the repository:

```sh
git clone https://github.com/phishdestroy/TgWitness.git
cd TgWitness
```

`Start.cmd` offers to install Python 3.12 for your Windows user if no
suitable Python is found (winget, or the signed python.org installer). `start.sh` prints
the exact install command for your Linux distribution or macOS if Python is missing.
The first source launch creates `.venv` and installs dependencies automatically.

Docker builds the application and starts it in the background; host Python is
unnecessary. `scripts\Docker.cmd` and `scripts/docker-start.sh` print the panel address and token when
the container is healthy. The equivalent Docker commands on every supported host are:

```sh
docker compose up -d --build --wait
docker compose exec tgwitness cat /data/panel-token.txt
```

Open **http://127.0.0.1:8787**. Use the token printed by the Docker helper or the second
Docker command, or read **data/live/panel-token.txt** for a portable or source installation. Continue at
**Connect Telegram** below. Native and Docker installations use separate storage;
starting Docker does not import an existing native journal.

For a server, [deployment](DEPLOYMENT.md) covers automatic HTTPS, restart,
published images, updates, and backups.

## Explore the interface

1. Run **TgWitness-Demo.cmd** in the portable package, **scripts\Demo.cmd** in a Windows source
   folder, or `sh start.sh --demo` on Linux/macOS. A source launch first creates `.venv`
   and installs dependencies.
2. Open **http://127.0.0.1:8787**.
3. The local demo opens the sample journal automatically. No token copy is needed for direct local access.

Demo messages are fictional. Demo mode cannot connect a real Telegram account.

## Connect Telegram

> [!WARNING]
> **Do not use anything you cannot afford to lose.** We strongly advise against connecting
> personal or valuable accounts and against creating an API ID / hash on an account you value.
> Telegram bans accounts unpredictably and often permanently, regardless of the client.
> A smooth test run depends on Telegram, not on TgWitness, and guarantees nothing for later.

1. If the native demo is running, stop it and run **Start.cmd** or `sh start.sh`.
   Otherwise, keep the live installation started above running.
2. Use the panel token for your installation method to open the panel.
3. If you need a proxy, save it under **Account → Settings → Connection settings → Change connection route**.
4. In **Account**, enter your phone number and press **Continue**, choose
   **QR code → Show QR code**, or select files and press **Connect account**.
   **API ID + Hash** is optional: the workspace uses its saved or imported pair,
   or a working pair from the built-in pool. To use your own app, paste one
   `API ID:API Hash` pair into API ID.
   For a complete authorization key, choose **Auth key**, paste all 512 hexadecimal
   characters, and select the supplied DC ID. User ID is optional and checked if entered.
5. Complete your selected sign-in method: phone/code/2FA, confirmation from a
   signed-in Telegram app for QR, or a supported authorized session import.
6. Check the displayed account ID. Open **Sources**: your chats load automatically; add your groups.
7. Under **Choose which changes to preserve**, select event categories or the
   **Messages, edits & deletions** preset, then save monitoring settings.
8. Choose attachment settings separately, then press **Start observation**.

API credentials identify your application; they do not authorize an account by
themselves. Private groups need no public username, but your account must have access.

For existing accounts, see [accounts and session formats](ACCOUNTS.md): the
panel accepts Telethon StringSession, Telethon/Pyrogram SQLite, single-account TData
ZIP, and supported account JSON. Select a session and its companion JSON together,
press **Connect account**. QR login is also
available with the same optional API settings. TDLib, bot sessions and CSV/JSON
account inventories are unsupported.

For several accounts, use **Accounts → Import accounts** and select their supported
session files. Companion JSON files are paired by basename; each imported account
gets its own workspace. See [bulk import and account groups](ACCOUNTS.md#bulk-import-and-account-groups).

To add another account, press **+** beside the account selector or open
**Account → Settings → Connection settings → Workspaces**, or use **Accounts**. Workspaces have separate sessions,
journals, keys, sources and queues. Switching views leaves other collectors running.
The same Telegram account cannot be assigned to two workspaces in this installation.
There is no fixed number of workspaces; they share one process, so capacity depends on the machine.

The live panel token protects access to your Telegram authorizations and saved
material; it is separate from Telegram API credentials. Only an explicitly started,
directly accessed local demo gets automatic entry. A remote/proxied demo still uses
`data/demo/panel-token.txt`.

## Review and export

- **Journal:** search and filter observations by source and event type.
- Select an event to inspect its original record, attribution and saved versions.
- Edit details show the available before/after content. Deletion details show the
  last captured content, if any; an unknown actor remains unknown.
- **Exports:** signed ZIP, JSONL, CSV and offline HTML.
- **Full chat export** (Sources → Full chat export): download one chat's entire visible
  history as a signed bundle with `chat.json` (Telegram-export style) and a readable
  `chat.html`. Private chats work when the account is a member. It is a current
  snapshot, not a reconstruction of deleted or previously edited messages. Verify a
  copy with `python verify.py chat-export.zip --fingerprint TRUSTED_SHA256`.
- **Save checkpoint:** keep the signed journal boundary outside the collector.
- **Download signed run receipt:** preserve the collector's program/version record.
- **Prepare timestamp request:** prepare an offline request for a timestamp authority;
  follow [TIMESTAMP.md](TIMESTAMP.md) to obtain and verify a response.
- **Verify journal:** check event signatures and chain links. ZIP export also checks media.

Supported browsers save large exports directly to a chosen file. Other browsers
buffer at most 128 MiB. While the server is running, the streaming CLI supports
larger downloads without buffering the whole response:

```sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
```

For another workspace, add `--profile ID` using **Exports → Workspace ID**.
For a remote server, add `--url https://your-server`. The default transfer limit is
5 GiB; `--max-mib` changes it. Signed ZIP content has a separate 4 GiB uncompressed
verification limit by default (**Parameters** raises it; verify such archives with
`verify.py --max-gib N`). Verify the archive using a trusted copy of the verifier and
an independently retained key fingerprint/checkpoint.

## Check the installation

```sh
python start.py --setup-only
python start.py --check
python start.py --check --json
```

`--check` probes local dependencies, signing support, storage, key configuration and
the listening address. It does not install anything or connect to Telegram. A busy
port may mean another instance is running. Use a different `--port` or stop it first.

The launcher installs into `.venv`. Auxiliary `python -m tgwitness...` commands must
use `.venv\Scripts\python.exe` on Windows or `.venv/bin/python` on Linux/macOS,
unless that environment is already activated.

## Sessions, protection and operation

A closed, consistent Telethon SQLite `.session` can be converted locally with
`python -m tgwitness.sessions account.session --out account.tgwitness-session`, then
loaded in Account. Direct file import and QR login are also available. See
[CONNECTION-SECURITY.md](CONNECTION-SECURITY.md) for login formats, SOCKS5,
HTTP CONNECT, MTProxy and external master keys.

**Pause observation** stops collection. **Lock** only closes browser access.
Closing a tab leaves the collector process running. Stopping the process interrupts
collection; a history snapshot cannot reconstruct all missed edits or deletions.
See [how collection works](COLLECTION.md) for event policies, attachment queues,
account isolation, and restart behavior.

Sessions and secrets are encrypted. Message content, media and exports require an
encrypted disk or volume. Signatures establish integrity relative to a trusted key;
they do not establish Telegram origin or prevent fabrication by an operator who
controls the collector and its key.

Read [OPERATIONS.md](OPERATIONS.md) for backup/restore, [DEPLOYMENT.md](DEPLOYMENT.md)
for hosting, and [deploy/](../deploy/README.md) for service examples. The installed
panel also includes an offline setup guide at `/guide.html`.

Actual verification and remaining boundaries are
recorded in [VERIFICATION.md](VERIFICATION.md) and [READINESS.md](internal/READINESS.md).
