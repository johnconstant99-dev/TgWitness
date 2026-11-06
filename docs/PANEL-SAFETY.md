[TgWitness](../README.md) / [Documentation](README.md) · [Getting started](QUICKSTART.md)

![Getting started](assets/presentation/chapter-start.svg)

# Panel safeguards

[Documentation](README.md) · [Accounts](ACCOUNTS.md) · [Storage](STORAGE.md)

The panel double-checks which account you're acting as, inspects imported files before
signing in and keeps chat actions off until you turn them on. It's about avoiding
mistakes; the server still checks permissions on its own.

<details>
<summary>On this page</summary>

- [File check](#file-check)
- [Account context](#account-context)
- [Read-only chat](#read-only-chat)
- [Downloads](#downloads)
- [Code map](#code-map)
- [Checks](#checks)

</details>

## File check

```text
!  No session found
   Only application settings. Add .session / TData,
   or sign in by phone or QR.

   [Choose files]  [Phone]  [QR]       [Connect — disabled]
```

```text
✓  Session found — Telegram will validate it on connect
   Device       Synthetic desktop
   Platform     Windows 11
   Version      5.13.1 x64
   Language     en

   [Connect]   or, when another account is connected:
   [Create workspace and connect]
```

Green means a usable session was decoded, not that Telegram accepted it. Broken ZIPs,
mixed app IDs and incomplete credentials each get their own error. A settings-only JSON
never shows success.

Extra workspaces can be deleted by typing their name, which also deletes their journal,
files and key. The main workspace can't be deleted here.

## Account context

```text
Workspace [Case A ▾]   / Exports       [avatar] @account_a

! You are viewing @account_a, but @account_b is selected.
  Actions are paused until the account is confirmed.
  Account in this link: @account_a.
  [Switch to the account in this link]
```

The URL decides the workspace. Late responses from a previous selection are ignored and
the mismatch notice blocks everything until you pick. Export confirmation names the
account and checks again after you confirm.

Direct links keep their page and workspace even if first setup isn't finished.
Reconnecting an account keeps its workspace and key, adding another one creates a new
workspace. Pending confirmations belong to the workspace they started in and get
cancelled when you switch. A temporary load failure offers **Retry** instead of logging
you out.

## Read-only chat

```text
[✓] Read only              [✓] Mask secrets
Sending and bot actions are hidden.

Password: B4X••••• [Show]
```

Turning on chat actions shows the composer and bot buttons. Sending or pressing a bot
button asks for confirmation naming the account; consent lasts ten minutes or until you
switch chat. Opening or joining a Telegram link has its own confirmation.

Secret masking is a heuristic (passwords, tokens, keys, OTPs, sessions, card numbers),
it won't catch everything. List previews always mask. Revealing a value writes a journal
note first, without the secret itself. Saved bytes and signed exports don't change; if
the recipient should get less, use a disclosure export.

## Downloads

If the file picker is denied or writing fails, the panel falls back to a normal browser
download through a short-lived one-time cookie. Tokens never go into URLs.

Prepared exports show size, SHA-256 and **Download again**. The cache keeps up to 20
files within 2 GiB plus the latest one. "Sent to the browser" doesn't mean received,
check your Downloads.

Big account archives stream straight from the job. A job can't be removed while its
archive is downloading.

## Code map

| Files (in `tgwitness/`) | What |
| --- | --- |
| `account_import.py`, `static/account-import.js`, `static/account-import.css` | Import preflight, account card, extra workspaces, deletion |
| `app.py`, `middleware.py`, `access.py` | Server checks, workspace identity, audited reveals, download auth |
| `static/core/workspace-safety.js`, `static/workspace-safety.css`, `static/router.js` | Account header, URL ownership, mismatch blocking |
| `static/app.js`, `static/chat-safety.js`, `static/views/chats.css` | Read-only chat, confirmations, history loading |
| `static/privacy.js`, `static/views/chat-list.js`, `static/analysis.js` | Masking and audited reveals |
| `export_history.py`, `downloads.py`, `static/views/exports.js` | Retained exports, download copies, cache limits |
| `static/components/journal.js`, `static/core/time.js` | Event numbering and missing-data labels |
| `locales/ru.json`, `english_fallbacks.json` | Russian copy and English fallbacks |

Analysis previews follow the same masking setting, but masking doesn't redact what gets
sent to a model after you approve it.

## Checks

```sh
python tools/check_import_preflight.py
python tools/check_chat_safety_browser.py
python tools/check_workspace_downloads_browser.py
python tools/check_prepared_export_access.py
python tools/check_services_browser.py
python tools/check_storage_services.py
python tools/test_settings_hub.py
node tools/check_privacy_js.cjs
```

Other engines:

```sh
python tools/check_workspace_downloads_browser.py --browser firefox
python tools/check_workspace_downloads_browser.py --browser webkit
```

WebKit via Playwright isn't the same as a real iPhone. Screenshots land in
`test-results/` and `build/ux-review/`. Telegram and storage are fake in these checks.
