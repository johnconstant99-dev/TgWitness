[TgWitness](../README.md) / [Documentation](README.md)

# Secret Chats (Pseudo-secret)

Telegram keeps a secret chat on one device only and its servers hold no copy, so the
ordinary collector, Takeout and later export cannot reach it. The only way to preserve
one is to take part in it while it happens. Pseudo-secret lets TgWitness join a secret
chat with the account's own authorization — no second login and no extra device in the
account's session list — and write every message, timer, file and deletion notice into
the signed journal as it arrives.

The feature is **optional and off by default**. The end-to-end protocol library is GPL-3.0
and is not bundled with installers or Docker images; it is installed only on request, and
the module is then turned on per account.

## Status

The published installer package checked on 8 November 2026, source `b35f8e18f3d1`,
release `b35f8e18f3d1-1ff85ec98bb2`, includes the backend, panel, API routes and collector
integration. Package and dependency-lock hashes and RSA signatures were verified;
the protocol library remains a separately installed optional dependency. The website
demonstrates the interface with fictional records.

## Install and turn on

```bash
pip install "tgwitness[secret-chats]"
```

The extra pins [KiaroSama/Telethon-Secret-Chat](https://github.com/KiaroSama/Telethon-Secret-Chat)
to a reviewed commit. Like the Ukrainian dictionary extra, it stays out of the signed hash
locks and is installed separately; without it the panel shows how to add it and the feature
stays unavailable.

Then open **Sources → Pseudo-secret** for the account:

1. **Turn on pseudo-secret for this account.** While it is on, the account stays connected
   so incoming messages arrive; Telegram holds them while it is offline.
2. **Start a chat** with a `@username` or user ID. The other side sees an ordinary
   secret-chat request and must accept it on their device.
3. **Incoming requests wait for a decision.** *Accept here* moves the chat to TgWitness: the
   account's other devices, such as a phone, no longer receive it. *Accept incoming requests
   automatically* does the same for every request; leave it off while the owner still uses the
   phone for these chats.

The panel refreshes chat records automatically while preserving an unsent message,
keyboard focus and the position being read. Drafts are kept in memory for the
current account and cleared when switching accounts or locking the panel.
Confirmations for accepting or ending a chat, and for automatic acceptance,
apply only to the account where the confirmation was opened. Switching accounts
or leaving the view cancels the pending confirmation action.

The panel initially loads the latest 2,000 records across this account's secret chats.
Use **Load older records** to continue backwards; new records arrive without removing
pages already loaded. Protocol message identifiers retain their full precision in the panel.

## What it records

| Record | When |
| --- | --- |
| `secret_chat.settings` | the module is turned on or off, or auto-accept changes |
| `secret_chat.requested` | this account starts a chat, or the other side asks for one |
| `secret_chat.accepted` | a request is accepted here, by hand or automatically |
| `secret_chat.ready` | the chat is established; carries the key picture value |
| `secret_chat.message` | every message, sent or received, with its self-destruct timer |
| `secret_chat.file` | a received file, decrypted and stored by its SHA-256 |
| `secret_chat.file_deferred` | a file left queued because of the size limit or low disk space |
| `secret_chat.action` | notices from the other side: deleted messages, cleared history, timer change, screenshot, read |
| `secret_chat.closed` | the chat ended here or at the other side, including "deleted for both" |

A deletion notice or an expired timer removes nothing from the journal: it is append-only,
so a message the other side deleted stays in the record and is marked as kept by TgWitness.
Received files go into the signed journal export like other attachments and are checked by
the bundled verifier.

Attachments use a persistent queue with one transfer at a time. Temporary failures and
storage deferrals are retried automatically with a delay increasing from five seconds to
five minutes; restarting the collector preserves pending work. The panel shows the pending
attachment count. Existing files are hashed before reuse. A damaged cached file is retained
under a `.corrupt-` name and replaced with the validated download; the file receipt records
the repair. Non-regular destinations are refused and the attachment remains queued.

## Witness behaviour

TgWitness acts as a silent witness in these chats: it **does not send read receipts, typing
or screenshot notices**. The other side sees its messages as unread, and media timers that
start on reading do not start — so timed and view-once content is preserved rather than
consumed.

Current controls:

- enable / disable per account;
- accept incoming requests automatically on / off;
- the account's read-only protection blocks starting, accepting, sending and closing;
- received files are preserved subject to the media size limit and a free-disk threshold
  (`secret_chat.file_deferred` when either is hit).

If a journal write fails, the decrypted message is held in the vault and written once the
write succeeds, rather than being lost. Secret-chat key material and counters are stored in
the workspace vault, not in a plaintext file.

## Compare the key picture

`secret_chat.ready` and the chat header show the hex digits of the key picture. The same
digits appear under **Encryption key** in the chat on the other device. Matching digits mean
no one sits between the two ends.

## Limits

- Only chats in which this TgWitness session takes part can be recorded. Chats that already
  exist on a phone stay on that device; a session import does not supply their keys.
- A request accepted on another device first does not reach TgWitness.
- Use a dedicated account, not a personal one (see [dedicated account](ACCOUNTS.md)); a
  spam-limited account cannot start a chat with a non-contact until the limit clears.

## Verification

The following checks were run; they establish the listed behaviour and nothing beyond it.

**Automated (synthetic store, real library):** `tools/test_secret_chat_safety.py` and
`tools/test_secret_chat_custody.py` cover key-material persistence; message, action and
lifecycle records; incoming-acceptance policy; read-only refusal of start/accept/send/close;
durable duplicate detection across a restart; attachment retry after a transient failure and
a restart; recovery of a held message after a journal-write failure; size- and disk-based
deferral; the absence of read, typing and screenshot signals; and that the module opens no
client, proxy or network connection of its own but reuses the account's single authorization.
The API authorization matrix covers the six `/api/secret-chats*` routes. These passed against
the pinned library, including on Linux.

**Live (two dedicated accounts, real end-to-end protocol):** key agreement with matching key
pictures; two-way messages across several chats; all media kinds (photo, video, voice, audio,
animation, document, including a multi-megabyte file) received, decrypted and saved
byte-for-byte (SHA-256 verified); self-destruct timer and deletion notices recorded; receipt
of files **without reading** them, with no read, typing or screenshot signal sent and the
timer not started; and, in ordinary (non-secret) chats, view-once and timed photos and videos
captured and classified with the observer recorded as not having opened them.

These are functional checks of the listed behaviour. They do not certify every external
service, and passing them is not a release qualification on their own.

## Library and licence

The protocol work is done by [Telethon Secret Chat](https://github.com/KiaroSama/Telethon-Secret-Chat)
(distribution `kiaro-telethon-secret-chat`), licensed GPL-3.0-or-later, derived from
[telethon-secret-chat](https://github.com/painor/telethon-secret-chat) by painor (MIT).
TgWitness itself stays MIT: the library is not bundled and is installed only on request,
pinned to a reviewed commit.

| Package | Licence | Why |
| --- | --- | --- |
| kiaro-telethon-secret-chat (optional) | GPL-3.0-or-later | Key agreement, encryption and message order for end-to-end chats |
