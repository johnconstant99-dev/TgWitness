[TgWitness](../README.md) / [Documentation](README.md)

# Secret Chats: implementation and availability

**Status checked on 6 November 2026:** a separate Secret Chat implementation exists
in development. It has not been merged into published `main` at `3d23e52b647b`.
The ordinary collector and Takeout export do not collect Secret Chats. The
interactive website scenario demonstrates the interface with fictional data;
it does not enable Telegram communication.

## Where the implementation lives

Commit `0e60f88e` added **Sources → Pseudo-secret** in the local development branch
`fix/panel-routes-sessions`. The checked snapshot is `bb8788fb685c`.
Its implementation includes `tgwitness/secret_chats.py`, application routes,
`tgwitness/static/views/secret-chats.js` and dedicated tests.

The optional `secret-chats` extra in that branch uses
[KiaroSama/Telethon-Secret-Chat](https://github.com/KiaroSama/Telethon-Secret-Chat),
pinned to `d87bf037b90060383c7b704d8a06ebb98c621c6f`. The library implements
Telegram's end-to-end chat protocol on the account's existing Telethon authorization.
Installing that library alone does not add the missing integration to `main`.

## What the development interface does

| Action | Recorded behavior |
| --- | --- |
| Start a chat by username or user ID | Send a request; the other participant must accept it. |
| Accept an incoming request | TgWitness becomes the receiving endpoint for that chat. Automatic acceptance is a separate setting, off by default. |
| Send or receive a message | Add an outgoing or incoming `secret_chat.message` record and show it in the thread. |
| Receive an attachment | Decrypt it, store its bytes by SHA-256 and record `secret_chat.file`. |
| Receive a timer or deletion notice | Record the notice and retain previously captured content. |
| Review the conversation | Show messages, files, notices and the key visualization. The open tab refreshes every four seconds. |

In a development build containing the integration, the operator enables the module
for the selected account and connects it. Starting, accepting and sending require
permission to interact and the account's read-only protection to be off. The other
participant must accept a new outgoing chat. These controls are not present in the
published application at the revision above.

Only chats created or accepted by this TgWitness session are covered. Existing
Secret Chats on a phone remain on that device. A session import does not supply
their separate encryption keys. Secret-chat key material and counters are stored
in the workspace vault; preserved messages and decrypted files follow the normal
workspace storage protections.

## Website demonstration

The website's **Try Secret Chat** scenario opens a fictional conversation. It lets
the reader start a request, simulate its acceptance, send a sample message, receive
a scripted reply and file, and inspect a timer and deletion notice. An incoming
request can also be accepted. The controls label simulated peer actions explicitly.

This scenario runs in browser memory. Reset or reload clears it. It does not log in,
contact Telegram, create real encryption keys or alter the signed sample downloads.
Its displayed messages are not signed evidence. The scenario demonstrates intended
interaction; it does not certify that the development implementation is ready.

## Checks and outstanding defects

The five existing tests cover encrypted key persistence, lifecycle and message
records, incoming acceptance policy, read-only sending and attachment export.
They passed against the pinned library during the 6 November review. Three
additional synthetic checks reproduced defects in the same snapshot:

| Finding | Consequence |
| --- | --- |
| Closing bypasses `read_only` | The close path can perform a remote action when interactions should be blocked. |
| Duplicate detection searches only 500 recent records | An older replay can create a duplicate after restart. |
| A failed attachment download removes its pending entry | A transient failure loses the retry job. |

These are open defects, also recorded in the
[published audit](../website/validation/audit/REPORT.md). Five passing tests do not
cover these failures. The review used synthetic workspaces and mocked Telegram
operations; it did not repeat a live handshake or qualify production deployment.
