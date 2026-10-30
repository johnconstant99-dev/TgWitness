# Telegram and Telethon research

Reviewed 26 October 2026 against public official documentation and installed
Telethon 1.45.0 source. Local reference copies, retrieval times and response SHA-256
values are under `test-results/research/` and excluded from public packages.
Server behavior and platform rules can change.

## Updates, scale and recovery

Source: https://core.telegram.org/api/updates

- Ordering/recovery uses seq, pts, pts_count and qts. Channels/supergroups have
  separate sequences; ordinary groups and private dialogs share account scope.
- `getDifference` and `getChannelDifference` retrieve differences, potentially in
  slices whose boundaries need handling.
- Server difference retention is finite. Internal sizes are not a guaranteed
  retention duration.
- `updateChannelTooLong` and `channelDifferenceTooLong` mean different things;
  the first does not automatically establish irrecoverable loss.
- Passive updates for channels/supergroups can be limited; additional short polling
  is described for open sources.
- The recommendation of ten simultaneously short-polled sources is not a total
  selected-chat limit.
- Several connections sharing one authorization have delivery implications. Cloned
  sessions in several workers are not independent redundancy.

TgWitness preserves the original update envelope and distinguishes gaps from history
snapshots. The saved update position and periodic recheck are described in
[evidence format](../EVIDENCE.md#durable-collection-and-process-receipts-02).

## Telethon sessions and update handlers

Sources:

- https://docs.telethon.dev/en/stable/concepts/sessions.html
- https://docs.telethon.dev/en/stable/concepts/updates.html
- Telethon 1.45.0 StringSession, MemorySession, `TelegramBaseClient.connect`,
  `_save_states_and_entities`, `UpdateMethods._update_loop` and `_keepalive_loop`.

StringSession serializes authorization/connection data, not durable update states
or the entity cache. `catch_up=True` without retained state cannot guarantee replay
after a restart. Telethon sequence state advances separately from the application
journal callbacks; periodic state persistence alone is not atomic journal acceptance.

`NewMessage.build` excludes MessageService. TgWitness handles relevant service
messages through raw updates instead.

## Deletions

Sources:

- https://core.telegram.org/constructor/updateDeleteMessages
- https://core.telegram.org/constructor/updateDeleteChannelMessages
- https://docs.telethon.dev/en/stable/modules/events.html

`updateDeleteMessages` has no peer; the channel variant has `channel_id`. Notices
usually lack the actor and precise action time. Telethon warns that deletion events
are not guaranteed for every deletion.

Ordinary-group message IDs may be correlated against previously captured IDs in the
same account scope, but this needs a strict ID model. Current TgWitness preserves the
unscoped notice and does not guess a source.

## Reactions

Sources:

- https://core.telegram.org/api/reactions
- https://core.telegram.org/constructor/updateMessageReactions
- https://core.telegram.org/method/messages.getMessageReactionsList

A reaction snapshot and a reactor list are distinct. Groups have an API for the
available list. For broadcasts, `BROADCAST_FORBIDDEN` prevents listing identities
to avoid deanonymization. Availability/anonymity flags also matter. TgWitness cannot
promise the actor of every reaction or treat a recent list as complete. Extra
reactor-list queries are not implemented.

## Admin log

Sources:

- https://core.telegram.org/api/recent-actions
- https://core.telegram.org/method/channels.getAdminLog
- https://core.telegram.org/constructor/channelAdminLogEventActionDeleteMessage

Admin-log events can provide an event ID, time, actor and action content. Access
may fail with `CHAT_ADMIN_REQUIRED` or `CHANNEL_PRIVATE`. A deletion action may
contain the original message. These would be separately labeled admin-log
observations, rather than silently treated as live updates. Polling is not yet
implemented. No universal retention guarantee is inferred from these references.

## API terms

Source: https://core.telegram.org/api/terms

Application identity, transparency, privacy and interaction with platform functions
require review before public release. A working MTProto client does not by itself
establish compliance with every API condition.

## Applied decisions

The implementation includes durable version-bound media jobs, streaming exports,
separate workspaces, original update envelopes, signed run receipts, automatic
local checkpoints, explicit source states and a synthetic capacity harness. Complete
MTProto recovery, admin log, extra reactor lists, priority polling and automatic
external anchoring remain unimplemented rather than hidden behind configuration.

## External timestamps

RFC 3161 SHA-256 checkpoint requests and OpenSSL reply verification are implemented.
Local tests use a synthetic CA/TSA, not an independent timestamp provider. Verification
checks exact bytes, nonce when requested and an explicit trusted CA. It does not
perform OCSP/CRL retrieval or archival validation.

OpenSSL source reviewed:
https://github.com/openssl/openssl/blob/openssl-3.5.3/apps/ts.c

The `ts` command's `create_cert_store` loads the supplied CAfile/CApath/CAstore.
`-no-CApath` and `-no-CAstore` are unsupported by this command. TgWitness supplies
only CAfile; a test checks that environment variables cannot make a different CA
trusted. See [TIMESTAMP.md](../TIMESTAMP.md) for the procedure and limits.
