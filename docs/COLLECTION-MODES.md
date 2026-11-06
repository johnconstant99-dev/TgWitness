[TgWitness](../README.md) / [Documentation](README.md)

![Collection](assets/presentation/chapter-collect.svg)

# Choose a collection method

Start with the result you need. These workflows preserve different observations;
choosing one does not silently start another or change the account's connection.

| Goal | Where | Result | Account use |
| --- | --- | --- | --- |
| Share material already saved | Exports → Saved observations | Signed journal archive, readable report or minimized handover | No Telegram reads; observation can continue |
| Keep future changes | Sources → start observation | Delivered messages, versions and deletion notices in the workspace | Owns the account while running |
| Add past history to the workspace | Sources → Full history | Current visible messages, media outcomes and available Recent Actions in the signed journal | Pause observation first; choose Standard API or Takeout |
| Create a separate account snapshot | Exports → Telegram account | Selected chats, files and optional account data in a separate signed archive | Requires an idle account; observation sources do not define this selection |
| Export one chat | Chats → Export chat | Signed selected history and context, optionally split across eligible accounts | Every selected account must be idle and already have access |
| Preserve an official-client session | Extras → Independent capture → Trusted Live | Guarded video, preserved native JSON and continuity artifacts | Separate recorder and manual official-client login; preview |
| Capture with GitHub workflow provenance | Exports → GitHub capture | Encrypted handoff and workflow attestation | Separate runner and explicitly authorized session; preview |

## Existing observations and fresh reads

An evidence ZIP exports the saved journal through a fixed boundary. It does not
query Telegram again and can be prepared while collection continues. A readable
report or minimized handover can select a subset; the full evidence ZIP retains
its documented complete-journal scope.

History and account/chat exports read Telegram now. They see what the selected
account can access during that run, not an atomic reconstruction of the past.
Changes and deletions that were never observed may be unavailable.

## One acquisition per account

Live observation, full history and account/chat acquisition are mutually exclusive
on one account. Starting a new task does not automatically pause another task.
Separate account workspaces can operate concurrently, with separate identities
and access rights.

During full history loading, new live changes are not recorded by that account's
live handlers. A later catch-up or history read cannot guarantee recovery of every
intermediate edit or vanished message. Comparing saved versions compares existing
observations; it does not establish simultaneous live coverage.

Pause, resume and account identity rules are described in [History](HISTORY.md),
[Account export](ACCOUNT-EXPORT.md) and [Distributed export](DISTRIBUTED-EXPORT.md).

## Official-client capture

[Trusted Live](TRUSTED-LIVE.md) uses its recorder's explicitly selected connector.
The API acquisition settings do not turn an MTProto task into official-client
capture. Native export is manual; this preview preserves JSON without its linked
attachment tree. Video-only capture has no structured message IDs. Hybrid comparison
requires operator annotations linked to preserved frames.

Continuity annotations appear in a separate chat view. Missing IDs or replies are
observations to investigate, not proof that Telegram deleted a message. Neither
WARP nor pacing guarantees that Telegram will not restrict an account.

## Read the result before handing it over

Review source scope, text completion, unavailable messages, attachment outcomes,
pauses and any witness or timestamp limitations separately. A valid signature
checks integrity against trusted inputs; it does not prove complete Telegram
delivery or authenticate Telegram as the author of the archive.

See [Current capabilities and qualification](STATUS.md) for what has been tested.
