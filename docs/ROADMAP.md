# TgWitness roadmap

Last looked at on 2 November 2026. What's shipped is in the [changelog](CHANGELOG.md),
this page is about what's next.

## Now: 0.8 preview

Account workspaces, observing what Telegram delivers, interaction records, media, signed
exports, scoped panel tokens, proxy policies and a separate witness that checks freshness
and continuity. It only covers what the account and collector actually receive.

Before each release we:

- run backend and browser checks on the release commit and write down what failed or wasn't tested;
- build source, wheel and Windows portable from that same commit, look inside and publish SHA-256 first;
- keep sessions, credentials, journals and test output out of the source archive;
- reject broken OpenTimestamps trees and report Bitcoin attestations as `bitcoin-unverified`
  (use `ots verify` for the real check); RFC 3161 still needs the recipient's `--tsa-ca`;
- mark English fallbacks where translations are still missing.

## Next: external witness controller

Other work runs alongside, each item judged on its own test:

| What | Done when | Status |
| --- | --- | --- |
| Long history loading | A crash mid-way loses nothing and repeats nothing | [Shipped](HISTORY.md) |
| Complete source list | Skipped and later-added chats are visible, only failed ones retry | Open |
| Everyday reading | Search, jumps by date and context, topics, gallery, forwards, reactions, versions | Open |
| Importing existing archives | Telegram Desktop JSON/HTML with attachments, resumable, marked as supplied | Open |
| Voice messages | Local transcription and search, original stays | [Shipped](MEDIA-ANALYSIS.md) |
| Accounts and access | Revoking access stops reading, nobody sees other people's chats | [Shipped](ACCESS.md) |
| Offline handover | Recipient reads and verifies without our server | [Shipped](CASE_REPORTS.md) |
| Operations and cost | Published CPU, memory, disk and recovery numbers | Open |
| Independent verification | Rewritten chain, cut tail, key change or missing witness gets caught | [Shipped](WITNESS.md) |

The controller with a real collector is the next milestone:

- every response bound to a fresh challenge, the registered collector key and a previously witnessed head;
- the observer set fixed when an investigation is registered, missing observers stay visible;
- outgoing receipts and jobs saved transactionally, survive restarts, retry with backoff;
- receipts exportable for offline checks, only metadata, commitments and signatures go to the witness;
- no free hosted pilot until resource use is measured.

Done when restarts, lost connectivity, repeated responses, a key change and an export
with an unwitnessed tail all stay checkable from the saved receipts.

## Next: independent observation and offline review

- Opt-in browser observer for authorized investigation accounts, with its own login, key and
  journal. Must tell a scrolled-away message from a deleted one.
- Offline replay of captured material in a browser, with clear marks for missing media.
- Look at a desktop/TDLib observer on a separate host (client, version, license).
- Match message IDs and versions across observers and keep disagreements. Reading the first
  collector's database is not a second observation.

Done when a test chat with sends, edits, deletes, changed buttons and observer restarts
looks right in the offline bundle.

## Later

- A small Go audit agent for collector lifecycle, file hashes, config changes and access
  metadata. Losing the agent must look different from "nothing happened".
- Hosted pilot only with isolated investigations, quotas, retention and admin audit.
- External anchoring of witness history, full OTS verification, maybe hardware keys and
  observers run by other people.
- Longer live runs, recovery tests, Linux/macOS installs and containers on real targets.

Signed receipts catch changes to history someone already witnessed. They can't prove a
compromised collector was honest before signing, and several containers on one host
are still one admin.

## Proposed: trust in the build

A recipient should be able to see which build collected the record, which journal it
showed, which witnesses kept it and where the gaps are. Today the run receipt measures
program files, the [code check](PANEL.md#code-check) compares them with a public commit
and the [witness](WITNESS.md) publishes checkpoints. Next, in order:

1. A full delivery manifest (files, deps, commit, workflow, artifact digest) tied to the run receipt.
2. A durable outgoing queue on the witness that survives restarts and shows retries.
   A late delivery never counts as on time.
3. Releases through a checked draft with attestations, then a guided fork setup.
4. GitHub as extra storage for hourly signed checkpoint blocks, no force-push.
5. Several witnesses run by different people, visible key rotation.
6. Live tests of restarts, lost connectivity, old backups and changed builds.

Not done yet either: threshold signing (FROST), a GitLab mirror, Nostr anchoring, co-signers.

## Release automation

Move to **draft → checked assets and attestations → publish**, pin build inputs, keep a
release manifest and check provenance on install. Queued jobs never count as passed checks.
