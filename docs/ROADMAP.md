# TgWitness roadmap

Status reviewed on 2 November 2026. This separates the current release from
prototypes and proposed work. The [changelog](CHANGELOG.md) records shipped changes;
[trust in the build](#proposed-trust-in-the-build-and-proof-delivery) summarizes the
proposed verification model.

## 0.8.0 preview: a verifiable local journal

The current source includes account workspaces, observation of available Telegram
events, interaction records, media capture, signed exports, scoped panel tokens,
proxy policies, and a separate witness with freshness and journal-continuity checks.
Coverage is limited to what the authorized account and collector actually receive.

Release acceptance:

- Run backend and browser checks against the release commit; record failures and
  untested platforms explicitly.
- Build source, wheel and Windows portable downloads from that same commit, inspect
  their contents and publish their SHA-256 hashes before making the release public.
- Include the public TSA test fixtures in the source archive; exclude local
  sessions, credentials, journals, audit scratch files and generated test output.
- Reject malformed OpenTimestamps trees. Report parsed Bitcoin attestations as
  `bitcoin-unverified`: the standalone verifier checks structure, while `ots verify`
  must authenticate the commitment against Bitcoin. RFC 3161 archive verification
  still requires the recipient's explicit `--tsa-ca` trust root.
- Keep English fallbacks explicit where translations of newer controls are pending.

## Next: connect the external witness controller

Archive usability and feature coverage have a parallel delivery track. Each direction
is accepted on its own test, and this roadmap does not claim overall superiority over
other archivers:

| Direction | Acceptance | Status |
| --- | --- | --- |
| Long history loading | A crash between a message and its position loses nothing and repeats nothing | [Shipped](HISTORY.md) |
| Complete source list | Listed, skipped-by-limit and later-added chats are visible; only failed sources retry | Open |
| Everyday reading | Search, date and context jumps, forum topics, gallery, forwards, reactions, versions | Open |
| Importing existing archives | Telegram Desktop JSON/HTML with attachments, resumable, marked as a supplied file | Open |
| Voice messages | Optional local transcription and search; recognized text never replaces the original | [Shipped](MEDIA-ANALYSIS.md) |
| Accounts and access | Revoking access stops reading; nobody sees another person's chats, sessions or jobs | [Shipped](ACCESS.md) |
| Offline handover | The recipient reads and verifies the package without the author's server | [Shipped](CASE_REPORTS.md) |
| Operations and cost | Published CPU, memory, disk and recovery measurements | Open |
| Independent verification | A rewritten chain, a cut tail, a key change or a missing witness is detected | [Shipped](WITNESS.md) |

A controller with a real collector integration is the next delivery milestone.

- Bind every response to a fresh challenge, the registered collector key and a
  previously witnessed journal head; verify continuation and the final export head.
- Fix the required observer set at investigation registration. Missing observers,
  timeouts and later recoveries remain visible in the exported history.
- Persist outgoing receipts and publication jobs transactionally; recover after a
  restart, retry with bounded backoff and expose delivery backlog and failures.
- Export receipts for offline checking without access to the service. Send only
  approved metadata, commitments and signatures to the witness.
- Measure resource use, batch commitments and limit concurrent investigations before
  offering a free hosted pilot. No unlimited-service claim until measured.

Acceptance: restart the controller and collector, lose connectivity, repeat a
response, change a key and submit an export with an unwitnessed tail. Each outcome
must remain independently checkable from the saved receipt bundle.

## Next: independent observation and offline review

- Add an opt-in browser observer for explicitly authorized investigation accounts:
  separate login, signing key and journal; preserve visible states, actions and
  downloaded media. Distinguish viewport changes from message deletion.
- Replay already captured material offline in a browser, with timestamps and clear
  indicators for missing media or incomplete observation.
- Evaluate a desktop/TDLib observer on a separate host. Record the actual client,
  version and license obligations; third-party client integration is not implemented.
- Match message IDs and versions across independent observations and preserve
  disagreements. A second process reading the first collector's database is not a
  second observation of Telegram.

Acceptance: in a controlled test conversation, send, edit and delete text and media,
change buttons, disconnect and restart each observer, then inspect the offline bundle.

## Later: host audit and hosted investigations

- A bounded Go audit agent may record collector lifecycle, approved file hashes,
  configuration changes and access metadata, with externally issued challenges.
  Loss of the audit source must be reported separately from absence of events.
- A hosted collection pilot needs isolated investigations, account lifecycle,
  quotas, retention, access separation and administrative audit before accepting users.
- Anchor witness history externally and qualify complete OTS verification; consider
  hardware-backed signing and independently operated observers where justified.
- Qualify longer live runs, recovery, Linux/macOS installation and container images
  on their actual target platforms.

Signed receipts can expose changes to previously witnessed history. They do not
prove that a compromised collector told the truth before signing. Multiple
containers under the same host administrator do not remove that shared control.

## Proposed: trust in the build and proof delivery

A recipient should be able to tell which build collected the record, which journal it
presented, which outside witnesses kept it and where the gaps are. A fork or a GitHub
token gives none of that on its own. Today the run receipt measures the program files,
the [code check](PANEL.md#code-check) compares them with a public commit, and the
[witness](WITNESS.md) publishes signed checkpoints. Proposed next, in this order:

1. A full delivery manifest with every executable file and resource, the dependency set,
   the commit, the workflow and the artifact digest, bound to the run receipt and to
   each proof.
2. A durable outgoing queue on the witness: a signed record and its delivery job are
   saved in one transaction, survive a restart and show attempts, the next retry and
   the oldest unsent record. Duplicates after a timeout are recognized by the record
   hash; a late delivery never counts as timely publication.
3. Releases through a checked draft with attestations, then a guided fork setup with a
   narrowly scoped token kept on the witness host.
4. GitHub as an extra store for hourly signed checkpoint blocks, each linking to the
   previous one, uploaded without force-push.
5. Several witnesses run by different operators, confirmation policies and visible key
   rotation: the old key announces the new one.
6. Live tests of restarts, lost connectivity, restoring an old backup and a changed build.

Also not yet implemented: threshold signing by several keys (FROST), a checkpoint
mirror on GitLab, anchoring on Nostr relays and co-signers who countersign checkpoints.

## Release automation

Move to **draft → checked assets and attestations → publication**, with a completeness
gate before enabling immutable releases. Pin build inputs, keep a release manifest,
and verify package provenance during installation. The current workflow starts
after publication; queued jobs must never be described as completed validation.
