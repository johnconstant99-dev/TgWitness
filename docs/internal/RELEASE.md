# Version 0.7.0

TgWitness is a self-hosted Telegram observation journal under the
[MIT License](../../LICENSE). Version 0.7.0 is the first GitHub release; later changes are
listed under **Unreleased** in the [changelog](../CHANGELOG.md). The release carries the
Windows portable package, the wheel and the source archive, each with its SHA-256.

## Included in this source tree

- A bearer-protected panel with isolated account workspaces, light/dark themes, 25 interface
  languages and a searchable Ctrl/Cmd+K navigation menu. Newer untranslated strings have
  explicit English fallbacks; quick-navigation labels also have Russian translations.
- Phone/code/2FA, QR sign-in and bounded import of supported Telethon/Pyrogram sessions,
  Telegram Desktop TData ZIP, StringSession and Auth Key inputs.
- Selection of individual chats, a Telegram folder or account-wide scope; capture of visible
  messages, edits, deletion notices, reactions and membership events, plus recorded coverage
  gaps and configurable history/rechecks. Telegram visibility and collection policy limit coverage.
- A panel mini-client for messages, replies, supported bot buttons and invitation joins.
  Each action is attributed to the selected account and recorded in its journal.
- SHA-256 hash chains, Ed25519 signatures, checkpoints, run receipts and JSONL/CSV/HTML/ZIP
  exports. Optional AES-256 ZIP passwords, full-chat exports and coordinated multi-account
  chat exports are available. An independent verifier checks exported records.
- Opt-in people profiles, notification delivery, timestamp tooling, encrypted S3-compatible
  copies and an independently operated witness process.
- Per-account SOCKS5/HTTP CONNECT/experimental MTProxy, encrypted credential vaults and
  optional external vault keys. Journals and local attachments require disk/volume encryption.
- Windows source/portable launchers, Linux/macOS launch scripts, Docker Compose, HTTPS and
  service templates. Demo mode uses synthetic data and does not connect to Telegram.

See [collection](../COLLECTION.md), [accounts](../ACCOUNTS.md), [evidence](../EVIDENCE.md),
[witness](../WITNESS.md) and [security](../../.github/SECURITY.md) for behavior and limits. Parameter ranges
and effective defaults are shown in the panel; avoid relying on limits from older releases.

## Publication and validation

The release workflow checks the version tag, invokes the checks workflow and builds source,
wheel, Windows portable and GHCR packages. Public source and wheel assets use allowlists;
the public site includes only presentation assets. Publication checks and dependency auditing
run in CI. See [publishing](PUBLISHING.md) for commands and deployment steps.

Version 0.7.0 was published by hand while hosted Actions were unavailable: its source archive,
wheel and Windows portable package were built locally from the tagged commit with the same
tools the workflow runs. No GHCR image exists for 0.7.0 yet; Docker users build locally with
`scripts/Docker.cmd` or `scripts/docker-start.sh`.

The [pre-publication audit](PREPUBLICATION-2026-10-29.md) records the latest local results.
Earlier backend and recovery findings are in the [whole-tool review](FULL-REVIEW-2026-10-29.md).
Local checks do not establish that GitHub-hosted workflows have run successfully.

TgWitness has run on a real Telegram account: one supergroup from 27 to 29 October 2026,
1,291 messages, 472 deletions and 12 edits, with the signatures of all 2,385 records
verified. See the [live test](../VERIFICATION.md#live-telegram-test--27-to-29-october-2026).

## Remaining validation

- A complete live Telegram matrix covering QR confirmation, roles, update delivery, media,
  rate limits, reconnects and sustained operation.
- Actual Linux/macOS installation and Docker runtime checks on their target environments.
- Independent security review, operator-resistant capture, legal admissibility and guaranteed
  event completeness. Signatures verify the journal; they do not certify Telegram's content.

The main panel token controls all workspaces. Issue scoped tokens for reviewers and analysts; see [access and permissions](../ACCESS.md). Keep dedicated
account credentials and collected data out of the repository. See [readiness](READINESS.md)
and [live acceptance](LIVE_ACCEPTANCE.md) for the remaining qualification work.
