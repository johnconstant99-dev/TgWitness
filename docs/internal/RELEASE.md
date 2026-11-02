# Version 0.8.0 preview

TgWitness is a self-hosted Telegram observation journal under the
[MIT License](../../LICENSE). Version 0.8.0 is the 2 November 2026 preview candidate; its
contents are listed in the [changelog](../CHANGELOG.md). The release packages are the
Windows portable package, the wheel and the source archive, each with its SHA-256.

## Included in this source tree

- A bearer-protected panel with isolated account workspaces, light/dark themes, 25 interface
  languages and a searchable Ctrl/Cmd+K navigation menu. English is canonical;
  export and recipient-report labels use DeepL translations in all other languages.
- Separate personal account exports and investigation workflows, with readable
  offline reports, privacy previews, minimized sharing copies and recipient notes.
- Resumable history loading, archive search and analysis, read-only MCP, optional
  local OCR/transcription and HMAC-signed webhooks.
- Phone/code/2FA, QR sign-in and bounded import of supported Telethon/Pyrogram sessions,
  Telegram Desktop TData ZIP, StringSession and Auth Key inputs.
- Selection of individual chats, a Telegram folder or account-wide scope; capture of visible
  messages, edits, deletion notices, reactions and membership events, plus recorded coverage
  gaps and configurable history/rechecks. Telegram visibility and collection policy limit coverage.
- A panel mini-client for messages, replies, supported bot buttons and invitation joins.
  Each action is attributed to the selected account and recorded in its journal.
- SHA-256 hash chains, Ed25519 signatures, checkpoints, run receipts and JSONL/CSV/HTML/ZIP
  exports, signed PDF reports and an offline report viewer with verified selections. Optional AES-256 ZIP passwords, full-chat exports and coordinated multi-account
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

Version 0.8.0 remains a preview. The release workflow publishes the exact Windows
portable artifact tested by the checks workflow, alongside the source archive
and wheel. A final job downloads all three published packages, checks their
SHA-256 sidecars and publishes `SHA256SUMS.txt` and `RELEASE-MANIFEST.json` with
the version, source revision and asset sizes. Existing release assets are not
overwritten. Docker users can also build locally with `scripts/Docker.cmd` or
`scripts/docker-start.sh`.

Local checks do not establish that GitHub-hosted workflows have run successfully.

The [verification record](../VERIFICATION.md) describes prior tests and their
limits. Check the release commit's Actions results and published package manifest
for this build's acceptance. Packaging and synthetic checks do not establish new
live Telegram coverage or native-platform qualification.

TgWitness has run on a real Telegram account: one supergroup from 27 to 29 October 2026,
1,291 messages, 472 deletions and 12 edits, with the signatures of all 2,385 records
verified. See the [live test](../VERIFICATION.md#live-telegram-test--27-to-29-october-2026).

## Remaining validation

The candidate is held from public release while the container HIGH/CRITICAL gate fails.
The [2 November audit](https://github.com/phishdestroy/TgWitness/actions/runs/41396355070)
passed Python dependency checks and CodeQL, but found 45 records (9 distinct CVEs)
in each runtime/sealed image and 72 records (29 distinct CVEs) in the media worker.
See the [container findings](CODE-SCANNING-2026-11-01.md#remaining-container-findings).
Do not disable the gate or describe this candidate as security-cleared.

CJK PDFs require a suitable installed font or `TGWITNESS_FONT_DIR`; when PDF rendering
is unavailable, the export keeps its HTML and JSON reports and records the limitation.

- A complete live Telegram matrix covering QR confirmation, roles, update delivery, media,
  rate limits, reconnects and sustained operation.
- Successful checks for this candidate on Linux, Windows and macOS, including the portable package.
  Prior platform results do not qualify a newer revision; use its Actions run and manifest.
- Independent security review, operator-resistant capture, legal admissibility and guaranteed
  event completeness. Signatures verify the journal; they do not certify Telegram's content.

The main panel token controls all workspaces. Issue scoped tokens for reviewers and analysts; see [access and permissions](../ACCESS.md). Keep dedicated
account credentials and collected data out of the repository. See [readiness](READINESS.md)
and [live acceptance](LIVE_ACCEPTANCE.md) for the remaining qualification work.
