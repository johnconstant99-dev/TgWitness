[TgWitness](../../README.md) / [Documentation](../README.md) / [Folder](README.md) · [Development](../ARCHITECTURE.md)

![Development](../assets/presentation/chapter-develop.svg)

# Version 0.9.3 preview

TgWitness is a self-hosted Telegram observation journal under the
[MIT License](../../LICENSE). Version 0.9.3 is the 11 November 2026 preview candidate; its
contents are listed in the [changelog](../CHANGELOG.md). The release packages are the
Windows portable package, the wheel and the source archive, each with its SHA-256.

## Included in this source tree

- A panel with access tokens, separate account workspaces, light/dark themes and
  Ctrl/Cmd+K search. Choose from 25 languages for the panel and reports.
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

Version 0.9.3 remains a preview. The release workflow publishes the exact Windows
portable artifact tested by the checks workflow, alongside the source archive
and wheel. A final job downloads all three published packages, checks their
SHA-256 sidecars and publishes `SHA256SUMS.txt` and `RELEASE-MANIFEST.json` with
the version, source revision and asset sizes. Existing release assets are not
overwritten. Docker users can also build locally with `scripts/Docker.cmd` or
`scripts/docker-start.sh`.

GitHub-hosted workflow results are confirmed in Actions.

The [verification record](../VERIFICATION.md) describes prior tests and their
limits. Check the release commit's Actions results and published package manifest
for this build's acceptance. Live Telegram coverage and native-platform
qualification are recorded from live runs.

Live Telegram runs recorded in the [verification record](../VERIFICATION.md):

| Date | Run | Scale |
| --- | --- | --- |
| 27–29 October | [One supergroup](../VERIFICATION.md#live-telegram-test--27-to-29-october-2026), then [the whole account](../VERIFICATION.md#live-telegram-test-whole-account--29-october-2026): messages, edits, deletion notices, attachments, rechecks and rate limits | 9,968 records over about 44 hours, every signature verified |
| 6 November | [Release audit and fresh exports](../VERIFICATION.md#release-audit-and-fresh-exports--6-november-2026); [public-history qualification](../EXPORT-BENCHMARK-2026-11-06.md) | 27,030 and 29,299 records; 48 archives with 3,598,381 records from 40 workspaces |
| 9 November | [Phala Intel TDX with a live account](../VERIFICATION.md#phala-cloud-with-live-telegram-account--9-november-2026), [a session key created inside the VM](../VERIFICATION.md#session-key-created-inside-the-tdx-vm--9-november-2026), [drand anchoring](../VERIFICATION.md#drand-checkpoint-anchoring-and-verify--9-november-2026), [parallel sessions](../VERIFICATION.md#parallel-session-and-session-integrity-tests--9-november-2026) | Quote, collector key binding and exports verified |
| 10 November | [Account security and interrupted exports](../VERIFICATION.md#account-security-and-interrupted-exports--10-november-2026): new-session alerts, witness probe, `kill -9` and resume | 32 probes, 28 answered live; resumed exports verified |

The collection code (`collector.py`, `telegram_client.py`, `store.py`,
`distributed_export.py`, `history.py`, `anchoring.py`) is unchanged between 0.9.2 and
0.9.3; the last revision used on 10 November differs from 0.9.2 by 14 added lines in these files. The
0.9.3 verifier was run on three archives from the 9 November runs (387, 389 and 804
records); every signature checked, with the same result as the verifier shipped
inside those archives.

## Remaining validation

Publication requires the release revision to pass dependency audits, CodeQL and
the container HIGH/CRITICAL gate, including findings without an available fix.
The container audit builds the AMD64 and ARM64 runtime, sealed collector and media
worker from the public source archive. Source-built Tesseract also has a separate
upstream advisory check. Use the release's Actions results for the current findings.

CJK PDFs require a suitable installed font or `TGWITNESS_FONT_DIR`; when PDF rendering
is unavailable, the export keeps its HTML and JSON reports and records the limitation.

Not yet run against a live account:

- Steps 4–8 of the [live acceptance](LIVE_ACCEPTANCE.md) procedure: sending, editing,
  deleting, reactions and membership changes made by the test accounts themselves, and QR
  sign-in confirmed from a phone.
- GitHub Actions capture: no sealed run on the current revision is recorded.
- MTProto frame matching against a captured PCAP, the S3-compatible off-site copy,
  SOCKS5 and HTTP proxies, MTProxy as the chosen route, alert delivery, the automatic
  only-session action and restoring a backup with an external vault key.
- Export at the `sealed` tier, the witness tier with a separate witness process, a
  Bitcoin-confirmed OpenTimestamps seal and Takeout throughput.

Platforms:

- Successful checks for this candidate on Linux, Windows and macOS, including the portable
  package. Prior platform results do not qualify a newer revision; use its Actions run
  and manifest.

The main panel token controls all workspaces. Issue scoped tokens for reviewers and analysts; see [access and permissions](../ACCESS.md). Keep dedicated
account credentials and collected data out of the repository. See [readiness](READINESS.md)
and [live acceptance](LIVE_ACCEPTANCE.md) for the remaining qualification work.
