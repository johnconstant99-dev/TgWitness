# Release readiness

Engineering assessment for the 0.8.0 preview candidate, updated 2 November 2026.
Public release is held while the container HIGH/CRITICAL vulnerability gate fails.
This assessment is not an independent audit or certification.

## Evidence and limits

| Area | Evidence available | Still required or limited |
| --- | --- | --- |
| Current application | [Checks on main at a6eb9b5a](https://github.com/phishdestroy/TgWitness/actions/runs/41392237410) passed Linux installation, browser suites and Docker/Compose integration; the phone fixes in #59 passed their PR checks and local browser checks | The release candidate must pass its own full platform run; prior results do not qualify a new revision |
| Platforms | The release workflow exercises Python 3.11–3.13 on Linux, Windows and macOS, and builds/tests Windows portable | Check the actual candidate run, including all nine matrix jobs and the portable artifact; synthetic installation is not sustained-operation qualification |
| Dependencies and containers | [2 November audit](https://github.com/phishdestroy/TgWitness/actions/runs/41396355070): all Python advisory checks and CodeQL passed | Runtime/sealed each have 45 HIGH/CRITICAL findings across 9 CVEs; media worker has 72 across 29 CVEs. The container gate failed |
| Reports | Signed HTML/JSON/PDF, offline viewer, archive verification, configurable contents and 25 report languages | CJK PDFs need an installed font or `TGWITNESS_FONT_DIR`. PDF availability is reported; HTML and JSON remain available |
| Telegram | A real-account test observed one supergroup on 27–29 October: 1,291 messages, 472 deletions and 12 edits; all 2,385 record signatures verified | A complete live matrix of roles, several accounts, attachment types, revocation, FloodWait, reconnects and sustained operation |
| Recovery | Saved update state, catch-up, periodic history rechecks, absent-ID rechecks and recorded coverage gaps | Atomic cursor/observation commits and lossless replay through every process/network failure are not established |
| Integrity | Hash chains, Ed25519 signatures, checkpoints and independent archive verification | Signatures do not authenticate Telegram content, prevent operator fabrication or establish legal admissibility |
| Storage | Encrypted credentials, optional external master key and password-protected ZIP exports | Local journals and attachments need disk/volume encryption |

The fresh scan improves on the previous container counts, but does not clear the
release gate. Keep the findings visible; see the
[container analysis](CODE-SCANNING-2026-11-01.md#remaining-container-findings).
Passing functional tests does not override a failed security check.

## Release acceptance

- Build source, wheel and Windows portable from one recorded revision. Verify every
  package checksum and bind the exact file list to that revision in the release manifest.
- Run the full platform checks and source/publication checks for that revision.
  Preserve failed or skipped results in the acceptance record.
- Keep the existing 0.7.1 tag, assets and container image unchanged. Do not publish
  this candidate as security-cleared or replace an existing release download.
- Keep the draft public showcase (#57) outside this candidate. Guided connection
  setup and portable WARP (#58) are included from main; their helper lifecycle passed
  the [full platform run](https://github.com/phishdestroy/TgWitness/actions/runs/41397629374).

Admin-log context, scoped panel permissions, supported TData import, QR sign-in
and isolated media processing are implemented. Their presence does not establish
complete Telegram coverage or independent operator custody.

See [verification](../VERIFICATION.md), [release contents](RELEASE.md) and
[live acceptance](LIVE_ACCEPTANCE.md) for test scope and remaining qualification.
