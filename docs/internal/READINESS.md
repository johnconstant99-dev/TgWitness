# Release readiness

This is an internal engineering assessment updated 29 October 2026, not an independent
audit or certification. It records the tested scope and known limitations of
TgWitness 0.7.0. Platform support and event completeness are assessed from actual tests.

## Established scope

| Area | Evidence available | Not established |
| --- | --- | --- |
| Windows/Python 3.12 | Local source tests, installed-package checks and browser acceptance | Every Windows/Python configuration |
| Linux/macOS | Portable code, dependency matrix, CI and service examples | Executed installation/soak qualification on those systems |
| Docker | Dockerfile/Compose and a runtime smoke check in CI | Local container build/run; Docker is unavailable here |
| Telegram | Live test on a real account: one supergroup, 27 to 29 October, 1,291 messages, 472 deletions, 12 edits, 8 FloodWait pauses handled; automated tests use synthetic clients | Several accounts at once, administrator roles, long outages and sustained operation |
| Restart recovery | Encrypted account/channel update-state persistence, Telethon catch-up and periodic history rechecks are implemented | Atomic cursor/observation commits and lossless replay through every process/network failure |
| Proxies | Loopback SOCKS5/HTTP CONNECT fixtures; bundled public lists, real HTTPS downloads from two sources, retained caches, filtered/pinned public addresses, operator override, own links and bilingual UI | Live Telegram delivery through these listed proxies, deployed project proxies, Fake TLS ee and automatic server selection |
| Witness bot setup | Pinned config download, own channel/API/proxy settings, offline preflight, signed posts through a local HTTP Bot API fixture and recorded posting failures | Hosted project witness, independent operator custody and live bot publication from this setup |
| Signatures | Detection of changed records, media and checkpoint mismatch | Telegram authenticity or prevention of operator fabrication |
| Storage | Encrypted secrets, optional external master key and optional password-encrypted ZIP exports | Application encryption of the local journal and attachments |

Docker/Podman were unavailable on this host; the WSL executable did not provide a
working Linux environment. No OS/hypervisor installation was performed. A CI file
does not count as a successful remote CI run.

The live test on a real account is described in
[VERIFICATION.md](../VERIFICATION.md#live-telegram-test--27-to-29-october-2026).

## Improvements in 0.4

Account now centers account login, keeps the route available before login, and
collapses storage/account-management details. Mobile navigation uses four visible
buttons. Text colors and input labels were revised. The browser acceptance harness
checks desktop/narrow layouts and solid-background text contrast; this is not a
complete accessibility audit or screen-reader evaluation.

Exports use native browser file streaming where available, a bounded 128 MiB fallback
otherwise, and an authenticated streaming CLI. Server temporary files are kept on
the workspace's data volume and interrupted files are cleaned on startup. The previous
Compose `/tmp` capacity bottleneck no longer applies to export construction.
Production-scale multi-gigabyte transfers still need target-system qualification.

The launcher has a no-install `--check` mode for dependencies, signing, storage,
address/port and key configuration. Service templates and a local setup guide ship
with the source. These improve deployment without certifying untested environments.

## Improvements in 0.5

The local demo now opens directly without copying an access token, while real
workspaces retain authentication. Sources offers explicit event-category selection
and presets. Policies are isolated by account, persist across restarts, control
the live handlers and record signed before/after changes. Defaults preserve the
previous behavior. No completeness, replay or new full-storage encryption claim
is implied by these controls.

## Remaining validation and reliability work

The seven defects from the 27 October review are addressed
in 0.5.1 with regressions recorded in [verification](../VERIFICATION.md). Windowless Windows startup is now exercised, including
the panel response and diagnostic file; Task Scheduler lifecycle qualification
remains separate. This does not remove the live-service/platform blockers below.

- A controlled live matrix of private groups, several accounts, edits/deletions,
  reactions, roles, attachments, revoked access and real FloodWait.
- Qualification of the implemented saved-state/catch-up recovery, including the boundary
  between cursor advancement and committed observations. Persisted `pts/qts/seq` and
  channel state exist; an atomic durable replay protocol is not established. Media
  recovery is a separate feature.
- Sustained operation, network/process/host failure, full disk and verified restore,
  with explicit accounting for known loss.
- Clean installation and actual execution on the target OS/container matrix.
- Large-transfer qualification on target browsers, proxies and storage.
- Independent security, attribution and evidence-handoff review.

Admin-log polling, extra reactor lists, priority polling, isolated workers, whole-store
application encryption and user roles remain separate features. Supported TData
import and QR login are implemented in 0.6; see [account formats](../ACCOUNTS.md).
Their absence must not be inferred away from a successful panel launch.

Actual commands, results and environmental observations are recorded in
[VERIFICATION.md](../VERIFICATION.md). Use [LIVE_ACCEPTANCE.md](LIVE_ACCEPTANCE.md) for
real-account qualification.
