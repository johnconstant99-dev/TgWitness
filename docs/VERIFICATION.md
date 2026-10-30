# TgWitness verification · updated 2026-10-29

## Live Telegram test, whole account · 29 October 2026

The same account kept running after the test below. On 29 October at 12:10 UTC its scope
was switched to the whole account (channels, groups, private chats and bots); the panel asked
for confirmation and the signed journal recorded it. By 17:59 UTC the journal held:

| Recorded, 27 October 21:36 to 29 October 17:59 UTC | Count |
| --- | ---: |
| Journal records | 9,968 |
| New messages | 5,308 |
| of them after the switch to the whole account | 3,878 |
| Deletions | 784 |
| of them deleted after TgWitness had saved the message | 596 |
| Edits | 41 |
| Messages added by rechecks | 2,273 |
| Messages a recheck could no longer find | 18 |
| Messages saved by history snapshots | 242 |
| Saved attachments | 247 |
| Collector starts | 19 |
| Telegram FloodWait pauses | 26 |

- The panel's **Verify** check confirmed the signatures and hash chain of all 9,968 records.
- Messages came from 2 groups or channels and 3 private chats and bots. One message button was
  pressed from **Chats**; the request and Telegram's answer are in the journal.
- New chats were added when the collector rescanned the account at a restart. Saving the
  earlier messages of new chats was off (`history = 0`), so it is not covered here.

Not covered: reactions, membership changes, people profiles, sending messages, joining by
invitation, proxies, notifications, the witness bot and several accounts at once. Public files
contain only counts.

## Password-protected export opened with libarchive · 29 October 2026

An archive written by the export encryption code (WinZip AES-256, the format 7-Zip and WinRAR
read) was opened with Windows `tar` (bsdtar 3.6.2, libarchive). With the right password the
extracted file matched the original SHA-256; a wrong password was refused with "Incorrect
passphrase". 7-Zip and WinRAR themselves were not run.

## Live Telegram test · 27 to 29 October 2026

One real Telegram account, signed in through the built-in API pair pool, recorded one
supergroup from **27 October 21:36 UTC to 29 October 05:15 UTC**. The collector was
started 12 times in that period.

| Recorded | Count |
| --- | ---: |
| Journal records, including heartbeats and service records | 2,385 |
| New messages | 1,291 |
| Deletions | 472 |
| of them deleted after TgWitness had saved the text | 347 |
| Edits | 12 |
| Messages missed while stopped, added by the recheck | 12 |
| Saved attachments | 17 |
| Attachments not downloaded (downloads off, or no file to download) | 14 |
| Telegram FloodWait pauses, 3 seconds each, during rechecks | 8 |

- The signatures and the hash chain of all 2,385 records verify against the journal's
  public key.
- After a restart the collector resumes from the saved update state (`pts`) and Telethon
  catches up; the recheck then adds messages that are still missing.
- On every FloodWait the collector waited the requested time and continued.
- The account stayed signed in, and the same session reconnected on 29 October.

Not covered by this test: several accounts at once, administrator roles, proxies, outages
longer than a few hours and the full [live acceptance procedure](internal/LIVE_ACCEPTANCE.md).
Public files contain only these counts: no account or chat identifiers, messages or
credentials.

Older entries below describe their own runs; most of them used synthetic test clients.
The latest automated results are below; [the pre-publication audit](internal/PREPUBLICATION-2026-10-29.md)
records the earlier baseline.

## Built-in public MTProxy lists · 29 October 2026

Added a bundled public snapshot and explicit HTTPS refresh from SoliSpirit/mtproto and
zakky8/mtproto-proxy-pro. On this host, the application downloader fetched both feeds
successfully on 29 October 2026 at 12:58 UTC: **118 unique compatible endpoints** after
filtering, deduplication and the 64-entry limit per source. This verifies list retrieval,
not connectivity or message delivery through those endpoints. No real account was
connected to a listed proxy during this work. [Operator and user guide](ru/PROXIES.md).

Failed/empty/incompatible source responses retain previous entries and dates. Updates
do not alter the selected route. Public addresses are validated and resolved IPs pinned
on selection; operator/manual routes remain separate. The connection probe is now
available in the panel before account login. Fake TLS ee and automatic proxy selection
remain unsupported. The operator's catalog overrides subscriptions completely.

- Full suite: **366 passed, 3 skipped**, 287.94 seconds. Existing dependency warnings
  and platform skips remain. Final public-list/localization regression: **36 passed**,
  including rejection of invalid download-proxy ports; this overlaps the full suite.
- Browser acceptance passed in English/Russian, light/dark at 390/1440 pixels: bundled
  choices, no external fetch on opening settings, explicit refresh, retained routes and
  cache during failures, pre-login probe, late-response workspace isolation, source
  details and layout/contrast. No JavaScript errors or external browser requests.
- Final static translation coverage passed for all 13 locales; new copy is translated
  into Russian with explicit English fallbacks elsewhere. The updated built-in guide
  passed layout/contrast checks in both themes.
- Ruff and publication checks passed (259 public files, 1,354 local links); updated
  Compose and CI YAML parsed. Docker and remote CI were not executed here.
- The rebuilt wheel passed isolated installation, bundled-list loading and signed-export
  verification. All 69 package resources matched the workspace; source hashes were checked.

Receipts: `test-results/public-proxy-research/download-receipt.json`,
`test-results/public-proxy-research/copy-receipt.json`,
`test-results/public-proxies-full-suite.log`, `test-results/public-proxies-final-focused.log`,
`test-results/public-proxies-browser/receipt.json` and `test-results/public-proxies-package.log`.
Browser/account/transport fixtures are synthetic; the two feed downloads above are real HTTPS requests.

## Optional extras presentation · 29 October 2026

The former Proof bot destination is now **Extras**: a short overview followed by a
separate setup page for the selected option. The witness form has three steps, with
connection management, network options and deployment details folded away. GitHub is
explicitly planned and has no credential form. [Russian overview](ru/EXTRAS.md).

- 30 focused tests passed for localization, witness setup and publication checks.
- Chromium setup acceptance passed in English/Russian, light/dark, at 390/1440 pixels:
  keyboard focus and return, no implicit connections when selecting extras, draft
  retention, pinned configuration/token downloads, token clearing on lock, and working
  local guide anchors. Layout and solid-background text contrast checks passed.
- Workspace-switch acceptance passed, including a delayed token response arriving
  after a switch. Quick navigation finds the extras through bot, proof and GitHub terms;
  its existing 320/390/1440-pixel and Russian/RTL checks also passed.
- No JavaScript errors or external browser requests were observed in the setup run.
  These are synthetic UI checks, not new live Telegram or bot publication evidence.
- Final language loading and dictionary coverage passed for all 13 locales, preserving
  explicit English fallbacks outside Russian. The expanded Proof guide also passed
  layout/contrast checks at 320/768/1440 pixels in both themes.
- The rebuilt wheel passed isolated installation and signed-export verification. All
  67 packaged resources matched the workspace; the source archive contains 253 public
  files. Source/link checking passed for 1,346 local documentation links.

Receipts: `test-results/setup-browser/receipt.json`,
`test-results/quick-navigation/receipt.json`, `test-results/extras-final.json`,
`test-results/extras-package.log` and `test-results/extras-artifacts.json`.
Screenshot assets use synthetic workspaces.

## Witness bot and proxy setup audit · 29 October 2026

The witness setup (now **Extras → A bot in your channel**) prepares an independently deployed witness: pinned collector
key, scoped token download, own channel, publication policy, HTTP/SOCKS5 route and custom
Bot API. The bot token remains on the witness host. Its new `--check-config` validates
configuration and files without opening a network connection or creating a key. JSON
file paths resolve beside the configuration. All Compose witness variants now forward
the HTTP proxy and Bot API settings.

Account settings support an operator-managed public MTProxy catalog, custom Telegram
proxy-link preview and the existing manual fields. Catalog responses omit secrets;
selection stores the route in the workspace vault. Missing/malformed catalogs leave
manual routes available. No project proxy addresses or hosted witness service are
invented or enabled by default. A Caddy example exposes only the scoped head endpoint
when an external witness must reach a collector whose panel stays private.

Validation:

- Full suite: **348 passed, 3 skipped**, 195.81 seconds. Windows limitations account
  for the skips; the two existing dependency deprecation warnings remain.
- Final witness/configuration/release regression run: **11 passed, 1 skipped**.
  This overlaps the full suite. Tests include path resolution, offline preflight,
  signing/publishing through an actual loopback HTTP Bot API fixture, recorded delivery
  failure, channel-token verification and proxy-secret exclusion.
- Chromium setup acceptance passed in English/Russian at 390/1440 pixels: pinned config
  and token downloads, token clearing on lock, catalog selection, custom-link preview
  followed by explicit save, layout/contrast and no JavaScript errors or external
  browser requests. Corrected narrow Russian account-heading and login-tab overflow.
- Ruff, source/link checks and Compose/workflow YAML parsing passed.
- The rebuilt wheel passed isolated installation, panel/static resource and API-auth
  checks, plus independent verification of direct and streamed 32-event synthetic exports.

Receipts: `test-results/setup-full-suite.log`, `setup-final-focused.log`,
`setup-browser/receipt.json`, `setup-browser-final.log` and `setup-package.log`.
These checks use synthetic accounts/proxies and a local Bot API fixture. They do not
claim a real bot publication, working public MTProxy server, remote CI run or Docker
deployment. The retained real Telegram observation history above remains a separate
piece of evidence. [Setup instructions](ru/WITNESS.md).

## Presentation and documentation review · 29 October 2026

The product page, access screen, English/Russian READMEs and presentation images now share
one visual style. Public screenshots use fictional demo data. The review also corrected
the outdated live-validation and recovery descriptions above.

- Focused localization, site and publication tests: **33 passed, 1 skipped**. The skipped
  test requires symlink creation unavailable on this host.
- General Chromium panel acceptance passed, including all language catalogs, RTL layout,
  light/dark themes, solid text contrast and workspace switching. The profile-creation
  check now waits for its actual HTTP response before checking the selected workspace.
- English/Russian access screens passed layout and contrast checks in both themes at
  320, 390, 768, 850 and 1440 pixels; the submit button stays in the initial viewport.
- Public-site acceptance passed at 320, 390, 768, 1024 and 1440 pixels, including message
  history controls, screenshot enlargement/Escape/focus return, keyboard tabs, clipboard
  refusal, project subpaths, reduced motion and the no-JavaScript fallback. No failed
  asset requests, external requests or JavaScript errors were observed.
- The rebuilt wheel passed an isolated installation check: panel resources and locales
  load, API access requires authentication, and direct/streamed exports independently
  verify all 32 synthetic events. Ruff and public-source/link checks passed.

Local receipts: `test-results/design-tests.log`, `design-panel-final.log`,
`design-review-final.log`, `design-site.log`, and `design-package/install-receipt.json`.
The full backend suite was not rerun for this presentation/documentation change;
its preceding result remains in the pre-publication audit.

## Version 0.6.1

0.6.1 changes the panel presentation, launchers, packaging and documentation;
collection, storage, signing and export code is unchanged. On Windows 11 / Python 3.12.10
with the pinned runtime:

- The full suite passed **137 tests** with **2 skips** and the existing Starlette warning.
  New tests cover the launcher's Ctrl+C handling (the server gets 30 seconds for an
  orderly stop) and actionable setup-step failures.
- Chromium (headless shell 156) passed all **45 general scenarios** and **35
  account-import/QR/Auth Key scenarios**, including the solid-text contrast check, no
  horizontal overflow at 320–1440 px and visible first login fields at 320/390 px.
  No page JavaScript errors or external requests were observed.
- `python start.py --setup-only` reinstalled the package as 0.6.1 and
  `python start.py --check` reported ready. A real `python -m tgwitness --demo` server
  returned the panel, stylesheet, script, logo, guide and `/api/status` version 0.6.1;
  the removed `workspace.css` returned 404.
- `Start.cmd` found a Python installation outside PATH. With no Python available it
  showed the installation offer; declining printed manual instructions and exited 1.
  The python.org download step fetched the 3.12.10 installer and passed the Python
  Software Foundation Authenticode check; the installer itself was not run on this host.
- `start.sh` without any Python printed the install hint and exited 1. `scripts\Docker.cmd` and
  `scripts/docker-start.sh` were exercised against fake `docker` executables: correct call
  sequence, panel address and token output, and no success message after a failure.
- `python tools/build_portable.py` built an 18.8 MiB Windows package after verifying the
  pinned embeddable-runtime checksum. Extracted to a path with spaces and started with only
  `C:\Windows` directories on PATH, its embedded Python passed `TgWitness-Check.cmd`, served
  the demo (32 events) and a live workspace, and Chromium rendered the journal and detail
  drawer without JavaScript errors. Data was written to the package's `data` folder.
- `python tools/build_preview.py` produced a 110-file source archive. A dry-run of
  `git add` listed the same 110 files with no session, key, database, token, log or export
  files, no local absolute paths and no secret-shaped strings.

Not executed in this particular 27 October packaging run: the automatic Python
installation itself, Docker build/Compose checks, Linux/macOS runs or a new live-account
exercise. Real Telegram evidence is recorded above and in the earlier account checks
below. CI definitions alone do not qualify platform execution.

## Version 0.6.0

The latest full pinned-runtime suite on Windows 11 / Python 3.12.10 passed **135 tests**,
with **1 skip**, in 26.53 seconds and the existing Starlette warning. The skip
requires POSIX permissions. After adding the QR
renderer to readiness checks and process measurements, 8 affected readiness/workspace
checks also passed.

New coverage includes Telethon schemas 7/8, Pyrogram schemas 2/3, complete JSON
keys and metadata-only JSON, matching/conflicting account files, TData passcodes,
checksum tampering and unsafe paths, offline/authenticated in-memory conversion,
online account-ID checks, QR success/2FA/expiry, stale cancellation, and account
isolation. TData fixtures use a separate AES-IGE implementation for encryption.

Chromium passed **45 general scenarios** and **35 account-import/QR/Auth Key scenarios**,
with no page JavaScript errors or external requests observed. New browser checks
cover all four input formats together, protected TData, API metadata, QR rendering,
expiry/retry, 2FA, wrong-account rejection, lock/workspace cancellation, responsive
layout, and late conversion responses after a newer file selection.

Both browser suites passed again after the account-entry changes. Live setup opens
the account form; demo mode opens its sample journal. The demo Account page shows
live startup instructions and hides credential inputs.
Focused checks at 320, 390, and 1440 pixels confirmed the number field and primary
button fit without scrolling and API fields are initially collapsed,
and text contrast remains readable. Capture and verification controls remain
covered after opening their new expandable sections.

The direct Auth Key flow was exercised with synthetic credentials through the real
import and authorization endpoints. Checks cover incomplete keys, missing DC,
imprecise User IDs, mismatched account identity, saved API credentials, visible
request progress, secret clearing, and late responses after edits or method changes.
All four sign-in methods were checked at 320, 390, and 1440 pixels. The file picker
precedes format guidance, and the Connect button fits the initial 844-pixel viewport
with API settings collapsed. No real Auth Key authorization was attempted in this
UI acceptance run.

The panel refresh was checked again with both browser suites: no page JavaScript
errors or external requests were observed. The account suite now covers pasting
one API ID/hash pair, rejecting malformed or multiple pairs without replacing
fields, metadata-only guidance, and ignoring stale import responses after a
sign-in method change or manual credential edit. Six additional focused checks
passed for the setup guide, explicit start/pause, empty-search recovery, and final
connection/local-guide layout and solid text contrast at 320, 390, and 1440 pixels.
The direct-login update adds a single phone/code-request operation and reuses the
current workspace's saved API pair for phone, QR, and session login. The full Python
suite above includes new persistence, partial-credential rejection, and workspace
isolation tests. Browser checks cover direct phone entry, saved-credential reuse,
metadata-only routing, one-button file authorization, and duplicate-account rejection.
The simplified panel-token and phone forms were also checked without initial scrolling
at 320, 390, and 1440 pixels. A compatibility check confirmed the direct phone form
can use the earlier configure/code endpoints while an older process is still running.

One user-supplied account was checked separately, outside public test fixtures.
Its Telethon, Pyrogram, and TData inputs resolved to the same authorization; the
companion JSON supplied API credentials. All four files were loaded through the
0.6.0 panel and Telegram confirmed the expected numeric account ID. Source files
remained unchanged. No sources were selected and observation remained off. This
qualifies one import/login example, not live collection, recovery, or capacity.

Telegram also issued a real QR token, which was cancelled without scanning. The
full QR confirmation and 2FA flows were exercised with synthetic clients; mobile
confirmation against a real Telegram app remains a separate acceptance step.
No real account identifiers, secrets, or screenshots are included in public files.

The launcher upgrade completed; source, installed metadata, and readiness marker
report 0.6.0, with qrcode 8.2 and a passing `pip check`. The installed wheel served
the panel and guide, rejected unauthenticated API requests, and independently
verified direct and streamed 32-event synthetic exports. The updated offline guide
was checked at 320, 390, and 1440 pixels. Public screenshots remain synthetic.

The source release contains 107 allowlisted files. Local documentation links resolve.
Docker/Caddy execution, remote CI/package publication, ARM64 runtime, sustained
collection, and the full live Telegram acceptance matrix remain unqualified here.

## Version 0.5.1

On Windows 11 / Python 3.12.10, the full project-environment suite passed:
**94 passed, 2 skipped**, in 31.21 seconds, with the existing Starlette warning.
The skips require POSIX permissions and symlink creation unavailable on this host.
The download HTTP fixture printed a request-thread diagnostic; all assertions
passed. This run does not establish absence of host transport issues.

New regression coverage exercises rejected StringSession, code and 2FA account
changes, cancelled identity lookup, pending login cancellation, and updates through
registered handlers on active, rejected, superseded and probe clients. Only the
active collector contributes events; saved credentials and signed history remain
intact. Other new checks cover Unicode search after reopening a database, inclusion
of monitoring-policy boundaries in Coverage, and public-source packaging exclusions.

The actual project `pythonw.exe` launched an isolated synthetic panel, returned
HTTP 200 and retained startup diagnostics in `logs/server.log`. The log did not
contain the generated panel token or HTTP access records. The test terminated only
its own synthetic process. No Task Scheduler task was registered; logon/sign-out,
sleep and service recovery remain separate qualifications.

Chromium acceptance passed **45 scenarios**, with no page JavaScript errors and
no external requests observed. New checks cover 601/768/850-pixel timeline dates
and times, attachment drafts across status refresh, newer edits made while saving,
cleared verification results on account switch, late verification responses after
switching away and back, and explicit verification boundaries when new events arrive.
The search icon/text spacing was also corrected and the browser suite rerun.

The browser run used the pinned runtime in `.venv` and the existing system-provided
Playwright 1.62.0/Chromium, appended after the project environment on the import path.
An optional development-dependency install was stopped during a slow Playwright
download; no new browser-tool version was qualified. A normal
`python start.py --setup-only` completed the application upgrade. Source, installed
metadata and the launcher's marker report 0.5.1; `pip check` passed. Readiness checks
passed on a fresh unused path, retaining the expected local-vault-key warning.

The 0.5.1 wheel was separately installed and smoke-tested: all panel/guide assets
were served, unauthenticated API access was rejected, and both direct and streamed
32-event evidence ZIPs passed independent verification. The application files in
the installed package were compared against source. The public source archive uses
an explicit file-type allowlist and refuses linked source files; runtime material
placed inside source directories is excluded by regression tests.

During the code-fix run, the public-source selection and Git candidate set contained
86 files, with no runtime data directories included. A scan for recognizable private-key, GitHub token,
Telegram bot-token and StringSession patterns found no matches. This is a bounded
pattern check, not a comprehensive secret audit. Ignore-rule probes cover twelve
common account/data/export artifacts. Workflow/issue/Compose YAML and the Windows
task script parsed successfully. Local documentation links resolve.

All seven findings from the 27 October review are addressed. GitHub
workflow execution, Linux/macOS/Docker runtime, real Telegram, outside proxy/TSA
interoperability and sustained-load qualification remain outside this local run.
No repository publication, service registration or real-account collection was
performed.

### English documentation update

The README, account/session reference, collection workflow, and bundled guide now
describe supported inputs, workspace behavior, event policies, and export formats
in English. The three public screenshots were refreshed using synthetic data.
At that point, the public-source selection contained 88 files, including the two new guides.
All 131 local links across 23 Markdown documents resolve.

After the interface and guide edits, Chromium acceptance again passed all
45 scenarios, with no page JavaScript errors or external requests observed.
The full Python suite was not rerun for this documentation and presentation update;
the 94-pass result above belongs to the preceding code-fix run.

The rebuilt wheel was installed into a fresh isolated target. Its panel and guide
assets served successfully, unauthenticated API access was rejected, and both
direct and streamed exports passed independent verification of 32 synthetic events.

### Installation and deployment update

The focused installer, packaging, and readiness checks passed **14 tests**, with
one skip for unavailable symlink creation. Native wrapper checks cover paths with
spaces, argument forwarding, setup/demo modes, and nonzero exit propagation.
Git Bash checks exercise the Docker shell helper with a simulated daemon, including
missing Docker, missing Compose, failed health wait, and a successful alternate-port
startup. These simulated checks do not establish Docker runtime compatibility.

A complete public-source copy was installed into a new Windows directory whose
path contains spaces. `scripts\Setup.cmd` created a fresh environment and installed the
pinned runtime; `Start.cmd --check --json` reported ready without creating its
target data directory. `pip check` passed. The rebuilt wheel also passed the
installed-package check, including direct and streamed 32-event exports.

Shell syntax and five workflow/Compose YAML files parsed. Source and image Compose
configurations agree on storage and runtime settings. At that stage, all 139 local
links across 23 Markdown documents resolved. The public-source selection contains 99 files.

The CI definitions now exercise fresh native setup on Windows/Linux/macOS, Compose
health/access control/persistence across container recreation, and Caddy configuration.
The release workflow gates publication on those checks and adds an emulated ARM64
smoke check. Docker is unavailable on this host: actual Compose/Caddy execution,
certificate issuance, ARM64 execution, and remote workflow/package publication
remain unqualified locally. The application/UI code was unchanged by this update;
the earlier full Python and browser results were not rerun.

## Version 0.5.0

The full pinned-runtime suite passed: **81 passed, 1 skipped**, in 22.00 seconds,
with the existing Starlette warning. The POSIX permissions check is skipped on
Windows. The new handler tests send messages, edits, scoped/unscoped deletions,
reactions, participant updates and membership service messages through different
policies. Disabled categories produce no corresponding live observations; coverage
diagnostics and explicit snapshots remain available. Tests verify persisted policy,
workspace separation, signed before/after audit records, unchanged-policy behavior,
strict validation and inclusion in the next process receipt.

Demo entry tests verify that its capability differs from the configured panel token,
cannot authorize a live workspace, cannot change collection settings, and is not
issued or accepted for remote, forwarded, cross-origin or invalid-Host requests.
Opening a stored demo without the explicit demo flag does not enable automatic entry.

Chromium acceptance passed **39 scenarios**, including local demo entry without
token input, monitoring presets, the transition from source selection to policy,
per-account independence and desktop/320/390-pixel layout and text contrast checks.
There were no page JavaScript errors. The host's AdGuard-injected requests remain
in the receipt. The download HTTP fixture logged a connection reset after a client
closed its connection; assertions still passed. This is not a live-service result.

The normal launcher upgraded the isolated environment to 0.5.0; source and installed
versions match and pip check passed. Existing secret-vault encryption, wrong/missing
key refusal and signature/media tamper checks passed in the full suite. No new
application encryption of message content or attachments is claimed.

The local demo is restarted to make the updated UI available. Existing synthetic
records are retained; stopping the old background demo process creates an offline
boundary on the next startup. No real Telegram session is used for these checks.

The running localhost:8787 panel returned version 0.5.0, automatic demo access,
the five monitoring controls and 33 retained synthetic journal events. The separate
installed 0.5.0 wheel served all panel/guide assets, rejected unauthenticated API
access, and produced a verified 32-event ZIP both directly and through the streaming
download helper. Runtime package versions remain pinned as recorded for 0.4.

## Version 0.4.0

The full pinned-runtime suite passed: **78 passed, 1 skipped**, in 19.77 seconds.
The skipped check requires POSIX permissions; the upstream Starlette TestClient
deprecation warning remains. New tests cover streamed download/workspace routing,
authorization headers, refusal to overwrite, redirects, truncated responses,
advertised/actual size limits, bounded reads, cleanup, filesystems without hard
links, readiness failures and launcher modes that must not install packages.
Export tests confirm workspace-local temporary files and selective orphan cleanup.

Chromium acceptance passed all 36 listed scenarios with no page JavaScript errors.
It exercises mock phone/code/2FA login, converted sessions, two workspaces and separate
routes/states, observations, signatures, checkpoints and timestamp requests, plus:

- Desktop and 320/390-pixel layouts, no horizontal overflow, visible navigation,
  and the first login field within the initial 844-pixel viewport.
- Solid-background text contrast at WCAG AA text thresholds. Disabled controls,
  opacity and image/gradient backgrounds are excluded; this is not a full WCAG audit.
- A real local export response written through a mocked OS file picker/writable,
  followed by independent ZIP verification; cancellation sends no export request.
- Writable failure aborts the destination; the 128 MiB fallback rejects an oversized
  advertised response without allocating a matching payload.
- The English local guide on desktop and both narrow widths.

The OS save dialog and actual multi-gigabyte browser writes were not automated or
qualified. Python download tests use bounded chunks and loopback fixtures. Full
deployment acceptance with real Telegram remains separate.

The normal installer upgraded `.venv` to 0.4.0. Source and installed metadata agree;
`pip check` passed. `python start.py --check --json` reported ready on a fresh
synthetic path without creating the data directory. Its local-key storage warning
correctly remains: journals/media are not encrypted by the application.

The 0.4.0 wheel was built and installed into a separate directory. All 23 application
files match the source byte-for-byte. The installed package served the panel and
English guide/assets, rejected unauthenticated API access, and exported a synthetic
32-event ZIP that passed verification. Its streaming download command also fetched
an independently verified ZIP from the running installed application.

Public documentation and the local guide are English; local documentation links
resolve. PowerShell parsed the Windows task template and Python parsed the macOS
plist. These are syntax checks, not service execution. No task/service was registered.
The CI configuration now includes readiness checks but remote CI has not run here.

The 0.4 browser run again observed host AdGuard injection and Windows asyncio
socket-cleanup OSError 10022. Browser assertions passed; these environmental
observations are retained rather than treated as fixed application behavior.
Initial OpenSSL/browser/pip sandbox attempts failed; the successful qualifying
runs used approved execution outside the sandbox.

## Version 0.3.1 focused readiness fixes

The affected launcher, evidence/storage and API checks passed: **31 passed,
1 skipped**, one upstream Starlette warning. The skipped check asserts POSIX
directory permissions and cannot establish those permissions on this Windows host.
The old-Python test simulates the version/import boundary; no Python 3.10 interpreter
was installed or qualified. The previously passing 0.3 suite is recorded below;
the entire suite and browser scenarios were not rerun for these focused changes.

The normal launcher upgraded the local environment to 0.3.1; source and installed
metadata agree, and pip check passed. A separately installed 0.3.1 wheel served
the panel/assets, rejected unauthenticated API access and produced a verified
32-event synthetic export. Workflow YAML parsed, but the new container runtime
check was not executed: no usable local Docker/Podman/Linux runtime was available.

See [readiness findings](internal/READINESS.md) for remaining usability, live-service and
platform gaps. This patch does not qualify additional operating systems.

## Version 0.3.0

The full pinned-runtime suite passed: **61 tests**, with one upstream Starlette
TestClient deprecation warning. Runtime metadata reports TgWitness 0.3.0 and
python-socks 2.8.2; pip check passed. The browser acceptance run passed with no
page JavaScript errors.

The 0.3.0 wheel was built and installed into a separate package directory. It
served the panel and assets, rejected an unauthenticated API request, and exported
a 32-event synthetic journal that passed independent verification. Local documentation
links resolve. After the MTProxy bare-key normalization correction, all nine
connection/security tests were rerun successfully.

New coverage includes:

- SOCKS5 username/password and HTTP CONNECT through actual loopback test servers;
  a dead configured proxy fails rather than falling back to the destination.
- Proxy validation, MTProxy transport selection, rejection of Fake TLS ee secrets,
  persistence, workspace isolation, rejection of changes while observing, and secret
  exclusion from API status and signed events.
- Read-only conversion of synthetic Telethon SQLite schemas 7 and 8; unchanged
  source hash; rejection of other formats, SQL views, and an outstanding WAL file.
- External vault master key: different derived workspace keys, successful reopen,
  wrong/missing key rejection, and no implicit migration of existing local vaults.
- Browser proxy settings, credential clearing, storage-protection disclosure,
  mobile connection page, converted-session file authorization, separate routes,
  and all previously covered collection/export scenarios with a fake Telegram client.

During development a loopback test waited indefinitely for peer shutdown; another
run observed a Windows connection reset after the handshake. The fixture now bounds
the entire exchange and treats EOF/reset after a completed handshake as connection
closure. Handshake/authentication assertions remain required. This does not qualify
real proxy providers or imply a fixed Telegram transport defect.

The host AdGuard request observation described below still applies. No real Telegram
account, outside SOCKS/HTTP proxy, or live MTProxy server was used. MTProxy is
experimental and its selected options/secret validation have been checked, not
live interoperability. New external-key and session conversion commands were
tested with synthetic secrets only. Linux/macOS/Docker remain unqualified here.

The 0.2 throughput measurement below was not repeated and must not be presented
as a new multi-account/proxy benchmark for 0.3.

## Version 0.2.0 baseline

Checked on Windows with Python 3.12.10. No real Telegram account was connected.

| Check | Result |
| --- | --- |
| Python suite | 52 passed in the development environment and 52 passed with the pinned runtime; one upstream Starlette TestClient deprecation warning in each run |
| JavaScript syntax | Passed with Node.js |
| Chromium acceptance | Passed; no page JavaScript errors |
| Desktop/mobile layout | Checked at 1440 × 1060 and 390 × 844; no horizontal document overflow |
| HTML-shaped message content | Rendered as text; injected script did not execute |
| Mock account flow | API credentials → phone → code → 2FA → select group → start → snapshot → pause → reload |
| Evidence in browser | Edit comparison, prior content after deletion, filters, ZIP download, checkpoint, signed process receipt, RFC 3161 request download and checkpoint binding |
| Multi-account | Separate journals, keys, sources and live states; browser switch leaves the other collector running; workspaces reopen after restart; duplicate account and account reassignment rejected |
| Cryptographic failures | Changed signed fields, added unsigned fields, wrong key, corrupt archive member, changed/missing media, checkpoint-detected truncation rejected |
| Storage | Concurrent appends verify; update/delete triggers reject; startup refuses a changed journal without appending and releases its lock |
| Media durability | Atomic message/job writes; restart recovery; original version descriptors retained; queue substitution and existing-file corruption rejected; FloodWait persisted; source failures isolated |
| Streaming | Stable prefix exported while new records append; retained checkpoint detects truncated journal; export does not materialize the entire event stream |
| RFC 3161 | OpenSSL 3.5.9 reads generated requests; locally generated synthetic CA/TSA response accepted; altered data, nonce and wrong CA rejected; ambient CA environment does not override explicit trust |
| Local setup | start.py --setup-only upgraded the isolated .venv to 0.2.0; source and installed metadata agree; pip check passed |
| Wheel | 0.2.0 built and separately installed under test-results; served panel/assets, rejected unauthenticated API, exported and verified a 32-event synthetic archive |

The source tests used FastAPI 0.159.1, Uvicorn 0.54.0, Telethon 1.45.0,
cryptography 50.0.2, pytest 9.1.1, and Playwright 1.62.0.
The pinned runtime uses FastAPI 0.162.0, Starlette 1.10.0,
Uvicorn 0.54.0, Telethon 1.45.0, and cryptography 50.0.2.
deploy/constraints.txt records runtime version pins; deploy/requirements.lock and
deploy/build.lock add the SHA-256 of every package file, and Docker and high-assurance
servers install only from them (pip --require-hashes). Neither is evidence of compatibility
on every configured CI platform. Remote CI has not run.

## Synthetic local capacity measurement

Command: `python tools/check_capacity.py --events 10000 --chats 100`

| Metric | Observed |
| --- | --- |
| Input | 10,000 synthetic message events across 100 synthetic selected sources |
| Message text | 400 characters; no media or network |
| Ingestion | 53.273 seconds; 187.7 events/second |
| Handler latency | p50 4.162 ms; p95 7.784 ms; maximum 129.118 ms |
| ZIP export | 19.868 seconds with tracemalloc enabled |
| Peak traced Python export allocations | 0.51 MiB; not process RSS |
| ZIP size | 4,610,962 bytes |
| Independent verification | All 10,000 events verified |

This measures the local serial recording/export path on this Windows host. It does
not measure MTProto delivery, concurrent accounts, Telegram throttling, media, a
long-running workload, or a guaranteed number of real chats. The measurement predates
the final offline timestamp tooling, which does not change the measured message path.

## Environmental observations

Windows sandbox restrictions blocked the default pytest/pip temporary directories
and the Playwright subprocess. Pytest used a new temporary directory inside the
project; installation and browser processes required approved execution outside
the sandbox.

The machine's AdGuard injected requests to local.adguard.org into the browser.
The browser receipt retains those requests. This run is **not** evidence of zero
outbound requests in an unmodified browser environment; the app source itself
contains no external asset/CDN/analytics requests. AdGuard settings were not changed.

The final browser run also logged a Windows asyncio socket-cleanup OSError 10022.
All browser assertions passed and no page JavaScript errors occurred. Its cause
was not established and this run does not demonstrate absence of host transport issues.

The first installed-package HTTP probe using urllib's connection-close requests
encountered connection resets, both inside and outside the sandbox and with both
dependency sets. The final probe used standard HTTP/1.1 persistent connections
via http.client and passed. Browser requests also passed. The precise origin of
the resets was not established; they were not labeled a fixed application defect.

## Remaining qualification

The retained live journal establishes real collection, edits, deletion notices, attachments,
rechecks and rate-limit handling. It does not establish exhaustive delivery or a controlled
matrix of role visibility, reaction actors, prolonged FloodWait, account bans and
network/process interruption recovery. QR-token issuance remains distinct from completed
mobile QR confirmation.

Docker build/run, Linux/macOS installation, sustained high load, independent security
review, a real independent TSA response, certificate revocation/archival validation and
forensic certification remain outside the recorded qualification. Saved MTProto state
and catch-up are implemented; atomic durable replay remains unestablished. Admin-log
collection, extra reactor lists and priority short polling remain separate features.
See [live acceptance](internal/LIVE_ACCEPTANCE.md) for the controlled qualification matrix.

Local detailed receipts and screenshots are under test-results/ (Git-ignored).
The public screenshot in docs/assets/ contains only fictional demonstration data.

## Public website and publication preparation · 27 October 2026

The separate `website/` presentation and Pages build were added after the panel
checks above. No live account configuration or collection logic was changed.

- The existing application suite passed: 138 passed, 1 POSIX-only skip, and one
  upstream Starlette/httpx deprecation warning. The 11 added site build tests passed
  independently, including unexpected-output rejection and linked-input rejection.
- Both application browser scripts passed using project-venv Playwright and Chromium
  headless shell 156. No page JavaScript errors or external requests were recorded.
  All account scenarios used fake transport and fictional data.
- `tools/check_site.py` passed at widths 320, 390, 768, 1024, and 1440, with a project
  URL subpath, keyboard tabs, successful/denied clipboard access, reduced motion,
  and disabled JavaScript. No failed asset requests or external requests occurred.
- `tools/build_site.py` produced 10 allowlisted public files, about 460 KB total.
  Browser screenshots and a receipt are in ignored `test-results/site/`.
- The wheel built successfully after installing the build-only setuptools/wheel
  tools in the project environment. Installing it into an isolated target and
  running `tools/check_install.py` passed: static assets, access control, a signed
  32-event synthetic export, and independently verified streaming download.
- `pip check` passed. A pattern scan of Git-selected public candidates found no
  recognizable private-key blocks, GitHub/bot/AWS tokens, long literal secret
  assignments, or merge-conflict markers. This is not proof that every possible
  secret format is absent. Runtime-data/session/key probes were Git-ignored.
- GitHub CLI authentication was invalid; no remote was configured and no initial
  commit existed. No push, hosted workflow, Pages deployment, or release was performed.
  Docker and live Telegram/platform qualification remain outside this check.

On this host the Playwright download lock failed on the E: workspace filesystem.
Installing Chromium under `%LOCALAPPDATA%/tgwitness-playwright` and using that same
`PLAYWRIGHT_BROWSERS_PATH` for the checks succeeded. This is an environment workaround,
not a change to the application's runtime dependencies.

## Interactive documentation and website metadata · 29 October 2026

The public site builds 12 English HTML pages: a homepage, a guide index and ten
guides. The artifact contains 28 explicitly listed presentation files,
approximately 1.85 MB, and no collector data. The public website is English;
application translations and translated repository guides are separate.

- Site, source-publication and release-boundary tests: **18 passed, 2 skipped**.
  The skips concern symlink creation on this Windows filesystem. Tests check
  unique page metadata, English-only public pages, canonical URLs, all sitemap
  entries, local assets/anchors, structured navigation and private-file exclusion.
- Both `tools/check_site.py` and `tools/check_docs_site.py` passed in Chromium at
  320, 390, 768, 1024 and 1440 pixels under a project URL subpath. The guide checks
  cover all 11 documentation pages, search and keyboard navigation, clipboard
  success/refusal and readable content without JavaScript.
- Five interactive examples passed: message playback/step/pause/reset with
  reduced motion and off-screen suspension; original/altered/rebuilt/truncated
  hash chains; witness acceptance/rollback/fork/no-response decisions; and
  complete/delayed/missing delivery scenarios; and an investigation map linking
  fictional cross-chat observations by sender ID, destination and attachment
  hash. The investigation controls passed keyboard navigation and no-JavaScript
  fallback checks. Browser SHA-256 results were
  independently compared with Python's `hashlib` and canonical JSON. The hash
  example also retained its readable fallback when Web Crypto was unavailable.
- Delivery ratios and chart markers matched the accessible table. Mobile axis
  labels were enlarged after visual review. Every example is labeled as
  illustrative or synthetic, and no browser example contacts Telegram.
- No external requests, failed HTTP requests or JavaScript errors were recorded.
  Desktop/mobile screenshots and receipts are under ignored `test-results/site/`
  and `test-results/docs-site/`. The documentation index, message/hash examples,
  witness layout, delivery chart and investigation map were inspected at
  desktop/mobile sizes.
- The publication scan passed for 282 public source files and 1,426 local
  documentation links. Ruff passed for the modified Python site tools and tests.
- `docs/HOW-IT-WORKS.md` provides a GitHub Markdown companion with Mermaid
  diagrams and formulas. `docs/INVESTIGATION.md` covers whole-account scope,
  per-chat history acquisition, people profiles, cross-chat references, timelines
  and a verified case handoff. Its steps and limits were checked against the
  current scope, collection, dossier, export, verifier and panel code. Hosted
  GitHub rendering was not checked.

This is a local website/documentation check. It does not add live Telegram
qualification or establish hosted Pages deployment, remote CI success or search
engine indexing. See [the publishing procedure](internal/PUBLISHING.md) and
[the website metadata notes](internal/SEO.md).
