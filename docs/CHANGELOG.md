# Changelog

## Unreleased

- OpenTimestamps summaries now parse bounded operation trees and attestation
  payloads, rejecting truncated, malformed and excessive proofs. Marker bytes in
  arguments or opaque payloads cannot produce a Bitcoin status. Parsed Bitcoin
  attestations are explicitly `bitcoin-unverified`; run `ots verify` for validation.
- Source releases include the exact public TSA fixtures used by the evidence tests.
  The synthetic calendar fixture now carries correct serialized URI lengths.
- Added the [delivery roadmap](ROADMAP.md), separating release acceptance, the
  external controller prototype and future independent-observer integrations.
- Evidence verification now reports the exact prefix covered by witness checkpoints and
  any unwitnessed tail. `--require-witness` requires a pinned witness and a matching final
  exported record; requested channel checks also reject missing claimed posts.
- Cloud journal checks reject missing startup records or expected collector keys and
  report unavailable host measurements. Deployment reports distinguish configuration
  checks from independent runtime attestation; supplied channel dates are not authenticated
  by witness signatures.
- Added access and permissions guides with reviewer/analyst examples, session limits,
  IP restrictions and revocation. Updated routing guides for automatic MTProxy,
  IP modes and external requests; connected the README, Wiki, website and bundled guide.
- Expanded the panel and complete documentation site to 25 languages, including German,
  French, Italian, Japanese, Korean and Hebrew. Language switches preserve the current
  documentation page; the static demo includes the new panel dictionaries. Existing
  Amharic guides and notices remain available separately.
- Site publication now rejects missing translations in a full-site language.

## 0.7.0 · 30 October 2026

- First GitHub release, with the Windows portable package, the wheel and the source archive.
  README and the website link the portable package directly: extract, double-click `TgWitness.cmd`.
- The setup guide has an "Open to everyone" section: no country or sanctions blocks, and
  Taylor Wessing as the only incompatibility we name. It is our position, not a licence condition.
- The website's changelog links point to `docs/CHANGELOG.md`.
- The README and Wiki now present the authors' Ethical Notice & Historical
  Continuity statement, with document references, historical context and an
  explicit explanation that MIT permission applies to everyone.
- Repository identity: a larger wordmark and investigation scene, three direct
  navigation choices, a dedicated handbook cover and a shorter README. Source
  connections, travelling records and the signature animate inline; phone layouts
  and reduced-motion alternatives retain the same visual hierarchy.
- Investigation presentation: the illustrated source-to-dossier animation now
  leads the README and Wiki. A clearer case route, direct evidence-model
  navigation and a vertical phone diagram keep the workflow and verification
  formulas readable; all moving illustrations have reduced-motion alternatives.
- High-assurance deployment (`python -m tgwitness.cloud`, [guide](HIGH-ASSURANCE.md)). It creates
  the collector through the API of Hetzner Cloud, DigitalOcean, Linode, Vultr or Amazon EC2:
  no SSH key, a provider firewall without inbound rules, SSH masked from the first boot,
  one fixed commit, and a panel reachable only through a Cloudflare Tunnel. The
  `verify` command lets a third party compare the provider's own log and firewall, the
  tunnel connector's address and the collector's signed `/api/assurance` statement. It
  writes a Markdown/JSON report for evidence handover. `generic` installs on any server
  with `install.sh` and is never reported as more than self-attested. With
  `TGWITNESS_ASSURANCE` set, the collector signs host measurements (SSH, logins, boot,
  metadata) into every process start and into `host.state` records whenever they change.
  Ordinary installations are unchanged.
- Two clicks to start: a local start (TgWitness.cmd, Start.cmd, start.sh, the demo
  launchers and the Docker helpers) opens the panel in the browser once it answers, and a
  real workspace shows its panel token in the console instead of in the address bar.
  Services, containers, scheduled and windowless starts never open a browser;
  `--no-browser` or `TGWITNESS_NO_BROWSER` turns it off.
- The operator notice and the Taylor Wessing page speak in our own voice.
- Returned to the MIT License. A tool whose output third parties must be able to check
  should not stumble over its licence. `LICENSE` is the standard MIT text again, the
  package declares MIT with the OSI classifier, and the container, portable package,
  website, Wiki and translated README labels say so. Our statement stays in NOTICE
  and on the Taylor Wessing page as our position; it adds no licence condition. The presentation artwork reads "open source" again.
- Added our Operator Incompatibility NOTICE to README, SECURITY,
  the documentation, Wiki and website. A single source keeps the complete statement
  consistent across those pages; source, Python and portable distributions include
  NOTICE alongside the licence.
- The documentation website gains a read-only online demo: the real panel, answered from
  recorded records of the fictional demo, in all 13 interface languages. Every change is
  refused in the browser, nothing is sent anywhere, and `tools/capture_demo.py` regenerates
  the recording. The home page and README link to it.
- Put the workspace preview near the top of the repository landing page, simplified
  wiki entry links and connected the issue chooser to the live handbook. GitHub
  and website sharing images now have reproducible PNGs in the investigation style.
  README and wiki now include video players for the illustrated investigation and
  message-history films. The gallery includes all three 12-second films; their MP4s
  and the two original GIFs are included in the source archive. Animated evidence
  explanations retain static alternatives for reduced-motion preferences.
- Fixed all eleven audit findings, each with a regression test. The portable builder
  no longer reuses an earlier build directory and refuses private or unexpected files.
  The verifier applies its archive limits at every entry point, including format
  detection and witness journals. The HTTP client bounds chunked reads. Individual and
  multi-account exports share one reservation per account; a workspace in a running
  multi-account export cannot be deleted; setup failures end an export as failed.
  People profiles count distinct replies and messages. Reference pages link to the
  GitHub editor, translated README sections collapse again, and the operations guide
  describes password-protected exports and priority rechecks correctly.
- The additional launchers moved to `scripts/`: `scripts\Demo.cmd`, `scripts\Setup.cmd`,
  `scripts\Docker.cmd` and `sh scripts/docker-start.sh`. They still run from the project
  root; `Start.cmd`, `start.sh` and `start.py` stay where they were.
- Redesigned the repository presentation with a message-history cover, GitHub and
  website preview images, and an illustrated observation-to-verification workflow.
  The English README now leads with the workspace, feature cards and a demo;
  detailed instructions remain in expandable sections. Wiki and documentation
  entry pages share the presentation, with an editable, reproducible artwork kit.
- Added an English project wiki with 13 user guides, a sidebar and footer, plus
  support guidance and a documentation issue template. A checked builder prepares
  GitHub Wiki links and a ZIP with hashes; CI publishes the bundle as a downloadable
  artifact. The wiki's separate publication procedure is documented.
- The documentation website gained a reference section: 17 repository documents rendered
  with search, contents and links that stay on the site, and their Mermaid diagrams drawn
  as SVG that animate into view (with a text version, and still when reduced motion is
  asked for). A new **Keep it secure** guide shows what leaves the machine, what each
  secret unlocks, what the protections cover and a hardening checklist. Pages gained a
  reading-progress bar, the current section in the contents, `/` and Ctrl/Cmd+K for search
  and content that eases in. SECURITY.md is split into sections with a summary table.
  Internal reviews and release notes moved to `docs/internal/`.
- The website is available in 13 languages (English, Russian, Ukrainian, Spanish,
  Brazilian Portuguese, Turkish, Arabic, Persian, Urdu, Hindi, Indonesian, Vietnamese,
  Simplified Chinese): home page, guides, interactive examples, diagrams and the reference,
  with a language menu, `hreflang` links, a multilingual sitemap and right-to-left layout
  for Arabic, Persian and Urdu. A changed English passage shows in English with a notice
  until it is translated again; the changelog stays in English. Added a light/dark theme
  button that follows the system until chosen, and rendered the reference's formulas.
- The Account page shows the current connection route with a **Proxy settings** link that
  opens the public MTProxy lists, your own proxy link and SOCKS5/HTTP fields at once; quick
  navigation finds it by "proxy". While observation runs, the route form says why it cannot
  be saved instead of only disabling the button.
- The README and its 12 translations gained a **What has been tested** table (real account,
  synthetic clients, local test servers, not tested yet) and mark untested integrations in
  place: notification services, MTProxy and public proxies, the witness bot, timestamp
  services, Docker/Caddy and the release workflow. The live test record now covers the
  whole-account run (9,968 verified records). Translations were regenerated from the
  current English README; the Russian one was corrected by hand.
- **Sign out of Telegram** on the Account page (`POST /api/auth/logout`): with observation
  paused, Telegram is asked to end the session (`auth.logOut`) and the session is removed from
  the vault; the journal, sources and keys stay and an `account.signed_out` record notes
  whether Telegram confirmed. Previously a connected account could not be removed from the
  panel at all. ACCOUNTS.md no longer claims that workspaces cannot be renamed or deleted.
- The panel's Russian was reviewed by hand: about 940 strings corrected (wrong machine
  translations such as "Anchor now" as "go to this page", inverted error messages, mixed
  terms) and the mini-client, dedicated-account guide and other English leftovers translated.
  In folder and whole-account modes the Sources page is titled "Observed chats" instead of
  "Choose chats", and the main workspace's default name follows the panel language.

- Publication checks now scan staged text, reject unresolved merges and require the full
  reviewed source in the Git index. A clean working file no longer hides a staged secret,
  and missing new modules or stale staged versions can no longer pass the release check.
- Account deletion reports filesystem failures, keeps incomplete deletions visible for
  retry, and preserves that state across restarts without reopening a half-erased vault.
  Successful deletion is recorded only after local files are removed.
- Valid panel and witness tokens remain usable after invalid requests from the same
  client address reach the rate limit. Witness failures share the bounded address cache.
- Fixed message loss after a long stop: the recheck recovered at most 1,000 missed messages
  and then continued above the newest saved one, so the rest of the gap below live messages
  was never fetched. It now continues from where the previous pass stopped, and a chat still
  catching up is rechecked on the next minute instead of after its 15-minute or 6-hour interval.
- The panel's notification list groups changes per chat and hour and keeps problems in it:
  on a live chat deleting a message every two minutes, all 60 entries were single deletions
  covering about one hour, so a sign-out or a full disk dropped out of the list within an hour.
- Rewrote the live-test record in plain terms: one real account, one supergroup, 27 to 29
  October 2026, 1,291 messages, 472 deletions (347 saved before deletion), 12 edits, all
  2,385 record signatures verified. The translated READMEs no longer claim that only a fake
  Telegram transport was tested.
- Review fixes. A link preview that Telegram fills in later, story views, paid media unlocked
  by this account and paid invoices are no longer recorded as edits. A link preview saves the
  file whose type and size were checked (its photo) instead of failing on its video. Reply
  keyboard presses are recognised only on newly sent messages after the keyboard, not on
  snapshots, recovered messages or edits. People profiles of private chats and bots include
  the other person.
- Scope fixes: a chat Telegram could not describe is no longer declined until the next scope
  refresh; a chat that left the folder stays paused when it falls outside the dialogs read;
  adding a removed chat again lifts its exclusion; folder mode starts with the folders read last
  time when Telegram does not answer; removing a chat with 5,000 exclusions is refused instead
  of breaking the scope settings; files still waiting for a removed source are recorded as failed.
- verify.py: a profile checked with `--evidence` also verifies that archive's signature, hash
  chain and files; with `--witness`, only answers signed by the export's own key count as
  witnessed, and a key the witness never saw stays "unpinned". Raising the heartbeat interval
  while observing no longer shows a coverage gap.
- Off-site copy: a missing or damaged preserved file is reported and retried next pass without
  stopping the other files, checkpoints and exports. Notifications also work with Apprise 1.x.
  The panel summary names the largest per-type attachment limit.
- Made independent bot setup visible in the panel with pinned configuration downloads,
  separate token files, publishing cadence and custom Bot API / HTTP proxy settings.
  Added operator-managed public MTProxy catalogs and preview/import of Telegram proxy
  links alongside manual routes. Added offline witness configuration checks and documented
  where continuity requires a full archive comparison rather than a growing counter.
- Corrected stale validation summaries using a read-only review of 2,385 retained live
  Telegram events with verified signatures and hash-chain continuity. Documented the
  existing saved update-state/catch-up implementation and its remaining replay limits.
- Refreshed the product page with a dark hero, an interactive message history, four
  screenshot views and a demo-first introduction. Redesigned the desktop access screen,
  refined Russian labels and reorganized the English/Russian READMEs around features and
  getting started. Added matching English/Russian covers and social artwork.
- Require Pillow 13.0.0 or newer (below 14) and pin 13.0.0: the dependency audit
  reported 39 advisories against 12.3.0, with fixes in 13.0.0. The minimum Python
  version remains 3.11. See the [upstream security fixes](https://pillow.readthedocs.io/en/stable/releasenotes/13.0.0.html#security).
- Pre-publication checks: source ZIPs allow only known locale JSON resources; wheels use
  explicit asset types and locale files, excluding arbitrary static files and namespace data
  directories. Git/Docker ignore common account JSON files. A publication check validates
  local documentation links, recognized secret patterns and the Git file list; CI now runs
  it and audits pinned runtime dependencies with pip-audit.
- Added a searchable **Go to…** menu (Ctrl/Cmd+K), keyboard navigation, focus restoration,
  current-page announcements, Russian labels and responsive light/dark styling. Closing the
  workspace also closes the menu. Added browser checks at 320, 390 and 1440 pixels.
- Fixed two broken documentation links and refreshed release documentation. Synthetic
  attachment fixtures use a fixed document date so comparison tests do not depend on timing.

- Whole-tool review: reject attachment downloads with the wrong byte count; scope replica
  progress to its destination/key; report missing or corrupt preserved files; verify restored
  media; reconcile identical overlapping journal segments and defer checkpoints beyond the
  copied journal boundary. Old unscoped replica progress triggers one complete local-data replay.
- Workspace switches and panel locking discard late API responses, including records, dossier
  caches, witness tokens and export dialogs. Actions wait for the selected workspace to load.
  Cancelling the file picker leaves a finished chat export available to download.
- Dossier builds cannot recreate a cache after it has been disabled or removed. Export cancellation
  waits for its file worker before removing temporary files. Added backend and workspace-browser
  regression coverage; existing English controls and translations are preserved.

- Corrected chat-switch routing, preserved successful action receipts through refresh failures,
  and disabled automatic RPC retries for callback and join actions. Added browser regressions
  for delayed chat responses and interrupted refreshes; included the mini-client check in CI.
- Rechecks and live edits compare attachment identity, entities and keyboard removal; temporary
  file-access metadata does not create versions. Background recovery respects own-action scope.
- Restore validates object paths in private staging, verifies every checkpoint and journal range,
  and publishes only a fully verified archive into an empty directory. Object Lock verification
  checks the actual requested deadline. Added regression coverage for each reviewed failure.
- Declared English fallbacks for untranslated interface sections while retaining existing
  translations and strict dictionary coverage checks.

- Panel mini-client in Chats: plain-text messages and replies, callback/text button presses
  with saved bot answers, and Telegram invite/username/bot-start previews followed by explicit
  join/open actions. Signed request/result receipts, persistent request deduplication, stale
  keyboard checks, FloodWait handling, and separate pending/unknown outcomes. The new controls
  use English text.

- Observation scope: chosen chats, one Telegram folder or the whole account, with channels, groups, private chats and bots as switchable types. New chats are added the moment they appear; excluded chats are never recorded. Switching to a folder or the whole account asks for confirmation, which the signed journal records.
- Own actions: outgoing messages and edits are labeled, reply-keyboard button presses are recognised, and they can be left out.
- Deletions in private chats and ordinary groups are recorded in their chat when a message with that ID was saved before, instead of staying unscoped.
- Rechecks in two tiers: priority sources every 15 minutes, others every 6 hours, at most 30 per pass, so accounts stay clear of FloodWait.
- Attachment limits per type (photos, videos, GIFs, round videos, voice, audio, stickers, files), up to 2,000 MiB.
- Sources can be removed (their people profiles are deleted; saved records stay in the journal) and starred as priority.
- People profiles per chat, opt-in: name and username history, Telegram flags, avatar SHA-256 and pHash with similar avatars, activity, replies, other observed chats and mentioned wallets, phones, usernames and links. Built only from saved records, each fact citing its record; exported as a separate signed file, optionally as an AES-256 ZIP; verify.py checks it against an evidence export.
- Independent witness: a separate process or container with its own key, journal and bot fetches the signed journal head with a read-only token, posts it to a channel and records when the collector does not answer. Witness page in the panel, Docker profile, deploy/compose/compose.witness.yaml for another server; verify.py checks evidence exports against the witness journal and channel posts.
- Reports and verify.py state continuous observation periods, gaps with their reason and message IDs that were never observed (not presented as deleted); signed ZIPs include coverage.json.
- Evidence manifests, chat exports, witness journals and profile files name their producer (TgWitness, PhishDestroy) in the signed part; the report and verify.py show it.
- Notifications: optional excerpts of deleted and edited messages (off by default), newly added chats, and a notification list in the panel.
- Off-site copy: the bucket's Object Lock and each pass's retention are read back, so storage that ignores Object Lock is reported.
- Parameters page: every limit and pace that was fixed in code is set per workspace in the panel, with its range and default, and each change is recorded in the signed journal. Covers the chat list size and refresh, heartbeat and checkpoint intervals, the startup buffer, how rechecks spread requests, disk reserve, download timeouts and retries, people-profile options including your own regular expressions, notification size and pace, snapshot, ZIP and browser-download limits, panel action timeout and Telegram client timeouts and retries.
- Recheck, attachment size, evidence and off-site copy intervals and the history snapshot size take any number in their range instead of a few presets; the default attachment limit goes up to 2,000 MiB.
- Coverage follows the heartbeat interval recorded in each heartbeat; verify.py takes `--max-gib` for archives above 4 GiB.
- Witness: `--timeout`, `--post all|changes|problems`, `--title`, a JSON config file (`--config`) and replaceable post wording; unknown options are refused.
- Investigation mode: one button sets the scope for an account that joins teams and talks to bots. Buttons under messages (links, web apps, texts to copy, callback data) are kept and shown in Chats, button-only edits become new versions live and at recheck, and every new chat or bot gets its profile (description, bot commands, members, invite link) and up to 1,000 earlier visible messages saved at once. Chats → Profile saves a source's profile on request.
- Dedicated account guide, linked from the sidebar, Account, Investigation mode and the setup guide: why the main account must not be used, why TgWitness works through public app hash/app ID pairs and why nobody can see anything of yours through them (with links to Telegram's documentation and to programs that use the same pairs), ways to create an extra account, and services for getting a number. The setup guide shares its new look.
- New dependency: Pillow, for avatar perceptual hashes.
- Light and dark theme, following the system by default; Telegram-style chat view and interface motion, which an "Animations always on" switch keeps when the system asks for less.

## 0.6.1 · 27 October 2026

- Renamed TgWatch to TgWitness; archives and checkpoints made under the old name still verify.
- Evidence mode: checkpoints are timestamped automatically by RFC 3161 authorities and OpenTimestamps, and verify.py checks the answers.
- The UI and docs say "workspace" throughout.
- Exports can be saved as a password-protected AES-256 ZIP that 7-Zip and WinRAR open.
- Notifications through Apprise: problems, changes in observed chats and a daily summary.
- Interface in 13 languages and README, Quick start and Deployment guide in 12 translations, made with DeepL.
- Off-site copy: everything goes encrypted to any S3-compatible storage, with Object Lock where available and a verified restore command.
- After a restart, observation catches up on Telegram updates missed while it was off.
- Observed chats are rechecked every 15 minutes for missed messages, edits and messages Telegram no longer returns.
- Photos and files are saved by default; downloads pause below 1 GiB of free disk.
- Sign in without your own API ID/hash using a built-in pool of public API pairs.
- The chat list loads on its own in Sources, and every journal record type has a readable title.
- New Chats view as the start screen, with deleted and edited messages highlighted.
- Export one chat with several accounts at once; each account signs the ranges it fetched.
- Observation keeps running during chat exports.
- No fixed limit on workspaces.
- Full chat export shows the expected time and progress.
- Chat exports list every author; People shows each person's saved, deleted and edited counts.
- New Accounts view to manage, rename and delete workspaces.
- Full chat export as a signed ZIP.
- Portable package checks run on a temporary port.
- Public project website.
- GitHub Pages build and deployment workflow.
- Windows portable package with an embedded Python runtime.
- Start.cmd finds or offers to install Python 3.12.
- start.sh finds more Python versions and prints the install command.
- start.py explains a missing venv package or failed dependency download.
- Ctrl+C in the launcher stops the server in order.
- Docker helpers print the panel address and token once the container is healthy.
- Rewritten accounts guide.
- Redesigned panel on one stylesheet.
- Bundled SVG icon set and a new logo.
- Easier-to-scan journal.
- Version in the sidebar; `--host`, `--port` and `--data-dir` in `--help`.
- Offline setup guide restyled to match the panel.
- Rewritten README with current screenshots.
- tools/capture_screenshots.py regenerates README images; browser checks can use installed Chrome or Edge.
- Cleaner download test output.
- Local Playwright browsers excluded from git and Docker builds.

## 0.6.0 · 27 October 2026

- Start live setup on a focused account form with Phone, QR code, Files, and Auth key tabs.
  Make API ID + Hash directly accessible and explain each supported file beside
  the picker, including companion JSON and the difference from an Auth Key.
- Accept Auth Key HEX and DC ID directly, with optional online User ID verification.
  Reject incomplete keys locally and discard conversions after inputs change.
- Put file selection before format guidance and show progress while reading files,
  requesting login codes, generating QR codes, or connecting to Telegram.
- Open demo mode on its sample journal. Show live startup instructions on its Account
  page instead of a login form that cannot authorize accounts.
- Start connected, unconfigured workspaces on source selection. Move journal
  counts, capture settings, and detailed verification into expandable sections.
- Put phone entry first and request the code directly, with API settings revealed
  only when missing. Reuse the current workspace's saved API pair for phone, QR,
  and session login without exposing saved secrets to the browser.
- Connect selected account files with one action; metadata-only JSON leads to
  phone entry. Collapse connection/storage settings and simplify the panel-token gate.
- Refresh the panel with a light workspace, dark navigation, larger journal text,
  and a next-step guide for account connection, source selection, and observation.
- Separate phone, QR, and file sign-in. Paste one `API ID:API Hash` pair to fill
  both fields; reject malformed pairs locally and discard stale imports when
  changing sign-in methods. No shared API credentials are bundled.
- Import Telethon and Pyrogram SQLite sessions, modern single-account TData ZIPs,
  Telethon StringSession text, and documented account JSON fields in Connection.
- Read up to four matching files together; companion JSON can supply API metadata.
  Conversion stays in server memory, with bounded input and no ZIP extraction.
- Support Desktop local passcodes and complete Auth Key HEX + DC ID JSON. Check
  imported user IDs against Telegram before retaining account authorization.
- Add locally rendered QR login, Telegram 2FA, expiry/retry, and cancellation on
  lock, workspace switch, route change, and replacement login.
- Add synthetic parser, isolation, QR lifecycle, and browser acceptance coverage;
  update English format, deployment, security, and offline documentation.

## 0.5.1 · 27 October 2026

- Disconnect rejected authorization clients and accept live updates only from the
  active account client. Resuming observation cancels unfinished login.
- Support windowless Windows launches with rotating startup/server diagnostics in
  the data directory's `logs/server.log`; HTTP access logging remains disabled.
- Clear journal verification results on workspace changes, discard late responses,
  and identify the verified journal boundary when new records arrive.
- Search Unicode text without case differences, preserving original signed records.
- Keep unsaved attachment settings during status refresh and edits made during saving.
- Show full UTC event dates/times at phone and tablet widths.
- Keep the search icon clear of the input text at every layout width.
- Include monitoring-policy changes in the Coverage filter.
- Add regression coverage, contribution/issue guidance and stricter public-source
  packaging exclusions.
- Expand English account-format and collection guides, add workflow diagrams and
  export tables, and align the README, quick start, and offline setup guide.
- Add Linux/macOS launch scripts, Python discovery on Windows, and Docker startup
  helpers that wait for web-server health. Document one-command installation.
- Add optional automatic HTTPS with Caddy, image-only Compose deployment, and
  versioned AMD64/ARM64 GHCR builds triggered by a GitHub Release after CI passes.
- Check first-run installation across CI platforms and Compose persistence after
  container recreation; document updates, reboot behavior, and data migration.
- Explain signature coverage for each export format and the investigation handoff
  workflow, including independently retained fingerprints and checkpoints.

See [verification](VERIFICATION.md) for executed checks and
[readiness](internal/READINESS.md) for remaining live-service and deployment work.

## 0.5.0 · 26 October 2026

- Add per-account monitoring categories, presets and signed policy changes.
- Allow direct local entry to isolated synthetic demos without copying a token.

Earlier preview capabilities and qualification history are described in
[release status](internal/RELEASE.md) and [verification](VERIFICATION.md).
