# Changelog

## 0.9.0 preview · 4 November 2026

- Reserve each account exclusively for monitoring, history or an export. Serialize Telegram RPCs and persist full FloodWait deadlines.
- Add durable distributed chat exports with date/language/reply filters, bounded labelled context, signed chunks and explicit pause/resume. See [Distributed chat export](DISTRIBUTED-EXPORT.md).
- Keep account reservations until every export worker has stopped, including repeated pause requests and sibling worker failures. History loading in sealed sessions also reserves the account exclusively.
- Add participant timelines from saved observations: names, membership, explicit deletion flags and message activity. Profile refreshes are bounded; optional presence recording preserves unavailable or expired status as unknown and does not attribute online activity to a chat.
- Save, import and reuse report layout profiles without copying case details or report filters. Profiles are validated and isolated by workspace.
- Automatically offload eligible attachments to configured external storage under disk pressure, with reserve-space checks, compression, optional encryption and full readback verification before local eviction. Journals remain local.
- Make the recording settings and chat tabs fit narrow screens, including wider system fonts, and fix profile controls and localized labels.
- Include reviewed website assets in source archives and verify conditional dependency versions in SBOM inventories.

## 0.8.1 preview · 2 November 2026

- Runtime, sealed and media containers moved to pinned Wolfi/glibc with Python 3.12 and
  hash-locked system packages (AMD64 + ARM64). Image scans are clean of HIGH/CRITICAL.
- Tesseract 5.5.4 built from verified source, English and Russian data pinned.
- Release checks now cover real OCR, offline transcription, signed multilingual PDFs and
  container restrictions. The source archive includes all container build inputs.
- **Extras → Independent capture** in the English panel: browser/AyuGram recorders with
  encrypted tokens, pinned keys, tab selection, start/pause, snapshots, checkpoints and
  verified ZIP downloads. Everything is off by default.
- New optional `tgwitness-capture` package: Chromium PNG/MHTML snapshots, AyuGram SQLite
  copies, optional silent video, Ed25519 event chains, signed ZIP/HTML reports and a
  standalone verifier. Each recorder has its own key and storage.
- Fixed Phala installs: source bundles were missing the capture package.

## 0.8.0 preview · 2 November 2026

**Reports**

- Report studio: eight designs (Classic, Editorial, Briefing, Analytics, Technical,
  Overview, Reading series, Ledger & margin), live preview, HTML and native signed PDF.
  Switching designs keeps filters, charts and notes.
- Pick report data by chat, author, date and event type and preview it before saving.
  Edits show before/after, deletions show what was saved earlier.
- Reports look like proper dossiers now: cover, key figures, evidence map, numbered
  findings, timeline. PDFs get an A4 cover with QR, bookmarks and page refs.
- Each report explains what its conclusions rest on: export-time checks, observations,
  missing material, how to check it independently (EN/RU/DE wording).
- Send, edit and observed times are shown separately, plus replies, threads and metadata.

**Case Board and groups**

- Private Case Board: signed bookmarks, exact-version highlights, action slices,
  collections, threaded comments and statuses. Team notes stay apart from observations;
  the verifier checks board exports too. Export permission alone doesn't reveal team notes.
- Account groups share settings. Members follow the group, an account's own value wins
  until reset. Changes show which accounts they hit and ask before overwriting. Access can
  be granted to a whole group.
- Group screen at `/groups/<id>`: accounts, problems, shared chats, group export.

**Setup and connection**

- Six-step first setup and one Settings page with simple/standard/expert levels, in all
  25 languages. Each step has its own URL, Back works.
- The setup asks whether the account is a separate one; a main account only records
  chosen chats. After Start it shows that connection, events, sources and files work.
- Guided Connection screen: pick accounts, prepare and check a route, then apply. Direct,
  own proxies, public MTProto pool, WireGuard profiles and portable WARP.
- Automatic connection tries public MTProxy, then WARP, then direct (if allowed) and shows
  a status indicator instead of failing silently.
- Video duration limits in file policies.

**Panel and safety**

- No more one-click accidents: pausing, excluding and removing sources are confirmed,
  sending from a chat needs "Write as @account" first, route changes while observing
  offer to pause.
- One set of counters everywhere (deleted with text, deleted before saving, missing on recheck).
- Account files are inspected before connecting. URL, workspace and account always agree,
  a mismatch blocks actions. Chats open read-only and mask detected secrets.
- Downloads fall back to normal browser downloads, big archives stream through one-time
  cookies. Prepared exports keep size, SHA-256 and "Download again".
- Panel token rotation keeps the new session alive. Temporary network failures offer Retry.
- Panel dialogs instead of `window.confirm`, journal paging fixed, lots of small UI fixes.
- Public-channel showcase: expiring read-only links with redacted authors and signed snapshots.

**Servers and evidence**

- Extras → Server 24/7: a Hetzner server from the panel with a quick tunnel or your own
  domain. `python -m tgwitness.cloud destroy` cleans everything up.
- Phala Cloud option: the collector runs in an Intel TDX confidential VM, `verify` checks
  the attestation up to Intel's root.
- Gateway DNS (`--gateway-dns`): the server only resolves through Cloudflare Gateway.
- Optional drand rounds and Telegram device lists in evidence mode.
- Setup by goal: four questions, suggested settings, credibility and reliability scales.

**Other**

- Notification service catalog with icons, optional operator control bot, Discord witness posts.
- Storage separates backups, verified file offloading and evidence retention.
- AI previews show the endpoint and outside route.
- Pull requests run both panel suites, including Firefox and WebKit downloads. Release
  packages wait for dependency, CodeQL and container audits.
- Docs: a [panel guide](PANEL.md) for every screen.

## 0.7.1 preview · 1 November 2026

- **Start here** with two paths: export my account, or follow an investigation.
- Account export through Telegram Takeout or the regular API, resumable, with signed progress
  and coverage records ([account export](ACCOUNT-EXPORT.md)).
- Separate signed sharing copies with filters, pseudonyms and optional text/file removal.
  Signatures prove integrity, not authorship or admissibility.
- Readable offline reports for account exports and sharing copies, printable, with record
  links and instructions for the recipient.
- Clear handoff after download: original vs sharing copy, report preview, instructions to copy.
- Rejected Telegram logins are told apart from paused accounts and network errors.
  **Sign in again** keeps the workspace.
- Load the history of enabled sources with pause/resume, plus a signed progress report
  ([history](HISTORY.md)).
- Read-only MCP at `/mcp`, local archive search with optional AI, local OCR/transcription,
  signed webhooks with retries.
- GitHub Actions capture preview: one chat on a temporary runner, encrypted result,
  pinned provenance ([sealed capture](SEALED-ACTIONS.md)).
- Self-contained signed reports in 25 languages with chain of custody; archives add
  `custody.json` and `SHA256SUMS`.
- Panel rework: workspace URLs, Back/Forward, drafts survive updates, Ctrl/Cmd+S, Sources
  split into tabs, Parameters search, journal filters and inspector, live updates.
- Batch session import, account groups, MTProxy dashboard with ping, countries and own lists.
- MTProxy decryption through OpenSSL (it used to eat a whole CPU core).
- Stronger masking in sharing copies, bounded media decoding, repeatable source ZIPs.
- Notification services refuse redirects. Weekly Dependabot, nightly CodeQL and container scans.
- Lots of fixes: stuck chat profiles, quick search, DST in search dates, 502s behind
  Caddy, GIF/sticker downloads, slow proxy list parsing, duplicate sessions on import.

## 0.7.0 preview · 31 October 2026

- OpenTimestamps proofs are parsed strictly; Bitcoin attestations show as
  `bitcoin-unverified` until you run `ots verify`.
- Verification reports which part of the journal witness checkpoints cover;
  `--require-witness` demands a pinned witness and matching final record.
- Access and permissions guides, updated proxy and IP mode guides.
- Panel and docs site in 25 languages. Site publishing fails on missing translations.
- Added the [roadmap](ROADMAP.md).

### Initial preview contents · 30 October 2026

- First GitHub release: Windows portable, wheel, source archive.
- The setup guide has an "Open to everyone" section: no country or sanctions blocks, and
  Taylor Wessing as the only incompatibility we name. It is our position, not a licence condition.
- The README and Wiki now present the authors' Ethical Notice & Historical
  Continuity statement, with document references, historical context and an
  explicit explanation that MIT permission applies to everyone.
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
- High-assurance deployment (`python -m tgwitness.cloud`, [guide](HIGH-ASSURANCE.md)) on
  Hetzner, DigitalOcean, Linode, Vultr or EC2: no SSH key, no inbound ports, panel only
  through a Cloudflare Tunnel, and a `verify` command for third parties.
- Local launchers open the panel in the browser once it's up.
- Read-only online demo of the real panel with fictional data.
- Wiki with 13 guides, docs website with a reference section, search, diagrams and 13 languages.
- **Sign out of Telegram** on the Account page.
- About 940 Russian panel strings fixed by hand.
- Observation scope: chosen chats, a folder or the whole account, by type. New chats are
  picked up immediately.
- Investigation mode for accounts that join groups and talk to bots.
- People profiles (opt-in per chat), independent witness bot, notification excerpts,
  Parameters page, light/dark theme.
- Panel mini-client: send messages, press bot buttons, preview and join invites.
- Fixed message loss after a long stop (rechecks used to stop after 1,000 messages).
- Many fixes from a full review: attachment byte counts, restore checks, scope edge cases,
  verify.py witness handling, off-site copy retries.
- Pillow 13 (39 advisories against 12.3).

## 0.6.1 · 27 October 2026

- Renamed TgWatch to TgWitness, old archives still verify.
- Evidence mode timestamps checkpoints with RFC 3161 and OpenTimestamps.
- Password-protected AES-256 ZIP exports.
- Notifications through Apprise.
- 13 interface languages; README, Quick start and Deployment in 12 languages.
- Encrypted off-site copy to S3-compatible storage with Object Lock.
- Catch-up after restart and rechecks every 15 minutes.
- Built-in pool of public API pairs, no own API ID needed.
- New Chats view, Accounts view, multi-account chat export, signed full chat export.
- Windows portable package, public website, GitHub Pages workflow.
- Better launchers on all platforms, redesigned panel, new logo.

## 0.6.0 · 27 October 2026

- New account form with Phone, QR code, Files and Auth key tabs.
- Auth Key + DC ID sign-in, Telethon/Pyrogram sessions, TData ZIPs, StringSession, account JSON.
- QR login with 2FA, Desktop local passcodes.
- Demo opens on its sample journal; refreshed panel look.

## 0.5.1 · 27 October 2026

- Only the active account client is accepted; rejected logins are disconnected.
- Windowless Windows launches with logs in `logs/server.log`.
- Case-insensitive Unicode search, full UTC dates on phones.
- Linux/macOS launch scripts, Docker helpers, optional HTTPS with Caddy, GHCR images.
- Docs on export signatures and investigation handoff.

## 0.5.0 · 26 October 2026

- Per-account monitoring categories, presets and signed policy changes.
- Direct local entry to synthetic demos.

Older history: [release status](internal/RELEASE.md) and [verification](VERIFICATION.md).
