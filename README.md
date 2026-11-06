<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="docs/assets/presentation/casework-hero-mobile.svg">
  <img src="docs/assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — Follow the trail. Preserve the evidence. A captured message, its saved edit and a retained record.">
</picture>

<p align="center">
  <a href="https://phishdestroy.github.io/TgWitness/demo/"><picture><source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-nav-demo-mobile.svg"><img src="docs/assets/presentation/readme-nav-demo.svg" width="32%" alt="Explore the interactive demo"></picture></a>
  <a href="#quick-start"><picture><source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-nav-download-mobile.svg"><img src="docs/assets/presentation/readme-nav-download.svg" width="32%" alt="Download and start TgWitness"></picture></a>
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><picture><source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-nav-handbook-mobile.svg"><img src="docs/assets/presentation/readme-nav-handbook.svg" width="32%" alt="Read the investigation handbook"></picture></a>
</p>

<p align="center"><strong>Self-hosted workspace for Telegram investigations.</strong><br>Save chats, keep edits and deletions, see who's connected to whom<br>and hand over signed exports anyone can check.</p>

<p align="center">
  <a href="docs/CHANGELOG.md"><img src="docs/assets/presentation/identity-meta-version.svg" width="144" height="30" alt="v0.9.1 · pre-release"></a>
  <a href="docs/VERIFICATION.md"><img src="docs/assets/presentation/identity-meta-verification.svg" width="158" height="30" alt="Tested environments"></a>
  <img src="docs/assets/presentation/identity-meta-languages.svg" width="279" height="30" alt="25 interface languages · 26 guide languages">
  <a href="LICENSE"><img src="docs/assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a>
</p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

The version badge describes this source tree. Installable builds are listed under
[Releases](https://github.com/phishdestroy/TgWitness/releases); a feature merged into
`main` is not automatically included in those downloads.
[Current capabilities and qualification](docs/STATUS.md) · [Choose a collection method](docs/COLLECTION-MODES.md)

## Install

Python included. Use the same commands to update.

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell or CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Ubuntu server: run as root. Desktop: run as your normal user.</sub>

[Setup & panel access](docs/INSTALLATION.md) ·
[Signatures & SHA-256](https://get.destroy.tools/#verification) ·
[Update](docs/INSTALLATION.md#update-an-existing-installation) ·
[ZIP downloads](https://github.com/phishdestroy/TgWitness/releases)

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce) and (prefers-color-scheme: dark)" srcset="docs/assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/readme-workspace-mobile-light-still.webp">
  <source media="(prefers-reduced-motion: reduce) and (prefers-color-scheme: dark)" srcset="docs/assets/presentation/readme-workspace-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/readme-workspace-light-still.webp">
  <source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="docs/assets/presentation/readme-workspace-mobile-dark.webp">
  <source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-workspace-mobile-light.webp">
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/presentation/readme-workspace-dark.webp">
  <img src="docs/assets/presentation/readme-workspace-light.webp" width="1440" alt="The TgWitness demo in motion: captured messages, saved versions and content retained after deletion. Fictional demonstration records.">
</picture>
</a>

<p align="center"><sub>Explore the actual interface with fictional records. Click the workspace to try it.</sub></p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/readme-divider-static.svg"><img src="docs/assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## From a conversation to a case

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-features-mobile.svg">
  <img src="docs/assets/presentation/readme-features.svg" width="1200" alt="Three animated workflows: export a chat to HTML and JSON, find a shared link across recorded chats, and retain captured versions after a deletion notice.">
</picture>

<p align="center">
  <a href="docs/wiki/Chat-Export.md"><picture><source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-nav-export-mobile.svg"><img src="docs/assets/presentation/readme-nav-export.svg" width="32%" alt="Chat export guide"></picture></a>
  <a href="docs/INVESTIGATION.md"><picture><source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-nav-investigate-mobile.svg"><img src="docs/assets/presentation/readme-nav-investigate.svg" width="32%" alt="Investigation guide"></picture></a>
  <a href="docs/COLLECTION.md"><picture><source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-nav-history-mobile.svg"><img src="docs/assets/presentation/readme-nav-history.svg" width="32%" alt="Collection and saved versions"></picture></a>
</p>

Two ways to use it: [export your account](docs/ACCOUNT-EXPORT.md) once, or
[follow an investigation](docs/INVESTIGATION.md) and keep saving changes.
Pick a few chats, a Telegram folder or the whole account. Each account gets its
own workspace, session and signing key.

[Export settings](docs/EXPORT_HASHES.md) cover regular API and Takeout acquisition,
message history before attachments, file downloads or server hashes, and compatible
Telegram Desktop JSON/HTML views. GitHub capture supports an account or a selected
chat, records partial results at its deadline, and splits large encrypted deliveries.

## Built for the rest of the investigation

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-capabilities-mobile.svg">
  <img src="docs/assets/presentation/readme-capabilities.svg" width="1200" alt="Track names and usernames by Telegram ID. Record supported bot interactions with signed receipts. Search archived messages and connect read-only MCP clients. Deploy a collector with SSH masked and provider records for review. Illustrative workflows.">
</picture>

<p align="center">
  <a href="docs/INVESTIGATION.md#4-connect-observations-across-chats"><picture><source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-nav-people-mobile.svg"><img src="docs/assets/presentation/readme-nav-people.svg" width="48%" alt="People and dossiers"></picture></a>
  <a href="docs/COLLECTION.md#act-from-the-panel"><picture><source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-nav-bots-mobile.svg"><img src="docs/assets/presentation/readme-nav-bots.svg" width="48%" alt="Bot investigation"></picture></a>
</p>
<p align="center">
  <a href="https://phishdestroy.github.io/TgWitness/docs/archive/"><picture><source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-nav-archive-mobile.svg"><img src="docs/assets/presentation/readme-nav-archive.svg" width="48%" alt="Archive search, AI and MCP"></picture></a>
  <a href="docs/HIGH-ASSURANCE.md"><picture><source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-nav-cloud-mobile.svg"><img src="docs/assets/presentation/readme-nav-cloud.svg" width="48%" alt="Sealed cloud deployment"></picture></a>
</p>

<details>
<summary><strong>Everything else</strong> · history, accounts, proxies, AI, integrations</summary>

| | |
| --- | --- |
| [Load older messages](docs/HISTORY.md) | Pull past history of selected chats, pause and resume any time |
| [Several accounts](docs/ACCOUNTS.md#multiple-accounts) | Export one chat through several accounts, each with its own session and key |
| [Batch import](docs/ACCOUNTS.md#bulk-import-and-account-groups) | Drop in a pile of session files, sort accounts into groups with shared settings |
| [MTProxy pool](docs/wiki/Proxies.md#pool-dashboard-and-custom-sources) | Ping, countries, filters, your own lists |
| [Existing sessions](docs/ACCOUNTS.md) | TData, Telethon, Pyrogram, StringSession, auth key |
| [Proxies](docs/CONNECTION-SECURITY.md#ip-modes) | SOCKS5, HTTP CONNECT or MTProxy per workspace. **Hide IP** never falls back to direct |
| [Search and AI](docs/ANALYSIS.md) | Local search, optional AI with sources you can check |
| [Full-text search](docs/SEARCH.md) | Word forms, exact phrases, domains, @usernames and Chinese without spaces, best matches first (**Preview**) |
| [MCP](docs/MCP.md) | Read-only access for MCP clients, limited to the chats you pick |
| [Command line](docs/CLI.md) | `search`, `context`, `messages`, `stats` and JSON Lines `export` with `--json` for scripts and agents, locally or with a scoped token (**Preview**) |
| [OCR and transcription](docs/MEDIA-ANALYSIS.md) | Runs locally, originals stay untouched |
| [Independent capture](docs/OPTIONAL-CAPTURE.md) | Optional browser/AyuGram recorders in Extras (preview, off by default) |
| [Trusted Live](docs/TRUSTED-LIVE.md) | Official Desktop/Web session, guarded video and native-export continuity analysis (preview; live qualification pending) |
| [Sealed official Web](docs/OFFICIAL-WITNESS.md) | Fresh official browser on GitHub Actions，restricted controls，signed video and independently expected source/settings |
| [Webhooks](docs/WEBHOOKS.md) | Signed outgoing events with retries, n8n example included |
| [Shared access](docs/ACCESS.md) | Give someone selected chats only, with expiry and IP limits |
| [Missing message numbers](docs/EVIDENCE.md#missing-message-numbers-gap_summary) | Numbers Telegram assigned that were never observed, per channel and for the whole account, in coverage, reports and MCP (**Preview**) |

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/readme-divider-static.svg"><img src="docs/assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<p align="center">
  <a href="https://phishdestroy.github.io/TgWitness/docs/start/"><picture><source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-nav-setup-mobile.svg"><img src="docs/assets/presentation/readme-nav-setup.svg" width="32%" alt="Setup guide"></picture></a>
  <a href="https://phishdestroy.github.io/TgWitness/docs/dedicated-account/"><picture><source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-nav-account-mobile.svg"><img src="docs/assets/presentation/readme-nav-account.svg" width="32%" alt="Prepare your account"></picture></a>
  <a href="docs/DEPLOYMENT.md"><picture><source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-nav-deploy-mobile.svg"><img src="docs/assets/presentation/readme-nav-deploy.svg" width="32%" alt="Docker and servers"></picture></a>
</p>

## Capture with GitHub provenance

**Preview.** Collect a chat on a GitHub-hosted runner with a pinned TgWitness and a
fresh Telegram session, then download the encrypted archive with its GitHub
attestation. The verifier checks the approved workflow and collector version, the
archive digest, the journal and attachments. Also available under **Exports** in the panel.

[Open the capture page](https://phishdestroy.github.io/TgWitness/docs/capture/) · [Instructions](docs/SEALED-ACTIONS.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/readme-divider-static.svg"><img src="docs/assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## A record someone else can check

An export carries the messages, files and the verifier. Send the recipient your
key fingerprint and a checkpoint through another channel and they can check it
themselves:

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --checkpoint checkpoint.json
```

The verifier checks signatures, the journal chain, the file manifest and attachments
against your trusted inputs. With a retained checkpoint it also checks the archive
against an earlier journal state.

[Archive verification](docs/wiki/Exports-and-Verification.md) · [Checks and tested scale](docs/VERIFICATION.md)

<details>
<summary><strong>Inside the signed record</strong> · hashes, signatures and independent checkpoints</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="docs/assets/presentation/casework-chain-mobile.svg">
  <img src="docs/assets/presentation/casework-chain.svg" width="1200" alt="New messages, saved edits and deletion observations form a linked, signed journal. Verify it against an independently trusted key.">
</picture>

[Evidence format](docs/EVIDENCE.md) · [Independent witness](docs/WITNESS.md) · [External timestamps](docs/TIMESTAMP.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/readme-divider-static.svg"><img src="docs/assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<!-- authors-manifesto:start -->

<a name="manifesto"></a>

## Check the capture and the saved record

<picture>
  <source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-manifesto-mobile.svg">
  <img src="docs/assets/presentation/readme-manifesto.svg" width="1200" alt="Capture the conversation. Verify the record. Save messages, edits and files, check signatures and checkpoints, and review the capture process.">
</picture>

TgWitness records content delivered to the connected Telegram account, with
chat, message and sender identifiers, captured versions and collection metadata.
The archive brings those records, preserved attachments and verification data
together for review.

| Check | What the recipient verifies |
| --- | --- |
| Signed journal and manifest | Record signatures, the hash chain and delivered files against the expected signing key. |
| Separately retained checkpoint | The journal against a previously recorded length and head hash. |
| Independent witness | The journal against checkpoints retained by a separate witness. |
| GitHub Actions capture | The archive against its attestation, approved hosted workflow and collector version. |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)
shows a Telegram conversation beside deliberately altered Desktop export files.
Compare the versions, inspect the changes, and follow the collection and
verification steps for a signed TgWitness archive.

[Verification steps](docs/wiki/Exports-and-Verification.md) ·
[GitHub capture](docs/SEALED-ACTIONS.md) ·
[Technical trust model](docs/SECURITY-MODEL.md)

<!-- authors-manifesto:end -->

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/readme-divider-static.svg"><img src="docs/assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="operations"></a>
<a name="layout-review"></a>

<details>
<summary><strong>Keep the investigation running</strong> · notifications, storage and recovery</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="docs/assets/presentation/readme-services-mobile.svg">
  <img src="docs/assets/presentation/readme-services.svg" width="1200" alt="Animated workflows: Apprise sends configured alerts; off-site copies are encrypted before upload to S3-compatible storage.">
</picture>

[Notifications](docs/OPERATIONS.md#notifications) · [Encrypted off-site copy](docs/wiki/Off-site-Copy.md) · [Backup and recovery](docs/wiki/Backup-and-Recovery.md) · [Troubleshooting](docs/OPERATIONS.md)

</details>

Collect cloud-chat data available to the connected account，with the selected period，
attachment policy and recorded collection outcomes．See the [mode comparison](docs/COLLECTION-MODES.md)
for history，live observation and sealed acquisition．

<p align="center">
  <a href="docs/README.md"><img src="docs/assets/presentation/readme-button-docs.svg" height="34" alt="Technical documentation"></a>
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><img src="docs/assets/presentation/readme-button-wiki.svg" height="34" alt="Investigation handbook"></a>
  <a href="docs/VERIFICATION.md"><img src="docs/assets/presentation/identity-meta-verification.svg" height="30" alt="Tested environments"></a>
</p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/readme-divider-static.svg"><img src="docs/assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<!-- operator-notice:start -->

<details>
<summary><strong>⚖️ Ethical Notice &amp; Historical Continuity</strong></summary>

We have recently learned that for certain law firms—and specifically Dr. Tobias Schelinski and Dr. Patrick Vincent Zurheide—mathematics and objective facts are irrelevant.

Selling GDPR non-compliance to corporations as a commercial service while failing at basic data handling yourselves is not legal expertise.

Operating under the delusion that you are the law, or that an elite signature on a falsified claim magically turns a lie into truth, does not mask technical incompetence.

This tool is incompatible with jurisdictions where the following prevail:

- Corporatocracy
- Privatized or commercial justice
- Plutocracy
- Kleptocracy and institutional corruption

A special mention to Dr. Patrick Zurheide, Dr. Tobias Schelinski, and those attempting to weaponize the "Right to be Forgotten" to bury their own data-processing failures, sanitize their institutional lineage, and erase the historical record:

> Taylor Wessing (Dr. Tobias Schelinski & Dr. Patrick Vincent Zurheide) → Wessing & Berenberg-Gossler → Stonewall Top 100 → Dr. Graf von der Goltz Dr. Wessing & Partner (since 1957) → Rüdiger Graf von der Goltz → Paragraph 175 in its 1935 revision

To strictly comply with the MIT License, we do not restrict the use of this software. However, let it be clear: corporate retainers, legal intimidation, and demands for digital erasure cannot override history, rewrite lineage, or conceal the truth.

[Source record](https://phishdestroy.io/steam_dossier/taylor_wessing)

[MIT License](LICENSE) · [Technical notice](docs/OPERATOR-INCOMPATIBILITY.md) · [Original NOTICE](NOTICE)

</details>

<!-- operator-notice:end -->

<a name="repository-map"></a>

<details>
<summary><strong>Repository map</strong> — source, deployment and contribution guides</summary>

| Directory | Contents |
| --- | --- |
| [`tgwitness/`](tgwitness/README.md) | Application, collector, journal, verifier and web panel |
| [`docs/`](docs/README.md) | Guides, Wiki source, screenshots and verification record |
| [`deploy/`](deploy/README.md) | Compose configurations and service templates |
| [`scripts/`](scripts/README.md) | Demo, setup and Docker launchers |
| [`tools/`](tools/README.md) | Builds, checks and packaging |
| [`website/`](website/README.md) | Documentation website and translations |
| [`.github/`](.github/AUTOMATION.md) | Workflows and contribution guides |

[Complete project guide](docs/PROJECT-GUIDE.md) · [Technical documentation](docs/README.md)

</details>

<details>
<summary><strong>Read the project overview in your language</strong></summary>

**English** · [Русский](docs/ru/README.md) · [Українська](docs/uk/README.md) · [Español](docs/es/README.md) · [Português (Brasil)](docs/pt/README.md) · [Türkçe](docs/tr/README.md) · [العربية](docs/ar/README.md) · [فارسی](docs/fa/README.md) · [اردو](docs/ur/README.md) · [हिन्दी](docs/hi/README.md) · [Bahasa Indonesia](docs/id/README.md) · [Tiếng Việt](docs/vi/README.md) · [简体中文](docs/zh/README.md)

</details>


<p align="center">
  <a href="https://github.com/phishdestroy"><img src="docs/assets/presentation/readme-button-project.svg" height="34" alt="Built by PhishDestroy"></a>
  <a href=".github/CONTRIBUTING.md"><img src="docs/assets/presentation/readme-button-contribute.svg" height="34" alt="Contribute"></a>
  <a href=".github/SUPPORT.md"><img src="docs/assets/presentation/readme-button-support.svg" height="34" alt="Get help"></a>
  <a href=".github/SECURITY.md"><img src="docs/assets/presentation/readme-button-security.svg" height="34" alt="Report a vulnerability"></a>
</p>
