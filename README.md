<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="docs/assets/presentation/casework-hero-mobile.svg">
  <img src="docs/assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — Follow the trail. Preserve the evidence. An illustrated message, captured edit and retained record show the investigation workflow.">
</picture>

<p align="center">
  <a href="https://phishdestroy.github.io/TgWitness/demo/"><picture><source media="(prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/casework-nav-demo-static.svg"><img src="docs/assets/presentation/casework-nav-demo.svg" width="296" height="76" alt="Explore the workspace"></picture></a>
  <a href="#quick-start"><picture><source media="(prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/casework-nav-start-static.svg"><img src="docs/assets/presentation/casework-nav-start.svg" width="296" height="76" alt="Start your first case"></picture></a>
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><picture><source media="(prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/casework-nav-wiki-static.svg"><img src="docs/assets/presentation/casework-nav-wiki.svg" width="296" height="76" alt="Open the handbook"></picture></a>
</p>

<p align="center">Self-hosted Telegram archive with message history and signed exports.</p>

<p align="center">
  <a href="docs/CHANGELOG.md"><img src="docs/assets/presentation/identity-meta-version.svg" width="144" height="30" alt="v0.7.0 · pre-release"></a>
  <a href="docs/VERIFICATION.md"><img src="docs/assets/presentation/identity-meta-verification.svg" width="158" height="30" alt="Tested environments"></a>
  <img src="docs/assets/presentation/identity-meta-languages.svg" width="279" height="30" alt="25 interface languages · 26 guide languages">
  <a href="LICENSE"><img src="docs/assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a>
</p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="docs/assets/presentation/readme-divider-static.svg"><img src="docs/assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Features

- Save messages, media, observed edits and deletion notices.
- Search across captured chats and connect people, replies and shared links.
- Keep separate sessions, sources and signing keys for each account.
- Export readable HTML, JSON or a signed evidence ZIP.
- Share selected accounts and chats with scoped access.
- Connect read-only MCP clients; review AI answers and separate analytical reports.
- Run optional local OCR/transcription and signed outgoing webhooks.

[Collection](docs/COLLECTION.md) · [Investigation](docs/INVESTIGATION.md) · [Access](docs/ACCESS.md)

[MCP setup](docs/MCP.md) · [Archive analysis](docs/ANALYSIS.md) · [Local media processing](docs/MEDIA-ANALYSIS.md) · [Webhooks](docs/WEBHOOKS.md)

<a name="screenshots"></a>

[![Workspace with fictional data](docs/assets/workspace.png)](https://phishdestroy.github.io/TgWitness/demo/)

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## Quick start

**Windows:** [download the portable package](https://github.com/phishdestroy/TgWitness/releases/download/v0.7.0/TgWitness-0.7.0-windows-amd64-portable.zip), extract it and run `TgWitness.cmd`.

**From source:** requires Python 3.11+. The launcher prepares the environment.

| | Windows | Linux / macOS |
| --- | --- | --- |
| Demo | `scripts\Demo.cmd` | `sh start.sh --demo` |
| Connect Telegram | `Start.cmd` | `sh start.sh` |

Open **http://127.0.0.1:8787**. Use a separate Telegram account. Stop the demo before
starting live mode; the live panel token is in `data/live/panel-token.txt`.

[Setup](https://phishdestroy.github.io/TgWitness/docs/start/) · [Dedicated account](https://phishdestroy.github.io/TgWitness/docs/dedicated-account/) · [Docker and servers](docs/DEPLOYMENT.md)

## Export through GitHub

[Open the capture page](https://phishdestroy.github.io/TgWitness/docs/capture/).
Run the pinned collector from your fork, select one chat and download an encrypted
archive with GitHub provenance. Also available under **Exports** in the panel.

[Instructions](docs/SEALED-ACTIONS.md) · [Русский](docs/ru/SEALED-ACTIONS.md)

<a name="how-it-works"></a>

## Verify an archive

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --checkpoint checkpoint.json
```

Obtain the key fingerprint and checkpoint independently. Verification checks
integrity against those trusted inputs. A local signing key alone does not prove
Telegram origin or complete history.

[Evidence format](docs/EVIDENCE.md) · [Witness](docs/WITNESS.md) · [Timestamps](docs/TIMESTAMP.md)

<a name="layout-review"></a>

## Operations

[Notifications](docs/OPERATIONS.md#notifications) · [Encrypted off-site copy](docs/wiki/Off-site-Copy.md) · [Backup and recovery](docs/wiki/Backup-and-Recovery.md) · [Troubleshooting](docs/OPERATIONS.md)

TgWitness can only collect what the connected account can access. It cannot recover
unseen deleted messages or Secret Chats; downtime may leave gaps.

[Documentation](docs/README.md) · [Wiki](https://github.com/phishdestroy/TgWitness/wiki) · [Security](.github/SECURITY.md) · [Tests](docs/VERIFICATION.md)

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
| [`tests/`](tests/README.md) | Synthetic regression tests |
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
