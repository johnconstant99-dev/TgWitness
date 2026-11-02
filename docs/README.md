![TgWitness documentation](assets/presentation/docs.svg)

# TgWitness documentation

Install TgWitness, connect your account and choose what to save.

[Project overview](../README.md) · [GitHub Wiki](https://github.com/phishdestroy/TgWitness/wiki) · [Offline handbook](wiki/Home.md) · [FAQ](wiki/FAQ.md)

![Observe, preserve and verify.](assets/presentation/workflow.svg)

## Start here

**Install TgWitness with Python included:**

Linux / macOS (Bash; root for an Ubuntu server, normal user on a desktop):

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

Windows (PowerShell or Command Prompt, no administrator):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

[Install, verify signatures and hashes, open the panel, update or remove](INSTALLATION.md).
The same links serve the current published preview build. Your program and data
stay on your machine; Cloudflare Workers hosts the download files.

**Licence:** [MIT License](../LICENSE). Our
[position on Taylor Wessing](TAYLOR-WESSING-EXCLUSION.md) adds no condition to it.

> **Ethical Notice & Historical Continuity**
> [Read our author statement](ETHICAL-NOTICE.md) and its source record.

Start with a local demo, then connect one account and check a captured message.
The proxy and witness bot are separate options.

1. [Try the demo](QUICKSTART.md#explore-the-interface) — explore the workspace with fictional data.
2. [Connect and collect](wiki/Getting-Started.md) — capture a message from a chat you control.
3. [Understand the record](HOW-IT-WORKS.md) — learn what signatures and coverage can establish.

## Find your workflow

[Panel safeguards and import checks](PANEL-SAFETY.md) · [Cloud storage, disk space and recovery](STORAGE.md)

History loading, archive analysis, MCP, local OCR/transcription and webhooks are
included in 0.7.1. [Start with the workflow guide](https://phishdestroy.github.io/TgWitness/docs/archive/).

| I want to… | Start here | What I should see |
| --- | --- | --- |
| Try the interface | [Quick start](QUICKSTART.md#explore-the-interface) | Fictional conversations; no Telegram login |
| Connect my account | [Account setup](ACCOUNTS.md) | A new test message in the journal |
| Choose a goal and change settings | [First setup and settings](SETTINGS.md) | Every value marked as the goal's or your own |
| Find my way around the panel | [Panel guide](PANEL.md) | What each screen, switch and Extras card does |
| Add independent browser or AyuGram capture | [Optional capture](OPTIONAL-CAPTURE.md) | Separate panels, switchable capture and video, signed originals and standalone verification; preview |
| Check how protected a workspace is | [Protection modes](PANEL.md#protection-modes) | The active protection layers and what is still missing |
| Check that the program matches GitHub | [Code check](PANEL.md#code-check) | A `source.checked` journal record listing any differing files |
| Run several accounts together | [Account groups](ACCOUNTS.md#bulk-import-and-account-groups) | Shared settings, one page for problems and shared chats, one group export |
| Capture one private chat from my fork | [GitHub Actions capture (preview)](SEALED-ACTIONS.md) | An encrypted archive and verification against the approved upstream workflow |
| Load older messages into the workspace | [Source history](HISTORY.md) | Resumable capture and a signed progress report |
| Export an account with a defined scope | [Account export](ACCOUNT-EXPORT.md) | Selected messages and files, resumable jobs and a signed archive with coverage records |
| Prepare a copy for a lawyer or another recipient | [Minimized disclosure](ACCOUNT-EXPORT.md#prepare-a-disclosure-for-a-lawyer-or-another-recipient) | A separate signed copy with participant pseudonyms and optional text/files; the source stays unchanged |
| Give a reviewer or analyst access | [Access and permissions](ACCESS.md) | Only the chosen accounts, chats and permitted actions |
| Connect an AI client | [Read-only MCP](MCP.md) | Expiring access to selected workspaces and chats |
| Ask questions and write a report | [Archive analysis](ANALYSIS.md) | Reviewed sources, verified references and separate analyst revisions |
| Keep team notes on a case | [Case Board](CASE-BOARD.md) | Signed bookmarks, highlights, slices and discussions, kept apart from observations |
| Hand over a readable report | [Case reports](CASE_REPORTS.md) | A signed HTML, PDF or JSON report with the chosen design, charts and scope |
| Read text in saved attachments | [Local OCR and transcription](MEDIA-ANALYSIS.md) | Hash-linked machine recognition, separate from original evidence |
| Connect n8n or a SIEM | [Signed webhooks](WEBHOOKS.md) | Scoped notifications with delivery status |
| Investigate across the whole account | [Complete investigation walkthrough](INVESTIGATION.md) | A source register, cited cross-chat timeline, people/file connections and verified evidence per workspace |
| Choose a connection route | [Proxy settings](CONNECTION-SECURITY.md) | A successful Telegram connection check |
| Share a verifiable record | [Export and verify](EVIDENCE.md#investigation-handoff) | Valid signatures and the expected key fingerprint |
| Publish checkpoints to a channel | [Witness bot](WITNESS.md#run-a-witness) | A signed post from the running witness |
| Leave it running on a server | [Deployment](DEPLOYMENT.md) | Persistent storage and capture after a restart |
| Let a third party check the server itself | [High-assurance deployment](HIGH-ASSURANCE.md) | A report from the provider, Cloudflare and the collector |
| Diagnose a problem | [Operations](OPERATIONS.md) | A concrete cause and a way to check recovery |

**What has actually been tested:** [verification record](VERIFICATION.md), including
a dated live server inventory of journal and message-event counts. Real Telegram
observations, synthetic tests and remaining live qualification work are recorded
separately. A signed journal establishes integrity relative to a trusted key;
a controlled delivery test checks particular Telegram events.

For step-by-step instructions, use the [wiki](wiki/Home.md).
For terminology, use the [glossary](wiki/Glossary.md).

<details>
<summary>Technical reference</summary>

- [Collection and visibility](COLLECTION.md)
- [Complete project guide](PROJECT-GUIDE.md)
- [Evidence format and trust boundaries](EVIDENCE.md)
- [Architecture](ARCHITECTURE.md)
- [Security model and data handling](SECURITY-MODEL.md)
- [Access scopes, permissions and sessions](ACCESS.md)
- [Connection and secret storage](CONNECTION-SECURITY.md)
- [Readiness and known limits](internal/READINESS.md)
- [Live acceptance procedure](internal/LIVE_ACCEPTANCE.md)
- [External timestamps](TIMESTAMP.md)
- [Release procedure](internal/RELEASE.md)

</details>

The online guides include examples you can try in your browser: follow a message
through its edits, check a signature or explore a sample investigation. These
examples use fictional data and do not contact Telegram.
[Preview it locally or publish it to GitHub Pages](internal/PUBLISHING.md#preview-the-website-locally).
[Website structure and SEO](internal/SEO.md) describes the metadata and post-deployment checks.


![Section divider](assets/presentation/divider.svg)

## Browse the source

[Repository map](../README.md#repository-map) · [Documentation assets](assets/README.md) · [Wiki source](wiki/README.md)
