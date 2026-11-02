<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/wiki-investigations-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/wiki-investigations-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/wiki-investigations-mobile.svg">
  <img src="../assets/presentation/wiki-investigations.svg" width="1200" alt="Follow the connections. Search across chats and return to the source records.">
</picture>

# Investigations across chats

**02 · INVESTIGATE AND EXPORT** · [All guides](Home.md) · [Get help](../../.github/SUPPORT.md)

<details>
<summary>On this page</summary>

- [Set up the case](#set-up-the-case)
- [Keep a source register](#keep-a-source-register)
- [Follow changes and connections](#follow-changes-and-connections)
- [Organize and review on Case Board](#organize-and-review-on-case-board)
- [Record deliberate actions](#record-deliberate-actions)
- [Work with the saved archive](#work-with-the-saved-archive)
- [Hand over the case](#hand-over-the-case)

</details>



Use one dedicated account and a clearly defined question. Keep source observations, your interpretation and unresolved questions separate throughout the case.

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-feature-investigate-static.svg"><img src="../assets/presentation/readme-feature-investigate.svg" width="420" alt="Illustrated workflow: follow a shared lead to its source records."></picture></p>

## Set up the case

1. Define the question, relevant time range and sources you intend to observe.
2. Choose an explicit scope in **Sources**. Use whole-account collection only when the dedicated account's other conversations also belong to the investigation.
3. Review outgoing-message, bot, attachment and event settings.
4. Start observation and record its start time.
5. Save current chat histories where earlier visible context is needed.

Investigation mode prepares collection of the account's visible chats and actions. Retain the history acquisition results alongside the coverage of ongoing observation.

## Keep a source register

For each source, retain its workspace, numeric chat ID, observed title/username, reason for inclusion, acquisition method and time range. Add access changes and gaps. The numeric ID keeps the source identifiable through name and username changes.


<picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture>

## Follow changes and connections

In **Journal**, search **All sources**. Open a matching record and retain its workspace, chat ID, message ID, sequence and hash. In **Chats**, compare saved versions.

People profiles are opt-in per chat. They can show observed names, reply relationships, mentions and other chats in the workspace where the same Telegram ID wrote. Open the cited records before treating a derived fact as a finding.

| Matching observation | What it supports |
| --- | --- |
| Same numeric sender ID | The saved records identify the same Telegram account |
| Same URL or wallet string | The records contain the same string; ownership is a separate question |
| Same attachment SHA-256 | The preserved file bytes match |
| Similar name or avatar | A lead to examine using the cited account records |

## Organize and review on Case Board

Open **Investigation → Case Board** in Standard or Expert mode and create a collection for
the case. Use **To board** (or **B**) beside a journal record or saved chat message to keep its
source reference on a card. Select an exact passage for **Highlight → board**, Shift-click two
records in one chat for **Slice between**, or save Journal's current filters as a slice.

Sort cards into collections, discuss them in threads and set a team status. Signed revisions
retain the team's changes. **Presentation** walks through cards, source context and comments
without editing controls. Workspace and chat permissions also apply; configure board rights
in [Access](Access.md).

Team annotations stay in the workspace with their own signed history, separately identifiable
from Telegram observations. Reports label them as team notes; minimized handovers include them
when selected. Evidence ZIPs carry the board, and slices export as signed JSON. See
[Case Board](../CASE-BOARD.md) for roles, exports and verification.

## Record deliberate actions

The panel can save an invitation preview, join/open a supported Telegram link, send text/replies and press supported bot buttons. These are real actions by the selected account. Keep their request/result records with the resulting messages.

An unknown action outcome should be checked before retrying. Callback presses in another Telegram app are not themselves visible to the collector. Payment, phone/location and web-app workflows are outside the mini-client's supported actions.


<picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture>

## Work with the saved archive

Use **Ask the archive** to search saved records and review optional AI answers.
For MCP clients, local OCR/transcription and outgoing webhooks, start with
[Archive and integrations](Archive-and-Integrations.md). Analytical reports keep
source references and revisions separately from the signed journal.

## Hand over the case

Build a timeline citing saved records, with both source time and observation time where available. Include the source register, scope changes, gaps, signed evidence ZIPs, separate history exports, checkpoints and trusted fingerprints.

In **Exports → Configure and preview**, choose the report's data, design, contents and written
findings. Include Case Board bookmarks and slices, or team comments, when useful to the recipient.
[Report studio](../CASE_REPORTS.md) offers eight designs for supported HTML and native PDF outputs.
Use the separate handover controls when the recipient needs a minimized copy.

**Accounts → group → Export group** packages the accounts' signed exports with a signed file
list. Keep each workspace's fingerprint with its records. A cross-account narrative and combined
timeline are assembled separately, citing the original workspace for each observation.

**Next:** [Case Board](../CASE-BOARD.md) · [Report studio](../CASE_REPORTS.md) · [Exports](Exports-and-Verification.md) · [Worked cross-chat case](../INVESTIGATION.md)
