# Account export and minimized disclosure

Open **Exports → Account export** as the installation administrator. Choose **New account export**, review the scope, and start. Every workspace has its own jobs, signing identity and storage. Issued panel access, including an unrestricted ordinary export grant, cannot open these account-wide routes.

This workflow exports data currently accessible to the connected account. The default uses [Telegram Takeout](https://core.telegram.org/api/takeout); it is not a backup of unavailable or deleted Telegram data. Secret Chats, inaccessible history and earlier edits are not recovered. Telegram can impose a waiting period before Takeout starts. The panel displays that wait; it does not silently switch transport. The explicit regular-API option has different coverage and records unsupported categories.

## Choose what is collected

| Setting | Meaning |
| --- | --- |
| Purpose | Record why this acquisition is needed. Do not put unnecessary names or sensitive case details here. |
| Chat kinds / chat IDs | All selected kinds, or just the listed chats; Saved Messages belongs to private chats. Archived chats are separately selectable. |
| Dates | UTC. The panel's From and Through calendar dates are both included. The API uses inclusive `from_utc` and exclusive `to_utc`; the panel sends the start of the day after Through. An empty bound leaves that side unrestricted. |
| Sender IDs | Only messages by the listed senders; an empty list includes all senders. |
| Text contains | Case-insensitive literal phrases, matched with OR. Sender/date/own-message conditions combine with AND. |
| Own messages | Keep only outgoing messages. |
| Media types | Select attachment categories, or clear all to avoid downloading message files. |
| File / total media limits | Per-file MiB and total downloaded-media GiB. Text, receipts, readable reports and ZIP overhead require additional disk space. |
| Account categories | Profile, contacts, profile photos, stories, session metadata and other Takeout data have separate controls. |

The **Minimize collection** preset disables files and account metadata. Sender/content filters apply before retained message pages and media downloads. Telegram still transmits API history pages containing messages needed to evaluate those filters: filtering is not a promise that unselected messages never enter process memory. Other ongoing observation in the workspace has its own scope and retention settings.

Profile-photo history and stories are not selected by default. Disable profile and contacts as well when the case needs messages only. If attachments or metadata are unnecessary, excluding them during acquisition avoids retaining another private copy in this export.

## Resume, coverage and verification

Each job freezes its options and account identity. Inventory and captured pages are signed; page receipts record hashes, cursors, times, attachment outcomes and their preceding receipt. Only committed pages advance progress. Restart/resume checks those records before continuing. A changed account, changed signed page or inconsistent receipt chain is rejected. Options cannot be edited halfway through an acquisition: start another job for another scope.

Pause releases the running account operation. Restarting the application leaves unfinished work available for explicit resume. An expired Takeout session requires an explicit resume; changing Telegram split ranges can require a new acquisition. Resume retains previous observations, so a long-running export is not one atomic snapshot. Other account-changing operations and conflicting exports are blocked during acquisition. Wait for packaging to finish before deleting a workspace.

Resume verifies already captured content before continuing. Large archives on slow storage can exceed the configured **Parameters → Panel action timeout** (120 seconds by default). Increase that setting before retrying; cancellation/storage interruption leaves a paused job, and failed integrity checks leave a failed job with an explanation. Verification must finish or stop safely before its files can be closed. No large-account throughput claim has been validated by the synthetic checks.

The panel distinguishes a completed selected scope from a partial archive, and records omissions and failed reads. Deliberately excluded files are different from failed or unavailable files. Inspect coverage even when integrity verification succeeds. No local reader can prove Telegram returned every message that ever existed.

Finished ZIPs remain available for repeated and HTTP-range downloads. An account archive contains `manifest.json`, `manifest.sig`, signed `job.json`, `inventory.json`, `receipts/`, authoritative `data/*.jsonl`, selected `media/`, readable HTML and a verifier. Pin the collector fingerprint through an independent channel, then verify using a trusted installation:

```sh
python -m tgwitness.verify account-export.zip --fingerprint TRUSTED_SHA256
```

For archives whose expanded contents exceed 4 GiB, set an explicit adequate `--max-gib`. The panel verifies its authenticated, completed local archives using their declared expanded size and published ZIP digest; the external CLI keeps its independent size limit. Verify before opening the readable HTML. The archive's bundled verifier is convenient, but a verifier obtained independently avoids trusting executable code delivered with the evidence.

The Ed25519 signature and SHA-256 hashes detect changes after the collector committed the relevant bytes. They do **not** prove that Telegram signed those messages, that the collector operator was honest, that the account's history is complete, or that a court will accept the material. Capture times use the collector's clock. Independent timestamps and independent acquisition provenance must be evaluated separately.

## Prepare a disclosure for a lawyer or another recipient

From a finished account export, choose **Prepare disclosure**. This builds a separate signed derivative. The source ZIP remains unchanged and private; do not send it together with a minimized derivative unless the recipient is authorized to receive its full contents.

1. Enter the disclosure purpose and select dates, sender IDs and literal text criteria.
2. Choose whether to keep identities, reveal only listed participants, or pseudonymize everyone. In either pseudonymized mode chat IDs/titles and message IDs are also replaced. Pseudonyms are stable inside one disclosure and change between independently prepared disclosures.
3. Keep message text, omit it entirely, or add literal names/phrases to mask. In private modes the tool also masks known hidden sender names and alternate usernames, whole-token sender IDs, direct-chat names, links, email addresses and phone-like strings. Known-name matching handles Unicode case folding, including `Straße`/`STRASSE`. Generic group/channel titles are not automatically removed from message text. If the known-identity masking limit is exceeded, narrow the source export or omit text; the tool refuses to silently skip later names. These are best-effort rules, not general anonymization.
4. Leave files excluded unless the recipient needs them. Included originals retain their pixels, audio, text and metadata. They are **not** anonymized by the tool.
5. Preview the counts, warnings and sample transformed messages, then explicitly confirm creation. Samples are limited to 12 messages and 2,000 text characters each. This is a sample, not a full review of the result. Changing settings requires another preview. A preview expires after 15 minutes and is bound to that administrator session and exact original ZIP; it cannot be reused after creation. A new preview invalidates the previous one for the same job and session.
6. Inspect the complete resulting `index.html` and `messages.jsonl` locally before handing it over. If it reveals unnecessary information, create a new disclosure with stronger exclusions. Do not edit the signed ZIP in place.

The minimized format omits structured account profiles, contacts, avatars, sessions, stories, raw Telegram objects, forwarding headers, reply quotations, contact cards and location metadata. It excludes the original JSONL files, private filter settings, pseudonym key and identity map. Selected text, explicitly retained identities and included files can still contain the same names, IDs or phrases used in those filters; they need separate review. The private policy and pseudonym key are retained encrypted in the local vault for the job; deleting the job clears its associated private disclosure records. The public policy records filter counts rather than filter values. The stated purpose is public in the manifest and HTML: explicit private criteria and, in pseudonymized modes, known hidden identities are masked there too, including when message text is omitted. Keep the purpose free of unnecessary personal details; unknown identifying context can remain.

Its manifest binds the derivative files, public policy and original ZIP's hash. Verification can establish integrity and, if the source is supplied locally, matching source linkage:

```sh
python -m tgwitness.verify minimized-disclosure.zip --fingerprint TRUSTED_SHA256
python -m tgwitness.verify minimized-disclosure.zip --fingerprint TRUSTED_SHA256 --evidence account-export.zip
```

Source linkage does not independently prove that the transformation selected every required item or removed every identifying detail. Original plaintext is not embedded as a proof. A fresh review is needed for that judgment.

## Data protection and the hosted Capture preview

These controls support purpose limitation and data minimization; they are not an automatic legal compliance check. [GDPR Articles 5 and 25](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng) address those principles and protection by design/default. A lawful basis, necessity, special-category conditions where applicable, retention, security and recipient access still need a decision appropriate to the case. A litigation purpose alone does not make every disclosure lawful. Pseudonymized data generally remains personal data; see the [EDPB explanation](https://www.edpb.europa.eu/topics/ai-and-technology/anonymisation-pseudonymisation_en).

Free text, dates, rare events and combinations of facts can identify people even after names are removed. Prefer text omission where message content is unnecessary; inspect the full derivative where it is necessary. Keep the source and vault protected, agree retention and sharing with the responsible person, and record which exact ZIP was handed over.

This feature runs in the local panel. The separately published [hosted Capture preview](https://phishdestroy.github.io/TgWitness/docs/capture/) uses a pinned disposable runner and its own attestation policy. Local collector signatures do not inherit that runner's provenance. A change here does not update an approved remote workflow or its trust pins; hosted full-account capture needs a separately reviewed and published collector/workflow pair and live runner acceptance. No hosted deployment or real Telegram account acquisition is claimed by local synthetic tests.

[Русская инструкция](ru/ACCOUNT-EXPORT.md) · [Evidence format](EVIDENCE.md)
