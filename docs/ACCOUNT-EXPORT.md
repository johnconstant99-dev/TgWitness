# Account export and minimized disclosure

An account export reserves its account exclusively. Pause monitoring or another
acquisition explicitly before starting or resuming; the app never stops it automatically.

As the installation administrator, choose **Start here → Export my account**, or **Exports → Telegram account → Configure account export**. Sign in if needed, review the scope, and explicitly start the export. Continuous observation is not required. **Saved observations** is a separate export of the existing journal; its ZIP includes all sources regardless of journal filters. Every workspace has its own jobs, signing identity and storage. Issued panel access, including an unrestricted ordinary export grant, cannot open these account-wide routes.

Sender and text filters expand under **Filter by sender or message text**. **Account data & connection method** contains optional account categories and the Takeout/regular-session choice; its summary shows the active choices even when closed. Closing these sections keeps their settings. Export and report drafts remain in the current panel session while changing views; they are not saved through a browser reload. Existing jobs remain reachable from either export choice.

This workflow exports data currently accessible to the connected account. The default uses [Telegram Takeout](https://core.telegram.org/api/takeout); it is not a backup of unavailable or deleted Telegram data. Secret Chats, inaccessible history and earlier edits are not recovered. Telegram can impose a waiting period before Takeout starts. The panel displays that wait; it does not silently switch transport. The explicit regular-API option has different coverage and records unsupported categories.

## Choose what is collected

| Setting | Meaning |
| --- | --- |
| Purpose | Record why this acquisition is needed. Do not put unnecessary names or sensitive case details here. |
| Report language | Choose the language of the readable report's labels. Original message text remains unchanged; untranslated template labels use English. The language is fixed with the signed job options. |
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

Photo payloads use the still-image variant identified in their metadata and hash manifests，including photos with an animated avatar variant．That animation is not substituted for the selected still image．A shorter or longer payload than the observed size is recorded as a failed attachment，and a changed representation during file-reference renewal is rejected．These failures leave the archive partial while retaining the message records．Independent verification also rejects saved attachments whose signed length contradicts their observed size or representation，including in older archives．

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

After downloading a finished export, keep the original ZIP and open `index.html`
from an extracted copy. The report explains its scope, available coverage and
limits. Its record references combine the archive reference, document path and
record number, so a recipient can locate the same entry in the HTML or printout.
For a worked example, [open the fictional report](https://phishdestroy.github.io/TgWitness/demo/report/).

From a finished account export, choose **Prepare a sharing copy**. This builds a separate signed derivative. The source ZIP remains unchanged and private; do not send it together with a minimized derivative unless the recipient is authorized to receive its full contents. Choose its report language separately. Changing the language or any selection setting requires another preview before creation.

1. Enter the disclosure purpose and select dates, sender IDs and literal text criteria.
2. Choose whether to keep identities, reveal only listed participants, or pseudonymize everyone. In either pseudonymized mode chat IDs/titles and message IDs are also replaced. Pseudonyms are stable inside one disclosure and change between independently prepared disclosures.
3. Keep message text, omit it entirely, or add literal names/phrases to mask. In private modes the tool also masks known hidden sender names and alternate usernames, whole-token sender IDs, direct-chat names, links, email addresses and phone-like strings. Known-name matching handles Unicode case folding, including `Straße`/`STRASSE`. Generic group/channel titles are not automatically removed from message text. If the known-identity masking limit is exceeded, narrow the source export or omit text; the tool refuses to silently skip later names. These are best-effort rules, not general anonymization.
4. Leave files excluded unless the recipient needs them. Included originals retain their pixels, audio, text and metadata. They are **not** anonymized by the tool.
5. Preview the counts, warnings and sample transformed messages, then explicitly confirm creation. Samples are limited to 12 messages and 2,000 text characters each. This is a sample, not a full review of the result. Changing settings requires another preview. A preview expires after 15 minutes and is bound to that administrator session and exact original ZIP; it cannot be reused after creation. A new preview invalidates the previous one for the same job and session.
6. Inspect the complete resulting `index.html` and `messages.jsonl` locally before handing it over. If it reveals unnecessary information, create a new disclosure with stronger exclusions. Do not edit the signed ZIP in place.

### Messages left out by the selection

**Preview.** A disclosure does not look complete when it is not. Inside every chat that keeps at least one disclosed message, messages the selection left out appear as markers, `[withheld by selection — rule: sender]` (or `text`, `period`). Choose **Messages left out by the selection**: one marker for each run of consecutive withheld messages (default) or one for each message. Markers carry only the rule and a count, never text, sender, date or files. Chats with nothing disclosed are left out entirely, so the package does not reveal that they exist.

Disclosed replies say what they answer: a message included in this copy, a message withheld by the selection, or a message that is not in the source export (deleted before the export or never exported; the export cannot tell which). A withheld message that a disclosed reply answers always gets its own marker, so the reply points at a record that explains why it is empty. These three states are distinct from deletions and collection gaps, which belong to the source export.

In `messages.jsonl` (format `tgwitness-account-disclosure-v2`) each message has `state`: `disclosed`, or `withheld` with `rules` and `count`. A disclosed reply has `reply_to` with the target `id` and `state` (`disclosed`, `withheld`, `not_in_source`). The manifest counts disclosed messages, chats, media and `withheld` messages. `verify.py` rejects a marker that carries content and a reply that points at a record missing from the package; version 1 packages verify as before.

The minimized format omits structured account profiles, contacts, avatars, sessions, stories, raw Telegram objects, forwarding headers, reply quotations, contact cards and location metadata. It excludes the original JSONL files, private filter settings, pseudonym key and identity map. Selected text, explicitly retained identities and included files can still contain the same names, IDs or phrases used in those filters; they need separate review. The private policy and pseudonym key are retained encrypted in the local vault for the job; deleting the job clears its associated private disclosure records. The public policy records filter counts rather than filter values. The stated purpose is public in the manifest and HTML: explicit private criteria and, in pseudonymized modes, known hidden identities are masked there too, including when message text is omitted. Keep the purpose free of unnecessary personal details; unknown identifying context can remain.

Its manifest binds the derivative files, public policy and original ZIP's hash. Verification can establish integrity and, if the source is supplied locally, matching source linkage:

```sh
python -m tgwitness.verify minimized-disclosure.zip --fingerprint TRUSTED_SHA256
python -m tgwitness.verify minimized-disclosure.zip --fingerprint TRUSTED_SHA256 --evidence account-export.zip
```

Source linkage does not independently prove that the transformation selected every required item or removed every identifying detail. Original plaintext is not embedded as a proof. A fresh review is needed for that judgment.

## Sharing and hosted capture

Select the messages and files the recipient needs，review the complete sharing copy，and retain the source separately．Record the delivered ZIP's hash so the recipient can identify and verify that exact copy．Pseudonymization replaces the selected identifiers；included text and original files remain part of the review．

GitHub Actions supports full-account and selected-chat exports through Takeout or the regular API，plus a one-chat event journal．The [hosted capture guide](https://phishdestroy.github.io/TgWitness/docs/capture/) explains settings verification and the 120-minute limit．To verify a sharing copy derived from hosted capture，check its source hash against the original archive and verify that archive's attestation with the [mode-specific checks](EVIDENCE.md#verification-scope)．

[Evidence format](EVIDENCE.md) · [Case reports](CASE_REPORTS.md)
