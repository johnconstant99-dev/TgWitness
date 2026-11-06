[TgWitness](../README.md) / [Documentation](README.md) · [Evidence and verification](EVIDENCE.md)

![Evidence & verification](assets/presentation/chapter-evidence.svg)

# File hashes and export preflight

Account Export supports `download`, `hashes_only` and `exclude` media actions with either regular API or Takeout. Use the existing export settings dialog, or send an [accepted configuration](../examples/export-hashes.json) to `POST /api/account-export/start`. `chat_ids: []` selects all visible chats of the chosen types; provide IDs to restrict the scope.

`media_types` selects eligible types. `media_action` is their default action; `media_actions` overrides individual types. An optional `media_rules[kind].action` is used when there is no corresponding `media_actions` override. For example, `{"photo":"download","video":"hashes_only"}` downloads selected photos and records selected video hashes. Unchecked types stay excluded regardless of overrides. Profile photos remain separately opt-in. Selected additional account JSON is not message media and is still downloaded when `include_other_data` is true.

Animated MP4s use the animation rule; video stickers use the sticker rule, regardless of Telegram attribute order. Account Export calls round video messages `video_message`; the restricted capture configuration uses `video_note` for the same media category.

`max_media_file_mib` bounds file downloads. `oversized_media: "hashes_only"` requests hashes for larger eligible files instead. Hash collection does not download their bytes. Takeout's server-side file eligibility ceiling is increased when hashes are requested, while the local payload writer still enforces the chosen download limit. Unsupported or unavailable hashes do not cause a silent fallback to downloading the file.

`max_total_gib` bounds unique saved media bytes, not the final ZIP, report or hash JSON. Repeated references reuse the bounded attachment cache and do not consume this budget repeatedly. `unique_media_bytes` reports actual distinct stored file bytes; the legacy `bytes_saved` counter still sums message references so old archives remain verifiable. Cache eviction can require another request; identical saved content still occupies one file.

`budget_exhausted: "hashes_only"` (the default) switches remaining eligible downloads to server hashes when the media budget or packaging reserve would be exceeded. `"stop_files"` records the missing files instead. Hash acquisition failures remain explicit. Successfully downloaded files and complete hash manifests are signed in a private result cache before their message page is sealed, so a stop in the middle of a page does not discard completed attachments.

With `messages_first: true` (the default), all selected history and account metadata pages are saved and signed before file or hash requests start. Expiring Telegram file references stay in an encrypted private queue. Resume verifies the frozen pages and continues from them without rereading edited or deleted messages. Attachment processing seals at most ten enriched messages at a time to bound memory when hash manifests are large. A paused local job can either resume or **Finish with saved data**; finishing creates an archive and explicitly records unavailable history and attachments.

`export_format` accepts `tgwitness`, `telegram_json`, `telegram_html` and `telegram_both`. The compatible views add `result.json` and/or `export_results.html` with offline chat pages. Core chat/message fields follow the [Telegram Desktop JSON schema](https://github.com/telegramdesktop/tdesktop/blob/dev/Telegram/SourceFiles/export/output/export_output_json.cpp); this is an independent rendering, not an export generated or signed by Telegram Desktop. Dates use UTC, messages are ordered by ID, and media paths refer to the same deduplicated files. `tgwitness_media` and `hashes/index.jsonl` retain hash-only outcomes. Signed JSONL remains authoritative, including source fields not mapped into the compatible view.

<details>
<summary>On this page</summary>

- [What the hashes mean](#what-the-hashes-mean)
- [Compare a downloaded file](#compare-a-downloaded-file)
- [Check settings before starting](#check-settings-before-starting)
- [Restricted GitHub capture and single-chat export](#restricted-github-capture-and-single-chat-export)
- [Limits and release status](#limits-and-release-status)

</details>

## What the hashes mean

Telegram's [`upload.getFileHashes`](https://core.telegram.org/method/upload.getFileHashes) supplies SHA-256 hashes for ranges. Each [`fileHash`](https://core.telegram.org/constructor/fileHash) has an offset, length and hash. These are different from a file ID, `access_hash`, or a checksum of metadata.

The export records the document or exact photo size variant, expected length, ordered ranges and whether they cover the entire file. Telegram's final range may extend beyond EOF; comparison hashes only the bytes that exist. A different photo variant can legitimately have different bytes. No access hash or expiring file reference is included in the public manifest.

Hash requests use the media's data centre. Repeated representations reuse the result. DC migration and expired references are handled without switching the configured transport. Unavailable/partial coverage is recorded and makes the selected acquisition incomplete; it cannot be counted as a complete hash-only attachment.

## Compare a downloaded file

First verify the archive with an independently trusted signing-key fingerprint. `hashes/index.jsonl` maps chat/message/attachment references to individual JSON manifests in `hashes/`. The same manifests are bound into signed message pages; archive verification checks the index and standalone manifest against those pages. The HTML transcript links to each complete hash manifest.

Run:

```text
python -m tgwitness.file_hashes path/to/hash-manifest.json path/to/local-file.jpg
```

The result distinguishes `match`, `different`, `missing`, `different_size_or_representation` and `incomplete_hash_coverage`. This command reads the local file, not Telegram. A match concerns the recorded ranges; it is not a Telegram-signed attestation or a claim about who authored the content.

## Check settings before starting

Use **Check settings and size** in the existing dialog, or `POST /api/account-export/preflight` with the same options. `?sample=false` checks configuration and local disk without reading Telegram.

The bounded sample reads at most 1,000 visible dialogs and the latest 25 messages from at most 12 matching chats, with a 20-second deadline. It does not start Takeout, download attachments, send messages, join chats or change export settings. Selection and media policy are applied to the sample. It reports known selected download bytes, duplicate references, unknown sizes and estimated hash-manifest size. Optional account metadata/avatars are not included in that estimate.

`fit: "unknown"` is intentional even when the sample fits. A recent-message sample cannot establish the total size of older history, particularly with date or sender filters. Hash JSON estimates assume 128 KiB ranges and 160 bytes per range plus per-file overhead, based on observed responses; actual ranges can differ. No fixed duration is promised because rate limits, approval, connectivity and report generation vary. Clearly excessive sampled bytes produce specific budget/disk warnings. Critically low free disk and an empty selection block starting.

Takeout approval is separate from QR/phone/2FA login. When Telegram requests approval, use an already authorized device to allow the export, then **Check approval** before the deadline if desired. The same export and authorization resume. Rate-limit waits are labelled separately.

## Restricted GitHub capture and single-chat export

The existing restricted capture form now exposes the same three media actions, per-type overrides/download limits, oversize behavior, avatar choice and messages-first processing. Its default UI choice is hashes only, with avatars off. It remains English by default. No new application page is added.

The restricted server accepts a [selection configuration](../examples/sealed-hashes.json) at `POST /api/preflight` or `POST /api/collect`. Preflight reads at most 25 recent messages from the selected chat in 20 seconds. It reports actual free disk, remaining capture time, known sampled payload bytes, estimated unique hash JSON and the separate delivery limits. It does not request hashes, download files or change the selection. Settings and chat become fixed when collection starts. The chosen policy is recorded in signed `sealed.selection`, observation and history records.

For full-account or selected-chat Account Export, use the same endpoints with the [account selection configuration](../examples/sealed-account.json): `mode: "account"` and `account_options`. This mode supports regular API and Takeout, dates, file policies, optional account sections and compatible output formats. The form defaults to all accessible chats and hashes only. The event-journal mode remains a separate single-chat regular API choice. Account preflight uses the bounded multi-chat sample described above.

Takeout approval is separate from successful phone, QR and 2FA authentication. Review Telegram's request in an existing session; newly logged-in clients may require an older session or a wait. The UI displays Telegram's actual delay and **Check export approval** resumes the same job. If approval exceeds the runner's lifetime, finish with an honest partial result and start another run after approval; fresh-session GitHub captures do not transfer Telegram authorizations across runs.

The signed `account-export.zip` is included in the outer evidence archive and bound to a `sealed.account_export` journal event. Verification checks both archives, their signing identity and the binding. At the runner's deadline or storage limit, already signed history and completed attachments are finalized; unread history and unfinished attachments are recorded as missing before the fresh authorization is revoked.

With `messages_first: true`, both attachment workers wait for the history read to finish. A paused history keeps them waiting. Complete hash acquisitions produce `media.hashed` records and one `hashes/<digest>.json` per unique manifest. The HTML report labels them **File hashes; content not downloaded**, names the source message, byte coverage and range count, and links the JSON. Incomplete hashes produce failed attachment records. The archive verifier checks complete range coverage and binds each hash file to its signed journal record. The fresh authorization is revoked at finish; failure to confirm revocation remains explicit.

The separate single-chat exporter also honors the shared capture policy, including hashes and disabled avatars. Configure it with the `capture` object from the example through `POST /api/capture`, then use the existing chat export. Hash records are bound into signed `chat.json`; their standalone manifests are checked by `verify_chat_export`. The existing regular recording form does not yet expose all these new policy fields; use Account Export's form or the restricted form when configuring hashes interactively.

## Limits and release status

| Path | Scope / transport | Hash policy | Preflight | Messages before attachments |
|---|---|---|---|---|
| Account Export | All / selected chats; regular API or Takeout | UI and API | UI and API; bounded multi-chat sample | Signed history first by default; resumable encrypted attachment queue |
| Single-chat export | One chat; regular API | Shared capture API | No dedicated form | Attachments still processed with each message |
| Restricted GitHub Account Export | All / selected chats; fresh regular API or Takeout session | Existing form and API | Bounded multi-chat sample | Required; partial finalization at deadline or storage limit |
| Restricted GitHub event journal | One chat; fresh regular API session | Existing form and API | Selected-chat sample | Configurable; enabled by default in the form |

The sealed lifetime includes login and approval. The supervisor allows at most 120 minutes of capture, with a 220-minute workflow limit covering build, sealing, attestation, encryption, upload and cleanup. The container has a 2 GiB RAM limit. A single evidence ZIP attempt has a 4 GiB **uncompressed** ceiling. Larger results use the multipart path below. Free disk is measured at runtime; no fixed runner disk amount is assumed. Account acquisition reserves space for its archive and, on a disposable runner, its outer encrypted copy. This is a conservative reserve, not a prediction or guarantee against external disk exhaustion.

When formatted ZIP generation exceeds that limit or runs out of disk, the restricted collector removes the failed temporary ZIP and tries compact packaging once. It retains the full signed journal, coverage, every preserved file, server-hash manifests, checkpoints and verification material. It omits duplicated CSV, formatted JSON/HTML/PDF reports, indicators and viewer files. `sealed.packaging` records the reason; the signed manifest and `PACKAGING.json` identify the compact result, and `index.html` explains how to read and verify it. A compact ZIP uses the same encrypted handoff and unchanged archive verifier. Permission failures and unrelated I/O errors do not trigger this fallback.

If the compact result exceeds the single-ZIP ceiling or its temporary copy cannot fit, the collector streams the compact ZIP directly into encrypted parts, retaining the journal and every preserved file. Successful ZIPs larger than 128 MiB also use parts. Each encrypted file contains at most 128 MiB of plaintext. `evidence.parts.json` signs the ordered names, sizes, plaintext hashes, encrypted hashes and whole-archive hash; GitHub attests this manifest. `delivery.tgwsealed` contains the manifest and attestation, while `delivery-000001.tgwsealed`, etc. contain the archive parts. Only encrypted files are uploaded.

After opening `delivery.tgwsealed` and extracting `delivery.zip`, keep the encrypted parts beside `evidence.parts.json` and run trusted installed tools:

```text
python -m tgwitness.sealed_parts evidence.parts.json --key sealed-key.json --out evidence.zip
python -m tgwitness.sealed_verify evidence.parts.json --bundle attestation.jsonl --repo OWNER/FORK --max-gib 64
```

Assembly rejects missing, reordered or changed parts and never overwrites an existing output. The verification ceiling is explicit; raise it only for an expected larger archive. The browser can decrypt individual numbered parts without loading the entire archive. If disk is exhausted even after the reserve and compact fallback, the run fails explicitly. There is no cross-run sealed authorization transfer or automatic continuation on another runner.

Account Export now paginates HTML chats. Each page has at most 250 message records and normally at most 512 KiB of source JSON; a single larger record remains intact. These are input bounds, not a hard HTML-byte guarantee. The first page retains `chats/ID.html`, subsequent pages use `chats/ID-2.html`, etc. Previous/next links, continuous record numbers and exact page citations work offline. All pages are signed through the archive manifest; authoritative JSONL, receipts and acquisition options remain unchanged. Pagination improves opening large chats, but does not cap the total size of reports or paginate standalone sharing copies.

The compatible renderer is tested against synthetic UTF-16 text/entities, chat IDs, message ordering, media policies, partial results and signed archive verification. It has not been compared byte-for-byte against a live Telegram Desktop export. Historical acquisition checks matched live range hashes against previously downloaded Telegram media bytes of the recorded representations; file IDs alone never establish byte identity.

Updating code in a fork alone does **not** update the pinned collector. Releases require immutable source/workflow commits and a matching trusted-policy entry; do not weaken verification to accept arbitrary fork code. Existing archives remain verifiable; new archives include the updated standalone verifier.
