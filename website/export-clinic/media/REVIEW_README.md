# The Export Clinic — review package

Controlled local-file experiment. Test accounts and scripted conversations. Files labeled modified were deliberately changed by a local helper. This is not a Telegram exploit.

## Start here

- `video/export-clinic-2min.mp4`: the condensed film, 1 minute 59.7 seconds. Acceleration is labeled.
- `video/ExportClinic_2026-11-03_12-50-40.mkv`: the complete, byte-identical original recording, 6 minutes 8.8 seconds.
- `data/export-clinic-paired-files.zip`: extract this ZIP to inspect the `before` and `modified` export trees. Read its README for the reconstruction method and file-level checksums.
- `description/article-en.md`: explanation, scope and limitations.
- `verification/recording-manifest.json`: the mapping from source time to edited time, plus hashes for the published video versions.
- `verification/publication-review.json`: the package-selection review.

The full MP4 mentioned in the video manifest is a browser-friendly container conversion, supplied separately on the page. It is omitted here because the original MKV already contains the complete recording.

## The paired files

Seven selected test conversations contain 45 message records; 17 records and 32 files differ. Changed original files were recovered from retained helper backups and matched to their recorded hashes. Unchanged viewer assets were copied from the captured export. The before directory is a reconstructed pre-change tree, not a separately preserved original whole-folder archive.

The helper's original work logs are not published. The selected ledger contains only relative export paths and before/after hashes. These are operator-generated records, not Telegram server attestations.

No PDF files were included in the recorded exports. Captions referring to PDFs do not supply the underlying attachment.

## Exclusions

The modification helper, its executables, source files, transformation rules, credentials, Telegram sessions, proxy settings, unrelated chats, old takes and complete working logs are not included. Standard `js/script.js` files inside the paired exports are Telegram's unchanged HTML-viewer asset.

## Verify a file

The root `SHA256SUMS.txt` covers every file in this ZIP except itself. The nested paired-files archive has its own checksums and file manifest. On Windows, use:

    Get-FileHash -LiteralPath '<path-to-file>' -Algorithm SHA256

Compare the result with the corresponding line. A matching checksum identifies the bytes supplied; it does not establish the truth of a conversation or independently certify its server origin. The host clock shown in the video is not a trusted timestamp.
