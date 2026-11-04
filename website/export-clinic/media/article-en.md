# A Telegram conversation and its altered export

Export Clinic · Desktop experiment · 3 November 2026

The test bot says **RESULT: FAIL** in Telegram. The exported page says
**RESULT: PASS**. The recording shows the official Telegram Desktop download,
sign-in and export, followed by comparisons of the conversation and the local files.
A disclosed helper deliberately changed selected export files. The official
client executable and the conversations displayed in Telegram were unchanged.

The seven scripted test conversations contain 45 message records. Comparing the
retained and modified versions found changes in 17 records and 32 files. Each
version contains 340 files, including HTML, JSON, selected images and the
standard Telegram viewer assets.

## Inspect the change

1. Watch the two-minute film or the complete recording.
2. Choose a conversation on the comparison page and inspect its changed messages.
3. Download the paired exports and open the corresponding HTML and JSON files.
4. Compare their SHA-256 hashes with the file manifest and selected change ledger.

Telegram's [export feature](https://telegram.org/blog/export-and-more) writes
local HTML or JSON files. In this experiment, a helper with write access changed
those files before they were reviewed. The familiar HTML presentation still
opened normally. The difference is visible when compared with the conversation
and the retained pre-change bytes.

## Capture and verify with TgWitness

The experiment illustrates why the collection step belongs in the record.
Signing an already altered export preserves that altered version. TgWitness
connects to Telegram and signs and links journal entries as it records the
content delivered to the account. The archive includes source identifiers,
captured versions, preserved attachments and verification data.

Retain the workspace's signing-key fingerprint and a checkpoint separately.
The recipient can then check the journal signatures, chain and file hashes
against the expected key and recorded journal state. A separate witness keeps
additional checkpoints; external timestamps provide dated commitments.
[Export and verification guide](https://phishdestroy.github.io/TgWitness/docs/exports/).

[GitHub Actions capture](https://phishdestroy.github.io/TgWitness/docs/capture/)
adds a verifiable collection process. A pinned TgWitness collector runs on a
GitHub-hosted runner with a fresh Telegram session. GitHub attests the completed
archive, which is encrypted for the recipient. Verification checks the approved
workflow and collector version, the archive digest, journal and attachments.
The [technical model](https://phishdestroy.github.io/TgWitness/docs/reference/security/)
describes the trusted components and operating conditions.

## Recording and files

- **Condensed film:** 1 minute 59.7 seconds. Setup and repeated steps are accelerated
  by factors of two to fifteen and labeled. Sign-in, the first export, selected
  comparisons and the closing explanation retain their original speed. The edit
  map covers the complete source timeline in order.
- **Full recording:** 6 minutes 8.8 seconds. The original MKV is supplied with its
  SHA-256. The full MP4 is a browser-friendly container conversion without video
  re-encoding. Recording times come from the host computer's clock.
- **Paired exports:** seven test conversations with HTML, JSON and selected images.
  The recording shows text and image comparisons; JSON was compared separately
  offline. The export settings excluded PDF attachments.
- **Before folder:** a reconstructed pre-change tree. Changed files were restored
  byte for byte from retained helper backups and matched to their recorded hashes.
  Unchanged viewer assets were copied from the captured export.

The smaller ZIP contains the paired exports, a file manifest, a selected ledger
of before/after hashes, checksums and reading instructions. The larger review ZIP
adds the original MKV, condensed film, publication-time description, edit map and
metadata review. That ZIP retains its original documentation; this page is the
current explanation. The full browser MP4 is available separately.

The public materials contain selected test data. The helper implementation,
transformation configuration, credentials, sessions and complete working logs
are excluded. The included `js/script.js` is Telegram's unchanged export viewer.

Use the published checksums to confirm that your downloads match the supplied
files, then inspect the recorded procedure and the before/after comparison.
