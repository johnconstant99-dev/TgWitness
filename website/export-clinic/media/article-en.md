# An official client does not authenticate a local export

The Export Clinic · Controlled demonstration · Test accounts

The point of this demonstration is the confidence created by an ordinary-looking procedure: download the official Telegram client, sign in, use its built-in export function, and open the familiar HTML archive. A recording of those steps can look convincing while leaving the provenance of the resulting files unresolved.

In this experiment, a disclosed local helper deliberately changed exported files. The recording then places the Telegram conversation beside the local HTML archive so that the difference can be inspected directly. One clear example shows **RESULT: FAIL** in the test bot conversation and **RESULT: PASS** in the exported page.

The review materials cover seven owned test conversations containing 45 message records. Offline comparison found changes in 17 message records and 32 files. The paired archive includes both versions of the HTML, JSON and included images, with the standard assets needed to open the HTML exports.

## This is not a Telegram vulnerability

This demonstration uses no Telegram exploit, compromises no Telegram server, and breaks no encryption protocol. The intervention is local file modification. The official client executable is not modified by the helper.

Telegram's documented export feature produces HTML or JSON for offline use. Once those files are written to storage, they are subject to the device's file-access controls. A process with sufficient write access can change them before they are opened or examined. The provenance of the application and the subsequent history of its output are separate questions. [Telegram: Export Telegram Data](https://telegram.org/blog/export-and-more)

The risk illustrated here is treating familiar presentation, an official application, or a well-documented series of clicks as sufficient authentication of a supplied local artifact. This experiment makes no finding about the evidence in a particular case or the conduct of a particular examiner.

## Valid signatures can cover altered data

An operator could also display a console computing hashes, signing records, and reporting successful verification. Those calculations could be completely genuine even if the input had already been altered.

A SHA-256 digest identifies the bytes that were hashed. An Ed25519 signature can bind particular bytes to a signing key. Neither operation determines whether a person actually sent the statement represented by those bytes. If altered input is signed, a successful signature check remains a successful check of altered input. This follows from the distinction between the message bytes verified by a signature algorithm and the external events those bytes describe. [Ed25519 signing and verification](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.7)

The same distinction applies to external timestamps: they can support a claim that particular data existed by a given time; they do not independently establish the truth of its contents. [RFC 3161: Time-Stamp Protocol](https://www.rfc-editor.org/rfc/rfc3161.html#section-1)

No signing-console sequence is claimed to appear in this recording. It is an explanation of the trust boundary, not an additional recorded result.

## What stronger collection can add

Direct API collection can reduce reliance on an export supplied after the event. TgWitness documents a collector that records observations, signs records, links them in a hash chain, and supports comparison with independently retained checkpoints and optional external timestamps. These mechanisms can make later changes detectable within their documented assumptions. [TgWitness: How evidence works](https://phishdestroy.github.io/TgWitness/docs/concepts/)

The signatures remain the collector's signatures. Their value depends on the acquisition environment, protection and identification of the signing key, collection coverage, and independent reference material. API access does not by itself provide a Telegram-issued, independently verifiable signature for each captured statement. A collector controlled before signing could sign misleading input; a chain rebuilt under the same control needs an independently retained reference to reveal the change. [TgWitness: Security](https://phishdestroy.github.io/TgWitness/docs/security/)

The objective is verifiable acquisition and independent checks. Cryptography can preserve and authenticate a record of an observation without making its contents self-authenticating historical truth.

## Recording and scope

- **Condensed viewing copy:** approximately 2:00. Setup, repeated exports and navigation are accelerated by factors of two to fifteen, with each accelerated section labeled. Account sign-in, the first export sequence including access confirmation, selected comparisons, and the closing explanation retain their original speed. The sequence remains chronological; the edit manifest maps the complete source timeline to the viewing copy.
- **Full recording:** approximately 6:09. The MP4 is a container conversion without video re-encoding. The original MKV is also supplied byte for byte, together with SHA-256 checksums and an edit manifest.
- The recording shows comparisons of displayed text and images in local HTML exports. The paired JSON was checked separately offline. PDF attachments were excluded by the selected export settings and are absent from the paired archive. Mobile-client behavior requires a separate experiment.
- The visible clock is the host computer's clock, not an independent trusted timestamp.
- The mechanism is disclosed as deliberate local-file modification. The public package includes selected test files and a derived change ledger, but excludes the helper implementation, transformation configuration, credentials, sessions and complete working logs.

## Inspection packages

The smaller ZIP contains `before` and `modified` trees for the seven conversations, a file manifest, a selected ledger of before/after hashes, checksums and a README. The before tree was reconstructed: changed files were restored byte for byte from retained helper backups, each checked against its recorded hash; unchanged assets were copied from the captured export. It is not a separately captured original whole-folder ZIP.

The complete review ZIP adds the untouched original MKV, the two-minute MP4, this description, the video edit map and the original metadata review. The full browser MP4 is supplied separately to avoid storing the same complete recording twice inside the ZIP.

The change records are operator-generated. They establish correspondence among the supplied versions, not independently authenticated Telegram server provenance. The included `js/script.js` files are Telegram's unchanged standard HTML-export viewer, not the local modification helper.

The checksums published with the videos allow recipients to compare downloaded files with these copies. They do not certify the underlying Telegram conversation.
