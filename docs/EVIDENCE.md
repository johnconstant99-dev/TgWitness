# Evidence format v1

An observation is not a conclusion. A sender ID is not a real-world identity.
The account-visible service update is the source; Telegram does not cryptographically
sign these saved records for a third-party investigator.

## What is signed

| Material | Protection | What to retain |
| --- | --- | --- |
| Every journal observation, including operational events | SHA-256 chain and an Ed25519 signature per event | Original `events.jsonl`, the trusted key fingerprint, and a retained checkpoint |
| Evidence ZIP contents | `manifest.sig` signs the canonical manifest, which lists hashes of the content files | The complete ZIP, including its manifest and signature |
| Preserved attachments | SHA-256 and byte count in a signed `media.saved` event; file hash in the signed ZIP manifest | The original bytes inside the verified ZIP |
| Checkpoint | Ed25519 signature over journal length, head hash, public key, and creation time | An independent copy retained before a disputed change |
| Run receipt | Separately signed collector measurements; also included in a signed `process.started` event | The receipt and associated journal; measurements are self-reported |
| Readable reports: `report.html` and its parts, `report.json`, `report.pdf`, `chat.pdf` | An Ed25519 seal per file over its content; the PDF also carries a standard PDF signature (see [Readable reports](#readable-reports)) | The file as received and the trusted key fingerprint; the ZIP it describes |
| Standalone CSV | No standalone cryptographic signature; event hashes alone are insufficient | Use the exact copy inside the verified ZIP for integrity checking |
| Screenshots, printouts, or PDF produced by a browser | No TgWitness signature on the derivative | Keep the original verified package and document how the derivative was made |

The collector verifies journal signatures before generating every export format.
That source check does not create a signature on a separately downloaded CSV or
HTML file. A valid JSONL event signature likewise does not provide the attachment
bytes or independently establish that the entire observed journal was supplied.

## Investigation handoff

1. Record the case reference, operator, numeric Telegram account ID, selected
   sources, collection policy, and collection period in your case notes. TgWitness
   preserves observations; case assignment and custody records are managed outside
   the application. Qualify the intended collection setup with the
   [live acceptance procedure](internal/LIVE_ACCEPTANCE.md).
2. Retain the workspace's public-key fingerprint independently before relying on
   its exports. Save signed checkpoints outside the collector during collection.
   Record interruptions and the limits of the account's visibility.
3. Export a **signed ZIP** and retain the signed run receipt. Use a checkpoint at
   or before the exported journal boundary. A later checkpoint can correctly reject
   an earlier export as too short. Exports include the full workspace journal,
   regardless of panel filters; review the material before sharing it.
4. Have the recipient verify the ZIP with a trusted copy of the verifier and the
   independently supplied fingerprint/checkpoint. From a trusted checkout with
   its Python environment active:

   ```sh
   python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_PUBLIC_KEY_SHA256 --checkpoint retained-checkpoint.json
   ```

   Successful output reports `key_pinned: true` and `checkpoint_checked: true`
   when both inputs are supplied and accepted. Preserve the verification result.

    For a handover requiring the final exported record to be witnessed, use
    `--witness witness.zip --witness-fingerprint TRUSTED_WITNESS_SHA256 --require-witness`.
    This refuses an export with an unwitnessed tail. See the
    [witness handover procedure](WITNESS.md#require-a-witnessed-export-boundary).
5. Record the archive's SHA-256, export boundary, transfer date, sender, and
   recipient in your custody record. Keep the original package intact and work
   from copies. Share evidence files rather than the application's private data
   directory, which also contains account sessions and signing secrets.
   For transfer, an export can be put into a password-protected AES-256 ZIP. The
   password only protects confidentiality and is not stored; the recipient extracts
   the archive and verifies the signed export inside, which is unchanged.
6. If independent time anchoring is required, follow the
   [RFC 3161 procedure](TIMESTAMP.md) and retain the request, checkpoint, trusted
   CA information, and verified authority response. Preparing a request alone
   does not obtain a timestamp.

Successful verification establishes integrity relative to the trusted collector
key and retained boundary. Source truth, complete Telegram delivery, trusted time,
and legal admissibility require separate evidence. This version has not completed
live Telegram qualification or an independent forensic/security assessment.

A copied collector key can sign a fabricated replacement journal. Verification against
an independently retained checkpoint or witness record detects a changed earlier prefix;
signature verification alone cannot. A witness fixes what the collector presented, so it
does not independently establish the truth of records fabricated before their first
external checkpoint. Cloud deployment reports check configuration and collector-reported
measurements; they do not establish that a private key was never copied during bootstrap.

Notifications sent through Apprise contain workspace and chat names and counts; short
excerpts of deleted and edited messages are added only when the operator turns them on
(off by default). They are a convenience signal, not evidence: delivery is not guaranteed,
and only the journal and its signed exports record what was observed. With a workspace
proxy, notifications use the same route; services that cannot use it, and MTProxy routes, are refused.

## Handover extract

A signed ZIP carries the whole workspace journal. When a court, a lawyer or an abuse desk needs
only some chats, a period or certain people, **Exports → Handover extract** prepares a minimised
copy (`tgwitness-handover-v1`) and does not disclose third parties the recipient does not need.
The operator states the purpose and chooses the chats, an optional period (UTC), the people the
extract is about, what happens to everyone else (shown, replaced by pseudonyms P01, P02… or left
out), which message texts stay, which attachments and profile photos are included, and whether
phone numbers and e-mail addresses in texts are masked. The purpose and these rules are in the
signed manifest and in the report; the journal records `handover.exported` with the access that
prepared it and the file's SHA-256, not the contents.

`verify.py` checks an extract in two ways. A record shown unchanged is verified in full: its
content against its hash, its Ed25519 signature and its link to an included predecessor. A
minimised record keeps the original hash and signature, so the signature still verifies, but the
withheld fields cannot be recomputed from it; the record names what was withheld and the report
marks it. The manifest names the journal length and head with the collector's signature over that
head, and counts the records left out; `coverage.json` describes the chosen chats. Names inside file
names are not detected. Keep the full signed ZIP: the extract is a disclosure, not a replacement.

## Readable reports

Every signed ZIP (evidence, handover extract, chat export) carries the same report three ways,
in the report language chosen in Report settings or for the one export. Each file is sealed on
its own with the workspace's Ed25519 key, so a report handed over without its ZIP still shows
any change, and `python verify.py FILE --fingerprint KEY [--evidence ZIP]` checks it.

- `report.html` / `chat.html`: the seal statement (`tgwitness-report-seal-v1`) closes the file and
  signs the SHA-256 of every byte before it. Long journals and chats are split into parts of a
  configurable size (Report settings, 500 to 100,000 records; 5,000 by default):
  `records/records-0001.html` or `messages/messages-0001.html`, each sealed with its number, range
  and the total, and listed with its SHA-256 in the signed manifest. Runs of collector heartbeats
  are shown as one line unless Report settings list them one by one.
- `report.json` (`tgwitness-report-json-v1`, keys `format`, `report`, `seal`): the seal signs the
  SHA-256 of the canonical JSON of `report`, so the facts can be read by case systems and scripts
  and a selection for data protection can be made from them while the signed file stays whole.
- `report.pdf` / `chat.pdf`: a formal document for printing and filing, signed twice over the same
  bytes, the whole file except the signature value (`/ByteRange`). The standard PDF signature
  (`adbe.pkcs7.detached`, CMS with SHA-256 and ECDSA P-256) uses a self-issued document-signing
  certificate kept in the workspace vault; its subject serial number is the Ed25519 key
  fingerprint. The Ed25519 seal travels inside the CMS as the unsigned attribute
  `2.25.240684792623320047764573196045913242332` and names the certificate's SHA-256 with
  `"content": "pdf-byte-range"`, so the Ed25519 key vouches for the certificate. A PDF reader shows
  whether the file changed after signing and calls the signer unknown until the certificate is
  trusted; compare the Ed25519 fingerprint instead. Chinese, Japanese and Korean PDFs need a font
  on the server (or in `TGWITNESS_FONT_DIR`); without one the ZIP carries the HTML and JSON reports
  only.

In a channel or supergroup Telegram numbers messages 1, 2, 3… in order. A chat export lists the
first and last number, how many are present and every run of absent numbers in
`message-ids.json`, the manifest and the `chat.json` header, and marks each gap where it falls in
the transcript. `verify.py` recounts them from `chat.json`. An absent number is a message Telegram
did not return (deleted before the export, or not visible to the account); in private chats and
basic groups numbers are shared by all of the account's chats and gaps are not counted.

After reading the history, the export asks Telegram for every absent number again, by number
(`channels.getMessages`, up to 10,000 numbers). The result is in `message-ids.json` and the report.
An empty answer means Telegram has no message under that number for this account; it does not say
whether the message was deleted or was never visible to the account. A message Telegram does return
then was missed while reading and is added to the export, marked `found_on_recheck`.

Every report opens with **In brief**: one paragraph, then what the material shows and what it does
not (who is behind an account, completeness of delivery, deletions before observation, clock time
without a timestamp). The page's own seal stamp turns amber when the browser has checked the seal's
signature, not the page: a browser does not give a page its own bytes. It turns green only when
the reader drops the file into the check at the end of the page and every byte matches, and only if
the page shown is that file; otherwise it turns red.

Each report names the program exactly: the git commit when the collector runs from a checkout or
the installer sets `TGWITNESS_COMMIT`, and the SHA-256 of its source files (`source_tree_sha256`,
the canonical JSON of path → SHA-256 of every `.py`, `.js`, `.css`, `.html` and `.svg` file in the
package), which a checkout of that commit reproduces unless files were changed. The Telegram
client is named with its library, API layer and data centre. When observation starts and when a chat
export begins and ends, the collector asks Telegram for its time (`updates.getState`, whole
seconds) and records Telegram's time minus the collector's clock, with the uncertainty from the
round trip; the reports show these measurements under Chain of custody. A chat export also records
when it read the history, apart from the dates of the messages.

### Offline report viewer and archive guide

Extract the complete ZIP before opening `chat.html` or `report.html`. The viewer provides search,
filters, participants, indicators, record details and JSON/CSV selections without a server. Keep
`viewer/` and `media/` next to the report. Selections are derivatives: use `verify.py SELECTION.json
--evidence ARCHIVE.zip` to compare them with the signed archive.
The verifier checks the report ID, signing key, archive boundary and every selected item; edited,
missing and duplicate items fail. Selection notes and creation time remain unsigned metadata.

Current archive exports store viewer chunks in `viewer/*.html`. Each chunk is loaded in a sandboxed
frame with scripts allowed but **without** same-origin access, and posts its JSON text to the report.
The report checks the message source and its SHA-256 against the signed descriptor before display.
The report's own CSP permits only its hashed application script. Missing data can be recovered by
choosing the matching ZIP in the Check tab; data read from the ZIP is parsed without execution.
Earlier exported reports keep their own embedded viewer and remain verifiable.

Message-number gaps are shown only for a complete, unfiltered ascending chat feed. Hiding a
category or failing to load a data chunk must not turn an omitted row into evidence of a missing
message. Search highlights operate on plain text before HTML escaping, preserving literal markup.

The browser checks manifest signatures, the report ID and key, and all listed file hashes. It
rejects ambiguous or malformed ZIP structures, duplicate names and unsafe paths, and caps files
at 256 MiB and declared total contents at 4 GiB. Use the standalone verifier for larger archives.
This browser check complements the verifier's checks of journal chains and data semantics.

`README.txt` contains a start guide, an aligned file inventory, verification instructions and data
format notes in the report language, followed by a complete English guide. `SHA256SUMS` covers the
files listed within it, excluding itself, `manifest.json` and `manifest.sig`; the signed manifest
also covers `SHA256SUMS`. Keep the original ZIP unchanged and save working files outside the
extracted folder. PDF reports include section bookmarks and case/report identification on later pages.

Report settings are saved per workspace. The report language can follow the panel or be fixed;
an explicit language on an export request overrides that choice for that export only. Every panel
language is accepted, including the four right-to-left languages.

The journal transcript switch controls its HTML viewer and PDF transcript. Full record JSON is
an HTML detail option: when enabled, the viewer carries the exact exported record, including a
minimised record in a handover. Disabling it does not alter the authoritative journal file. Photo
previews apply to both chat and journal HTML. Consecutive heartbeat runs can be collapsed without
removing records; expanding long runs loads their rows incrementally.

`part_size` is the maximum item count per viewer data file (500–100000), and the maximum transcript
size included in a PDF. Viewer chunks also split at a 16 MiB data budget. Longer PDF transcripts
are omitted with an explicit pointer to the signed source files and HTML viewer. A standalone HTML
report embeds at most 20000 items or 32 MiB of item data; once exceeded, it releases those items and
directs the reader to the archive. These display limits never truncate the signed source files.
The PDF font setup combines CJK fonts where needed: a Chinese font alone may lack Korean Hangul.

### The chat at export time

A chat export records what Telegram said about the chat when the export began: Telegram's own
labels (`scam`, `fake`, `restricted` with its reasons, `verified`), usernames, description, member
and admin counts, the linked discussion, content protection, whether new members see earlier
messages and from which message on this account sees the history (`available_min_id`), the date
of message 1 when it is the chat's creation, and the SHA-256 of the chat photo (saved in `media/`).
It records the exporting account's place in the chat: role, join date, who invited it and, for an
admin, its rights. A request Telegram refuses is named instead.

When the exporting account is an admin, the export reads the chat's admin log (Telegram keeps about
48 hours) into `admin-log.json`: deletions and edits with the content and the account that acted. It
is the one record of a deletion that names who deleted.

### Indicators

The reports list, and the archive carries as `indicators.csv`, `indicators.stix.json` (STIX 2.1)
and `indicators.misp.json` (MISP event), what an abuse desk can act on in the recorded messages:
links and domains (also hidden behind text, in buttons and in link previews), cryptocurrency
addresses, Telegram usernames and invite links, phone numbers, e-mail addresses and saved pictures.
Bitcoin, Litecoin, Dogecoin and TRON addresses are listed only when their base58 checksum holds,
segwit addresses when their bech32 or bech32m checksum holds and TON addresses when their CRC
holds; EVM and Solana addresses are marked as not checked. Pictures carry SHA-256 and a perceptual
hash (dHash, 64 bits) that recompressed or resized copies keep nearly unchanged. Reports write
indicators so that they do not open by accident (`hxxps[://]example[.]com`); the files keep the
values as they were. Every indicator is marked unknown and not for automatic detection (STIX
`indicator_types: unknown`, MISP `to_ids: false`, distribution to the own organisation): being
listed says that a message contained it, not that it is malicious. A link whose text shows a
different address than it opens is marked in the report.

The PDF reports end with an examiner's declaration to sign by hand, a checklist for a notary or
court expert, and a QR code (also on the first page) with the report ID, the key fingerprint and
the SHA-256 of the authoritative data, so that a printout leads back to its archive.

## Event canonicalization

The hash input consists of exactly these fields:

~~~text
seq, observed_at, source_at, kind, chat_id, message_id, actor_id, payload, previous_hash
~~~

Serialize using Python-compatible JSON with UTF-8, sorted object keys, no ASCII
escaping, no insignificant whitespace, and no NaN/infinity:

~~~python
json.dumps(value, ensure_ascii=False, sort_keys=True,
           separators=(",", ":"), allow_nan=False).encode("utf-8")
~~~

SHA-256 of those bytes becomes the event hash. The signature is Ed25519 over the
32 raw hash bytes, then base64 encoded. The first previous_hash is 64 zeroes.
Sequence numbers start at 1 and increase by 1. All events, including operational
events, share one chain. There is no duplicate-delivery suppression: repeated
observations are distinct receipts, not a claim of distinct Telegram actions.

Raw Telegram dates are ISO strings; binary fields become objects containing
bytes_base64. Message text, entities, media descriptors, reply metadata, reactions,
and service actions are retained in raw message metadata when supplied.

observed_at is the collector's UTC wall clock. source_at is a supplied Telegram date
when available. Deletion notifications do not supply an exact deletion time, so
source_at remains null. Transport reception order is not necessarily source-event
order. History snapshots use older source dates but current observation times.

## Actor semantics

message.new actor_id is the message sender. message.edited has no inferred
editor; payload.sender_id records the sender of the observed message. Deletion
actor_id remains null. Membership service messages retain the sender and action
type, without converting every removal into a voluntary leave. Raw participant
updates retain actor_id as supplied. Reaction snapshots do not invent a change actor.

Deletion notifications for private chats and ordinary groups contain only message IDs.
Those chats share one account-wide ID sequence, so an ID identifies a single message of
this account. When a message with that ID was saved earlier in this journal, the
deletion is recorded in that chat as message.deleted with payload.chat_resolution
naming the method. IDs that were never saved are kept as deletion.unscoped with no
chat_id; nothing is guessed. Channels and supergroups number messages per chat and are
never matched this way. When the deleted message was sent by the observed account,
payload.deleted_message_was_outgoing is true; the deleter is still not supplied.

## Coverage: continuity, gaps and unobserved IDs

Every signed ZIP carries `coverage.json`, the HTML report opens with the same summary, and
`verify.py` recomputes it from `events.jsonl` instead of trusting the file:

- **Continuously observed from X to Y.** A period starts with `observation.started` and
  ends at a pause, a stop, a lost Telegram connection, a sign-out, a process start without
  an orderly stop, or more than three minutes without any record while observing
  (heartbeats are written every minute, so silence means the process stopped, froze or the
  computer slept). When the heartbeat interval is changed in **Parameters**, each heartbeat
  records it and the allowed silence becomes three intervals, never less than three minutes.
- **Gaps** list the time between periods with the reason. A gap still open at the last
  record is marked `not_resumed_by_last_record`.
- **Message IDs not observed.** For channels and supergroups, which number messages per
  chat, the IDs missing between observed ones are listed as ranges. They are reported as
  *not observed* — deleted, never delivered, or outside the saved history — never as
  deleted. Private chats and ordinary groups share an account-wide sequence, so gaps there
  mean nothing and are not listed.
- Chat-level gap notices (for example Telegram asking for difference recovery in one
  channel) are counted as notes; they do not interrupt global coverage.

When Telegram stops accepting the account, the `coverage.gap` record that ends observation
carries `cause` (`account_banned`, `account_frozen`, `account_deleted`, `session_duplicated`,
`session_revoked`, `session_expired`, `session_ended` or `not_authorized`) and the Telegram
error; `verify.py` names the cause where the period ends.

Coverage describes what this collector recorded. It is not proof that Telegram delivered
every update during a continuous period.

## Producer

The signed manifest of evidence ZIPs, chat exports, witness journals and the statement of
people-profile files contain `producer`: software, version, project (PhishDestroy),
homepage and source repository. The HTML report shows the same line, and `verify.py`
prints it as part of what it verified. Archives made before this field existed verify as
before and are reported as not naming a producer.

Each `observation.started` record also names the Telegram client that observed: its `api_id`
(never the hash), whether that is a built-in public pair or the operator's own application,
the client description sent in Telegram's connection request, and the kind of connection
route with the IP mode (no proxy address or secret). The report and `custody.json` list every
distinct client and route with when they were recorded, and the times no listed proxy answered
and Telegram saw the server's address. Journals recorded before this say so.

## People profiles

A profile file (`tgwitness-dossier-v1`, JSON) is built on request from records already in
the journal for one chat; nothing is fetched from Telegram and profile contents are never
written to the journal (switching profiles on and off is recorded as `dossier.changed`).
For every person with a saved message it lists name and username history, Telegram flags
(bot, scam, fake, premium, verified, restricted, deleted) as seen at saving time, profile
photo IDs, SHA-256 and perceptual hash (pHash, compatible with `imagehash.phash`) of the
avatar from the local avatar cache with similar avatars, activity (first and last message,
counts, edited and deleted shares, messages by UTC hour), who replies to whom, other chats
in this journal where the person wrote, and mentioned wallets (BTC, EVM, TRON, TON, LTC,
DOGE, XMR, SOL; Base58Check addresses are checksum-validated), phone numbers, usernames and
links, including links hidden behind text.

Every fact lists the journal records (`seq`) it comes from, and `record_hashes` holds the
hash of each referenced record. The statement is signed with the workspace key:

```sh
python verify.py tgwitness-dossier-CHAT.json --fingerprint TRUSTED_SHA256 --evidence tgwitness-evidence.zip
```

checks the signature, verifies the evidence export itself (signature, hash chain and files)
and that every referenced record exists unchanged in that export of the same workspace. Avatar hashes are labeled as coming from the local cache
(not journal records). Mentions are pattern matches — leads to check, not verified facts.
Profiles are switched on per chat, can be exported as an AES-256 ZIP with a password, and
are deleted when switched off or when the chat is removed from sources.

## Independent witness

A witness journal (`tgwitness-witness-v1`) and its channel posts are checked against an
evidence export with `verify.py --witness … --channel …`; see [independent witness](WITNESS.md).

## Manifest and checkpoints

manifest.json includes the format, export time, public key, fingerprint, journal
length, head hash, scope, producer, limitations, and SHA-256 of every content member other
than `manifest.json` and `manifest.sig` themselves.
manifest.sig is the base64 Ed25519 signature over canonical manifest JSON.
The verifier rejects unexpected/missing members, duplicate names, corrupt files,
broken sequence/chain, invalid signatures, and mismatch with a provided checkpoint.
It never extracts archive paths. It limits total declared uncompressed size to 4 GiB;
`--max-gib N` allows larger archives made with a raised **Parameters** limit.

Obtain verifier code from a trusted checkout or reviewed independent copy. A verifier
inside an untrusted archive is executable material supplied by that archive's author;
its presence is a portability convenience, not an independent trust anchor.

A checkpoint signs a statement containing the public key, journal length, head
hash, and creation time. The verifier can check that a later archive contains the
same prefix. Retain a checkpoint outside the collector before a disputed change:
an attacker controlling both archive and checkpoint can replace both.

A valid signature from an unpinned key establishes internal consistency only.
Even a pinned key cannot prove truthful source content if the collector or key was
compromised before recording. External timestamping and trusted capture are separate
requirements. TgWitness does not promise admissibility or forensic certification.

## Attachments

Files are addressed by SHA-256 under media/. A media.saved event links a hash and
byte length to a specific message event. Raw filenames are metadata, never local
paths. Media bytes are downloaded asynchronously, so immediate deletion may prevent
capture. Disabled collection, oversize/unknown-size files, download failures,
and interrupted downloads are visible as outcomes. A process crash can leave
unreferenced partial files; they are not included in exports.

The ZIP exporter verifies stored media against their names. JSONL, CSV, and HTML
exports verify event signatures but do not carry media bytes. Derivative reports
are conveniences; events.jsonl is the authoritative event representation.

A full chat export saves attachments within the workspace's attachment settings into
media/, named by SHA-256. Each message record in chat.json names its file (`file`,
`file_sha256`) or the reason it is absent (`file_status`), together with what the reader saw
around the text: links behind the text, forward origin, bot buttons, signature, views and
the auto-delete timer. `verify.py` checks that every named file is in the signed manifest
under that hash.

## Durable collection and process receipts (0.2)

A media job and its message event commit in one transaction. The job stores the
original TL message descriptor; the signed observation binds its SHA-256, account,
and size policy. Recovery verifies that binding before downloading. It never fetches
the current message and silently substitutes a newer attachment. Interrupted jobs
are retried, while permanent failure remains an explicit outcome.

Each workspace has its own journal and signing identity. A process.started event includes
a run ID, local clocks, dependency versions, source-file hashes, initial account/scope,
and capture settings. Heartbeats include the run ID, monotonic time, and queue state.
The process receipt can also be downloaded as a separately signed statement.
File measurements are self-reported and are not trusted hardware attestation.

Automatic checkpoints are retained locally on startup, every five minutes while
observing (**Parameters → Signed checkpoint every**), and on orderly stop. Startup verification and export compare the journal
against the latest retained local checkpoint. This can detect a database rollback
when the checkpoint survives; an operator controlling both can still replace both.
Independent retention and external trusted timestamps remain separate requirements.

After a restart the saved Telegram update position is resumed (`catch_up_from` in
`observation.started`) and missed updates are requested. A periodic recheck records
`message.recovered` for missed messages and `message.missing_on_recheck` when Telegram no
longer returns a saved message; the latter is not a deletion notice and names no deleter or time.

### Off-site copy and restore (S3)

The off-site copy (Exports, off by default) uploads journal segments, preserved files, checkpoints
with their timestamps and finished chat exports to S3-compatible storage, encrypted with
AES-256-GCM before upload under a key kept in the workspace vault; Object Lock retention applies
when the bucket supports it. Without the downloaded key the copy cannot be read. Restore and verify
with `python -m tgwitness.replica restore --key-file KEY.json --out DIR`.

Restore requires an empty ordinary directory. Downloads and decrypted objects stay in private
temporary storage until the entire journal and every retained checkpoint verify. Unsafe object
paths, inconsistent segment ranges and journals shorter than a checkpoint are rejected; failed
verification publishes no restored files. Retention checks compare the returned Object Lock
mode and date with the deadline sent at upload (one second of rounding tolerance). An expired,
invalid or shortened deadline does not count as verified. The status reports the sampled object
whose retention was read back for that upload pass.

Copy progress is scoped to the destination and encryption key. Changing the endpoint, bucket
or prefix starts a complete copy of the locally retained journal, media and checkpoints to
that destination. Old unscoped progress is preserved but replayed once after upgrade. Historical
chat exports already removed from the local outbox remain at their previous destination.

Missing or corrupt local media is reported as the pass's error and keeps the media cursor before
it, so the file is tried again next pass; the files, checkpoints and exports after it are still
copied. Restore checks
all preserved-media references against decrypted hashes and recorded sizes. Identical overlapping
journal segments from interrupted uploads are deduplicated; conflicting overlaps are rejected.
Checkpoints created during an upload are deferred until their covered journal records have been
copied, so a completed pass does not publish a checkpoint ahead of its journal.

### Streaming export snapshots

Streaming exports use a stable SQLite read snapshot. Its head may be older than the
current live journal when download completes. A checkpoint created after that
snapshot can correctly report that the archive is shorter; compare with a checkpoint
at or before the exported prefix, not an arbitrary later checkpoint.

## RFC 3161 preparation and response verification (0.2)

Evidence mode (off by default) sends only the SHA-256 of each signed checkpoint to the listed
RFC 3161 authorities and OpenTimestamps calendars, over the workspace route and never over MTProxy.
Answers are kept in `checkpoints/anchors/`, exported, and checked by `verify.py` (`--tsa-ca` checks
the TSA signature; confirm OpenTimestamps proofs with `ots upgrade` and `ots verify`).

The panel prepares a request archive containing canonical checkpoint.json bytes,
a SHA-256 message imprint and random nonce in timestamp.tsq, checksums, and instructions.
No network request is made. Preparation is not a trusted timestamp.

`python -m tgwitness.anchor verify` calls OpenSSL ts twice: once against checkpoint
bytes and once against the original request. A trusted CA file is required explicitly;
included certificates are not automatically trusted. Request checking is optional at
the CLI, so retain and supply --request to check the nonce. The result states whether
it was checked. The collector checkpoint signature and journal must still be verified
separately with the trusted collector fingerprint.

The current verifier does not fetch revocation information or implement long-term
archival validation after certificate expiry. Do not equate successful signature
verification with a qualified timestamp or legal admissibility. A real independent
TSA has not been contacted during development. See [procedure](TIMESTAMP.md).

## Optional records in evidence mode: drand and Telegram devices

Two more records can run on the same passes as the timestamps. Both are off by default and
take effect only while evidence mode is on: Extras → Evidence → **More witnesses · optional**,
or `"drand": true` and `"devices": true` in `POST /api/evidence`. One failing does not stop the
other or the timestamps; the panel shows the latest result of each under the form.

**drand** (`beacon.drand`). Each pass writes the newest round of drand quicknet, the public
randomness of the League of Entropy (a round every 3 seconds), into the journal: `chain`,
`round`, `randomness`, `signature`, `round_time` and the `relay` that answered. Nobody knows a
round's value before its time, so every record after it was written later. A timestamped
checkpoint bounds the same records from the other side: together they show that the journal
was written as it went, not prepared afterwards. The collector asks `drand.cloudflare.com`
first, then the relays of Protocol Labs, through the workspace route, one request per pass.

`verify.py` checks that each randomness is the SHA-256 of its signature and that the round
time is right, and reports the rounds, the longest stretch without one and how far behind
drand the collector's clock was. It does not check the BLS signature. `--check-drand`
compares the rounds with a Cloudflare relay and a Protocol Labs relay, all of them or a random
sample of 100 in a long journal; a round that differs fails the verification.

**Telegram devices** (`account.devices`). Each pass reads the account's sessions with
`account.getAuthorizations`, the list Telegram shows in Settings → Devices, and records it:
in full when it changed since the previous pass, with the `added` and `removed` session
hashes, otherwise only its count and SHA-256. Device model, platform, app and version,
creation and last activity, country and region are kept; IP addresses are not, because
evidence exports leave your hands. The collector's own session is active all the time, so
only other sessions' activity counts as a change. `verify.py` reports how often the list
was recorded and each new and ended session. It reads the list only while observation runs.

What they do not show: drand proves no more than the order of records against public time,
and the device list is Telegram's statement through the collector, signed by the collector
like every other record.

Tested on 1 November 2026: `tools/check_evidence_witnesses.py --live` wrote a real round from
`drand.cloudflare.com`, exported the journal and confirmed the round with `drand.cloudflare.com`
and `api.drand.sh`; the device list ran against simulated Telegram answers, not a real account.

**Cloudflare Gateway log** (`cloudflare.gateway_dns`). For a server that resolves through
Cloudflare Gateway ([Gateway DNS](HIGH-ASSURANCE.md#cloudflare-as-an-outside-witness)), each
pass copies what Gateway logged since the previous copy: one record per window of at most three
hours with `from`, `until`, the `location_id`, the server's `address` when one is set, and the
`queries` as `[at, name, type, rcode, decision, colo]`, also when there were none. Set it under
**Cloudflare Gateway log**: account, location, optional address and a read-only token (Account
Analytics Read; Zero Trust PII Read to keep one address of a shared location). The panel checks
them with one request before saving; the token stays encrypted and never enters the journal.
`verify.py` lists the windows, the names looked up most and any time no copy covers; a record
whose count does not match its queries fails. A window that holds more than one page of
queries in a single second keeps that page and says the rest is missing. The copy is
Cloudflare's answer through the collector, signed by the collector; within 24 hours anyone with
a read-only token can compare it with Cloudflare.
