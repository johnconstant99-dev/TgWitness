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
| Standalone CSV or HTML | No standalone cryptographic signature; event hashes alone are insufficient | Use the exact copy inside the verified ZIP for integrity checking |
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

Coverage describes what this collector recorded. It is not proof that Telegram delivered
every update during a continuous period.

## Producer

The signed manifest of evidence ZIPs, chat exports, witness journals and the statement of
people-profile files contain `producer`: software, version, project (PhishDestroy),
homepage and source repository. The HTML report shows the same line, and `verify.py`
prints it as part of what it verified. Archives made before this field existed verify as
before and are reported as not naming a producer.

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
