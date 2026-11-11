[TgWitness](../README.md) / [Documentation](README.md) · [Evidence and verification](EVIDENCE.md)

![Evidence & verification](assets/presentation/chapter-evidence.svg)

# Limits and objections

[Independent verification](TRUST.md) · [What the record establishes](FOR-THE-RECORD.md) · [Validation record](VERIFICATION.md)

**ZERO TRUST.** You do not have to trust anyone: not the operator who collected an
archive, not PhishDestroy, and not any title or signature. Each answer below states
what the record establishes and gives the command or file that checks it.

Trusted inputs come from a channel other than the file being checked: the collector
fingerprint from the sender, a timestamp authority's root from that authority, a commit
from your own review. Run the verifier from an installation or commit you trust; the
copy inside an archive is a convenience ([manifest and checkpoints](EVIDENCE.md#manifest-and-checkpoints)).
The verifier is one file, [`tgwitness/verify.py`](../tgwitness/verify.py), assembled from
[`tgwitness/verifier/`](../tgwitness/verifier/README.md);
`python tools/build_standalone_verifier.py --check` detects drift between the two.
It needs Python 3.11+ and `cryptography`.

<details>
<summary>On this page</summary>

- [Commands used on this page](#commands-used-on-this-page)
- [The proof is only the collector's own signature](#the-proof-is-only-the-collectors-own-signature)
- [The operator can fabricate records in local mode](#the-operator-can-fabricate-records-in-local-mode)
- [The checkpoint and witness are not independent](#the-checkpoint-and-witness-are-not-independent)
- [A Desktop export with a qualified eIDAS timestamp is just as good](#a-desktop-export-with-a-qualified-eidas-timestamp-is-just-as-good)
- [Rule 902 is US law](#rule-902-is-us-law)
- [A deleted message stays in the record](#a-deleted-message-stays-in-the-record)
- [A public MTProxy relays encrypted traffic only](#a-public-mtproxy-relays-encrypted-traffic-only)
- [Built-in API pairs identify a client, not an account](#built-in-api-pairs-identify-a-client-not-an-account)
- [The installer pipes curl into bash](#the-installer-pipes-curl-into-bash)
- [The benchmark dates look like the future](#the-benchmark-dates-look-like-the-future)
- [The project is only two weeks old](#the-project-is-only-two-weeks-old)

</details>

## Commands used on this page

**Evidence archive.** `--require evidence` exits with code 2 unless integrity, the
pinned collector key and third-party time covering the last record are all met.
Add `--explain` for a plain description of what each check shows and does not show.

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --check-bitcoin --require evidence
```

To read witness posts from Telegram, add
`--witness witness.zip --witness-fingerprint WITNESS_SHA256 --channel https://t.me/s/WITNESS_CHANNEL`.
`--require-tier TIER` exits with code 2 below that [assurance tier](FOR-THE-RECORD.md#1-what-each-step-establishes).

**Release source ZIP** ([release source archive](TRUST.md#release-source-archive)).
`COMMIT` is the full SHA you reviewed:

```sh
gh attestation verify "TgWitness-${VERSION}.zip" --repo phishdestroy/TgWitness \
  --signer-workflow phishdestroy/TgWitness/.github/workflows/provenance.yml \
  --signer-digest "$COMMIT" --source-digest "$COMMIT" \
  --source-ref "refs/tags/v${VERSION}" --deny-self-hosted-runners
```

**GitHub Actions capture** ([sealed evidence](TRUST.md#sealed-evidence)). `WORKFLOW_SHA`
is a `workflow_sha` listed in `tgwitness/sealed_policy.json` of an installation you trust:

```sh
gh attestation verify evidence.zip --bundle attestation.jsonl --repo OWNER/TgWitness \
  --signer-workflow phishdestroy/TgWitness/.github/workflows/sealed-collector.yml \
  --signer-digest WORKFLOW_SHA --deny-self-hosted-runners
python -m tgwitness.sealed_verify evidence.zip --bundle attestation.jsonl --repo OWNER/TgWitness
```

**Installer script before it runs** ([verify before running](INSTALLATION.md#verify-before-running)):

```sh
curl -fSLO https://get.destroy.tools/install.sh && curl -fSLO https://get.destroy.tools/install.sh.sig &&
curl -fSLO https://get.destroy.tools/release-signing.pub &&
test "$(openssl dgst -sha256 release-signing.pub | awk '{print $NF}')" = \
  '039d98a658ccda14253e45a00335b4a68d840976d8ec18b8d4355cc7c458447d' &&
openssl dgst -sha256 -verify release-signing.pub -signature install.sh.sig install.sh && bash install.sh
```

## The proof is only the collector's own signature

**Objection.** A record signed by the collector proves only that the collector signed it.

**Facts.**

- The signature protects a record after it arrives. Where it came from is established
  by the connection it arrived through, and that is checked separately
  ([where the messages come from](EVIDENCE.md#where-the-messages-come-from)).
- Telegram delivers messages to every client, official apps included, inside an MTProto
  session. Its authorization key is negotiated against Telegram's pinned server key, and
  each update is decrypted and integrity-checked (`msg_key`) under that key. A proxy or
  relay on the way cannot read, insert or change an update.
- The connection goes to Telegram's published network ranges. **More tools → System map**
  shows for each connected account whether its endpoint is in the Telegram pool
  (`TELEGRAM_NETWORKS` in [`tgwitness/topology.py`](../tgwitness/topology.py)).
- Captured MTProto frames can be decrypted with the session's own key and matched to
  journal entries by message identifier and payload SHA-256
  ([`tgwitness/forensics/`](../tgwitness/forensics/)).
- Each record carries the identifiers and server dates Telegram assigned: chat, message
  and sender. Another account in the same chat receives the same identifiers, and
  `--compare` checks two exports against each other
  ([comparing chat exports](EVIDENCE.md#comparing-chat-exports)).
- A [witness probe](ACCOUNTS.md#witness-probe) from a second account shows that the
  session received updates live; a second client on the same key shows up as missed
  answers. The verifier reports "Witness probes: sent N, answered live N".
- GitHub Actions capture and Intel TDX bind a session created inside the run and the
  signing key to the attested execution (`key_origin: created`;
  [verification scope](EVIDENCE.md#verification-scope)).

**What the verifier reports.** With `--fingerprint` alone: `self_attested` (signatures,
hash chain, manifest and file hashes). With third-party time covering the last record:
`EVIDENCE: minimum met`. With a checked attested run: profile `attested`
(`evidence_conditions` in [`tgwitness/verifier/witness.py`](../tgwitness/verifier/witness.py)).

## The operator can fabricate records in local mode

**Objection.** Whoever controls the collector can sign records that Telegram never delivered.

**Facts.**

- Each observation is signed when it arrives and linked into a hash chain
  ([what is signed](EVIDENCE.md#what-is-signed)). Evidence mode timestamps signed
  checkpoints every 10 minutes by default at three TSAs, one of them the Belgian
  government's qualified eIDAS TSA (`DEFAULT_TSA` in `tgwitness/anchoring.py`), and on
  OpenTimestamps.
- A record covered by a stamp cannot be changed, inserted or removed afterwards: the
  hash chain breaks and the verifier rejects the archive. Records after the last stamp are
  named: `EVIDENCE: minimum met up to record N of M · later records need a binding`.
- With drand on, each pass also writes a public drand round that nobody knew before its
  time. The round sets the earliest time and the next stamp the latest, so a checkpoint
  cannot be prepared in advance; `--check-drand` compares the rounds with public relays
  ([drand](EVIDENCE.md#optional-records-in-evidence-mode-drand-and-telegram-devices)).
- Observation times that go backwards are reported as chronology regressions
  (`tgwitness/verifier/journal.py`).
- A record must match what Telegram delivered to every other member of the chat. An
  independent export of the same chat shows any difference
  ([comparing chat exports](EVIDENCE.md#comparing-chat-exports)):
  `python -m tgwitness.verify first.zip --compare second.zip --fingerprint FIRST_SHA256 --compare-fingerprint SECOND_SHA256`.
- A witness with its own key retains earlier journal prefixes, and witness posts read
  live from t.me carry dates Telegram set ([witness](WITNESS.md)).
- GitHub Actions capture and Intel TDX take acquisition away from the operator: the
  session is created inside the attested run (an imported session does not reach the
  `attested` profile), and the attestation binds the archive to the approved collector
  ([verification scope](EVIDENCE.md#verification-scope)).

**What the verifier reports.** The records each stamp covers, and the interval between
a record and the next stamp. In evidence mode that interval is the stamping schedule.

## The checkpoint and witness are not independent

**Objection.** The collector's operator can produce both a retained checkpoint and a witness.

**Facts.**

- A checkpoint is signed with the collector key. It binds only if the recipient
  received it before the archive, through another channel
  ([manifest and checkpoints](EVIDENCE.md#manifest-and-checkpoints)).
- A witness can run next to the collector: "same host — independent process and
  key, but the same operator" ([witness](WITNESS.md)). The verifier checks that the
  witness key differs from the collector key; "Who holds that key is shown by the
  custodian's key-control record, kept with its fingerprint" (`CONDITION_SCOPE` in
  [`tgwitness/verifier/witness.py`](../tgwitness/verifier/witness.py)).
- Both are supporting checks; the minimum for evidence is third-party time.
- For `--channel`, only an `https://t.me/s/…` or `https://telegram.me/s/…` page read
  live supplies Telegram-set dates. Edited posts are ignored, and a Telegram Desktop
  export or a saved page counts only as supplied metadata.

**Scope.** A checkpoint binds from the moment the recipient received it. A witness on
another operator's machine is independent of the collector; retain the custodian and
key-control record with its fingerprint ([witness](WITNESS.md)).

## A Desktop export with a qualified eIDAS timestamp is just as good

**Objection.** Export the chat with Telegram Desktop and have a qualified TSA stamp
the files; no special tool is needed.

**Facts.**

- Telegram Desktop writes its export as HTML or JSON files without a signature. They
  can be edited before they are stamped, and a qualified time stamp then confirms
  that the edited files existed at that time. The
  [Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/) shows a
  conversation beside deliberately altered Desktop export files.
- TgWitness signs each observation when it arrives and links it into the hash chain
  ([what is signed](EVIDENCE.md#what-is-signed)). When evidence mode is turned on (in
  settings, or by the **Follow chats** and **Evidence for a case** setup goals), it
  timestamps signed checkpoints on a schedule.
- TgWitness can use a qualified TSA. The manual RFC 3161 procedure sends a checkpoint
  to any TSA and checks the reply with
  `python -m tgwitness.anchor verify --checkpoint checkpoint.json --request timestamp.tsq --response timestamp.tsr --ca trusted-tsa-root.pem`
  ([procedure](TIMESTAMP.md#procedure)). The Intel TDX attestation certificate is
  sealed by the Belgian government's qualified TSA, whose root is pinned in
  `tgwitness/tsa_roots.py` ([attestation certificate](HIGH-ASSURANCE.md#attestation-certificate)).

- Evidence mode sends each checkpoint to the Belgian government's qualified TSA
  together with freetsa.org and Sectigo (`DEFAULT_TSA` in `tgwitness/anchoring.py`).
  With `--tsa-ca` set to that provider's root, `verify.py` reports the stamp as a
  qualified eIDAS time stamp and names the time stamping unit from the EU trusted list
  (`qualified_timestamp` in `tgwitness/verifier/timestamps.py`). Under Regulation (EU)
  No 910/2014, article 41(2), such a stamp carries the presumption that its time is
  accurate and that the bound data is intact, in every EU member state.

**Difference.** TgWitness signs each record on receipt and stamps checkpoints on a
schedule, so the stamped bytes are the bytes received. A Desktop export is protected only
from the moment it is stamped, after it could be edited.

## Rule 902 is US law

**Objection.** The court template is useless outside the United States.

**Facts.**

- The court package's certification is "pre-filled in the shape of a Rule
  902(13)/(14) certificate" ([documents for court](INVESTIGATION-MODE.md#documents-for-court)).
  Its notice begins "Under the US Federal Rules of Evidence" and ends "Adapt this
  template to the rules that apply before signing" (`NOTICE` in
  [`tgwitness/court.py`](../tgwitness/court.py)).
- [Jurisdiction guidance](JURISDICTION_GUIDANCE.md) in Report Studio covers 25
  jurisdictions as reference material and notes that "a country is not a substitute
  for identifying the actual court". The narrative jurisdiction catalogs are "a
  reference table, not a legal opinion", and every language is marked
  machine-assisted, not reviewed ([templates and jurisdictions](NARRATIVE.md#templates-and-jurisdictions)).
- Archive verification does not depend on any jurisdiction: signatures, RFC 3161,
  Bitcoin and attestation checks are technical.

**Scope.** Outside US federal courts, the template is a starting point. Admissibility
and weight are for the court.

## A deleted message stays in the record

**Objection.** Keeping text that its author deleted conflicts with the GDPR right to erasure.

**Facts.**

- TgWitness "records content delivered to the connected Telegram account"
  ([README](../README.md)): the messages that account's own Telegram app receives,
  and nothing beyond them. When a deletion notice arrives, live observation records
  the notice and keeps the text by design.
- The software has no telemetry and no hosted service ([README](../README.md)), so
  it holds no one's data on its own behalf. As with a screenshot or a Telegram Desktop
  export, data protection duties fall on whoever collects and uses the record. The project
  guide names the legitimate interests commonly relied on (GDPR Art. 6(1)(f),
  Recitals 47 and 49; Art. 9(2)(f) for legal claims) and the erasure exception "for
  the establishment or defence of legal claims (Art. 17(3)(e))"
  ([responsibility and data protection](PROJECT-GUIDE.md#responsibility-and-data-protection-gdpr)).
- The journal is append-only, so single records cannot be removed without breaking
  the signature chain. Retention is planned per workspace, and deleting the workspace
  removes its records. Off-site copies under S3 Object Lock cannot be deleted before
  their retention date (same section).
- People profiles are off by default and switched on per chat. Exports make it
  possible to answer access requests under Art. 15 (same section).

**Scope.** GDPR governs people and organisations that process data, not a program.
A deleted message stays in the record the way it stays in any copy saved before the
deletion; the guide lists the legal bases used for legal claims.

## A public MTProxy relays encrypted traffic only

**Objection.** Default connections run through proxies operated by unknown people.

**Facts.**

- New workspaces default to **Automatic MTProxy · public lists** with **Hide the
  address** ([MTProto, Telethon and proxies](CONNECTION-SECURITY.md#mtproto-telethon-and-proxies)).
  The lists come from the public sources named under
  [public proxies](CONNECTION-SECURITY.md#public-proxies-supplied-by-your-installation).
- An MTProxy carries Telegram traffic only. That traffic is encrypted under a session
  key negotiated against Telegram's pinned server key
  ([where the messages come from](EVIDENCE.md#where-the-messages-come-from)), so a
  proxy relays it without reading messages or keys. As a network relay, it still
  receives the connecting address and the timing and volume of the traffic.
- "No Telegram session, API credentials, panel token or bot token is sent to feed
  providers" ([public proxies](CONNECTION-SECURITY.md#public-proxies-supplied-by-your-installation)).
- The operator chooses the other outbound services. Timestamp services receive
  checkpoint hashes, not messages ([procedure](TIMESTAMP.md#procedure)). AI starts
  disabled in every workspace and shows the data it will send before each request
  ([analysis](ANALYSIS.md)). Notifications carry no message text unless excerpts are
  turned on ([project guide](PROJECT-GUIDE.md#responsibility-and-data-protection-gdpr)).
  **More tools → System map** lists the connections the process attempts
  ([system map](SYSTEM-MAP.md)).
- An operator catalog set with `TGWITNESS_PROXY_CATALOG` "disables external
  subscriptions entirely"; your own SOCKS5 or HTTP route is the other alternative
  ([connection security](CONNECTION-SECURITY.md)).

**Scope.** A public proxy sees connection metadata: that the server connects to
Telegram, when and how much, as any proxy or VPN does. It cannot read or change
messages, and it can drop the connection. Where metadata matters, use an operator
catalog or your own route.

## Built-in API pairs identify a client, not an account

**Objection.** TgWitness signs in with API pairs it did not register and presents itself
as Telegram Desktop.

**Facts.**

- An API ID and API hash "identify the application to Telegram; they do not authorize
  an account by themselves" ([API ID and API hash](ACCOUNTS.md#before-you-start-api-id-and-api-hash)).
  A pair is not linked to anyone's account or data and gives no access to them. Access
  to an account comes only from its own sign-in: a login code and 2FA password, or a
  session that account already authorized.
- [`tgwitness/api_pool.py`](../tgwitness/api_pool.py) contains 50 public API pairs
  already used by open-source clients ([project guide](PROJECT-GUIDE.md#connect-a-telegram-account)).
  A fresh login tries Telegram Desktop's pair (2040) first, then up to seven shuffled
  others (`login_order`). "Only the Telegram Desktop pair (2040) is sent with a
  matching Telegram Desktop client description"
  ([authentication methods](CONNECTION-SECURITY.md#authentication-methods)).
  Missing device fields come from bundled opentele2 catalogs
  ([API ID and API hash](ACCOUNTS.md#before-you-start-api-id-and-api-hash)).
- This lets someone sign in without creating a Telegram API application. If you enter
  your own pair from [my.telegram.org](https://my.telegram.org), TgWitness uses it
  instead.
- Each `observation.started` record names the `api_id` (never the hash), whether the
  pair is built-in or the operator's own, the client description and the route type.
  Reports and `custody.json` list them ([producer](EVIDENCE.md#producer)), so a
  recipient can see which client observed.
- Telegram's [API terms](https://core.telegram.org/api/obtaining_api_id) apply to
  every client ([project guide](PROJECT-GUIDE.md)). Telegram can refuse a published
  pair (`API_ID_PUBLISHED_FLOOD`) or restrict an account, and the guide recommends "a
  dedicated account you can afford to lose".

**Scope.** The pair that signed in does not change what the account receives or what
the record proves. "Telegram decides restrictions on its side, whichever client profile
is used" ([accounts](ACCOUNTS.md#before-you-start-api-id-and-api-hash)).

## The installer pipes curl into bash

**Objection.** Piping a downloaded script into a shell runs code without checking it.

**Facts.**

- A one-line installer is the usual way developer tools are installed: Claude Code
  (`curl -fsSL https://claude.ai/install.sh | bash`), rustup
  (`curl … https://sh.rustup.rs | sh`), Homebrew and Docker's `get.docker.com` script use
  the same pattern. TgWitness adds the checks below on top of it.
- The [verify-first commands](INSTALLATION.md#verify-before-running) download the
  script, its detached signature and the public key, check the key's SHA-256, verify
  the signature with OpenSSL and only then run the script. The expected key hash is
  the SHA-256 of [`deploy/installer/release-signing.pub`](../deploy/installer/release-signing.pub):
  `git show origin/main:deploy/installer/release-signing.pub | sha256sum`.
- The installer checks the SHA-256 and RSA signature of the application package and
  dependency lock before installing, and "Both Bash and PowerShell stop when a
  required check fails" (same section).
- [installer.yml](../.github/workflows/installer.yml) builds from the exact `main`
  revision and qualifies the result on Linux and Windows. It waits for `checks.yml`
  and `security-audit.yml` on the same commit, publishes only if `main` has not moved,
  and then checks the public downloads. The [manifest](https://get.destroy.tools/manifest.json)
  records the version, commit, release ID and each artifact's SHA-256.
- GitHub Releases with an attested source ZIP ([release source archive](TRUST.md#release-source-archive)),
  source installation and [Docker](DEPLOYMENT.md) are the alternatives.

**Scope.** As with any one-line installer, piping runs the script before you have read
it. To check the script first, use the verify-first commands; the installer checks the
package and lock signatures either way. Source provenance is attested for the
[release source ZIP](TRUST.md#release-source-archive).

## The benchmark dates look like the future

**Objection.** The measurements are dated November 2026, which looks wrong.

**Facts.**

- Each measurement names its revision. The release audit and fresh exports used source
  `92e539af40d8`; `git show -s --format=fuller 92e539af40d8` shows 2026-11-06, and
  GitHub ran [Checks](https://github.com/phishdestroy/TgWitness/actions/runs/42263850905)
  and the [Installer](https://github.com/phishdestroy/TgWitness/actions/runs/42263850962)
  on that commit ([REPORT.md](../website/validation/audit/REPORT.md)). The installer
  inspection on 8 November used `b35f8e18f3d1`, with
  [CI](https://github.com/phishdestroy/TgWitness/actions/runs/42446658989) and the
  [installer run](https://github.com/phishdestroy/TgWitness/actions/runs/42446659252)
  ([validation record](VERIFICATION.md)).
- GitHub records when each Actions run took place. Sigstore's transparency log
  timestamps each release attestation ([public records and SBOM](TRUST.md#public-records-and-sbom)).
- The audit signature binds the published measurements to the audit key: run
  `python VERIFY.py --key-sha256 e419743db20096763ea06e480c2e6c161341de2f1023cd339c77758fb69e212f`
  in [`website/validation/audit/`](../website/validation/audit/REPORT.md).
- If your information predates these records, check them before concluding that the
  dates are wrong.

**Scope.** Git commit dates alone are set by whoever commits, so rely on the GitHub
Actions run records and Sigstore log entries above, which third parties keep. The public
history was squashed on 3 November 2026 ([TRUST.md](TRUST.md#release-source-archive) lists
the original commits), and the [public-history qualification](EXPORT-BENCHMARK-2026-11-06.md)
names the exact base and candidate commits it ran. Detailed operational records stay
private ([validation record](VERIFICATION.md)).

## The project is only two weeks old

**Objection.** The repository was created at the end of October 2026, so the software is
two weeks old.

**Facts.**

- TgWitness has been developed and tested for about six months. The collector, the signed
  journal and the verifier came first; the web panel and the add-on modules were built on
  them later ([testing history](OVERVIEW.md#testing-history-and-duration)).
- This repository was created new on 29 October 2026 for publication and began with the
  existing code: its first commit, `8fb40fe0e` "Initial version", already contains 658 files
  and 134,944 lines. Check: `git show --shortstat 8fb40fe0e`.
- The [changelog](CHANGELOG.md) starts at version 0.5.0, dated 26 October 2026, before the
  repository was created. Sigstore log entries and GitHub Actions run records for the
  0.7.1–0.8.1 releases name the original commits ([TRUST.md](TRUST.md#release-source-archive)).

**Scope.** The repository's creation date and commit count describe this repository, not
the age of the software in it.
