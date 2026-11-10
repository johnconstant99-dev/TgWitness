[TgWitness](../README.md) / [Documentation](README.md) · [Evidence and verification](EVIDENCE.md)

![Evidence & verification](assets/presentation/chapter-evidence.svg)

# Limits and objections

[Independent verification](TRUST.md) · [What the record establishes](FOR-THE-RECORD.md) · [Validation record](VERIFICATION.md)

**ZERO TRUST.** You do not have to trust anyone: not the operator who collected an
archive, not PhishDestroy, and not any title or signature. Each answer below gives
the command or file that checks it. Where an objection is correct, the answer says so.

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
- [There is no independent audit](#there-is-no-independent-audit)
- [It is a pre-release preview](#it-is-a-pre-release-preview)
- [Intel TDX was tested without a Telegram account](#intel-tdx-was-tested-without-a-telegram-account)
- [A Desktop export with a qualified eIDAS timestamp is just as good](#a-desktop-export-with-a-qualified-eidas-timestamp-is-just-as-good)
- [Rule 902 is US law](#rule-902-is-us-law)
- [Deleted messages are kept despite GDPR Article 17](#deleted-messages-are-kept-despite-gdpr-article-17)
- [Data goes to third parties through public MTProxy servers](#data-goes-to-third-parties-through-public-mtproxy-servers)
- [Some features are dual-use](#some-features-are-dual-use)
- [It uses public API pairs and a Telegram Desktop profile](#it-uses-public-api-pairs-and-a-telegram-desktop-profile)
- [The installer pipes curl into bash](#the-installer-pipes-curl-into-bash)
- [The authors are not neutral](#the-authors-are-not-neutral)
- [The benchmark dates look like the future](#the-benchmark-dates-look-like-the-future)

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

- With `--fingerprint` alone, the verifier reaches `self_attested`: signatures, hash
  chain, manifest and file hashes match the collector key (`assurance` in
  [`tgwitness/verifier/witness.py`](../tgwitness/verifier/witness.py)).
- Telegram does not sign individual messages. It delivers them over the account's
  authenticated MTProto session ([where the messages come from](EVIDENCE.md#where-the-messages-come-from)),
  so the only signature on a record is the collector's.
- For this reason, the minimum for evidence requires third-party time covering the
  last record: RFC 3161 with `--tsa-ca`, OpenTimestamps with `--check-bitcoin`, a
  witness post read live from Telegram with `--channel`, a witness Bitcoin seal or a
  checked GitHub attestation (`evidence_conditions` in the same file). Without one, the
  first line reads `EVIDENCE: minimum not met` and `--require evidence` exits with code 2.
- The acquisition is checked separately. GitHub Actions capture and Intel TDX
  (`python -m tgwitness.cloud verify`) bind the signing key to an attested run
  ([verification scope](EVIDENCE.md#verification-scope)).

**Limit.** Yes. In local mode, the signature identifies a key, not the honesty of the
person who holds it. Third-party time shows when the bytes existed, not where they came from.

## The operator can fabricate records in local mode

**Objection.** Whoever controls the collector can sign records that Telegram never delivered.

**Facts.**

- The signing private key is stored Fernet-encrypted in the workspace vault on the
  operator's machine ([encryption and signatures](CONNECTION-SECURITY.md#encryption-and-signatures)).
  The run receipt records the collector version and source-file hashes, but the
  collector writes that receipt itself ([what is signed](EVIDENCE.md#what-is-signed)).
- Third-party time limits the window for changes. Records covered by a checked
  timestamp existed by that time; changing them later breaks the commitment. Records
  after the last stamp are reported as uncovered:
  `EVIDENCE: minimum met up to record N of M · later records need a binding`.
- For a chat that another account can also read, compare the archive with an
  independent export of the same chat
  ([comparing chat exports](EVIDENCE.md#comparing-chat-exports)):
  `python -m tgwitness.verify first.zip --compare second.zip --fingerprint FIRST_SHA256 --compare-fingerprint SECOND_SHA256`.
- GitHub Actions capture requires a Telegram session created inside the run and
  rejects imported sessions. Its attestation binds the archive to the approved
  workflow and collector commits ([verification scope](EVIDENCE.md#verification-scope)).

**Limit.** Yes. Local mode cannot rule out a modified collector, or records invented
before the first external timestamp. When the acquisition itself is disputed, use
attested capture.

## The checkpoint and witness are not independent

**Objection.** The collector's operator can produce both a retained checkpoint and a witness.

**Facts.**

- A checkpoint is signed with the collector key. It binds only if the recipient
  received it before the archive, through another channel
  ([manifest and checkpoints](EVIDENCE.md#manifest-and-checkpoints)).
- A witness can run next to the collector: "same host — independent process and
  key, but the same operator" ([witness](WITNESS.md)). The verifier checks only that
  the witness key differs from the collector key: "Who controls that key is a custody
  fact this verifier cannot check" (`CONDITION_SCOPE` in
  [`tgwitness/verifier/witness.py`](../tgwitness/verifier/witness.py)).
- Both are therefore supporting checks, not part of the minimum, which requires
  third-party time.
- For `--channel`, only an `https://t.me/s/…` or `https://telegram.me/s/…` page read
  live supplies Telegram-set dates. Edited posts are ignored, and a Telegram Desktop
  export or a saved page counts only as supplied metadata.

**Limit.** Yes. Neither is independent by itself. A witness is only as independent as
whoever runs it, so retain the custodian and key-control record with its fingerprint
([witness](WITNESS.md)).

## There is no independent audit

**Objection.** Nobody outside the project has reviewed the code.

**Facts.**

- No external audit is published. The maintainers produced the "Signed English audit"
  ([`website/validation/audit/REPORT.md`](../website/validation/audit/REPORT.md)) and
  signed it with their own audit key. The report states: "These are operator
  measurements, not independent attestation". To check its signature, run
  `python VERIFY.py --key-sha256 e419743db20096763ea06e480c2e6c161341de2f1023cd339c77758fb69e212f`
  in that directory.
- The [qualification status](VERIFICATION.md#qualification-status) says:
  "Independent security review and forensic certification are external steps."
- CodeQL, Trivy, OpenSSF Scorecard and zizmor run in public workflows. Scorecard
  "is automated, not a human audit" ([public records and SBOM](TRUST.md#public-records-and-sbom)).
- You can test the verifier without an audit. It is one file of about 7,000 lines;
  change one byte of `events.jsonl` in an evidence archive, and the verifier rejects it
  because the signed manifest lists that file's SHA-256
  ([manifest and checkpoints](EVIDENCE.md#manifest-and-checkpoints)).

**Limit.** Yes. Until an external review is published, statements about code quality
and test coverage are the maintainers' own.

## It is a pre-release preview

**Objection.** The software is not finished.

**Facts.**

- The README badge reads "v0.9.2 · pre-release", [current capabilities](STATUS.md)
  says "0.9.2 preview", and the [changelog](CHANGELOG.md) labels releases from 0.7.0
  onward as preview. GitHub Actions capture is marked "Preview available from `main`"
  ([GitHub capture](SEALED-ACTIONS.md)).
- The signed audit of 6 November 2026 lists open findings for its snapshot
  ([REPORT.md](../website/validation/audit/REPORT.md)), and the
  [qualification status](VERIFICATION.md#qualification-status) lists the controlled
  runs still pending.
- The public history starts at `8fb40fe0e` (author date 2026-10-30), a squashed import
  that already contains 658 files and 134,944 lines. Releases 0.7.1–0.8.1 are recorded
  by their Sigstore log entries and GitHub Actions runs ([TRUST.md](TRUST.md#release-source-archive)).
  Development before publication: [MAINTAINER: development start date, testing history].

**Limit.** Yes. Pin the commit or release you rely on, cite the run that tested it,
and treat untested paths as untested.

## Intel TDX was tested without a Telegram account

**Objection.** The confidential-VM path has not collected from a real account.

**Facts.**

- The validation record says: "No Telegram account was connected to these CVMs", and
  under "Not covered" it lists "a Telegram account on the CVM"
  ([live Phala deployment](VERIFICATION.md#live-phala-cloud-deployment--4-november-2026)).
- That run covered deployment, all 16 verifier checks (including the Intel TDX quote
  and OS measurements), restart evidence, a report sealed with a qualified eIDAS time
  stamp, and deletion (same section).
- On 9 November a Phala Cloud deployment of commit `427621d4` observed three channels
  with a dedicated test account; all six TDX checks passed and the export verified. The
  session was imported, so the tier was `self_attested`
  ([Phala Cloud with live Telegram account](VERIFICATION.md#phala-cloud-with-live-telegram-account--9-november-2026)).
  A separate run of commit `206fef76` signed in by phone code inside the VM and recorded
  `key_origin: created` ([session key created inside the TDX VM](VERIFICATION.md#session-key-created-inside-the-tdx-vm--9-november-2026)).
- The attestation relies on Intel's TDX module and microcode. "The host controls the
  machine's time source and network"
  ([attestation certificate](HIGH-ASSURANCE.md#attestation-certificate)).
- GitHub Actions capture is also preview. Its automated checks "use a synthetic
  Telegram client plus a separate real GitHub certificate test"
  ([GitHub capture](SEALED-ACTIONS.md)), and the validation record contains no entry
  for a live-account GitHub capture.

**Limit.** Partly. Live collection on TDX has run with an imported key and with a key
created in the VM. Verifying an export from such a run at the `sealed` tier, and QR login
from a phone, remain open ([qualification status](VERIFICATION.md#qualification-status)).

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

**Limit.** A qualified stamp covers the bytes it binds, whoever produced them. In local
mode, records can still be invented before the first stamp (see above). The difference is when signing happens: TgWitness signs on receipt, while a
Desktop export is protected only from the moment it is stamped.

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

**Limit.** Yes. Outside US federal courts, the template is only a starting point.
Admissibility and weight are for the court.

## Deleted messages are kept despite GDPR Article 17

**Objection.** TgWitness keeps text that its author deleted, contrary to the right to erasure.

**Facts.**

- Live observation keeps a message's text after a deletion notice by design ([README](../README.md)).
- The operator decides what is collected and is usually the controller. The project
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

**Limit.** Yes. The software does not decide whether keeping a deleted message is
lawful. The operator needs a purpose and a legal basis, and Art. 17(3)(e) applies only
where its conditions are met.

## Data goes to third parties through public MTProxy servers

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

**Limit.** Yes, for connection metadata. Public proxy operators can see that the
server connects to Telegram, when and how much, and they can drop the connection.
Where that matters, use an operator catalog or your own route.

## Some features are dual-use

**Objection.** Online watch, watchlists, people profiles, personas and case links can
be used against people.

**Facts.**

- These features exist. Online watch checks every 1–60 minutes, up to 100 accounts
  per request ([online watch](INVESTIGATION-MODE.md#online-watch), [README](../README.md)). The project guide
  says "People profiles are profiling". Personas and authorisations are described under
  [cover and authority](INVESTIGATION-MODE.md#cover-and-authority). Case links record
  the time, network address and user agent of each request
  (`tgwitness/forensics/canary.py`, described in [AGENTS.md](../AGENTS.md)).
- Investigation mode is off under the **Evidence for a case** goal, where "Conversation
  plans, watchlists, the online watch and translation refuse to run"
  ([what stays out](INVESTIGATION-MODE.md#what-stays-out)). People profiles are off by
  default and switched on per chat.
- Online watch "is an action by the investigating account and every check is
  journaled". The undercover activity record flags activity outside an authorisation's
  period or chats, and "TgWitness records and flags. It does not decide whether an
  authorisation was required or sufficient"
  ([cover and authority](INVESTIGATION-MODE.md#cover-and-authority)).
- The MIT License does not restrict use, and the README notice says "we do not
  restrict the use of this software".

**Limit.** Yes. The software records its operator's actions, but in local mode the
operator also holds that journal. Lawful use is the operator's responsibility
([responsibility and data protection](PROJECT-GUIDE.md#responsibility-and-data-protection-gdpr)).

## It uses public API pairs and a Telegram Desktop profile

**Objection.** TgWitness signs in with other applications' API pairs and presents itself
as Telegram Desktop.

**Facts.**

- [`tgwitness/api_pool.py`](../tgwitness/api_pool.py) contains 50 public API pairs.
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

**Limit.** Yes. Whether a published pair suits the account and Telegram's terms is the
operator's decision; entering your own pair avoids the question.

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

**Limit.** As with any one-line installer, piping runs the script before you have read
it. To check the script first, use the verify-first commands; the installer checks the
package and lock signatures either way. Source provenance is attested for the
[release source ZIP](TRUST.md#release-source-archive).

## The authors are not neutral

**Objection.** The maintainers take public positions, so their tool cannot be trusted.

**Facts.**

- The maintainers do take positions. The README's Ethical Notice and
  [TAYLOR-WESSING-EXCLUSION.md](TAYLOR-WESSING-EXCLUSION.md) state their position in a
  dispute, and the signed `producer` field names PhishDestroy ([producer](EVIDENCE.md#producer)).
- Verification does not depend on the authors. Its inputs are the collector
  fingerprint from the sender, the TSA root from the authority, Bitcoin block headers,
  dates that Telegram sets on witness posts, and GitHub and Sigstore attestations. None
  of them is issued by PhishDestroy.
- "Nothing is sent to the authors": there is no telemetry and no hosted service
  ([project guide](PROJECT-GUIDE.md#responsibility-and-data-protection-gdpr)).
- The verifier is MIT-licensed source in one file. It can be read, run from a reviewed
  commit or reimplemented from the documented formats ([evidence format](EVIDENCE.md)).
- The maintainers' benchmark figures, their testing history in
  [OVERVIEW.md](OVERVIEW.md#testing-history-and-duration) and the signed audit remain
  their own claims.

**Limit.** Partly. You still run code the authors wrote, so review the verifier or pin
a reviewed commit. Provenance shows which commit built a release, not that the code
is correct.

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
- The audit signature binds the published measurements to the audit key; see
  [There is no independent audit](#there-is-no-independent-audit).
- If your information predates these records, check them before concluding that the
  dates are wrong.

**Limit.** Git commit dates alone are set by whoever commits, so rely on the GitHub
Actions run records and Sigstore log entries above, which third parties keep. The public
history was squashed on 3 November 2026 ([TRUST.md](TRUST.md#release-source-archive) lists
the original commits), and the [public-history qualification](EXPORT-BENCHMARK-2026-11-06.md)
names the exact base and candidate commits it ran. Detailed operational records stay
private ([validation record](VERIFICATION.md)).
