[TgWitness](../README.md) / [Documentation](README.md) · [Evidence and verification](EVIDENCE.md)

![Evidence & verification](assets/presentation/chapter-evidence.svg)

# What this record establishes

<details>
<summary>On this page</summary>

- [1. What each step establishes](#1-what-each-step-establishes)
- [2. Coverage, absences and outside records](#2-coverage-absences-and-outside-records)
- [3. What each step relies on](#3-what-each-step-relies-on)
- [4. Check it yourself in five minutes](#4-check-it-yourself-in-five-minutes)
- [5. Read the statuses literally](#5-read-the-statuses-literally)

</details>

## 1. What each step establishes

Read the `ASSURANCE` line first. Each green step means that its named checks passed. The reported tier is the highest step reached in order. Checks concern the complete exported journal head; a timestamp or witness fixes the prefix it covers, and later records rely on the next anchor.

The steps rely on a verifier obtained from a trusted source, the stated external trust sources and the standard cryptographic assumptions for the algorithms and keys.

* **self_attested.** Any change to the signed bytes is detected unless it is signed again with the collector's signing key. This step verifies journal integrity against the selected key; the steps above it bind the journal to parties and times outside the collector.
* **timestamped.** Changing the committed prefix while retaining the same valid external proof requires defeating the hash commitments or the external trust source. A TSA proof relies on its accepted certificate authority and clock. A Bitcoin proof places the commitment in a particular block, whose header date gives its approximate time.
* **witnessed.** Replacing the collector head independently retained by the confirmed witness requires breaking the checked commitments or replacing the witness evidence. Independence comes from who runs the witness: a witness on another host under another operator holds a separate copy. The witness's recorded observation time comes from its own clock.
* **fresh.** Preparing the checked challenge before the referenced drand value became available requires predicting that value or compromising the trust used to authenticate it. This verifier compares every credited anchor with HTTPS drand relays. The lower bound applies to the signed response that contains the drand value.
* **witness_anchored.** Changing the sealed witness prefix without invalidating its Bitcoin commitment requires defeating the hash commitments or the external block evidence. Every listed daily seal must be confirmed, with no missing days, and a seal must cover a witness record matching the export head. Confirmation means evaluated OTS operations, matching Bitcoin headers from two HTTPS explorers, and at least six confirmations reported by both.
* **sealed.** Substituting an acquisition outside the reviewed execution policy requires defeating the checked attestation, its issuer, or that policy's assumptions. The integrated path checks a GitHub-hosted acquisition against an explicitly supplied policy and a recorded newly created Telegram session, run by reviewed code on GitHub's hosted execution. Intel TDX deployments are checked with the separate TDX verifier.

`keys.count` counts recorded Telegram authorizations, and `origin` describes how the last Telegram session key was created. A session created inside a sealed run is fresh; an imported session is labelled as dependent on its source. The journal signing key is a separate key.

## 2. Coverage, absences and outside records

The package preserves captured observations, account and source identifiers, acquisition intervals and verification records. Review coverage for the selected scope and external comparison results when they are included. Recheck results and deletion notices are separate observations. Deletion IDs record what Telegram reported; the deleter and the reason appear where Telegram supplied them.

A signed journal proves what was recorded. Empty periods, unanswered checks and missing seals remain visible, so a reader sees exactly which periods the record covers. Independently retained commitments fix the journal from the moment they are made.

S3 response metadata is the provider's response, recorded under the collector's signature; the assurance tier comes from the steps above. Compliance retention protects a specific object version for its retention period. Recipient encryption protects the archive in transit and storage.

## 3. What each step relies on

| Step | Changing the record requires | Strengthen it with |
| --- | --- | --- |
| self_attested | The collector signing key | An independent checkpoint, witness or timestamp |
| timestamped | A different valid external commitment, defeated hashes, or a compromised trusted time source | Several independent time sources |
| witnessed | Witness key or evidence, plus a compatible collector history | A witness under another operator, anchored externally |
| fresh | A predictable drand value or compromised relay trust | Agreement between the Cloudflare and Protocol Labs relays |
| witness_anchored | Defeated hash commitments, altered Bitcoin evidence, or both trusted explorer responses | Headers checked against your own Bitcoin node |
| sealed | The attestation issuer or execution, the approved code or the trusted policy | A reviewed workflow and a pinned verification policy |

## 4. Check it yourself in five minutes

Use a trusted checkout with Python and `cryptography`. Obtain fingerprints separately from the packages. Replace `COLLECTOR_FP` and `WITNESS_FP`. Network services can take longer or be unavailable.

```sh
python -m tgwitness.verify evidence.zip --fingerprint COLLECTOR_FP --strict --plain
python -m tgwitness.verify witness.zip --witness-fingerprint WITNESS_FP --strict --json
python -m tgwitness.verify evidence.zip --witness witness.zip --witness-fingerprint WITNESS_FP --require-tier witness_anchored --strict --plain
```

For a pinned first package without a checkpoint, witness or timestamp, the first line is `EVIDENCE: minimum not met · missing: independent binding of the last record or external time`, followed by each evidence condition with its role (required, at least one of these, optional) and how to add it, and a `Next step:` line with the options to add; `--require evidence` returns 2 until the minimum is met. The second command includes `days`, `missing_days` and `freshness`; offline OTS remains unconfirmed. The third command checks external sources and returns 0 only if all required lower steps and witness seals pass; insufficient evidence returns 2. Verification reads the timestamps created during collection. For RFC 3161, supply an independently trusted root using `--tsa-ca`.

Compatibility mode retains exit codes 0/1. With `--strict`, 2 also means the signer is unpinned and 3 means a correctly signed format needs a newer verifier. A bad signature returns 1. JSON `verified` reports integrity; read `signer_pinned`, `requirements_met`, `evidence_profile`, `result.evidence` and `result.assurance` as well.

## 5. Read the statuses literally

* **pass:** the named check was performed and succeeded, within its stated scope and trust assumptions.
* **absent:** the evidence for that check was not supplied; it is a missing input, not a finding against the record.
* **fail:** the checked data contradicts a required commitment or condition; its cause is assessed separately.
* **no_response:** the witness recorded no usable response for that check; the witness records show the circumstances.
* **missing_days:** dates between the first and last daily seals for which no seal is present.

The verifier passes a check only when its evidence is present and valid.
