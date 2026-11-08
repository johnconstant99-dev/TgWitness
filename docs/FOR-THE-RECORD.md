[TgWitness](../README.md) / [Documentation](README.md) · [Evidence and verification](EVIDENCE.md)

![Evidence & verification](assets/presentation/chapter-evidence.svg)

# What this record establishes

Draft for reader review. A lawyer has not reviewed this text or tested it aloud with a reader.

<details>
<summary>On this page</summary>

- [1. What the package asserts](#1-what-the-package-asserts)
- [2. What the package does not assert](#2-what-the-package-does-not-assert)
- [3. Who could falsify what](#3-who-could-falsify-what)
- [4. Check it yourself in five minutes](#4-check-it-yourself-in-five-minutes)
- [5. Read the statuses literally](#5-read-the-statuses-literally)

</details>

## 1. What the package asserts

Read the `ASSURANCE` line first. Each green step means that its named checks passed. The reported tier stops at the first missing step. Checks concern the complete exported journal head. A timestamp or witness covering an earlier prefix does not certify a later tail.

The claims below assume an independently obtained, trusted verifier and the stated external trust sources. Cryptographic resistance is an assumption about the algorithms and keys, not an unconditional mathematical promise. A malicious verifier can print a false result.

* **self_attested.** Changing authenticated bytes without detection requires the signing key or defeating the checked cryptography. The collector holds that key and can create a different signed history. This step verifies journal integrity against the selected key; external dates are checked at the timestamped step.
* **timestamped.** Changing the committed prefix while retaining the same valid external proof requires defeating the hash commitments or the external trust source. A TSA proof depends on its accepted certificate authority and clock. A Bitcoin proof establishes a commitment in a particular block. Its header date is not an exact UTC receipt time.
* **witnessed.** Replacing the collector head independently retained by the pinned witness requires breaking the checked commitments or replacing the witness evidence. This does not prove that the two operators acted independently. The witness's recorded observation time comes from its own clock.
* **fresh.** Preparing the checked challenge before the referenced drand value became available requires predicting that value or compromising the trust used to authenticate it. This verifier compares every credited anchor with HTTPS drand relays. It does not verify the BLS signature itself. The displayed lower bound concerns the signed response, not the creation of each message.
* **witness_anchored.** Changing the sealed witness prefix without invalidating its Bitcoin commitment requires defeating the hash commitments or the external block evidence. Every listed daily seal must be confirmed, with no missing days, and a seal must cover a witness record matching the export head. Here confirmation means evaluated OTS operations, matching Bitcoin headers from two HTTPS explorers, and at least six confirmations reported by both. This is not full Bitcoin chain validation.
* **sealed.** Substituting an acquisition outside the reviewed execution policy requires defeating the checked attestation, its issuer, or that policy's assumptions. The integrated path checks a GitHub-hosted acquisition against an explicitly supplied policy and a recorded newly created Telegram session. It depends on GitHub execution and reviewed code. TDX claims alone do not pass this step; this CLI does not integrate a TDX check.

`keys.count` counts recorded Telegram authorizations. `origin` describes the last Telegram session key. Neither field proves that no secret key copies exist. The journal signing key is a different key. An imported session is explicitly identified as dependent on its source.

## 2. What the package does not assert

The package preserves captured observations, account and source identifiers, acquisition intervals and verification records. Review coverage for the selected scope and external comparison results when they are included. A missing message on recheck is not a deletion notice. Several deletion IDs do not establish a cleared history, who deleted it, or another participant's intent.

A signed journal proves what was recorded. Empty periods, unanswered checks and missing seals remain visible. An absent record is not proof that nothing happened. An operator can omit observations before they enter any independently retained commitment.

S3 response metadata is a provider response recorded under the collector's signature. It is not S3's independent signature and does not raise the assurance tier. Compliance retention protects a specific object version for its retention period. Recipient encryption does not prove that the collecting operator erased plaintext or temporary keys.

## 3. Who could falsify what

| Step | What an attacker needs | Practical limitation |
| --- | --- | --- |
| self_attested | Collector signing key | The collector already holds it. |
| timestamped | Different valid external commitment, defeated hashes, or compromised trusted time source | Independent proof constrains an already committed prefix. |
| witnessed | Witness key/evidence, plus a compatible collector history | Collector and witness can collude before external commitment. |
| fresh | Predictable drand value or compromised relay trust | Current verification trusts TLS relay responses, not local BLS verification. |
| witness_anchored | Defeated hash commitments, altered Bitcoin evidence, or both trusted explorer responses | Explorer agreement is not an independently validated full chain. |
| sealed | Attestation issuer/execution, approved code or trusted policy | This path verifies GitHub acquisition provenance against the approved code and policy; Intel TDX has a separate verification path. |

## 4. Check it yourself in five minutes

Use a trusted checkout with Python and `cryptography`. Obtain fingerprints separately from the packages. Replace `COLLECTOR_FP` and `WITNESS_FP`. Network services can take longer or be unavailable.

```sh
python -m tgwitness.verify evidence.zip --fingerprint COLLECTOR_FP --strict --plain
python -m tgwitness.verify witness.zip --witness-fingerprint WITNESS_FP --strict --json
python -m tgwitness.verify evidence.zip --witness witness.zip --witness-fingerprint WITNESS_FP --require-tier witness_anchored --strict --plain
```

For a signature-only first package, the first line is `ASSURANCE: self_attested`. The second command includes `days`, `missing_days` and `freshness`; offline OTS remains unconfirmed. The third command checks external sources and returns 0 only if all required lower steps and witness seals pass; insufficient evidence returns 2. It does not create a timestamp. For RFC 3161, supply an independently trusted root using `--tsa-ca`.

Compatibility mode retains exit codes 0/1. With `--strict`, 2 also means the signer is unpinned and 3 means a correctly signed format needs a newer verifier. A bad signature returns 1. JSON `verified` reports integrity; read `signer_pinned`, `requirements_met` and `result.assurance` as well.

## 5. Read the statuses literally

* **pass:** the named check was performed and succeeded, within its stated scope and trust assumptions.
* **absent:** the verifier lacks sufficient checked evidence; **absent does not mean forgery**.
* **fail:** the checked data contradicts a required commitment or condition; it does not establish intent.
* **no_response:** the witness recorded no usable response for that check; it does not establish why.
* **missing_days:** dates between the first and last daily seals for which no seal is present; this does not account for unsealed time outside that interval.

The verifier can refuse confirmation. It cannot turn missing evidence into a passed check.
