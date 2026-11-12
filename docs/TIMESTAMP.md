[TgWitness](../README.md) / [Documentation](README.md) · [Evidence and verification](EVIDENCE.md)

![Evidence & verification](assets/presentation/chapter-evidence.svg)

# Independent timestamps and evidence handoff

TgWitness prepares RFC 3161 requests and verifies timestamp authority (TSA) responses.
This manual procedure neither selects a TSA nor submits data; evidence mode does both on a
schedule ([evidence format](EVIDENCE.md#rfc-3161-preparation-and-response-verification-02)). A prepared request is
**not yet a timestamp proof**.

## What the proof binds

```mermaid
flowchart LR
    A[Account observations] --> B[SHA-256 chain and Ed25519 signatures]
    B --> C[Signed checkpoint]
    C --> D[Exact-byte hash and random nonce]
    D --> E[RFC 3161 request]
    E --> F[Independent TSA]
    F --> G[Signed TSA response]
    C --> H[Verify data, nonce and explicit CA trust]
    G --> H
```

The collector signature binds records to its key. A trusted TSA response can
establish that a particular checkpoint existed by the TSA's stated time. The
checkpoint can then bind the journal prefix. This upper time bound applies to
that committed prefix; individual Telegram actions retain their recorded event times.

## Procedure

The journal verifier reports backward steps and unparseable `observed_at` values
in `chronology` when present, and includes a warning in its command output. It
preserves the signed timestamps and still checks their signatures. A backward step
can come from a clock correction, so review it with the host's clock records.
Independent time comes from verified external timestamps, witness posts read from
their public t.me page and drand rounds; `--strict` governs signer pinning and
supported formats.

Recorded drand values receive structural and hash self-consistency checks offline.
`--check-drand` compares selected recorded rounds with HTTPS relay responses; the
result states how many rounds were compared and which relays answered, and the
compared rounds supply the authenticated lower time bound.

1. Retain the collector key fingerprint through a separate trusted channel; it
   identifies the collector independently of the examined ZIP.
2. In **Exports → Prepare timestamp request**, download the selected workspace's
   request ZIP. Extract `checkpoint.json`, `timestamp.tsq`, `SHA256SUMS` and
   `README.txt`. Do not change the checkpoint bytes.
3. Choose a TSA appropriate to the investigation. Submit `timestamp.tsq` using its
   documented method, with `application/timestamp-query` for an HTTP service.
   Save the original binary reply as `timestamp.tsr`, the endpoint, retrieval time
   and request outcome. The request contains a hash and nonce rather than messages;
   network metadata still reveals the request.
4. Obtain the trusted root certificate independently of the reply, plus any
   intermediates required. A certificate in the reply does not become trusted merely
   because it is included there.
5. From a trusted TgWitness installation, verify:

```sh
python -m tgwitness.anchor verify --checkpoint checkpoint.json --request timestamp.tsq --response timestamp.tsr --ca trusted-tsa-root.pem
```

Add `--intermediates tsa-intermediates.pem` or `--openssl /path/to/openssl` if needed.
OpenSSL must support `ts`. On Windows the verifier also searches the standard Git
installation. OpenSSL 3.5.9 was used for the synthetic CA/TSA tests and for the live
service check below.

6. Export a signed journal ZIP after the checkpoint so it includes that prefix.
   Verify using the independently known fingerprint:

```sh
python tgwitness/verify.py evidence.zip --fingerprint TRUSTED_SHA256 --checkpoint checkpoint.json
```

   This shows that the export contains the timestamped prefix. `verify.py` reads
   timestamp receipts only from the ZIP, where evidence mode stores them; the manual
   reply is checked in step 5 and covers the records up to this checkpoint.

7. Preserve the ZIP, checkpoint, request, reply, certificate chain, verification
   results and handoff record outside the collector. Repeat verification at receipt.

To prepare a request from a saved checkpoint:

```sh
python -m tgwitness.anchor prepare checkpoint.json --out timestamp-request.zip
```

Preparation canonicalizes JSON and includes the matching checkpoint in the archive.
Use the **checkpoint bytes from that archive** for TSA verification, even if the
input file had different whitespace.

## Verification boundaries

| Check | Current behavior |
| --- | --- |
| Data | SHA-256 of the exact checkpoint bytes must match the response |
| Request | With `--request`, the original query and nonce are verified |
| TSA signature | OpenSSL verifies the signature and chain to the explicit CA |
| Collector signature | Separately verified by the journal verifier with a pinned key |
| Revocation | Evidence mode stores OCSP/CRL evidence that `verify.py` checks |
| Scheduled submission | Evidence mode, off by default |

`--request` is technically optional, but omitting it prevents verification of the
original nonce. For this full procedure, the result's `request_checked` must be true.
Certificate verification follows the installed OpenSSL's rules and verification time.

The TSA response anchors the submitted checkpoint bytes to its stated time.
Review that result with the acquisition records and environment verification for
the selected mode. Evidence mode includes the Belgian government's qualified TSA
(`http://tsa.belgium.be/connect`; RFC 3161 replies are signed, so plain HTTP does not
weaken them). With that provider's root passed to `--tsa-ca`, `verify.py` reports a
qualified eIDAS time stamp and its time stamping unit; Regulation (EU) No 910/2014,
article 41(2), presumes the accuracy of its time and the integrity of the bound data.

### Signing certificate revocation

Right after each reply, evidence mode fetches revocation evidence for the TSA signing
certificate: an OCSP response from the certificate's AIA OCSP address, otherwise the CRL
from its distribution point (at most 4 MiB). It is stored next to the reply as
`checkpoint-N.<service>.ocsp` or `.crl` and exported with it. A failed fetch never holds
back the time stamp; the `anchor.completed` record lists it as `unavailable` with the reason.

`verify.py` checks the OCSP response signature (by the issuer, or by a responder certificate
the issuer gave the OCSP signing purpose), the certificate ID and the status, and that the
answer was issued at or after genTime or was still current then (nextUpdate). For a CRL it
checks the issuer's signature, the same time window and that the serial number is not listed.
It then reports `signing certificate not revoked as of <time> (OCSP|CRL)`, the failed check,
or `revocation not checked (no OCSP/CRL in the archive)`. A signing certificate revoked at or
before genTime fails verification; a later revocation is shown as a warning.

## Handoff record

Record the case identifier, sender and recipient, UTC transfer time and its source,
purpose, filenames/SHA-256 values, collector fingerprint, sequence range, known
gaps, verifier version and verification outcome. Sign and independently retain this
record through your organization's process. A multi-user custody-record system is
not implemented in TgWitness.

## Live service check, 9 November 2026

One RFC 3161 request was sent to each default service. Both granted it.

| Service | Reply | Signing unit | Verifier result |
| --- | --- | --- | --- |
| `http://tsa.belgium.be/connect` | Granted, policy 2.16.56.13.6.3.1.1000 | Timestamp Unit 202301 | Qualified eIDAS time stamp |
| `https://freetsa.org/tsr` | Granted | FreeTSA | RFC 3161 time stamp |

The Belgian signing certificate carries the qcStatements compliance statement and
matches the unit recorded in the verifier. Local tests also use a synthetic CA/TSA to
check rejection of changed data, a changed nonce and a wrong CA.

On 10 November 2026 the Belgian OCSP responder, a delegated responder certificate, answered
"good" for Timestamp Unit 202301. FreeTSA's OCSP address (port 2560) did not answer within
40 seconds from the test host; its CRL (PEM, 1 KB) was used instead.
