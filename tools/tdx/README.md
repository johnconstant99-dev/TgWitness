[TgWitness](../../README.md) / [tools](../README.md)

<picture>
  <source media="(max-width: 640px)" srcset="../../docs/assets/presentation/section-tools-mobile.svg">
  <img src="../../docs/assets/presentation/section-tools.svg" width="1200" alt="TgWitness / Build and verify">
</picture>

# Intel TDX test vectors

Real quotes and Intel collateral for `tools/check_tdx.py`, the quotes as hex text. They are checked
against the pinned Intel SGX Root CA by `tgwitness.tdx`, at a time inside each collateral's
validity window.

| File | Source |
| --- | --- |
| `intel-v4.quote.hex`, `intel-v4.collateral.json` | `sample/tdx_quote*` of [Phala-Network/dcap-qvl](https://github.com/Phala-Network/dcap-qvl) (MIT): a version 4 TDX quote at TCB level UpToDate |
| `intel-v5-td15ex.quote.hex`, `intel-v5-td15ex.collateral.json` | `sample/tdx_quote_td15ex*` of dcap-qvl: a version 5 quote with a TD 1.5 report |
| `intel-outdated.collateral.json` | `sample/tdx_quote_outdated_collateral.json` of dcap-qvl: TCB Info whose TDX module levels are out of date |
| `dstack-v4.json` | `dstack/verifier/fixtures/quote-report.json` of [Dstack-TEE/dstack](https://github.com/Dstack-TEE/dstack) (Apache-2.0): a dstack guest agent `GetQuote` answer with its RTMR3 event log |
| `dstack-v4.collateral.json` | Intel's collateral for that quote's platform, fetched from Intel's PCS by `tgwitness.tdx.fetch_collateral` on 2026-10-31 |
| `phala-dstack-0.5.12.json` | The `GetQuote` answer of a Phala Cloud CVM (`tdx.small`, US-WEST-1, production `dstack-0.5.12`) on 2026-11-04, with its VM configuration, the TDVF sections of the image's `ovmf.fd` and the SHA-256 of its firmware, kernel and initrd |
| `phala-dstack-0.5.12.collateral.json` | Intel's collateral for that quote's platform, fetched from Intel's PCS on 2026-11-04 |

`../tsa/time-stamps.json` holds real RFC 3161 replies of the Belgian government's qualified
time-stamping authority and of FreeTSA over a fixed report, for `tools/check_attestation_report.py`.

The collateral files use dcap-qvl's JSON layout, which `python -m tgwitness.cloud verify --tdx-collateral` accepts.
