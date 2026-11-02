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

The collateral files use dcap-qvl's JSON layout, which `python -m tgwitness.cloud verify --tdx-collateral` accepts.
