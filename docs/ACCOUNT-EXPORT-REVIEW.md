# Account export integration checks

The account-export and disclosure implementation was integrated onto upstream
`24236360f1be83fbe5aa03ab3f1d05b1cd3352c5`. The newer panel navigation,
Capture, MCP, analysis and report workflows were retained.

Checks completed with synthetic data:

- 93 worker, disclosure, API and workspace-lifecycle checks passed.
- 92 account-verifier, archive-limit, evidence, coverage and report checks passed.
- Panel browser checks passed for account setup, workspace isolation/deletion,
  navigation, interactions, export policy and disclosure preview. The general
  browser check covered language catalogs, narrow layouts and injection handling.
- The real local demo served source and disclosure ZIPs repeatedly with identical
  bytes. Their signatures and source linkage verified independently. The static
  demo includes those files and refuses acquisition and policy mutations.

Three review agents separately examined backend access/lifecycle, evidence
verification and user flows. No live Telegram acquisition, multi-gigabyte
throughput test or hosted account-export runner qualification was performed.
Synthetic acceptance is not a claim of complete Telegram history or legal
admissibility. The existing hosted Capture policy and trust pins are unchanged.

See [the account-export guide](ACCOUNT-EXPORT.md) for scope, disclosure review and
verification instructions. Existing signatures establish integrity relative to a
trusted collector key; they do not prove Telegram authorship or correct redaction.
