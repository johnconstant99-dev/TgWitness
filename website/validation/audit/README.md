[TgWitness](../../../README.md) / [Validation](../README.md)

![Evidence & verification](../../../docs/assets/presentation/chapter-evidence.svg)

# Signed release audit

**6 November 2026 · v0.9.1 · source `92e539af40d8`**

[Read the English report](REPORT.md) · [View the graphs](https://phishdestroy.github.io/TgWitness/docs/validation/)

| File | Purpose |
| --- | --- |
| [REPORT.md](REPORT.md) | Results, test scope and open findings |
| [MEASUREMENTS.csv](MEASUREMENTS.csv) | Aggregate figures used by the graphs |
| [PROOF.json](PROOF.json) | Signed statement and file digests |
| [SHA256SUMS.txt](SHA256SUMS.txt) | Published file checksums |
| [VERIFY.py](VERIFY.py) | Signature and file verification |

## Verify the original files

Run from this directory with Python and `cryptography` installed:

```sh
python VERIFY.py --key-sha256 e419743db20096763ea06e480c2e6c161341de2f1023cd339c77758fb69e212f
```

The five original files retain their signed bytes. This directory guide is
outside that signed package. The report records the state at audit time;
later changes to deployment state do not amend it.

These are operator measurements with an integrity signature. They do not
establish independent attestation, Telegram authorship or GDPR certification.
