[TgWitness](../../README.md) / [Website](../README.md)

![Evidence & verification](../../docs/assets/presentation/chapter-evidence.svg)

# Measurements and verification

Sources for the [public validation page](https://phishdestroy.github.io/TgWitness/docs/validation/).
The English page presents dated measurements and links to the signed audit.

[![Acquisition and complete export rates for two measured workloads](performance.svg)](audit/REPORT.md)

| File | Purpose |
| --- | --- |
| [snapshot.json](snapshot.json) | Aggregate measurements and their scope |
| [page.html](page.html), [validation.css](validation.css), [validation.js](validation.js) | Page layout, responsive styles and chart controls |
| [texts.json](texts.json) | Page translations |
| [performance.svg](performance.svg) | Static comparison for GitHub and readers without JavaScript |
| [audit/](audit/README.md) | Signed English report, measurements, checksums and verifier |

The [site integration](../../tools/site_validation.py) copies the public files.
Private validation checks compare page figures
with the signed measurements and validate the pinned signature.

Measurements apply to their recorded workload and revision. A report signature
establishes integrity; it is not independent attestation or GDPR certification.
Private captures, accounts, credentials and operational backups are excluded.
