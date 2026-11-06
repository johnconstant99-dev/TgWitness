[TgWitness](../../../README.md) / [narrative](../README.md)

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../../../docs/assets/presentation/section-docs-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../../../docs/assets/presentation/section-docs-static.svg">
  <source media="(max-width: 640px)" srcset="../../../docs/assets/presentation/section-docs-mobile.svg">
  <img src="../../../docs/assets/presentation/section-docs.svg" width="1200" alt="TgWitness / Documentation">
</picture>

# Jurisdiction reference data

Structured terminology and source references selected by the narrative CLI's
`--jurisdiction` option. Each JSON file records its scope, check date and review
status alongside the terms included in the report.

| Fields | Purpose |
| --- | --- |
| `code`, `scope`, `checked_at`, `review` | Catalog identity and review metadata |
| `expert_role`, `esig_regulation`, `data_access_basis` | Referenced terms and source material |
| `timestamp_recognition`, `evidence_rules`, `dpa` | Additional reference entries, where supplied |
| `sources` | Labels and URLs reproduced in the report |

See [`DE.json`](DE.json) for the file structure and [`render.py`](../render.py)
for its use in reports. Preserve source URLs and review metadata when updating
a catalog. The [narrative guide](../../../docs/NARRATIVE.md) explains the scope
of these references and the remaining review requirements.
