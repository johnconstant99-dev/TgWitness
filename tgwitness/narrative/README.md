[TgWitness](../../README.md) / [tgwitness](../README.md)

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../../docs/assets/presentation/section-source-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../../docs/assets/presentation/section-source-static.svg">
  <source media="(max-width: 640px)" srcset="../../docs/assets/presentation/section-source-mobile.svg">
  <img src="../../docs/assets/presentation/section-source.svg" width="1200" alt="TgWitness / Application">
</picture>

# Evidence narrative generator

Build a report from a verified full evidence ZIP, with facts linked to journal
records. The generator supports PDF, HTML, JSON and SVG diagrams. It checks the
archive and selected trust requirements before rendering into an empty directory.

| Component | Role |
| --- | --- |
| [`__main__.py`](__main__.py) | CLI, archive verification, generation and run receipt |
| [`config.py`](config.py) | Explicit local settings, named profiles and CLI overrides |
| [`model.py`](model.py) | Recorded scenes, facts, evidence references and limits |
| [`render.py`](render.py), [`diagrams.py`](diagrams.py) | Documents, timelines, data flow, assurance ladder and file diagrams |
| [`text.py`](text.py), [texts/](texts/README.md) | Report catalogs and bounded plural-template rendering |
| [jurisdictions/](jurisdictions/README.md) | Optional terminology and source references |
| [`expert.py`](expert.py), [examination/](examination/README.md) | Expert examination protocol draft and per-jurisdiction rules for expert reports |
| [`review-policy.json`](review-policy.json) | Translation review status and release requirements |

Run `python -m tgwitness.narrative --help` from the repository root.
The [narrative guide](../../docs/NARRATIVE.md) covers output files, trust inputs
and current qualification; [configuration examples](../../docs/examples/README.md)
provide reusable profiles.
