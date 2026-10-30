![Build and review tools](../docs/assets/presentation/folder-tools.svg)

# Build and review tools

[Project](../README.md) · [Documentation](../docs/README.md) · [Wiki](../docs/wiki/Home.md) · [Support](../.github/SUPPORT.md)

Maintainer commands for public builds, documentation, browser acceptance and local
verification. Run them from the project root in the development environment.

## Build artifacts

| Command | Output or purpose |
| --- | --- |
| `python tools/sync_notice.py` / `--check` | Regenerate or verify the NOTICE copies in README, SECURITY, documentation and Wiki |
| `python tools/build_source.py` | Public source ZIP and checksums in `dist/` |
| `python tools/build_wiki.py` | Separate GitHub Wiki bundle and manifest in `dist/` |
| `python tools/build_site.py` | Local public-site build |
| `python tools/build_portable.py` | Windows portable package; review the script's options and prerequisites first |

These build commands prepare files. Publishing remains a separate workflow.

## Review the output

| Command | What it checks |
| --- | --- |
| `python tools/check_publication.py` | Selected public files, local Markdown links and recognized secret formats |
| `python tools/check_site.py` | Built website in a local browser |
| `python tools/check_docs_site.py` | Public guides and their visual examples |
| `python tools/check_browser.py` | Synthetic end-to-end panel workflow |
| `python tools/capture_screenshots.py` | Synthetic screenshot review set under `test-results/` |
| `python tools/capture_demo.py` | Record the fictional demo's answers for the read-only online demo (`website/demo/fixtures.json`) |

Account, workspace, quick-navigation, interaction, proxy and Proof browser checks
have separate `check_*_browser.py` entry points. Inspect their usage before running;
Compose and install checks have additional environment requirements.


![Section divider](../docs/assets/presentation/divider.svg)

## Documentation and translation helpers

[`site_content.py`](site_content.py) defines the guide/reference inventory;
[`site_wiki.py`](site_wiki.py) renders Markdown references;
[`site_diagrams.py`](site_diagrams.py) renders their diagrams;
[`site_i18n.py`](site_i18n.py) handles public-site languages.
[`i18n_keys.py`](i18n_keys.py) lists application translation keys.

## Specialist utilities

[`verify_live_probe.py`](verify_live_probe.py) checks an already captured canary
sequence in independently pinned exports; it sends nothing.
[`check_capacity.py`](check_capacity.py) is a synthetic benchmark.
[`research_sources.py`](research_sources.py) downloads public official references.

See [Contributing](../.github/CONTRIBUTING.md) for the review workflow and
[wiki maintenance](../docs/internal/WIKI.md) for wiki publication steps.
