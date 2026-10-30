![Public website](../docs/assets/presentation/folder-website.svg)

# Public website

[Project](../README.md) · [Documentation](../docs/README.md) · [Wiki](../docs/wiki/Home.md) · [Support](../.github/SUPPORT.md)

Source templates, styles, interactive examples and translations for the TgWitness
project website. The authenticated application panel lives in
[`tgwitness/static/`](../tgwitness/static/README.md).

## Source map

| Files | Purpose |
| --- | --- |
| [`index.html`](index.html), [`style.css`](style.css), [`site.js`](site.js) | Project landing page and shared presentation |
| [`docs.html`](docs.html), [`docs.css`](docs.css), [`docs.js`](docs.js) | Documentation layout and local search |
| [`guide_intro.html`](guide_intro.html), [`guides/`](guides/README.md) | Practical guide content |
| [`learn.css`](learn.css), [`learn.js`](learn.js) | Interactive explanatory examples |
| [`i18n/`](i18n/README.md) | Public-site translation catalogues |
| [`render_presentation.py`](render_presentation.py) | Current investigation-style PNGs for GitHub and website sharing |
| [`render_repository_banner.py`](render_repository_banner.py) | Technical grid banners matching the PhishDestroy repository family, with desktop, phone and still variants |
| [`render_identity.py`](render_identity.py) | Repository and handbook covers: outlined wordmark, the original investigation illustration and inline motion |
| [`render_case_assets.py`](render_case_assets.py) | Investigation navigation and case-path diagrams, with desktop, phone and still variants |
| [`capture_readme.py`](capture_readme.py) | Real demo workflow for the README, with light/dark, phone and reduced-motion exports |
| [`demo/`](demo/mock.js) | Read-only online demo: the request-answering script and the recorded fictional records |
| [`artwork.html`](artwork.html), [`render_artwork.py`](render_artwork.py) | Original HTML/CSS presentation artwork and renderer |

## Build and inspect

From the project root:

```sh
python tools/build_site.py
python tools/check_site.py
```

Follow the [local preview instructions](../docs/internal/PUBLISHING.md#preview-the-website-locally)
for serving the generated pages. Edit these sources, not generated files in `dist/`.
Preserve keyboard navigation, both themes and the no-JavaScript fallback.

The homepage notice links to the complete, attributed [operator statement](../docs/OPERATOR-INCOMPATIBILITY.md).
Its original text and the licence are included as local site downloads. Run
`python tools/sync_notice.py --check` before building. Publish the checked output
using the [Pages procedure](../docs/internal/PUBLISHING.md#publish-the-generated-static-branch).

The examples use fictional data. Changes to explanatory diagrams should stay aligned
with the [evidence model](../docs/EVIDENCE.md).
