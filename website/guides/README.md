![Website guides](../../docs/assets/presentation/folder-website-guides.svg)

# Website guides

[Project](../../README.md) · [Documentation](../../docs/README.md) · [Wiki](../../docs/wiki/Home.md) · [Support](../../.github/SUPPORT.md)

HTML source fragments for the public site's practical guides. The English source is
in [`en/`](en/README.md); language handling is described in
[`../i18n/`](../i18n/README.md).

[`modes.html`](modes.html) is the complete capability-guide template. Its text uses
`{{modes.*}}` keys from all 26 catalogues, including `i18n/en.json`. The site builder
renders `/guides/modes.html` and each language's equivalent, with no translation
requests in the browser. `tools/site_modes.py` rejects missing keys and escapes
translated text. The page uses `style.css`, `learn.css`, `site.js` and the existing
canonical SHA-256 implementation in `learn.js`.

The 13 additional languages cover this page and its navigation. Their links to the
setup guide and reference documentation currently open English pages, as disclosed
on the translated page.

The guide inventory and next-page order are defined in
[`tools/site_content.py`](../../tools/site_content.py). The builder combines these
fragments with the documentation layout, navigation and translated text.

## Edit a guide

Keep instructions consistent with the corresponding document in
[`docs/`](../../docs/README.md). Build and check the site using the commands in
the [website README](../README.md). Use fictional examples and retain record
references in investigation walkthroughs.

The [`ru/`](ru/README.md) directory currently contains no translated HTML guide
fragments; public-site language catalogues are maintained separately.
