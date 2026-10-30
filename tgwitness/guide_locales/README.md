# Setup and dedicated-account translations

These catalogs extend the two bundled guides to 26 languages. The panel keeps its
separate catalog in `tgwitness/locales`; adding a guide language does not label the
panel as translated.

`keys.json` records the English keys from both pages (as visited by `pageKeys()`)
and the dynamic copy-button labels in `guide.js`. Each extra catalog must cover
every key. Commands, inline code, placeholders and link destinations stay intact.

French, German, Italian, Uzbek, Korean, Traditional Chinese, Malay, Polish,
Japanese, Thai, Hebrew and Bengali were translated through the project's DeepL
client. Amharic was translated separately because the configured DeepL API does
not support it. Original English content remains the no-JavaScript fallback.

The application serves these dictionaries through `/locale.js?scope=guide`.
The static site build publishes `demo/guide-locales/<language>.js`. Both guides
accept `?lang=de` (or any supported language) and preserve that choice in their
links. An explicit link takes precedence over the saved language.

Run `tests/test_i18n.py`, `tests/test_site.py` and `tools/check_guide_languages.py`
after changing the guides or catalogs. The source archive and wheel must include
these JSON resources too.
