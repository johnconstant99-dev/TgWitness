# Setup and dedicated-account translations

The two bundled guides support 26 languages. Their 25 full-site languages now use
the panel catalogs in `tgwitness/locales`; Amharic uses its separate catalog here.
The other files are retained as translation sources for the guides.

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

Run `python tools/build_site.py` and `python tools/check_guide_languages.py`
after changing the guides or catalogs. The source archive and wheel must include
these JSON resources too.
