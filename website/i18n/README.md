![Website languages](../../docs/assets/presentation/folder-website-i18n.svg)

# Website languages

[Project](../../README.md) · [Documentation](../../docs/README.md) · [Wiki](../../docs/wiki/Home.md) · [Support](../../.github/SUPPORT.md)

Language catalogues for the public website, separate from the application's
[`tgwitness/locales/`](../../tgwitness/locales/README.md) dictionaries.

English source templates live in [`website/`](../README.md). The language JSON files
provide translated site text; [`site_i18n.py`](../../tools/site_i18n.py) defines language
metadata, direction and translation handling.

The capability guide uses a `modes` dictionary of stable keys in all 26 catalogues.
English lives in `en.json`; other site pages keep their existing `strings`/`blocks`
format. Add or change a guide key in every language together. Translation text is
escaped at build time and never inserted as executable markup. Code examples and
fictional protocol fixtures remain language-neutral.

[`site_modes.py`](../../tools/site_modes.py) defines the additional languages shared
by the capability guide and both project notices. These do not imply translations
of the entire site or application.
Translations were prepared with DeepL, with a separate Amharic translation because
the configured DeepL API does not offer Amharic. Russian terminology and limitations
were additionally reviewed. These are not certified or native-speaker-reviewed
translations; review technical limitations when editing a catalogue.

The licence-position and operator-notice pages use the same `strings`/`blocks`
catalogues as the rest of the site. All 26 languages include their full text,
including quoted paragraphs. The original MIT `LICENSE` and plain-text `NOTICE`
remain unchanged. A missing notice translation stops the site build.

After updating notice translations, run `python tools/sync_notice_translations.py`
to regenerate both documents under `docs/<language>/` and links in existing READMEs.
`python tools/sync_notice_translations.py --check` checks that these copies match
the website catalogues. The 13 additional languages have translated navigation,
search and links between the notices; other detailed manuals link to English.

## Review a catalogue change

Preserve placeholders, URLs, element identifiers and code examples. Rebuild the site
and inspect navigation, search and the changed guide in its language. Arabic, Persian
Urdu and Hebrew also need a right-to-left layout check.

```sh
python tools/build_site.py
python tools/check_site.py
```

Run these commands from the project root. See [website development](../README.md)
for the rest of the workflow.
