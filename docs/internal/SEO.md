# Website structure and search metadata

The homepage, documentation, case guides and panel share **25 languages**: English
at the root and the other languages under `/<code>/` (`tools/site_i18n.py`). The
builder publishes each full-site language's homepage, guide index, practical guides,
reference index and reference pages. Amharic retains its existing capability guide
and project notices. The site can be built locally without importing the collector
or opening account data.

## Languages

Translated pages name their language versions (`hreflang`, plus `x-default` for English)
and the sitemap lists their canonical URLs. The English-only changelog keeps working
inside each language's navigation, but those copies canonicalize to the English page
and are excluded from language alternates and the sitemap. Arabic, Persian, Urdu and Hebrew pages are right-to-left; the
stylesheets use logical properties and pick fonts that carry each script. A language
menu in the header leads to the same page in another language, and a theme button
switches light and dark (the system's choice until the reader picks one, kept in
`localStorage` only).

Translations live in `website/i18n/<code>.json`: interface strings, and text units
(the inner HTML of a paragraph, list item, heading, cell, link or button) keyed by the
SHA-256 of their English. They are made with DeepL by the maintainers' translation script,
which sends only missing strings and units and refuses a translation whose links, code,
placeholders or inline tags do not come back intact. When an English unit changes, its
key changes: publishing a full-site language is blocked until that unit is translated
again. The changelog stays in English in every language. Hand-checked Russian replaces
the machine translation of the site's navigation and titles.

## Pages people can use

- `/`: product overview, demo entry point and guide links.
- `/docs/`: task-based index with local search.
- The current guide inventory is `tools/site_content.py`: setup, dedicated accounts,
  proxies, collection, capture, exports, investigations, archive integrations, access,
  witnesses, security, server operation and troubleshooting.
- `/docs/reference/`: the repository's Markdown documents (listed in
  `tools/site_content.py`) rendered by `tools/site_wiki.py`. Links between them stay on
  the site; Mermaid blocks become SVG diagrams (`tools/site_diagrams.py`) that draw
  themselves when shown and carry a text version. Other repository links go to GitHub.

Every guide has a short outcome, concrete steps, related instructions and a full
reference link. Advanced material uses native disclosure controls. The content and
navigation work without JavaScript. Search reads one static `search.json` per language
from the site itself; queries do not leave the browser. There are no external fonts, analytics
or runtime service calls.

The visual guides include a controllable message animation, a SHA-256 sandbox,
witness decision scenarios, a delivery chart, network/deployment diagrams and a
complete whole-account investigation with an interactive case map. Examples are
clearly marked as fictional; no chart claims to
be a live measurement. Formulas and static explanations remain readable without
JavaScript. Animation starts on interaction and respects reduced-motion settings.
The [Markdown companion](../HOW-IT-WORKS.md) uses native Mermaid and math for GitHub.

## Implemented metadata

Each canonical page has a distinct title and description, an HTTPS canonical,
Open Graph metadata and a 1200 × 630 social image. Language alternates come from
the page's actual language inventory. English-only copies use English metadata.

JSON-LD describes `WebSite`, `WebPage`, guide `BreadcrumbList` entries and the
homepage's `SoftwareSourceCode`: repository, language, runtime, author and MIT license.
The sitemap includes canonical HTML pages; text editions and the synthetic demo
are not separate sitemap entries. HTML heads link to the sitemap, text edition and
LLM index. All assets and navigation work under a project subpath or a custom domain.

The generated `robots.txt` advertises the sitemap when served at the host root.
On GitHub project Pages, `/TgWitness/robots.txt` does not control crawling:
crawlers read `https://phishdestroy.github.io/robots.txt`. Submit the project sitemap
directly in Search Console; don't mistake a subdirectory file for a host-wide rule.

## Text editions and LLM discovery

`llms.txt` is a task index, built from the public guide inventory. `llms-full.txt`
combines the English handbook into one file. Every indexed HTML route also has
a Markdown edition: `/docs/accounts/index.md`, for example, or `/guides/modes.md`.
Translations retain their own text editions. Each names its canonical HTML source.

The exporter keeps commands, lists, tables, source links and diagram labels while
omitting navigation and scripts. Capture instructions are rendered from the existing
English/Russian source documents, so the wizard's setup procedure is also readable
without JavaScript. Other capture language editions retain the English reference.
These are public documentation exports, not an MCP endpoint or an account-data API.

The files are regenerated with the site, checked against the publication allowlist,
and advertised with `rel=alternate` (`text/markdown`) and `rel=describedby` links.
The [llms.txt proposal](https://llmstxt.org/) describes reader discovery; Google
[does not require a special AI file](https://developers.google.com/search/docs/appearance/ai-features).

These choices follow Google's documentation on [page titles](https://developers.google.com/search/docs/appearance/title-link),
[descriptions](https://developers.google.com/search/docs/appearance/snippet),
[canonical URLs](https://developers.google.com/search/docs/crawling-indexing/consolidate-duplicate-urls)
and [breadcrumbs](https://developers.google.com/search/docs/appearance/structured-data/breadcrumb).
Metadata helps describe and discover pages; it does not guarantee indexing, a
particular snippet, a rich result or a ranking.

## Maintain the site

| Change | Source |
| --- | --- |
| Guide title, description, order or search synonyms | `tools/site_content.py` |
| Guide instructions, diagrams and examples | `website/guides/en/` |
| Shared layout, styles and local search | `website/docs.html`, `docs.css`, `docs.js` |
| Interactive examples and their styles | `website/learn.js`, `learn.css` |
| Documentation introduction | `website/guide_intro.html` |
| Homepage | `website/index.html` |
| Metadata, relative URLs, sitemap and publication allowlist | `tools/build_site.py` |
| LLM task index and Markdown extraction | `tools/site_llms.py` |

Add a guide to the explicit guide inventory and its navigation group. Do not copy
private files into these presentation directories. The builder rejects linked
inputs and unexpected output files; it does not recursively copy the repository.

```sh
python -m pytest --noconftest -q tests/test_site.py tests/test_site_llms.py
python tools/build_site.py
python tools/check_site.py
python tools/check_docs_site.py
```

## After deployment

1. Confirm the actual Pages/custom-domain URL and rebuild if it differs from the
   canonical base. `TGWITNESS_SITE_URL` sets a custom base; DNS is configured separately.
2. Open the homepage and visual guides on a phone. Check playback, hash scenarios,
   keyboard navigation, search, images and the public `sitemap.xml`.
3. Add the site URL and a concise description to the repository's **About** section.
   Suggested description: “Self-hosted Telegram observation journal with edit
   history, deletion notices and signed, verifiable exports.”
4. Verify the site in Search Console, submit the sitemap and inspect representative
   URLs. Check live structured data with Google's Rich Results Test where applicable.
5. After indexing, use actual query and landing-page data to improve wording.

The local build and checks do not publish the site, run remote Actions or establish
that a search engine has indexed it. Publication steps are in [PUBLISHING.md](PUBLISHING.md).
