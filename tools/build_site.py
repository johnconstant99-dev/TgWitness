"""Build the public project site from an explicit list of presentation files.

No application import, account data, dependency install, or Telegram connection. The
reference pages are the repository's own Markdown documents (tools/site_content.REFERENCE).
English lives at the site root and every other language under /<code>/ (tools/site_i18n.py);
translations come from website/i18n/<code>.json, made by test-results/site_translate.py.
"""
import argparse
import html
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import posixpath
import re
import tomllib
from urllib.parse import urlsplit

if __package__:
    from .site_content import GROUPS, GUIDES, LABELS, NEXT, REFERENCE, REFERENCE_GROUPS
    from . import site_diagrams, site_i18n, site_wiki, site_modes
else:
    from site_content import GROUPS, GUIDES, LABELS, NEXT, REFERENCE, REFERENCE_GROUPS
    import site_diagrams
    import site_i18n
    import site_wiki
    import site_modes

ROOT = Path(__file__).resolve().parents[1]
LANGS = tuple(site_i18n.LANGUAGES)
NOTICE_SLUGS = ("license", "notice")
NOTICE_LANGUAGES = site_modes.LANGUAGES
ASSETS = {
    "assets/mark.svg": "tgwitness/static/mark.svg",
    "assets/chats-dark.png": "docs/assets/chats-dark.png",
    "assets/workspace.png": "docs/assets/workspace.png",
    "assets/detail.png": "docs/assets/detail.png",
    "assets/exports.png": "docs/assets/exports.png",
    "assets/off-site-copy.png": "docs/assets/off-site-copy.png",
    "assets/tgwitness-social.png": "docs/assets/presentation/preview-social.png",
    "assets/public-proxies.png": "docs/assets/public-proxies.png",
    # Home page films and their reduced-motion stills; the evidence explanations below.
    "assets/investigation.mp4": "docs/assets/presentation/investigation.mp4",
    "assets/investigation-static.png": "docs/assets/presentation/investigation-static.png",
    "assets/message-history.mp4": "docs/assets/presentation/message-history.mp4",
    "assets/message-history-static.png": "docs/assets/presentation/message-history-static.png",
    "assets/evidence-chain-static.svg": "docs/assets/presentation/evidence-chain-static.svg",
    "assets/evidence-tamper-static.svg": "docs/assets/presentation/evidence-tamper-static.svg",
    "assets/evidence-checkpoint-static.svg": "docs/assets/presentation/evidence-checkpoint-static.svg",
}
# Screenshots that reference pages show; a reference page using any other image fails the build.
WIKI_ASSETS = {
    "assets/evidence-chain-animated.svg": "docs/assets/presentation/evidence-chain-animated.svg",
    "assets/evidence-tamper-animated.svg": "docs/assets/presentation/evidence-tamper-animated.svg",
    "assets/evidence-checkpoint-animated.svg": "docs/assets/presentation/evidence-checkpoint-animated.svg",
    "assets/sources.png": "docs/assets/sources.png",
    "assets/connection.png": "docs/assets/connection.png",
}
STATIC = {"style.css": "website/style.css", "site.js": "website/site.js",
          "sealed.html": "website/sealed.html", "sealed.js": "website/sealed.js", "sealed.css": "website/sealed.css",
          "LICENSE": "LICENSE", "NOTICE": "NOTICE",
          "docs.css": "website/docs.css", "docs.js": "website/docs.js",
          "learn.css": "website/learn.css", "learn.js": "website/learn.js", **ASSETS, **WIKI_ASSETS}
TRANSLATIONS = tuple(f"website/i18n/{lang}.json" for lang in site_modes.LANGUAGES)
MODES_PAGES = site_modes.FILES
# The read-only online demo: the panel's own files, answered from recorded demo records
# (website/demo/mock.js, tools/capture_demo.py). Nothing on the website can change data.
DEMO_STATIC = {"demo/" + name: "tgwitness/static/" + name
               for name in ("style.css", "theme.js", "i18n.js", "app.js", "mark.svg", "guide.css", "guide.js")}
DEMO_STATIC.update({"demo/mock.js": "website/demo/mock.js", "demo/fixtures.json": "website/demo/fixtures.json"})
DEMO_PAGES = {"demo/index.html": "tgwitness/static/index.html", "demo/guide.html": "tgwitness/static/guide.html",
              "demo/dedicated-account.html": "tgwitness/static/dedicated-account.html"}
DEMO_LOCALES = {f"demo/locales/{lang}.js": lang for lang in LANGS}
DEMO_GUIDE_LOCALES = {f"demo/guide-locales/{lang}.js": lang for lang in site_modes.LANGUAGES}
DEMO_DICTIONARIES = ("tgwitness/english_fallbacks.json", *(f"tgwitness/locales/{lang}.json" for lang in LANGS if lang != "en"))
GUIDE_DICTIONARIES = ("tgwitness/guide_locales/keys.json", *(f"tgwitness/guide_locales/{lang}.json" for lang in site_modes.EXTRA_LANGUAGES))
INPUTS = ("website/index.html", "website/docs.html", "website/guide_intro.html", site_modes.SOURCE, *STATIC.values(),
          *DEMO_STATIC.values(), *DEMO_PAGES.values(), *DEMO_DICTIONARIES, *GUIDE_DICTIONARIES,
          *(f"website/guides/en/{slug}.html" for slug in GUIDES),
          *dict.fromkeys(entry[3] for entry in REFERENCE.values()))
WIKI_HUB = "docs/reference/"
LOCAL_PAGES = ("", "docs/", *(f"docs/{slug}/" for slug in GUIDES), WIKI_HUB, *(f"{WIKI_HUB}{slug}/" for slug in REFERENCE))
NOTICE_PAGES = tuple(f"{WIKI_HUB}{slug}/" for slug in NOTICE_SLUGS)
PAGE_LOCALES = tuple((lang, local) for lang in NOTICE_LANGUAGES
                     for local in (LOCAL_PAGES if lang in LANGS else NOTICE_PAGES))
PAGES = tuple(("" if lang == "en" else lang + "/") + local for lang, local in PAGE_LOCALES)
SEARCH_FILES = tuple(("" if lang == "en" else lang + "/") + "docs/search.json" for lang in NOTICE_LANGUAGES)
SEARCH_TEXT = 4000  # characters of each page in the search index
HOME_TITLE = "Telegram message history & signed exports | TgWitness"
HOME_DESCRIPTION = ("A self-hosted Telegram observation journal. Preserve observed messages, compare edits, "
                    "track deletion notices, and export signed records you can verify.")
HOME_OG = "Your accounts. Your journal. A verifiable record. An open-source Telegram workspace that runs on your own machine."
HOME_IMAGE_ALT = "TgWitness — Follow the trail. Preserve the evidence. A Telegram investigation workspace."
WIKI_DESCRIPTION = ("The complete TgWitness reference: installation, accounts, proxies, collection, evidence format, "
                    "witnesses, timestamps, security, architecture and test results.")
# Words of the page frame that are not in LABELS.
FRAME = ("Visual guide", "Security", "Language", "Switch between light and dark theme", "Link to this section",
         "Parts of this page are still in English: the English original changed after it was translated.",
         "This page is available in English only.")
NOTICE_LINK_NOTE = ("The two project notices and the capability guide are translated into this language. "
                    "Other linked guides and reference pages are in English.")
NOTICE_FRAME = (*LABELS.values(), *FRAME[:5], "Security & project", NOTICE_LINK_NOTE)
THEME_SCRIPT = ("(()=>{try{const s=localStorage.getItem('tgw-theme');document.documentElement.dataset.theme="
                "s||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light')}catch(e){}})()")


def prefix(lang):
    return "" if lang == "en" else lang + "/"


def page_languages(local):
    """Full documentation languages, plus the existing Amharic notices."""
    return NOTICE_LANGUAGES if local in NOTICE_PAGES else site_i18n.LANGUAGES


def render(template, values):
    def replace(match):
        if match[1] not in values:
            raise ValueError("Unresolved site template variable: " + match[1])
        return values[match[1]]
    return re.sub(r"@@([A-Z_]+)@@", replace, template)


def relative(page, target):
    return posixpath.relpath(target or ".", page or ".").rstrip("/") + "/"


def relative_file(page, target):
    return posixpath.relpath(target, page or ".")


def json_script(value):
    return json.dumps(value, ensure_ascii=False).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")


class PlainText(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.parts = []
        self.skip = 0
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.skip += tag in ("svg", "script", "style")

    def handle_endtag(self, tag):
        self.skip -= tag in ("svg", "script", "style") and self.skip > 0

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)

    @property
    def text(self):
        return " ".join(" ".join(self.parts).split())


def seo(base_url, path, title, description, lang, alternates, *, crumbs=(), extra_only=False, languages=site_i18n.LANGUAGES):
    canonical = base_url + "/" + path
    code = languages[lang][1]
    graph = [{"@type": "WebPage", "@id": canonical, "url": canonical, "name": title,
              "description": description, "inLanguage": code, "isPartOf": {"@id": base_url + "/#website"}}]
    if not path:
        graph.append({"@type": "WebSite", "@id": base_url + "/#website", "url": base_url + "/",
                      "name": "TgWitness", "inLanguage": "en"})
    if crumbs:
        graph.append({"@type": "BreadcrumbList", "itemListElement": [
            {"@type": "ListItem", "position": i + 1, "name": name, "item": base_url + "/" + url}
            for i, (name, url) in enumerate(crumbs)]})
    links = "".join(f'<link rel="alternate" hreflang="{languages[other][1]}" '
                    f'href="{html.escape(base_url + "/" + other_path, quote=True)}">'
                    for other, other_path in alternates)
    links += f'<link rel="alternate" hreflang="x-default" href="{html.escape(base_url + "/" + alternates[0][1], quote=True)}">'
    extra = links + '<script type="application/ld+json">' + json_script({"@context": "https://schema.org", "@graph": graph}) + '</script>'
    if extra_only:
        return extra
    title, description, canonical = (html.escape(v, quote=True) for v in (title, description, canonical))
    return (f'<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f'<meta name="theme-color" content="#0b1120"><title>{title}</title>\n'
            f'<meta name="description" content="{description}"><link rel="canonical" href="{canonical}">\n'
            f'<meta property="og:type" content="website"><meta property="og:site_name" content="TgWitness">\n'
            f'<meta property="og:locale" content="{languages[lang][3]}">\n'
            f'<meta property="og:title" content="{title}"><meta property="og:description" content="{description}">\n'
            f'<meta property="og:url" content="{canonical}"><meta property="og:image" content="{html.escape(base_url, quote=True)}/assets/tgwitness-social.png">\n'
            f'<meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">\n'
            f'<meta property="og:image:alt" content="TgWitness — Telegram observation journal">\n'
            '<meta name="twitter:card" content="summary_large_image">\n' + extra)


def headings(content):
    """(id, text) of every h2, for the page contents list."""
    return [(id_, html.escape(PlainText(inner).text.rstrip("#").strip(), quote=False))
            for id_, inner in re.findall(r'<h2 id="([^"]+)">(.*?)</h2>', content, re.S)]


def home_body(template):
    start, end = template.index("<body>") + len("<body>"), template.index("</body>")
    return template[start:end]


def inventory(root=ROOT):
    """Everything that is translated: (UI strings, HTML fragments, diagram texts). The translation
    script and the build use this one list, so nothing is translated that the site does not show."""
    root = Path(root)
    strings = list(LABELS.values()) + list(FRAME) + [HOME_TITLE, HOME_DESCRIPTION, HOME_OG, HOME_IMAGE_ALT, WIKI_DESCRIPTION, NOTICE_LINK_NOTE]
    for title, description, keywords, _ in GUIDES.values():
        strings += [title, description, keywords]
    for label, heading, _ in GROUPS:
        strings += [label, heading]
    for slug, (title, description, keywords, _) in REFERENCE.items():
        strings += [title, description, keywords]
    strings += [label for label, _ in REFERENCE_GROUPS]
    for name in ("website/learn.js", "website/docs.js", "website/site.js"):
        strings += site_i18n.script_strings((root / name).read_text(encoding="utf-8"))
    fragments = {"home": home_body((root / "website/index.html").read_text(encoding="utf-8")),
                 "intro": (root / "website/guide_intro.html").read_text(encoding="utf-8")}
    for slug in GUIDES:
        fragments["guide:" + slug] = (root / f"website/guides/en/{slug}.html").read_text(encoding="utf-8")
    diagrams = list(site_diagrams.WORDS)
    for slug, entry in REFERENCE.items():
        source = (root / entry[3]).read_text(encoding="utf-8")
        if slug in site_i18n.ENGLISH_ONLY:
            continue
        if slug in NOTICE_SLUGS:
            strings.append(site_wiki.split_title(source)[0])
        fragments["reference:" + slug] = site_wiki.markup(site_wiki.split_title(source)[1])[0]
        for block in site_wiki.diagram_sources(source):
            diagrams += site_diagrams.labels_of(block)
    for fragment in fragments.values():
        strings += site_i18n.attribute_values(fragment)
    return list(dict.fromkeys(s for s in strings if s)), fragments, list(dict.fromkeys(diagrams))


def build_site(root=ROOT, *, repository="phishdestroy/TgWitness", base_url=None, branch="main"):
    root = Path(root).resolve()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository):
        raise ValueError("Repository must be OWNER/REPOSITORY")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", branch):
        raise ValueError("Site branch must be a simple branch name")
    owner, name = repository.split("/")
    default_url = "https://" + owner.lower() + ".github.io"
    if name.lower() != owner.lower() + ".github.io":
        default_url += "/" + name
    base_url = (base_url or default_url).rstrip("/")
    parsed = urlsplit(base_url)
    if (parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password
            or parsed.query or parsed.fragment or re.search(r'[\s<>"\\]', base_url)):
        raise ValueError("Base URL must be an HTTPS site URL without credentials, query, or fragment")
    version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    repo_url = "https://github.com/" + repository
    values = {key: html.escape(value, quote=True) for key, value in {
        "REPO_URL": repo_url, "REPO_NAME": name,
        "BASE_URL": base_url, "VERSION": version, "BRANCH": branch,
    }.items()}
    output = root / "dist/site"
    # Never clean/copy a directory recursively: an unexpected file must block the
    # upload rather than be carried into the public Pages artifact.
    expected = {*(path + "index.html" for path in PAGES), *SEARCH_FILES, *STATIC, ".nojekyll", "robots.txt", "sitemap.xml",
                *DEMO_STATIC, *DEMO_PAGES, *DEMO_LOCALES, *DEMO_GUIDE_LOCALES, *MODES_PAGES}
    if output.resolve() != output:
        raise ValueError("Site output must not be a linked directory")
    if output.exists():
        for path in output.rglob("*"):
            output_name = path.relative_to(output).as_posix()
            if path.is_symlink() or path.resolve() != path:
                raise ValueError("Linked file in site output: " + output_name)
            if path.is_file() and output_name not in expected:
                raise ValueError("Unexpected file in site output: " + output_name)
    output.mkdir(parents=True, exist_ok=True)

    def read_public(relative_path):
        source = root / relative_path
        if source.resolve() != source or not source.is_file():
            raise ValueError("Site input must be an ordinary repository file: " + relative_path)
        return source.read_bytes()

    def write(path, content):
        target = output / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content.replace("\r\n", "\n"), encoding="utf-8", newline="\n")

    translations = {}
    for lang in NOTICE_LANGUAGES:
        if lang == "en":
            translations[lang] = None
            continue
        path = root / f"website/i18n/{lang}.json"
        if path.exists():
            read_public(f"website/i18n/{lang}.json")  # an ordinary file, not a link
        translations[lang] = site_i18n.load(root, lang)
    sources = {slug: site_wiki.split_title(read_public(entry[3]).decode("utf-8"))[1] for slug, entry in REFERENCE.items()}
    home_template = read_public("website/index.html").decode("utf-8")
    doc_template = read_public("website/docs.html").decode("utf-8")
    intro_template = read_public("website/guide_intro.html").decode("utf-8")
    modes_template = read_public(site_modes.SOURCE).decode("utf-8")
    modes_english = site_modes.catalogue(read_public, "en")
    fragments = {slug: read_public(f"website/guides/en/{slug}.html").decode("utf-8") for slug in GUIDES}
    script_keys = []
    for script in ("website/learn.js", "website/docs.js", "website/site.js"):
        script_keys += site_i18n.script_strings(read_public(script).decode("utf-8"))
    images = {}

    # A language in the main selector must have the complete current documentation.
    # Changed English text must be translated before it can be published under that language.
    inventory_strings, inventory_fragments, inventory_diagrams = inventory(root)
    required_strings = set(inventory_strings + inventory_diagrams)
    for lang in LANGS:
        if lang == "en":
            continue
        data = translations[lang]
        missing = sorted(text for text in required_strings if not data["strings"].get(text, "").strip())
        if missing:
            raise ValueError(f"Incomplete site labels: {lang}: {missing[0]}")
        for name, fragment in inventory_fragments.items():
            if name in {"reference:license", "reference:notice"}:
                continue  # The dedicated notice checks below retain their specific diagnostics.
            missing = [text for text in site_i18n.unit_texts(fragment)
                       if not data["blocks"].get(site_i18n.digest(text), "").strip()]
            if missing:
                raise ValueError(f"Incomplete site translation: {lang}/{name} ({len(missing)} blocks)")

    english_page_ids = {}
    for lang in NOTICE_LANGUAGES:
        data, base = translations[lang], prefix(lang)
        full_site = lang in LANGS
        page_slugs = tuple(REFERENCE) if full_site else NOTICE_SLUGS
        rtl = NOTICE_LANGUAGES[lang][2] == "rtl"
        arrow = "←" if rtl else "→"

        def t(value, data=data):
            return site_i18n.text(data, value)
        if lang != "en":
            required = [value for slug in NOTICE_SLUGS for value in REFERENCE[slug][:3]]
            if not full_site:
                required += list(NOTICE_FRAME) + site_i18n.script_strings(read_public("website/docs.js").decode("utf-8"))
            missing = [value for value in required if not data["strings"].get(value, "").strip()]
            if missing:
                raise ValueError(f"Incomplete notice labels: {lang}: {missing[0]}")
        labels = {key: t(value) for key, value in LABELS.items()}
        guides = {slug: (t(e[0]), t(e[1]), t(e[2]), e[3]) for slug, e in GUIDES.items()}
        reference = {slug: (t(e[0]), t(e[1]), t(e[2]), e[3]) for slug, e in REFERENCE.items()}
        hub, wiki_hub = base + "docs/", base + WIKI_HUB
        wiki_page = {entry[3]: f"{base if full_site or slug in NOTICE_SLUGS else ''}{WIKI_HUB}{slug}/"
                     for slug, entry in REFERENCE.items()}
        dictionary = {key: data["strings"][key] for key in script_keys if data and key in data["strings"]}

        def localize(fragment, data=data):
            return site_i18n.localize(fragment, data)

        # Reference pages: render once to learn every heading, then fix the links between them.
        rendered, missing_by_page, diagrams = {}, {}, 0
        page_ids = {} if full_site else dict(english_page_ids)
        for slug in page_slugs:
            english = slug in site_i18n.ENGLISH_ONLY
            labels_map = None if (data is None or english) else data["strings"]
            content, count, missing = site_wiki.to_html(
                sources[slug], diagrams + 1, labels_map, None if (data is None or english) else localize,
                None if data is None else data["strings"])
            if lang != "en" and slug in NOTICE_SLUGS and missing:
                raise ValueError(f"Incomplete notice translation: {lang}/{slug} ({missing} blocks)")
            diagrams += count
            rendered[slug] = content
            missing_by_page[f"{wiki_hub}{slug}/"] = missing
            page_ids[f"{wiki_hub}{slug}/"] = site_wiki.ids(content)
        if lang == "en":
            english_page_ids = dict(page_ids)
        for slug in page_slugs:
            source = reference[slug][3]
            rendered[slug] = site_wiki.rewrite_links(rendered[slug], source, f"{wiki_hub}{slug}/", wiki_page, page_ids,
                                                     relative_file, repo_url, branch, images, root)

        github = re.compile(r'href="' + re.escape(html.escape(repo_url, quote=True)) + r'/blob/'
                            + re.escape(html.escape(branch, quote=True)) + r'/([^"#]+)(?:#([^"]*))?"')

        def links(content, path, wiki_page=wiki_page, page_ids=page_ids):
            """Links to rendered documents on GitHub stay on the site, in this language."""
            def replace(match):
                target = wiki_page.get(match.group(1))
                if match.group(1) in ("LICENSE", "NOTICE"):
                    return 'href="' + html.escape(relative_file(path, match.group(1)), quote=True) + '"'
                if not target:
                    return match.group(0)
                anchor = match.group(2)
                fragment = "#" + anchor if anchor and anchor in page_ids[target] else ""
                return 'href="' + html.escape(relative(path, target) + fragment, quote=True) + '"'
            return github.sub(replace, content)

        modes_words = site_modes.catalogue(read_public, lang, modes_english)
        modes_path, modes_html = site_modes.render_page(
            modes_template, modes_words, lang=lang, base_url=base_url, values=values, dictionary=dictionary,
            render=render, seo=seo, theme_script=THEME_SCRIPT)
        write(modes_path, links(modes_html, posixpath.dirname(modes_path)))

        def alternates(local):
            return [(other, prefix(other) + local) for other in page_languages(local)]

        def language_menu(path, local):
            languages = page_languages(local)
            current = languages[lang]
            items = "".join(
                f'<a href="{relative(path, prefix(other) + local)}" hreflang="{languages[other][1]}" '
                f'lang="{languages[other][1]}"' + (' aria-current="true"' if other == lang else '')
                + f'>{html.escape(languages[other][0])}</a>' for other in languages)
            return (f'<details class="lang-menu"><summary aria-label="{html.escape(t("Language"), quote=True)}">'
                    f'<span aria-hidden="true">◍</span> {html.escape(current[0])}</summary>'
                    f'<div class="lang-list">{items}</div></details>')

        def theme_toggle():
            return (f'<button type="button" class="theme-toggle" data-theme-toggle hidden '
                    f'aria-label="{html.escape(t("Switch between light and dark theme"), quote=True)}">'
                    '<svg class="icon-sun" viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><circle cx="12" cy="12" r="4.5" '
                    'fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2'
                    'M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M5.3 18.7l1.6-1.6M17.1 6.9l1.6-1.6" stroke="currentColor" stroke-width="1.8" '
                    'stroke-linecap="round"/></svg><svg class="icon-moon" viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">'
                    '<path d="M20 14.5A8.5 8.5 0 1 1 9.5 4a7 7 0 0 0 10.5 10.5z" fill="none" stroke="currentColor" stroke-width="1.8" '
                    'stroke-linejoin="round"/></svg></button>')

        language_values = {"LANG": NOTICE_LANGUAGES[lang][1], "DIR": NOTICE_LANGUAGES[lang][2], "LANG_CODE": lang,
                           "THEME_SCRIPT": THEME_SCRIPT, "SITE_DICT": json_script(dictionary), "ARROW": arrow}

        if full_site:
            # Home page.
            body, _ = localize(home_body(home_template))
            home = home_template[:home_template.index("<body>") + len("<body>")] + body + home_template[home_template.index("</body>"):]
            write(base + "index.html", links(render(home, {
                **values, **language_values, "ROOT": "" if not base else relative(base, ""), "TITLE": html.escape(t(HOME_TITLE), quote=True),
                "DESCRIPTION": html.escape(t(HOME_DESCRIPTION), quote=True), "CANONICAL": html.escape(base_url + "/" + base, quote=True),
                "OG_LOCALE": site_i18n.LANGUAGES[lang][3], "OG_DESCRIPTION": html.escape(t(HOME_OG), quote=True),
                "OG_IMAGE_ALT": html.escape(t(HOME_IMAGE_ALT), quote=True),
                "LANGUAGE_MENU": language_menu(base, ""), "THEME_TOGGLE": theme_toggle(),
                "EXTRA_HEAD": seo(base_url, base, t(HOME_TITLE), t(HOME_DESCRIPTION), lang, alternates(""), extra_only=True)}), base))

        texts = {}

        def guide_values(path):
            return {**values, "ROOT": relative(path, ""),
                    **{"GUIDE_" + key.upper(): relative(path, (hub if full_site else "docs/") + key + "/") for key in GUIDES}}
        guide_html, guide_missing = {}, {}
        for slug in (GUIDES if full_site else ()):
            translated, missing = localize(fragments[slug])
            guide_html[slug], guide_missing[slug] = translated, missing
            texts[hub + slug + "/"] = PlainText(render(translated, guide_values(hub + slug + "/"))).text
        for slug in page_slugs:
            texts[f"{wiki_hub}{slug}/"] = PlainText(rendered[slug]).text
        search = {"labels": {k: labels[k] for k in ("empty", "results", "prompt")}, "pages": [
            {"title": modes_words["modes.sealed.title"], "description": modes_words["modes.sealed.body"],
             "keywords": "GitHub Actions sealed capture", "text": modes_words["modes.sealed.body"],
             "url": relative_file(hub, "sealed.html") + "?lang=" + ("ru" if lang == "ru" else "en")},
            *({"title": guides[key][0], "description": guides[key][1], "keywords": guides[key][2],
               "text": texts[hub + key + "/"][:SEARCH_TEXT], "url": key + "/"} for key in (GUIDES if full_site else ())),
            {"title": modes_words["modes.eyebrow"], "description": modes_words["modes.seo"],
             "keywords": modes_words["modes.title"], "text": PlainText(modes_html).text[:SEARCH_TEXT],
             "url": "../" + site_modes.LOCAL},
            *({"title": labels["wiki"] + " · " + reference[key][0], "description": reference[key][1],
               "keywords": reference[key][2], "text": texts[f"{wiki_hub}{key}/"][:SEARCH_TEXT],
               "url": "reference/" + key + "/"} for key in page_slugs)]}
        write(hub + "search.json", json.dumps(search, ensure_ascii=False, separators=(",", ":")))

        def sidebar(path):
            items = [f'<a href="{relative_file(path, base + site_modes.LOCAL)}">{html.escape(modes_words["modes.eyebrow"])}</a>']
            items.append(f'<a href="{relative_file(path, "sealed.html")}?lang={"ru" if lang == "ru" else "en"}">'
                         f'{html.escape(modes_words["modes.sealed.title"])}</a>')
            if not full_site:
                wiki = ''.join(f'<a href="{relative(path, wiki_hub + key + "/")}"'
                               + (' aria-current="page"' if path == wiki_hub + key + '/' else '')
                               + f'>{html.escape(reference[key][0])}</a>' for key in NOTICE_SLUGS)
                return ''.join(items), wiki
            for label, heading, keys in GROUPS:
                items.append(f'<p class="nav-label">{t(label)}</p>')
                for key in keys:
                    mark = ' aria-current="page"' if path == hub + key + "/" else ''
                    items.append(f'<a href="{relative(path, hub + key + "/")}"{mark}>{guides[key][0]}</a>')
            wiki = [f'<p class="nav-label"><a class="nav-label-link" href="{relative(path, wiki_hub)}"'
                    + (' aria-current="page"' if path == wiki_hub else '') + f'>{labels["wiki"]}</a></p>']
            for label, keys in REFERENCE_GROUPS:
                inside = any(path == f"{wiki_hub}{key}/" for key in keys)
                entries = "".join(f'<a href="{relative(path, wiki_hub + key + "/")}"'
                                  + (' aria-current="page"' if path == f"{wiki_hub}{key}/" else '')
                                  + f'>{reference[key][0]}</a>' for key in keys)
                wiki.append(f'<details class="wiki-group"{" open" if inside else ""}><summary>{t(label)}</summary>{entries}</details>')
            return "".join(items), "".join(wiki)

        def page(local, title, description, crumbs, content, toc, footer, notice=""):
            path = base + local
            breadcrumb = ' <span aria-hidden="true">/</span> '.join(
                f'<a href="{relative(path, url)}">{html.escape(label)}</a>' if url != path
                else f'<span aria-current="page">{html.escape(label)}</span>' for label, url in crumbs)
            guides_nav, wiki_nav = sidebar(path)
            toc_html = (f'<p class="nav-label">{labels["toc"]}</p>' + ''.join(f'<a href="#{id_}">{text}</a>' for id_, text in toc)
                        if toc else "")
            context = {**guide_values(path), **language_values,
                       "PAGE_CLASS": "notice-page" if local in NOTICE_PAGES else "docs-root",
                       **{key.upper(): html.escape(value, quote=True) for key, value in labels.items()},
                       "HOME": relative(path, base if full_site else ""), "HUB": relative(path, hub if full_site else "docs/"),
                       "WIKI_HUB": relative(path, wiki_hub if full_site else WIKI_HUB),
                       "OPERATOR_URL": relative(path, wiki_hub + "notice/"),
                       "SIDEBAR": guides_nav, "WIKI_NAV": wiki_nav, "VISUAL": html.escape(t("Visual guide")),
                       "SECURITY": html.escape(t("Security")), "LANGUAGE_MENU": language_menu(path, local),
                       "THEME_TOGGLE": theme_toggle(), "SEARCH_URL": relative_file(path, hub + "search.json"),
                       "HEAD": seo(base_url, path, title + " | TgWitness", description, lang, alternates(local), crumbs=crumbs, languages=page_languages(local)),
                       "BREADCRUMBS": breadcrumb, "NOTICE": notice, "CONTENT": content, "CONTENTS": toc_html,
                       "GUIDE_FOOTER": footer}
            write(path + "index.html", links(render(doc_template, context), path))

        def card(path, url, number, title, text):
            return (f'<a class="guide-card" href="{relative(path, url)}"><span class="card-number">{number} '
                    f'<span aria-hidden="true">↗</span></span><h3>{title}</h3><p>{text}</p></a>')

        def notice(missing, english=False):
            if english and lang != "en":
                return f'<p class="language-notice">{html.escape(t(FRAME[6]))}</p>'
            if missing:
                return f'<p class="language-notice">{html.escape(t(FRAME[5]))}</p>'
            return ""

        if full_site:
            # Documentation hub: guides, then the reference.
            intro, intro_missing = localize(intro_template)
            content = (f'<p class="eyebrow">TGWITNESS / {labels["docs"].upper()}</p><h1>{labels["title"]}</h1>'
                       f'<p class="guide-outcome">{labels["intro"]}</p>' + render(intro, guide_values(hub)))
            content += (f'<a class="guide-card" href="{relative_file(hub, base + site_modes.LOCAL)}">'
                        f'<span class="card-number" aria-hidden="true">04 / 08 ↗</span>'
                        f'<h2>{html.escape(modes_words["modes.eyebrow"])}</h2>'
                        f'<p>{html.escape(modes_words["modes.seo"])}</p></a>')
            for index, (label, heading, keys) in enumerate(GROUPS):
                if index == 0:
                    content += (f'<a class="guide-card" href="{relative_file(hub, "sealed.html")}?lang={"ru" if lang == "ru" else "en"}">'
                                f'<h2>{html.escape(modes_words["modes.sealed.title"])}</h2>'
                                f'<p>{html.escape(modes_words["modes.sealed.body"])}</p></a>')
                content += f'<h2 id="section-{index}">{t(heading)}</h2><div class="guide-grid">'
                content += "".join(card(hub, hub + key + "/", f"{list(GUIDES).index(key) + 1:02d}", *guides[key][:2]) for key in keys)
                content += '</div>'
            content += (f'<h2 id="reference">{labels["wiki_title"]}</h2><p>{labels["wiki_intro"]}</p>'
                        f'<div class="wiki-index">' + "".join(
                            f'<div class="wiki-column"><p class="nav-label">{t(label)}</p>' + "".join(
                                f'<a href="{relative(hub, wiki_hub + key + "/")}">{reference[key][0]}</a>' for key in keys)
                            + '</div>' for label, keys in REFERENCE_GROUPS) + '</div>')
            page("docs/", labels["docs"], labels["description"], [(labels["home"], base), (labels["docs"], hub)], content, [], "",
                 notice(intro_missing))

            for slug in GUIDES:
                path = hub + slug + "/"
                title, description = guides[slug][:2]
                guide = render(guide_html[slug], guide_values(path))
                content = f'<p class="eyebrow">{labels["docs"]} / {list(GUIDES).index(slug) + 1:02d}</p><h1>{title}</h1>' + guide
                next_slug = NEXT[slug]
                target = wiki_page.get(GUIDES[slug][3])
                footer = ((f'<a class="reference" href="{relative(path, target)}">{labels["reference"]} {arrow}</a>' if target else "")
                          + f'<a class="next-guide" href="{relative(path, hub + next_slug + "/")}"><span>{labels["next"]}</span>'
                            f'<strong>{guides[next_slug][0]} {arrow}</strong></a>')
                page(f"docs/{slug}/", title, description, [(labels["home"], base), (labels["docs"], hub), (title, path)],
                     content, headings(content), footer, notice(guide_missing[slug]))

            # Reference hub and pages.
            content = (f'<p class="eyebrow">TGWITNESS / {labels["wiki"].upper()}</p><h1>{labels["wiki_title"]}</h1>'
                       f'<p class="guide-outcome">{labels["wiki_intro"]}</p>')
            number = 0
            for index, (label, keys) in enumerate(REFERENCE_GROUPS):
                content += f'<h2 id="group-{index}">{t(label)}</h2><div class="guide-grid">'
                for key in keys:
                    number += 1
                    content += card(wiki_hub, wiki_hub + key + "/", f"{number:02d}", *reference[key][:2])
                content += '</div>'
            page(WIKI_HUB, labels["wiki"], t(WIKI_DESCRIPTION),
                 [(labels["home"], base), (labels["docs"], hub), (labels["wiki"], wiki_hub)], content, headings(content), "")
        order = list(page_slugs)
        for index, slug in enumerate(order):
            path = f"{wiki_hub}{slug}/"
            title, description, keywords, source = reference[slug]
            group = next(t(label) for label, keys in REFERENCE_GROUPS if slug in keys)
            english = slug in site_i18n.ENGLISH_ONLY
            content = (f'<p class="eyebrow">{labels["wiki"]} / {html.escape(group)}</p><h1>{html.escape(title)}</h1>'
                       f'<p class="guide-outcome">{html.escape(description)}</p>'
                       f'<div class="wiki-body"{" lang=en dir=ltr" if english and lang != "en" else ""}>{rendered[slug]}</div>')
            following = order[(index + 1) % len(order)]
            # /edit/, not /blob/: the document-link rewriter keeps /blob/ links on the site,
            # which would turn "Edit this page on GitHub" into a link to this same page.
            footer = (f'<a class="reference" href="{values["REPO_URL"]}/edit/{values["BRANCH"]}/{source}">{labels["source"]} ↗</a>'
                      f'<a class="next-guide" href="{relative(path, wiki_hub + following + "/")}"><span>{labels["next"]}</span>'
                      f'<strong>{reference[following][0]} {arrow}</strong></a>')
            page(f"{WIKI_HUB}{slug}/", title, description,
                 [(labels["home"], base if full_site else ""), (labels["docs"], hub if full_site else "docs/"),
                  (labels["wiki"], wiki_hub if full_site else WIKI_HUB), (title, path)],
                 content, headings(content), footer,
                 notice(missing_by_page[path], english) if full_site else
                 '<p class="language-notice">' + html.escape(t(NOTICE_LINK_NOTE)) + '</p>')

    for name, source in images.items():
        if WIKI_ASSETS.get(name) != source:
            raise ValueError("Reference page uses an unlisted image: " + source)
    for target, source in {**STATIC, **DEMO_STATIC}.items():
        destination = output / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(read_public(source))
    build_demo(read_public, write)
    (output / ".nojekyll").write_text("", encoding="utf-8")
    (output / "robots.txt").write_text("User-agent: *\nAllow: /\nSitemap: " + base_url + "/sitemap.xml\n", encoding="utf-8")
    (output / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">\n'
        + ''.join('<url><loc>' + html.escape(base_url + '/' + prefix(lang) + local) + '</loc>' + ''.join(
            f'<xhtml:link rel="alternate" hreflang="{page_languages(local)[other][1]}" '
            f'href="{html.escape(base_url + "/" + prefix(other) + local)}"/>' for other in page_languages(local)) + '</url>\n'
            for lang, local in PAGE_LOCALES)
        + ''.join('<url><loc>' + html.escape(base_url + '/' + path) + '</loc>' + ''.join(
            f'<xhtml:link rel="alternate" hreflang="{site_modes.LANGUAGES[other][1]}" '
            f'href="{html.escape(base_url + "/" + ("" if other == "en" else other + "/") + site_modes.LOCAL)}"/>'
            for other in site_modes.LANGUAGES) + '</url>\n' for path in MODES_PAGES)
        + '</urlset>\n', encoding="utf-8")
    return output


# An explicit ?lang= link takes precedence over the saved choice, then the browser's
# languages. Written before the deferred scripts.
def demo_language_script(languages, folder):
    return ("<script>(function(){var known=" + json.dumps(list(languages)) + ","
            "saved=(document.cookie.match(/(?:^|; )tgwitness-lang=([^;]+)/)||[])[1];"
            "try{saved=saved&&decodeURIComponent(saved)}catch(e){saved=''}"
            "function match(tag){tag=String(tag||'').toLowerCase().replace(/_/g,'-');"
            "var exact=known.find(function(x){return x.toLowerCase()===tag});if(exact)return exact;"
            "if(/^zh-/.test(tag)&&/(?:^|-)(?:hant|tw|hk|mo)(?:-|$)/.test(tag))return known.find(function(x){return x==='zh-Hant'});"
            "return known.find(function(x){return x===tag.split('-')[0]})}"
            "var asked=new URLSearchParams(location.search).get('lang'),"
            "browser=navigator.languages||[navigator.language||'en'],"
            "pick=[asked,saved].concat(browser).map(match).find(Boolean)||'en';"
            "document.write('<script src=\"" + folder + "/'+pick+'.js\"><\\/script>');})();</script>")


def build_demo(read_public, write):
    """Panel pages with relative paths, the request answering script and one dictionary per language."""
    for target, source in DEMO_PAGES.items():
        page = read_public(source).decode("utf-8").replace('href="/"', 'href="../"')
        page = re.sub(r'\b(src|href)="/(?=[A-Za-z])', r'\1="', page)
        guide = target != "demo/index.html"
        original_loader = ('<script src="guide-locale.js"></script>' if guide
                           else '<script src="guide-locale.js" data-scope="panel"></script>')
        if original_loader not in page:
            raise ValueError("Demo page no longer loads locale.js where expected: " + source)
        answering = '<script src="mock.js"></script>' if target == "demo/index.html" else ""
        loader = demo_language_script(site_modes.LANGUAGES if guide else LANGS, "guide-locales" if guide else "locales")
        page = page.replace(original_loader, answering + loader)
        page = page.replace("<head>", '<head>\n<meta name="robots" content="noindex">', 1)
        write(target, page)
    fallbacks = json.loads(read_public("tgwitness/english_fallbacks.json"))
    required = json.loads(read_public("tgwitness/guide_locales/keys.json"))["keys"]
    for target, lang in {**DEMO_LOCALES, **DEMO_GUIDE_LOCALES}.items():
        guide = target in DEMO_GUIDE_LOCALES
        if lang == "en":
            words = {}
        elif lang in site_modes.EXTRA_LANGUAGES:
            words = json.loads(read_public(f"tgwitness/guide_locales/{lang}.json"))
        else:
            words = {**{text: text for text in fallbacks}, **json.loads(read_public(f"tgwitness/locales/{lang}.json"))}
        if guide and lang != "en" and any(not words.get(key) for key in required):
            raise ValueError("Incomplete setup-guide translation: " + lang)
        scope = 'window.TGW_SCOPE="guide";' if guide else ''
        write(target, scope + "window.TGW_LANG=" + json.dumps(lang) + ";window.TGW_DICT="
              + json.dumps(words, ensure_ascii=False, separators=(",", ":")) + ";\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "phishdestroy/TgWitness"))
    parser.add_argument("--base-url", default=os.environ.get("TGWITNESS_SITE_URL") or None)
    parser.add_argument("--branch", default="main")
    args = parser.parse_args()
    output = build_site(repository=args.repository, base_url=args.base_url, branch=args.branch)
    files = [p for p in output.rglob("*") if p.is_file()]
    print(f"Built {len(files)} public files ({sum(p.stat().st_size for p in files):,} bytes): {output}")


if __name__ == "__main__":
    main()
