"""Build the public project site from an explicit list of presentation files."""
import argparse
import hashlib
import html
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import posixpath
import re
import sys
import tomllib
from urllib.parse import urlsplit

if __package__:
    from . import site_seo
    from .site_content import GROUPS, GUIDES, LABELS, NEXT, REFERENCE, REFERENCE_GROUPS
    from . import site_diagrams, site_i18n, site_wiki, site_modes, site_account, site_llms, site_export_clinic, site_typography, site_validation, site_context
else:
    import site_seo
    from site_content import GROUPS, GUIDES, LABELS, NEXT, REFERENCE, REFERENCE_GROUPS
    import site_diagrams
    import site_i18n
    import site_wiki
    import site_modes
    import site_account
    import site_llms
    import site_export_clinic
    import site_typography
    import site_validation
    import site_context

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

    "assets/investigation.mp4": "docs/assets/presentation/investigation.mp4",
    "assets/investigation-static.png": "docs/assets/presentation/investigation-static.png",
    "assets/message-history.mp4": "docs/assets/presentation/message-history.mp4",
    "assets/message-history-static.png": "docs/assets/presentation/message-history-static.png",
    "assets/evidence-chain-static.svg": "docs/assets/presentation/evidence-chain-static.svg",
    "assets/evidence-tamper-static.svg": "docs/assets/presentation/evidence-tamper-static.svg",
    "assets/evidence-checkpoint-static.svg": "docs/assets/presentation/evidence-checkpoint-static.svg",
}

WIKI_ASSETS = {
    **{f"assets/chapter-{name}.svg": f"docs/assets/presentation/chapter-{name}.svg"
       for name in ("start", "collect", "investigate", "evidence", "operate", "develop", "project", "capture", "integrations", "notice", "case")},
    "assets/performance.svg": "website/validation/performance.svg",
    "assets/case-board.png": "docs/assets/case-board.png",
    "assets/dossier-en.png": "docs/assets/reports/dossier-en.png",
    "assets/dossier-pdf.png": "docs/assets/reports/dossier-pdf.png",
    "assets/evidence-chain-animated.svg": "docs/assets/presentation/evidence-chain-animated.svg",
    "assets/evidence-tamper-animated.svg": "docs/assets/presentation/evidence-tamper-animated.svg",
    "assets/evidence-checkpoint-animated.svg": "docs/assets/presentation/evidence-checkpoint-animated.svg",
    "assets/sources.png": "docs/assets/sources.png",
    "assets/connection.png": "docs/assets/connection.png",
}
STATIC = {"style.css": "website/style.css", "site.js": "website/site.js", "discovery.css": "website/discovery.css",
          "sealed.html": "website/sealed.html", "sealed.js": "tgwitness/static/cloud-capture.js", "sealed.css": "tgwitness/static/cloud-capture.css",
          "site-redirect.js": "website/site-redirect.js", "capture-site.css": "website/capture-site.css",
          "capture-locales.js": "tgwitness/static/cloud-capture-locales.js",
          "sealed-story.js": "tgwitness/static/cloud-capture-story.js", "sealed-story.css": "tgwitness/static/cloud-capture-story.css",
          "LICENSE": "LICENSE", "NOTICE": "NOTICE",
          "docs.css": "website/docs.css", "docs.js": "website/docs.js", "context.css": "website/context.css",
          "learn.css": "website/learn.css", "learn.js": "website/learn.js",
          "workflows.css": "website/workflows.css", "workflows.js": "website/workflows.js", **ASSETS, **WIKI_ASSETS, **site_export_clinic.STATIC, **site_validation.STATIC}
SITE_SCRIPTS = ("website/learn.js", "website/docs.js", "website/site.js", "website/workflows.js")
MODES_PAGES = site_modes.FILES


DEMO_STATIC = {"demo/" + name: "tgwitness/static/" + name
               for name in ("style.css", "theme.js", "i18n.js", "dialogs.js", "app.js", "router.js", "integrations.js", "analysis.js", "media-analysis.js", "webhooks.js", "proxies.js", "fleet.js", "review.js", "live.js", "mark.svg", "guide.css", "guide.js",
                            "cloud-capture-locales.js", "cloud-capture.js", "cloud-capture.css", "cloud-capture-story.js", "cloud-capture-story.css", "capture.html",
                            "services.js", "services.css", "services-icons.svg", "account-import.js", "account-import.css",
                            "independent-capture.js", "independent-capture.css", "investigate.js", "investigate.css",
                            "privacy.js", "chat-safety.js", "workspace-safety.css")}
DEMO_STATIC.update({"demo/core/" + name: "tgwitness/static/core/" + name
                    for name in ("time.js", "view-host.js", "workspace-safety.js")})
DEMO_STATIC.update({"demo/components/" + name: "tgwitness/static/components/" + name
                    for name in ("shell.js", "shell.css", "layout.css", "health.js", "health.css", "health-actions.js", "collection.js", "collection.css", "workspaces.js", "forms.js", "forms.css", "connection-notice.js", "feedback.css", "account-state.js", "modes.js", "modes.css")})
DEMO_STATIC.update({"demo/views/" + name: "tgwitness/static/views/" + name
                    for name in ("sources.js", "sources.css", "parameters.js", "parameters.css", "exports.js", "exports.css", "accounts.js", "accounts.css", "access.js", "access.css", "system-log.js", "chats.css", "chat-list.js", "chat-list.css", "workflows.css", "setup.js", "setup.css", "disclosure-preview.js", "disclosure-preview.css", "connection.js", "connection.css", "settings-hub.js", "settings-hub.css", "group-settings.js", "group.js", "group.css", "board.js", "board.css", "report-selection.js", "report-profiles.js", "people-timeline.js", "secret-chats.js", "home.js")})
DEMO_STATIC.update({"demo/mock.js": "website/demo/mock.js", "demo/fixtures.json": "website/demo/fixtures.json"})
DEMO_STATIC["demo/system-map-data.js"] = "website/demo/system-map-data.js"
DEMO_STATIC["demo/views/secret-chats.js"] = "tgwitness/static/views/secret-chats.js"
DEMO_STATIC.update({"demo/views/" + name: "tgwitness/static/views/" + name
                    for name in ("system-map.js", "system-map-scene.js", "system-map.css")})
DEMO_STATIC.update({"demo/views/topology.js": "tgwitness/static/views/topology.js",
                    "demo/views/topology.css": "tgwitness/static/views/topology.css",
                    "demo/topology-data.js": "website/demo/topology-data.js"})
DEMO_STATIC.update({"demo/" + name: "website/demo/" + name for name in ("secret-chats.js", "secret-chats.css")})
DEMO_STATIC.update({"demo/views/report-guidance.js": "tgwitness/static/views/report-guidance.js",
                    "demo/jurisdictions.json": "tgwitness/jurisdictions.json"})
DEMO_STATIC.update({"demo/report/" + name: "website/demo/report/" + name
                    for name in ("index.html", "report.html", "sharing-copy.zip", "example.json")})
DEMO_STATIC.update({"demo/components/" + name: "tgwitness/static/components/" + name
                    for name in ("notifications.js", "notifications.css", "journal.js", "journal.css", "priority.js")})
DEMO_STATIC.update({"demo/downloads/" + name: "website/demo/downloads/" + name for name in (
    "tgwitness-demo.zip", "tgwitness-demo.jsonl", "tgwitness-demo.csv", "tgwitness-demo.html",
    "tgwitness-demo-checkpoint.json", "tgwitness-demo-run-receipt.json", "tgwitness-demo-timestamp-request.zip",
    "tgwitness-demo-account-export.zip", "tgwitness-demo-minimized-disclosure.zip")})
DEMO_PAGES = {"demo/index.html": "tgwitness/static/index.html", "demo/guide.html": "tgwitness/static/guide.html",
              "demo/dedicated-account.html": "tgwitness/static/dedicated-account.html"}
DEMO_LOCALES = {f"demo/locales/{lang}.js": lang for lang in LANGS}
DEMO_GUIDE_LOCALES = {f"demo/guide-locales/{lang}.js": lang for lang in site_modes.LANGUAGES}
DEMO_DICTIONARIES = ("tgwitness/english_fallbacks.json", *(f"tgwitness/locales/{lang}.json" for lang in LANGS if lang != "en"))
GUIDE_DICTIONARIES = ("tgwitness/guide_locales/keys.json", *(f"tgwitness/guide_locales/{lang}.json" for lang in site_modes.EXTRA_LANGUAGES))
CAPTURE_DOCS = {"en": "docs/SEALED-ACTIONS.md", "ru": "docs/ru/SEALED-ACTIONS.md"}
WIKI_HUB = "docs/reference/"
LOCAL_PAGES = ("", "docs/", *(f"docs/{slug}/" for slug in GUIDES), WIKI_HUB, *(f"{WIKI_HUB}{slug}/" for slug in REFERENCE))
NOTICE_PAGES = tuple(f"{WIKI_HUB}{slug}/" for slug in NOTICE_SLUGS)
PAGE_LOCALES = tuple((lang, local) for lang in NOTICE_LANGUAGES
                     for local in (LOCAL_PAGES if lang in LANGS else NOTICE_PAGES)) + (("en", site_export_clinic.PATH),) + tuple((lang, site_validation.PATH) for lang in site_validation.LANGUAGES)
PAGES = tuple(("" if lang == "en" else lang + "/") + local for lang, local in PAGE_LOCALES)
SEARCH_FILES = tuple(("" if lang == "en" else lang + "/") + "docs/search.json" for lang in NOTICE_LANGUAGES)
MARKDOWN_PAGES = {path + "index.html": site_llms.markdown_path(path) for path in PAGES}
MARKDOWN_PAGES.update({path: site_llms.markdown_path(path) for path in MODES_PAGES})
LLM_FILES = (*(base + name for lang in NOTICE_LANGUAGES for base in ("" if lang == "en" else lang + "/",)
               for name in ("llms.txt", "llms-full.txt", "llms-full.md")), *MARKDOWN_PAGES.values())
SEARCH_TEXT = 4000
HOME_TITLE = "Telegram chat export & verifiable evidence | TgWitness"
HOME_DESCRIPTION = ("Install with one command, export Telegram chats and verify signed archives. "
                    "Use GitHub capture or investigate saved messages, edits and deletions.")
HOME_OG = "Start with a Telegram chat export. Preserve observed changes, investigate the archive and share records others can verify."
HOME_IMAGE_ALT = "TgWitness, a Telegram investigation workspace for following the trail and preserving the evidence."
WIKI_DESCRIPTION = ("The complete TgWitness reference: installation, collection, Case Board, report design, signed exports, "
                    "witnesses, integrations, security and operations.")

FRAME = ("Visual guide", "Security", "Language", "Switch between light and dark theme", "Link to this section",
         "Parts of this page are still in English: the English original changed after it was translated.",
         "This page is available in English only.")
NOTICE_LINK_NOTE = ("The two project notices and the capability guide are translated into this language. "
                    "Other linked guides and reference pages are in English.")
NOTICE_FRAME = (*(value for key, value in LABELS.items() if key not in {"title", "intro", "description"}),
                *FRAME[:5], "Security & project", NOTICE_LINK_NOTE)
THEME_SCRIPT = ("(()=>{try{const s=localStorage.getItem('tgw-theme');document.documentElement.dataset.theme="
                "s||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light')}catch(e){}})()")


def prefix(lang):
    return "" if lang == "en" else lang + "/"


def page_languages(local):
    if local == site_validation.PATH:
        return {lang: site_i18n.LANGUAGES[lang] for lang in site_validation.LANGUAGES}
    if local == site_export_clinic.PATH:
        return {"en": site_i18n.LANGUAGES["en"]}
    return NOTICE_LANGUAGES if local in NOTICE_PAGES else site_i18n.LANGUAGES


def canonical_path(path):
    local = path.split("/", 1)[1] if path.split("/", 1)[0] in LANGS and "/" in path else path
    if local == WIKI_HUB + "overview/" and path not in {local, "ru/" + local}:
        return local
    return local if local in {WIKI_HUB + slug + "/" for slug in site_i18n.ENGLISH_ONLY} else path


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


def seo(base_url, path, title, description, lang, alternates, *, crumbs=(), extra_only=False, languages=site_i18n.LANGUAGES, software=None, version=None):
    canonical = base_url + "/" + canonical_path(path)
    alternates = [(other, target) for other, target in alternates if canonical_path(target) == target]
    if canonical_path(path) != path or path in {WIKI_HUB + slug + "/" for slug in site_i18n.ENGLISH_ONLY}:
        lang = "en"
        slug = canonical_path(path).split("/")[-2]
        title, description = REFERENCE[slug][0] + " · " + LABELS["wiki"] + " | TgWitness", REFERENCE[slug][1]
    code = languages[lang][1]
    graph = [{"@type": "WebPage", "@id": canonical, "url": canonical, "name": title,
              "description": description, "inLanguage": code, "isPartOf": {"@id": base_url + "/#website"}}]
    graph.append({"@type": "WebSite", "@id": base_url + "/#website", "url": base_url + "/",
                  "name": "TgWitness", "inLanguage": "en"})
    if software:
        graph[0]["about"] = {"@id": base_url + "/#software"}
        if path in {prefix(other) for other in LANGS}:
            graph[0]["mainEntity"] = {"@id": base_url + "/#software"}
        graph.append({"@type": "SoftwareSourceCode", "@id": base_url + "/#software", "name": "TgWitness",
                      "url": base_url + "/", "codeRepository": software, "description": HOME_DESCRIPTION,
                      "programmingLanguage": ["Python", "JavaScript"], "runtimePlatform": "Python 3.11+",
                      "license": "https://spdx.org/licenses/MIT.html", "isAccessibleForFree": True,
                      "author": {"@type": "Organization", "name": "PhishDestroy", "url": "https://phishdestroy.io/"}})
        if version:
            graph[-1]["version"] = version
    context_path = ("ru/" if lang == "ru" else "") + WIKI_HUB + "overview/"
    graph[0]["relatedLink"] = [base_url + "/" + context_path,
                               base_url + "/" + ("ru/" if lang == "ru" else "") + site_validation.PATH]
    graph[0]["encoding"] = {"@type": "MediaObject", "encodingFormat": "text/markdown",
                             "contentUrl": base_url + "/" + site_llms.markdown_path(path)}
    if crumbs:
        graph[0]["breadcrumb"] = {"@id": canonical + "#breadcrumb"}
        graph.append({"@type": "BreadcrumbList", "@id": canonical + "#breadcrumb", "itemListElement": [
            {"@type": "ListItem", "position": i + 1, "name": name, "item": base_url + "/" + url}
            for i, (name, url) in enumerate(crumbs)]})
    links = "".join(f'<link rel="alternate" hreflang="{languages[other][1]}" '
                    f'href="{html.escape(base_url + "/" + other_path, quote=True)}">'
                    for other, other_path in alternates)
    default_path = next((other_path for other, other_path in alternates if other == "en"), alternates[0][1])
    links += f'<link rel="alternate" hreflang="x-default" href="{html.escape(base_url + "/" + default_path, quote=True)}">'
    links += (f'<link rel="alternate" type="text/markdown" href="{html.escape(base_url + "/" + site_llms.markdown_path(path), quote=True)}">'
              f'<link rel="describedby" href="{html.escape(base_url, quote=True)}/{prefix(lang)}llms.txt" type="text/plain">'
              f'<link rel="help" href="{html.escape(base_url, quote=True)}/{context_path}" title="TgWitness: start, scale and evidence">'
              f'<link rel="sitemap" type="application/xml" href="{html.escape(base_url, quote=True)}/sitemap.xml">')
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
    return [(id_, html.escape(PlainText(inner).text.rstrip("#").strip(), quote=False))
            for id_, inner in re.findall(r'<h2 id="([^"]+)">(.*?)</h2>', content, re.S)]


def home_body(template):
    start, end = template.index("<body>") + len("<body>"), template.index("</body>")
    return template[start:end]


def inventory(root=ROOT):
    root = Path(root)
    strings = list(LABELS.values()) + list(FRAME) + [HOME_TITLE, HOME_DESCRIPTION, HOME_OG, HOME_IMAGE_ALT, WIKI_DESCRIPTION, NOTICE_LINK_NOTE,
                                                  site_context.SUMMARY, site_context.OVERVIEW, site_context.MEASUREMENTS]
    for title, description, keywords, _ in GUIDES.values():
        strings += [title, description, keywords]
    for label, heading, _ in GROUPS:
        strings += [label, heading]
    for slug, (title, description, keywords, _) in REFERENCE.items():
        strings += [title, description, keywords]
    strings += [label for label, _ in REFERENCE_GROUPS]
    for name in SITE_SCRIPTS:
        strings += site_i18n.script_strings((root / name).read_text(encoding="utf-8"))
    fragments = {"home": home_body((root / "website/index.html").read_text(encoding="utf-8")),
                 "intro": (root / "website/guide_intro.html").read_text(encoding="utf-8")}
    for slug in GUIDES:
        if slug == "dedicated-account":
            continue
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


def validate_demo_assets(root):
    published = set(DEMO_STATIC.values()) | set(DEMO_PAGES.values())
    reference = re.compile(r'''["']([^"'\s<>]+\.(?:js|css)(?:\?[^"'\s<>]*)?)["']''')
    for source in sorted(published):
        if not source.startswith("tgwitness/static/") or Path(source).suffix not in (".html", ".js", ".css"):
            continue
        for value in reference.findall((root / source).read_text(encoding="utf-8")):
            parts = urlsplit(html.unescape(value))
            if parts.scheme or parts.netloc:
                continue
            target = ("tgwitness/static" + parts.path if parts.path.startswith("/") else
                      posixpath.normpath(posixpath.join(posixpath.dirname(source), parts.path)))
            if source in DEMO_PAGES.values() and target == "tgwitness/static/guide-locale.js":
                continue
            if target.startswith("tgwitness/static/") and (root / target).is_file() and target not in published:
                raise ValueError("Referenced panel asset is missing from the demo: " + target)


def build_site(root=ROOT, *, repository="phishdestroy/TgWitness", base_url=None, branch="main", output=None):
    root = Path(root).resolve()
    validate_demo_assets(root)
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
    output = Path(output).absolute() if output is not None else root / "dist/site"


    expected = {*(path + "index.html" for path in PAGES), *SEARCH_FILES, *STATIC, ".nojekyll", "robots.txt", "sitemap.xml",
                *DEMO_STATIC, *DEMO_PAGES, *DEMO_LOCALES, *DEMO_GUIDE_LOCALES, *MODES_PAGES, *LLM_FILES}
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

    markdown_documents = {}
    validation_texts = json.loads(read_public("website/validation/texts.json"))

    def write(path, content):
        if path in MARKDOWN_PAGES:
            code = path.split("/", 1)[0]
            code = code if code in NOTICE_LANGUAGES else "en"
            context = site_context.render(path, code, translations[code], version)
            if path == prefix(code) + "index.html":
                context = site_typography.homepage(context)
            stylesheet = relative_file(posixpath.dirname(path), "context.css")
            content = content.replace('</head>', f'<link rel="stylesheet" href="{stylesheet}"></head>', 1)
            content = content.replace('</main>', context + '</main>', 1)
        if path in MARKDOWN_PAGES:
            content = site_seo.enrich(content, path)
        target = output / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content.replace("\r\n", "\n"), encoding="utf-8", newline="\n")
        if path in MARKDOWN_PAGES:
            url = base_url + "/" + (path.removesuffix("index.html") if path.endswith("index.html") else path)
            plain = site_llms.markdown(content, url)
            markdown_documents[path] = plain
            (output / MARKDOWN_PAGES[path]).write_text(plain, encoding="utf-8", newline="\n")

    translations = {}
    for lang in NOTICE_LANGUAGES:
        if lang == "en":
            translations[lang] = None
            continue
        path = root / f"website/i18n/{lang}.json"
        if path.exists():
            read_public(f"website/i18n/{lang}.json")
        translations[lang] = site_i18n.load(root, lang)
    sources = {slug: site_wiki.split_title(read_public(entry[3]).decode("utf-8"))[1] for slug, entry in REFERENCE.items()}
    home_template = read_public("website/index.html").decode("utf-8")
    doc_template = read_public("website/docs.html").decode("utf-8")
    intro_template = read_public("website/guide_intro.html").decode("utf-8")
    modes_template = read_public(site_modes.SOURCE).decode("utf-8")
    modes_english = site_modes.catalogue(read_public, "en")
    fragments = {slug: read_public(f"website/guides/en/{slug}.html").decode("utf-8")
                 for slug in GUIDES if slug != "dedicated-account"}
    account_template = read_public(site_account.SOURCE).decode("utf-8")
    capture_instructions, images = {}, {}
    for code, source in CAPTURE_DOCS.items():
        body = site_wiki.to_html(site_wiki.split_title(read_public(source).decode("utf-8"))[1])[0]
        capture_instructions[code] = site_wiki.rewrite_links(
            body, source, "", {}, {}, lambda page, target: "@@ROOT@@" + target,
            repo_url, branch, images, root)
    script_keys = []
    for script in SITE_SCRIPTS:
        script_keys += site_i18n.script_strings(read_public(script).decode("utf-8"))


    inventory_strings, inventory_fragments, inventory_diagrams = inventory(root)
    required_strings = set(inventory_strings + inventory_diagrams)
    pending = {}
    for lang in LANGS:
        if lang == "en":
            continue
        data = translations[lang]
        labels = sum(1 for text in required_strings if not data["strings"].get(text, "").strip())
        blocks = {name: sum(1 for text in site_i18n.unit_texts(fragment)
                            if not data["blocks"].get(site_i18n.digest(text), "").strip())
                  for name, fragment in inventory_fragments.items() if name not in {"reference:license", "reference:notice"}}
        blocks = {name: count for name, count in blocks.items() if count}
        if labels or blocks:
            pending[lang] = {"labels": labels, "blocks": blocks}
    if pending:
        print("Translation pending (shown in English): " + "; ".join(
            f"{lang} {item['labels']} labels, {sum(item['blocks'].values())} blocks"
            + (" (" + ", ".join(sorted(item["blocks"])) + ")" if item["blocks"] else "")
            for lang, item in sorted(pending.items())), file=sys.stderr)

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

        def guide_values(path):
            return {**values, **language_values, "ROOT": relative(path, ""),
                    **{"REF_" + key.upper().replace("-", "_"): relative(path, wiki_page[entry[3]])
                       for key, entry in REFERENCE.items()},
                    **{"GUIDE_" + key.upper().replace("-", "_"): relative(path, (hub if full_site else "docs/") + key + "/") for key in GUIDES}}

        if full_site:

            body, _ = localize(home_body(home_template))
            home = home_template[:home_template.index("<body>") + len("<body>")] + body + home_template[home_template.index("</body>"):]
            home_dictionary = {key: site_typography.prose(t(key)) for key in
                               site_i18n.script_strings(read_public("website/site.js").decode("utf-8"))}
            write(base + "index.html", site_typography.homepage(links(render(home, {
                **guide_values(base), "ROOT": "" if not base else relative(base, ""), "TITLE": html.escape(t(HOME_TITLE), quote=True),
                "SITE_DICT": json_script(home_dictionary),
                "VALIDATION_URL": relative(base, prefix(lang if lang in site_validation.LANGUAGES else "en") + site_validation.PATH),
                "DESCRIPTION": html.escape(t(HOME_DESCRIPTION), quote=True), "CANONICAL": html.escape(base_url + "/" + base, quote=True),
                "OG_LOCALE": site_i18n.LANGUAGES[lang][3], "OG_DESCRIPTION": html.escape(t(HOME_OG), quote=True),
                "OG_IMAGE_ALT": html.escape(t(HOME_IMAGE_ALT), quote=True),
                "LANGUAGE_MENU": language_menu(base, ""), "THEME_TOGGLE": theme_toggle(),
                "EXTRA_HEAD": seo(base_url, base, t(HOME_TITLE), t(HOME_DESCRIPTION), lang, alternates(""), extra_only=True, software=repo_url, version=version)}), base)))

        texts = {}

        guide_html, guide_missing = {}, {}
        account_page = site_account.translate(account_template, site_account.catalogue(read_public, lang)) if full_site else ""
        for slug in (GUIDES if full_site else ()):
            translated, missing = ((site_account.main_content(account_page), 0) if slug == "dedicated-account"
                                   else localize(fragments[slug]))
            if slug == "capture":
                source_lang = lang if lang in CAPTURE_DOCS else "en"
                translated += (f'<details class="detail-block"><summary>{labels["reference"]}</summary>'
                               f'<div class="wiki-body" lang="{source_lang}" dir="ltr">'
                               + capture_instructions[source_lang] + '</div></details>')
            if slug == "concepts":
                translated += ('<p class="callout" lang="en" dir="ltr"><a href="@@ROOT@@docs/export-clinic/">'
                               'Export Clinic: watch the controlled Desktop experiment</a>. Compare the two-minute film, '
                               'the original recording and seven pairs of test exports. Local modification is disclosed.</p>')
            guide_html[slug], guide_missing[slug] = translated, missing
            texts[hub + slug + "/"] = PlainText(render(translated, guide_values(hub + slug + "/"))).text
        for slug in page_slugs:
            texts[f"{wiki_hub}{slug}/"] = PlainText(rendered[slug]).text
        search = {"labels": {k: labels[k] for k in ("empty", "results", "prompt")}, "pages": [
            {"title": validation_texts.get(lang, validation_texts["en"])["title"],
             "description": validation_texts.get(lang, validation_texts["en"])["description"],
             "keywords": "benchmark speed audit validation servers tests", "text": validation_texts.get(lang, validation_texts["en"])["description"],
             "url": relative(hub, (base if lang in site_validation.LANGUAGES else "") + site_validation.PATH)},
            {"title": site_export_clinic.TITLE + (" · English" if lang != "en" else ""),
             "description": site_export_clinic.DESCRIPTION, "keywords": site_export_clinic.KEYWORDS,
             "text": site_export_clinic.DESCRIPTION,
             "url": relative(hub, site_export_clinic.PATH)},
            *({"title": guides[key][0], "description": guides[key][1], "keywords": guides[key][2],
               "text": texts[hub + key + "/"][:SEARCH_TEXT], "url": key + "/"} for key in (GUIDES if full_site else ())),
            {"title": modes_words["modes.eyebrow"], "description": modes_words["modes.seo"],
             "keywords": modes_words["modes.title"], "text": PlainText(modes_html).text[:SEARCH_TEXT],
             "url": "../" + site_modes.LOCAL},
            *({"title": labels["wiki"] + " · " + reference[key][0], "description": reference[key][1],
               "keywords": reference[key][2] + (" " + REFERENCE[key][2] if lang != "en" else ""),
               "text": texts[f"{wiki_hub}{key}/"][:SEARCH_TEXT],
               "url": "reference/" + key + "/"} for key in page_slugs)]}
        write(hub + "search.json", json.dumps(search, ensure_ascii=False, separators=(",", ":")))

        def sidebar(path):
            items = [f'<a href="{relative_file(path, base + site_modes.LOCAL)}">{html.escape(modes_words["modes.eyebrow"])}</a>']
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
                    if key == "concepts":
                        mark = ' aria-current="page"' if path == site_export_clinic.PATH else ''
                        suffix = ' · EN' if lang != "en" else ''
                        items.append(f'<a lang="en" dir="ltr" href="{relative(path, site_export_clinic.PATH)}"{mark}>Export Clinic{suffix}</a>')
                        validation_lang = lang if lang in site_validation.LANGUAGES else "en"
                        validation_path = prefix(validation_lang) + site_validation.PATH
                        mark = ' aria-current="page"' if path == validation_path else ''
                        items.append(f'<a lang="{validation_lang}" dir="ltr" href="{relative(path, validation_path)}"{mark}>{html.escape(validation_texts[validation_lang]["title"])}</a>')
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
            metadata_title = title
            if local.startswith(WIKI_HUB) and local != WIKI_HUB and local not in NOTICE_PAGES:
                metadata_title += " · " + labels["wiki"]
            breadcrumb = ' <span aria-hidden="true">/</span> '.join(
                f'<a href="{relative(path, url)}">{html.escape(label)}</a>' if url != path
                else f'<span aria-current="page">{html.escape(label)}</span>' for label, url in crumbs)
            guides_nav, wiki_nav = sidebar(path)
            toc_html = (f'<p class="nav-label">{labels["toc"]}</p>' + ''.join(f'<a href="#{id_}">{text}</a>' for id_, text in toc)
                        if toc else "")
            context = {**guide_values(path), **language_values,
                       "PAGE_CLASS": "docs-root validation-page" if local == site_validation.PATH else "notice-page" if local in NOTICE_PAGES else "docs-root docs-hub" if local == "docs/" else "docs-root",
                       **{key.upper(): html.escape(value, quote=True) for key, value in labels.items()},
                       "HOME": relative(path, base if full_site else ""), "HUB": relative(path, hub if full_site else "docs/"),
                       "WIKI_HUB": relative(path, wiki_hub if full_site else WIKI_HUB),
                       "OPERATOR_URL": relative(path, wiki_hub + "notice/"),
                       "SIDEBAR": guides_nav, "WIKI_NAV": wiki_nav, "VISUAL": html.escape(t("Visual guide")),
                       "SECURITY": html.escape(t("Security")), "LANGUAGE_MENU": language_menu(path, local),
                       "THEME_TOGGLE": theme_toggle(), "SEARCH_URL": relative_file(path, hub + "search.json"),
                       "HEAD": seo(base_url, path, metadata_title + " | TgWitness", description, lang, alternates(local), crumbs=crumbs, languages=page_languages(local), software=repo_url, version=version),
                       "BREADCRUMBS": breadcrumb, "NOTICE": notice, "CONTENT": content, "CONTENTS": toc_html,
                       "GUIDE_FOOTER": footer}
            result = render(doc_template, context)
            if local == "docs/":
                search_start = result.index('<div class="search"')
                search_end = result.index('<article class="guide-content">', search_start)
                search = result[search_start:search_end]
                result = result[:search_start] + result[search_end:]
                result = result.replace('<div data-hub-search></div>', search, 1)
                result = re.sub(r'<p class="verification-shortcut">.*?</p>', '', result, count=1)
            if "data-workflow=" in content:
                assets = relative(path, "")
                result = result.replace('</head>', f'<link rel="stylesheet" href="{assets}workflows.css">'
                                        f'<script defer src="{assets}workflows.js"></script></head>')
            if local == "docs/capture/":
                assets = relative(path, "")
                extra = ''.join(f'<link rel="stylesheet" href="{assets}{name}">' for name in ("sealed.css", "sealed-story.css", "capture-site.css"))
                extra += ''.join(f'<script defer src="{assets}{name}"></script>' for name in ("capture-locales.js", "sealed-story.js", "sealed.js"))
                result = result.replace('</head>', extra + '</head>')
            if local == site_export_clinic.PATH:
                assets = relative(path, "")
                result = result.replace('</head>', f'<link rel="stylesheet" href="{assets}export-clinic.css">'
                                        f'<script defer src="{assets}export-clinic.js"></script></head>')
            if local == site_validation.PATH:
                assets = relative(path, "")
                result = result.replace('</head>', f'<link rel="stylesheet" href="{assets}validation/validation.css">'
                                        f'<script defer src="{assets}validation/validation.js"></script></head>')
            write(path + "index.html", links(result, path))

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

            intro, intro_missing = localize(intro_template)
            content = (f'<p class="eyebrow">TGWITNESS / {labels["docs"].upper()}</p><h1>{labels["title"]}</h1>'
                       f'<p class="guide-outcome">{labels["intro"]}</p>' + render(intro, guide_values(hub)))
            content += '<section class="hub-catalog" id="guide-catalog">'
            content += (f'<a class="guide-card" href="{relative_file(hub, base + site_modes.LOCAL)}">'
                        f'<span class="card-number" aria-hidden="true">04 / 08 ↗</span>'
                        f'<h2>{html.escape(modes_words["modes.eyebrow"])}</h2>'
                        f'<p>{html.escape(modes_words["modes.seo"])}</p></a>')
            for index, (label, heading, keys) in enumerate(GROUPS):
                content += f'<h2 id="section-{index}">{t(heading)}</h2><div class="guide-grid">'
                content += "".join(card(hub, hub + key + "/", f"{list(GUIDES).index(key) + 1:02d}", *guides[key][:2]) for key in keys)
                if "concepts" in keys:
                    content += '<div lang="en" dir="ltr">' + card(hub, site_export_clinic.PATH, "EXPERIMENT / EN", site_export_clinic.TITLE, site_export_clinic.DESCRIPTION) + '</div>'
                content += '</div>'
            content += (f'<h2 id="reference">{labels["wiki_title"]}</h2><p>{labels["wiki_intro"]}</p>'
                        f'<div class="wiki-index">' + "".join(
                            f'<div class="wiki-column"><p class="nav-label">{t(label)}</p>' + "".join(
                                f'<a href="{relative(hub, wiki_hub + key + "/")}">{reference[key][0]}</a>' for key in keys)
                            + '</div>' for label, keys in REFERENCE_GROUPS) + '</div></section>')
            page("docs/", labels["docs"], labels["description"], [(labels["home"], base), (labels["docs"], hub)], content, [], "",
                 notice(intro_missing))

            for slug in GUIDES:
                path = hub + slug + "/"
                title, description = guides[slug][:2]
                if slug == "dedicated-account":
                    head = seo(base_url, path, title + " | TgWitness", description, lang,
                               alternates("docs/dedicated-account/"),
                               crumbs=[(labels["home"], base), (labels["docs"], hub), (title, path)], software=repo_url, version=version)
                    write(path + "index.html", site_account.render_page(
                        account_page, lang=lang, path=path, relative=relative, relative_file=relative_file,
                        head=head, docs_label=labels["docs"]))
                    continue
                guide = render(guide_html[slug], guide_values(path))
                content = f'<p class="eyebrow">{labels["docs"]} / {list(GUIDES).index(slug) + 1:02d}</p><h1>{title}</h1>' + guide
                next_slug = NEXT[slug]
                target = wiki_page.get(GUIDES[slug][3])
                footer = ((f'<a class="reference" href="{relative(path, target)}">{labels["reference"]} {arrow}</a>' if target else "")
                          + f'<a class="next-guide" href="{relative(path, hub + next_slug + "/")}"><span>{labels["next"]}</span>'
                            f'<strong>{guides[next_slug][0]} {arrow}</strong></a>')
                page(f"docs/{slug}/", title, description, [(labels["home"], base), (labels["docs"], hub), (title, path)],
                     content, headings(content), footer, notice(guide_missing[slug]))


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
        if lang == "en":
            content = ('<p class="eyebrow">Documentation / Controlled experiment</p><h1>Export Clinic</h1>'
                       + site_export_clinic.content(read_public, render, guide_values(site_export_clinic.PATH), json_script))
            footer = '<a class="next-guide" href="../concepts/"><span>Continue reading</span><strong>See how evidence works →</strong></a>'
            page(site_export_clinic.PATH, site_export_clinic.TITLE, site_export_clinic.DESCRIPTION,
                 [(labels["home"], base), (labels["docs"], hub), (site_export_clinic.TITLE, site_export_clinic.PATH)],
                 content, headings(content), footer)
        if lang in site_validation.LANGUAGES:
            words = validation_texts[lang]
            content = site_validation.content(read_public, render, guide_values(base + site_validation.PATH), lang)
            page(site_validation.PATH, words["title"], words["description"],
                 [(labels["home"], base), (labels["docs"], hub), (words["title"], base + site_validation.PATH)],
                 content, headings(content), "")
        order = [key for _, keys in REFERENCE_GROUPS for key in keys if key in page_slugs]
        for index, slug in enumerate(order):
            path = f"{wiki_hub}{slug}/"
            title, description, keywords, source = reference[slug]
            group = next(t(label) for label, keys in REFERENCE_GROUPS if slug in keys)
            english = slug in site_i18n.ENGLISH_ONLY
            content = (f'<p class="eyebrow">{labels["wiki"]} / {html.escape(group)}</p><h1>{html.escape(title)}</h1>'
                       f'<p class="guide-outcome">{html.escape(description)}</p>'
                       f'<div class="wiki-body"{" lang=en dir=ltr" if english and lang != "en" else ""}>{rendered[slug]}</div>')
            following = order[(index + 1) % len(order)]


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
    llms_index = site_llms.index(base_url, repo_url, branch, version, GUIDES, REFERENCE)
    llms_index += site_llms.directory(base_url, GUIDES, REFERENCE)
    llms_index += "\n## Language editions\n\n" + "\n".join(
        f"- [{info[0]}]({base_url}/{prefix(code)}llms.txt)" for code, info in NOTICE_LANGUAGES.items()) + "\n"
    llms_index += f"\n## Controlled experiment\n\n- [Export Clinic]({base_url}/{site_export_clinic.PATH}index.md): {site_export_clinic.DESCRIPTION}\n"
    llms_index += f"\n## Checks and measurements\n\n- [Checks & measurements]({base_url}/{site_validation.PATH}index.md): {validation_texts['en']['description']}\n"
    write("llms.txt", llms_index)
    handbook_paths = [f"docs/{slug}/index.html" for _, _, keys in GROUPS for slug in keys]
    handbook_paths.append(site_export_clinic.PATH + "index.html")
    handbook_paths.append(site_validation.PATH + "index.html")
    handbook_paths += [f"{WIKI_HUB}{slug}/index.html" for _, keys in REFERENCE_GROUPS for slug in keys]
    handbook = site_llms.full(llms_index, [markdown_documents[path] for path in handbook_paths]
                             + [markdown_documents[site_modes.LOCAL]])
    write("llms-full.txt", handbook)
    write("llms-full.md", handbook)
    for code, info in NOTICE_LANGUAGES.items():
        if code == "en":
            continue
        base = prefix(code)
        data = translations[code]
        localized_guides = {key: tuple(site_i18n.text(data, value) for value in entry[:2])
                            for key, entry in GUIDES.items()} if code in LANGS else {}
        localized_reference = {key: tuple(site_i18n.text(data, value) for value in entry[:2])
                               for key, entry in REFERENCE.items() if code in LANGS or key in NOTICE_SLUGS}
        index = site_llms.localized_index(base_url, base, info[0], repo_url, branch, version,
                                           localized_guides, localized_reference)
        write(base + "llms.txt", index)
        paths = [base + path for path in handbook_paths if base + path in markdown_documents]
        paths.append(base + site_modes.LOCAL)
        translated_handbook = site_llms.full(index, [markdown_documents[path] for path in paths])
        write(base + "llms-full.txt", translated_handbook)
        write(base + "llms-full.md", translated_handbook)
    (output / ".nojekyll").write_text("", encoding="utf-8")
    (output / "robots.txt").write_text("User-agent: *\nAllow: /\nSitemap: " + base_url + "/sitemap.xml\n", encoding="utf-8")
    (output / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">\n'
        + ''.join('<url><loc>' + html.escape(base_url + '/' + prefix(lang) + local) + '</loc>' + ''.join(
            f'<xhtml:link rel="alternate" hreflang="{page_languages(local)[other][1]}" '
            f'href="{html.escape(base_url + "/" + prefix(other) + local)}"/>' for other in page_languages(local)
            if canonical_path(prefix(other) + local) == prefix(other) + local)
            + f'<xhtml:link rel="alternate" hreflang="x-default" href="{html.escape(base_url + "/" + local)}"/></url>\n'
            for lang, local in PAGE_LOCALES if canonical_path(prefix(lang) + local) == prefix(lang) + local)
        + ''.join('<url><loc>' + html.escape(base_url + '/' + path) + '</loc>' + ''.join(
            f'<xhtml:link rel="alternate" hreflang="{site_modes.LANGUAGES[other][1]}" '
            f'href="{html.escape(base_url + "/" + ("" if other == "en" else other + "/") + site_modes.LOCAL)}"/>'
            for other in site_modes.LANGUAGES)
            + f'<xhtml:link rel="alternate" hreflang="x-default" href="{html.escape(base_url + "/" + site_modes.LOCAL)}"/></url>\n'
            for path in MODES_PAGES)
        + '</urlset>\n', encoding="utf-8")
    return output


def demo_language_script(languages, folder, revision=""):
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
            "document.write('<script src=\"" + folder + "/'+pick+'.js?v=" + revision + "\"><\\/script>');})();</script>")


def build_demo(read_public, write):
    revision = hashlib.sha256(b"".join(read_public(path) for path in
        (*DEMO_DICTIONARIES, *GUIDE_DICTIONARIES))).hexdigest()[:16]
    for target, source in DEMO_PAGES.items():
        page = read_public(source).decode("utf-8").replace('href="/"', 'href="../"')
        page = re.sub(r'\b(src|href)="/(?=[A-Za-z])', r'\1="', page)
        guide = target != "demo/index.html"
        original_loader = ('<script src="guide-locale.js"></script>' if guide
                           else '<script src="guide-locale.js" data-scope="panel"></script>')
        if original_loader not in page:
            raise ValueError("Demo page no longer loads locale.js where expected: " + source)
        answering = '<script src="mock.js?v=handoff1"></script>' if target == "demo/index.html" else ""
        loader = demo_language_script(site_modes.LANGUAGES if guide else LANGS, "guide-locales" if guide else "locales", revision)
        page = page.replace(original_loader, answering + loader)
        page = page.replace("<head>", '<head>\n<meta name="robots" content="noindex">', 1)
        if not guide:
            launch = '<button class="secondary" type="button" data-secret-demo-open lang="en" data-no-translate>Try Secret Chat</button>'
            page = page.replace('<div class="demo-actions">', '<div class="demo-actions">' + launch, 1)
            source_summary = '<div class="sources-summary"'
            page = page.replace(source_summary, '<p>' + launch + '</p>' + source_summary, 1)
            page = page.replace('</head>', '<link rel="stylesheet" href="secret-chats.css?v=1"></head>', 1)
            preview = read_public("website/demo/secret-chats.html").decode("utf-8")
            page = page.replace('</body>', preview + '<script src="secret-chats.js?v=1"></script></body>', 1)
        write(target, page)
    fallbacks = json.loads(read_public("tgwitness/english_fallbacks.json"))
    required = json.loads(read_public("tgwitness/guide_locales/keys.json"))["keys"]
    for target, lang in {**DEMO_LOCALES, **DEMO_GUIDE_LOCALES}.items():
        guide = target in DEMO_GUIDE_LOCALES
        if lang == "en":
            words = {}
        elif lang in site_modes.EXTRA_LANGUAGES:
            words = {**{text: text for text in fallbacks},
                     **json.loads(read_public(f"tgwitness/guide_locales/{lang}.json"))}
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
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = build_site(repository=args.repository, base_url=args.base_url, branch=args.branch, output=args.output)
    files = [p for p in output.rglob("*") if p.is_file()]
    print(f"Built {len(files)} public files ({sum(p.stat().st_size for p in files):,} bytes): {output}")


if __name__ == "__main__":
    main()
