"""Publish the bundled account guide intact, using its existing translations."""
import html
import json
import re
from urllib.parse import urlsplit

try:
    from . import site_i18n
except ImportError:
    import site_i18n

SOURCE = "tgwitness/static/dedicated-account.html"
INLINE = {"a", "b", "br", "code", "em", "i", "kbd", "small", "span", "strong"}
SKIP = {"script", "style", "template", "pre", "textarea"}


def translate(source, words):
    """Same text units as the panel's walkPage; keep markup and SVGs intact."""
    edits = []

    def normal(text):
        return re.sub(r"\s+", " ", text).strip()

    def inline(node):
        return all(c.tag in INLINE and "id" not in c.attrs and inline(c) for c in node.children)

    def walk(node):
        if node.svg or node.tag in SKIP or "data-no-translate" in node.attrs:
            return
        start_tag = source[node.open_start:node.open_end]
        for match in re.finditer(r'\b(placeholder|aria-label|title|alt)="([^"]*)"', start_tag):
            key = normal(html.unescape(match[2]))
            if key in words:
                edits.append((node.open_start + match.start(2), node.open_start + match.end(2),
                              html.escape(words[key], quote=True)))
        inner = source[node.open_end:node.close_start]
        key = normal(inner)
        if node.children and inline(node) and key in words:
            edits.append((node.open_end, node.close_start, words[key]))
            return
        position = node.open_end
        for child in [*node.children, None]:
            end = child.open_start if child else node.close_start
            raw = source[position:end]
            key = normal(html.unescape(raw))
            if key in words:
                lead, trail = re.match(r"\s*", raw)[0], re.search(r"\s*$", raw)[0]
                edits.append((position, end, lead + html.escape(words[key], quote=False) + trail))
            if child:
                walk(child)
                position = child.close_end

    walk(site_i18n._Tree(source).root)
    for start, end, value in sorted(edits, reverse=True):
        source = source[:start] + value + source[end:]
    return source


def catalogue(read_public, lang):
    if lang == "en":
        return {}
    words = json.loads(read_public(f"tgwitness/locales/{lang}.json"))
    required = json.loads(read_public("tgwitness/guide_locales/keys.json"))["pages"]["dedicated-account.html"]
    if any(not words.get(key) for key in required):
        raise ValueError("Incomplete account-guide translation: " + lang)
    return words


def main_content(source):
    return re.search(r'<main\b[^>]*>(.*?)</main>', source, re.S)[1]


def render_page(source, *, lang, path, relative, relative_file, head, docs_label):
    """Use the original layout at the canonical docs URL, with project-relative links."""
    base = "" if lang == "en" else lang + "/"
    page = re.sub(r'<html lang="[^"]*">',
                  f'<html lang="{site_i18n.LANGUAGES[lang][1]}" dir="{site_i18n.LANGUAGES[lang][2]}">', source, count=1)
    page = re.sub(r"<title>.*?</title>", lambda _: head, page, count=1)

    def asset(match):
        attr, value = match[1], match[2]
        parts = urlsplit(value)
        target = "demo/" + (parts.path.lstrip("/") or "index.html")
        url = relative_file(path, target)
        if target.endswith(("guide.html", "index.html")):
            url += "?lang=" + lang
        if parts.fragment:
            url += "#" + parts.fragment
        return attr + '="' + url + '"'

    page = re.sub(r'\b(href|src)="(/[^"/][^"]*|/)"', asset, page)
    loader = relative_file(path, "demo/guide-locale.js")
    page = page.replace('src="' + loader + '"',
                        'src="' + relative_file(path, f"demo/guide-locales/{lang}.js") + '"')
    page = page.replace("<body>", '<body data-guide-root="' + relative(path, "") + '">', 1)
    docs_link = '<a href="' + relative(path, base + "docs/") + '">' + html.escape(docs_label) + '</a>'
    page = page.replace('class="top-nav">', 'class="top-nav">' + docs_link, 1)
    nojs_links = " · ".join('<a href="' + relative(path, ("" if code == "en" else code + "/")
                                           + "docs/dedicated-account/") + '" lang="' + info[1] + '">'
                            + html.escape(info[0]) + '</a>' for code, info in site_i18n.LANGUAGES.items())
    page = page.replace('<main id="top">', '<main id="top"><noscript><nav>' + nojs_links + '</nav></noscript>', 1)
    return page
