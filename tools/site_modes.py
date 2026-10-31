"""Keyed, statically translated capability guide; no runtime translation fetch."""
import html
import json
import posixpath
import re

try:
    from .site_i18n import LANGUAGES as SITE_LANGUAGES
except ImportError:
    from site_i18n import LANGUAGES as SITE_LANGUAGES

# Amharic retains its existing guide and notice translations; DeepL does not support it.
EXTRA_LANGUAGES = {
    "am": ("አማርኛ", "am", "ltr", "am_ET"),
}
LANGUAGES = {**SITE_LANGUAGES, **EXTRA_LANGUAGES}

SOURCE = "website/guides/modes.html"
LOCAL = "guides/modes.html"
FILES = tuple(("" if lang == "en" else lang + "/") + LOCAL for lang in LANGUAGES)
KEY = re.compile(r"\{\{(modes\.[a-z0-9_.]+)\}\}")
DOCS = {"collection": "COLLECTION.md", "investigation": "INVESTIGATION.md", "evidence": "EVIDENCE.md",
        "witness": "WITNESS.md", "how-it-works": "HOW-IT-WORKS.md", "accounts": "ACCOUNTS.md"}


def catalogue(read_public, lang, required=None):
    words = json.loads(read_public(f"website/i18n/{lang}.json"))["modes"]
    if required is not None and set(words) != set(required):
        raise ValueError(f"Incomplete modes catalogue: {lang}")
    if any(not isinstance(text, str) or not text.strip() for text in words.values()):
        raise ValueError(f"Empty modes translation: {lang}")
    return words


def render_page(template, words, *, lang, base_url, values, dictionary, render, seo, theme_script):
    """Resolve text separately from layout; translated values are always escaped."""
    base = "" if lang == "en" else lang + "/"
    path = base + LOCAL
    parent = posixpath.dirname(path)

    def relative(target):
        return posixpath.relpath(target, parent)

    def text(key):
        return html.escape(words["modes." + key], quote=True)

    def replace(match):
        if match[1] not in words:
            raise ValueError("Unknown modes key: " + match[1])
        return html.escape(words[match[1]], quote=True)

    translated = KEY.sub(replace, template)
    language_links = "".join(
        f'<a href="{relative(("" if code == "en" else code + "/") + LOCAL)}" '
        f'lang="{info[1]}" hreflang="{info[1]}"' + (' aria-current="page"' if code == lang else '')
        + f'>{html.escape(info[0])}</a>' for code, info in LANGUAGES.items())
    languages = ('<details class="lang-menu"><summary aria-label="' + text("language") + '">'
                 + html.escape(LANGUAGES[lang][0]) + '</summary><div class="lang-list">' + language_links + '</div></details>')
    theme = ('<button type="button" class="theme-toggle" data-theme-toggle hidden aria-label="' + text("theme") + '">'
             '<svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><circle cx="12" cy="12" r="8" '
             'fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M12 4a8 8 0 0 1 0 16Z" fill="currentColor"/></svg></button>')
    head = seo(base_url, path, words["modes.eyebrow"] + " | TgWitness", words["modes.seo"], lang,
               [(code, ("" if code == "en" else code + "/") + LOCAL) for code in LANGUAGES], languages=LANGUAGES)
    head = re.sub(r'(<meta property="og:image:alt" content=")[^"]*', lambda m: m[1] + text("eyebrow"), head)
    rendered = render(translated, {
        **values, "LANG": LANGUAGES[lang][1], "DIR": LANGUAGES[lang][2], "HEAD": head,
        "ROOT": relative(".").rstrip("/") + "/", "HOME": relative(base if lang in SITE_LANGUAGES and base else ".") + "/",
        "SETUP": relative("demo/guide.html") + "?lang=" + lang,
        "DEDICATED": relative("demo/dedicated-account.html") + "?lang=" + lang,
        "PANEL": relative("demo/index.html") + "?lang=" + (lang if lang in SITE_LANGUAGES else "en"),
        "LANGUAGE_MENU": languages, "THEME_TOGGLE": theme, "THEME_SCRIPT": theme_script,
        "LANGUAGE_NOTE": ('<p class="m-note">' + text("linkedEnglish") + '</p>') if lang in EXTRA_LANGUAGES else "",
        "SITE_DICT": json.dumps({**dictionary, **words}, ensure_ascii=False).replace("<", "\\u003c").replace("&", "\\u0026"),
        **{"DOC_" + key.upper().replace("-", "_"): values["REPO_URL"] + "/blob/" + values["BRANCH"] + "/docs/" + filename
           for key, filename in DOCS.items()},
    })
    if "{{modes." in rendered:
        raise ValueError("Unresolved modes translation")
    return path, rendered
