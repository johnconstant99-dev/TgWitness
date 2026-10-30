"""Languages of the public site and how translated text is stored and applied.

English is the source. website/i18n/<lang>.json holds, per language:
  "strings": English string -> translation (labels, titles, script texts, attribute values)
  "blocks":  SHA-256 of an English text unit -> translated unit
A text unit is the inner HTML of one paragraph, list item, heading, cell, caption, button, link
and the like: text with at most inline markup. Structure around it (sections, lists, labs, code,
SVG) is never sent for translation, so it cannot be changed by it. When an English unit changes
its hash changes, and the page shows that unit in English until it is translated again
(test-results/site_translate.py) and says so; nothing stale is shown as current.
"""
import hashlib
import html
import json
import re
from html.parser import HTMLParser
from pathlib import Path

# code: (native name, html lang, direction, Open Graph locale)
LANGUAGES = {
    "en": ("English", "en", "ltr", "en_US"),
    "ru": ("Русский", "ru", "ltr", "ru_RU"),
    "uk": ("Українська", "uk", "ltr", "uk_UA"),
    "es": ("Español", "es", "ltr", "es_ES"),
    "pt": ("Português (Brasil)", "pt-BR", "ltr", "pt_BR"),
    "tr": ("Türkçe", "tr", "ltr", "tr_TR"),
    "ar": ("العربية", "ar", "rtl", "ar_AR"),
    "fa": ("فارسی", "fa", "rtl", "fa_IR"),
    "ur": ("اردو", "ur", "rtl", "ur_PK"),
    "hi": ("हिन्दी", "hi", "ltr", "hi_IN"),
    "id": ("Bahasa Indonesia", "id", "ltr", "id_ID"),
    "vi": ("Tiếng Việt", "vi", "ltr", "vi_VN"),
    "zh": ("简体中文", "zh-Hans", "ltr", "zh_CN"),
}
# Release notes retain their original English. Project notices use the selected language;
# the canonical MIT LICENSE and NOTICE files remain available through their original links.
ENGLISH_ONLY = {"changelog"}
ATTRIBUTES = ("aria-label", "title", "alt", "placeholder")
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
# Inline markup a sentence may carry. <small> is left out: the pages set it as its own line.
INLINE = {"a", "abbr", "b", "br", "cite", "code", "em", "i", "img", "kbd", "mark", "q", "s", "span",
          "strong", "sub", "sup", "time", "u", "wbr"}
# Containers whose children are translated one by one even when they are all inline (a menu of links).
SPLIT = {"nav", "ul", "ol", "table", "thead", "tbody", "tr", "header", "footer", "main", "section", "article",
         "figure", "aside", "dl", "details", "form", "select"}
NEVER = {"pre", "script", "style", "code", "kbd", "textarea"}
LETTERS = re.compile(r"[^\W\d_]", re.U)


def digest(unit):
    return hashlib.sha256(unit.strip().encode("utf-8")).hexdigest()


class _Node:
    __slots__ = ("tag", "attrs", "open_start", "open_end", "close_start", "close_end", "children", "svg")

    def __init__(self, tag, attrs, open_start, open_end, svg):
        self.tag, self.attrs, self.open_start, self.open_end, self.svg = tag, dict(attrs), open_start, open_end, svg
        self.close_start = self.close_end = open_end
        self.children = []


class _Tree(HTMLParser):
    """Elements of an HTML fragment with the offsets of their tags."""
    def __init__(self, source):
        super().__init__(convert_charrefs=False)
        self.source = source
        self.lines = [0] + [i + 1 for i, c in enumerate(source) if c == "\n"]
        self.root = _Node("#root", (), 0, 0, False)
        self.root.close_start = self.root.close_end = len(source)
        self.stack = [self.root]
        self.feed(source)
        self.close()

    def here(self):
        line, column = self.getpos()
        return self.lines[line - 1] + column

    def handle_starttag(self, tag, attrs):
        start = self.here()
        parent = self.stack[-1]
        node = _Node(tag, attrs, start, start + len(self.get_starttag_text()), parent.svg or tag == "svg")
        parent.children.append(node)
        if tag not in VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        start = self.here()
        parent = self.stack[-1]
        parent.children.append(_Node(tag, attrs, start, start + len(self.get_starttag_text()), parent.svg))

    def handle_endtag(self, tag):
        if tag in VOID or not any(node.tag == tag for node in self.stack[1:]):
            return
        start = self.here()
        end = self.source.index(">", start) + 1
        while self.stack[-1].tag != tag:
            node = self.stack.pop()
            node.close_start = node.close_end = start
        node = self.stack.pop()
        node.close_start, node.close_end = start, end


def _has_text(source):
    text = re.sub(r"<(pre|code|kbd|script|style|svg)\b.*?</\1>", " ", source, flags=re.S)
    text = re.sub(r"<[^>]+>|@@[A-Z_]+@@|WIKISLOT\d+X|&\w+;|&#\w+;", " ", text)
    return bool(LETTERS.search(text))


def units(fragment):
    """(start, end) of every translatable text unit, in document order, without overlaps."""
    found = []

    def inline_only(node):
        # A part marked translate="no" (a number, an address) is kept apart from the words around it.
        return all(child.tag in INLINE and child.attrs.get("translate") != "no" and inline_only(child)
                   for child in node.children)

    def gaps(node):
        position = node.open_end
        for child in node.children:
            yield position, child.open_start
            position = child.close_end
        yield position, node.close_start

    def walk(node):
        if node.tag in NEVER or node.attrs.get("translate") == "no":
            return
        if node.svg:
            if node.tag == "text" and not node.children and _has_text(fragment[node.open_end:node.close_start]):
                found.append((node.open_end, node.close_start))
            for child in node.children:
                walk(child)
            return
        inner = fragment[node.open_end:node.close_start]
        if node.tag != "#root" and node.tag not in SPLIT and inline_only(node) and _has_text(inner):
            own = any(_has_text(fragment[start:end]) for start, end in gaps(node))
            texts = sum(1 for child in node.children if _has_text(fragment[child.open_start:child.close_end]))
            if own or texts <= 1:  # a sentence, not a row of separate links or labels
                found.append((node.open_end, node.close_start))
                return
        for start, end in gaps(node):
            piece = fragment[start:end]
            if _has_text(piece):
                lead = len(piece) - len(piece.lstrip())
                trail = len(piece) - len(piece.rstrip())
                found.append((start + lead, end - trail))
        for child in node.children:
            walk(child)
    walk(_Tree(fragment).root)
    return sorted(found)


def unit_texts(fragment):
    return [fragment[start:end] for start, end in units(fragment)]


def attribute_values(fragment):
    found = []
    for name in ATTRIBUTES:
        for value in re.findall(r'\b' + name + r'="([^"@]*[^\W\d_][^"@]*)"', fragment):
            found.append(html.unescape(value))
    return found


def localize(fragment, data):
    """The fragment in another language; returns the HTML and how many units are still English."""
    if data is None:
        return fragment, 0
    blocks, strings, missing, out, position = data["blocks"], data["strings"], 0, [], 0
    for start, end in units(fragment):
        unit = fragment[start:end]
        translated = blocks.get(digest(unit))
        if translated is None:
            missing += 1
            translated = unit
        out += [fragment[position:start], translated]
        position = end
    out.append(fragment[position:])
    result = "".join(out)

    def attribute(match):
        value = html.unescape(match.group(2))
        return f'{match.group(1)}="{html.escape(strings.get(value, value), quote=True)}"'
    result = re.sub(r'\b(' + "|".join(ATTRIBUTES) + r')="([^"]*)"', attribute, result)
    return result, missing


def script_strings(source):
    """Keys passed to T('...') in a site script."""
    return [match.group(1).replace("\\'", "'") for match in re.finditer(r"\bT\('((?:[^'\\]|\\.)*)'", source)]


def load(root, lang):
    if lang == "en":
        return None
    path = Path(root) / "website" / "i18n" / (lang + ".json")
    if not path.is_file():
        return {"strings": {}, "blocks": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {"strings": data.get("strings", {}), "blocks": data.get("blocks", {})}


def text(data, value):
    return value if data is None else data["strings"].get(value, value)
