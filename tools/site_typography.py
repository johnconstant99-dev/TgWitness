"""Fullwidth punctuation for homepage prose, after translation and rendering."""
import html
from html.parser import HTMLParser
import re


ASCII = "?!:;,./\\()[]{}\"'@#$%&*+-=~_|"
PUNCTUATION = str.maketrans({c: chr(ord(c) + 0xFEE0) for c in ASCII} | {
    "—": "，", "–": "－", "“": "＂", "”": "＂", "‘": "＇", "’": "＇",
})
# Keep copyable addresses, versions, machine identifiers and JS interpolation keys.
LITERAL = re.compile(
    r"https?://[^\s<>\"']*[^\s<>\"'.,;!?)]"
    r"|\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d+)?\b"
    r"|\bv?\d+(?:\.\d+)+(?::\d+)?\+?"
    r"|\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b"
    r"|\{\w+\}"
)
VERBATIM = {"pre", "code", "kbd", "samp", "script", "style", "textarea"}
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
ATTRIBUTES = {"alt", "title", "aria-label", "placeholder"}
META_TEXT = {"description", "og:title", "og:description", "og:image:alt", "twitter:title", "twitter:description", "twitter:image:alt"}
ATTRIBUTE = re.compile(r"(?P<name>[^\s=<>/]+)\s*=\s*(?P<quote>[\"'])(?P<value>.*?)(?P=quote)", re.S)


def prose(text):
    parts, position = [], 0
    for match in LITERAL.finditer(text):
        parts.extend((text[position:match.start()].translate(PUNCTUATION), match[0]))
        position = match.end()
    parts.append(text[position:].translate(PUNCTUATION))
    return "".join(parts)


class _Homepage(HTMLParser):
    """Edit text spans only; retain markup, executable text and URL attributes."""

    def __init__(self, source):
        super().__init__(convert_charrefs=False)
        self.source = source
        self.lines = [0] + [i + 1 for i, char in enumerate(source) if char == "\n"]
        self.stack = []
        self.edits = []
        self.text_spans = []
        self.feed(source)
        self.close()
        for start, end in self.text_spans:
            value = html.escape(prose(html.unescape(source[start:end])), quote=False)
            self.edits.append((start, end, value))

    def position(self):
        line, column = self.getpos()
        return self.lines[line - 1] + column

    def literal(self):
        return bool(self.stack and self.stack[-1][1])

    def start(self, tag, attrs, closed=False):
        attrs = dict(attrs)
        literal = self.literal() or tag in VERBATIM or attrs.get("data-typography") == "literal"
        if not literal:
            names = ATTRIBUTES
            if tag == "meta" and (attrs.get("name") or attrs.get("property")) in META_TEXT:
                names = names | {"content"}
            for match in ATTRIBUTE.finditer(self.get_starttag_text()):
                if match["name"].lower() in names:
                    start, end = match.span("value")
                    value = html.escape(prose(html.unescape(match["value"])), quote=True)
                    self.edits.append((self.position() + start, self.position() + end, value))
        if not closed and tag not in VOID:
            self.stack.append((tag, literal))

    def handle_starttag(self, tag, attrs):
        self.start(tag, attrs)

    def handle_startendtag(self, tag, attrs):
        self.start(tag, attrs, closed=True)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def text(self, length):
        if not self.literal():
            start, end = self.position(), self.position() + length
            if self.text_spans and self.text_spans[-1][1] == start:
                self.text_spans[-1] = (self.text_spans[-1][0], end)
            else:
                self.text_spans.append((start, end))

    def handle_data(self, data):
        self.text(len(data))

    def entity(self, raw):
        end = self.position() + len(raw)
        self.text(len(raw) + (self.source[end:end + 1] == ";"))

    def handle_entityref(self, name):
        self.entity("&" + name)

    def handle_charref(self, name):
        self.entity("&#" + name)


def homepage(source):
    out, position = [], 0
    for start, end, value in sorted(_Homepage(source).edits):
        out.extend((source[position:start], value))
        position = end
    out.append(source[position:])
    return "".join(out)
