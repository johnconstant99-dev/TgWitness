"""Reference pages: the repository's Markdown documents rendered for the public site.

Links between rendered documents stay on the site (anchors are checked against the rendered
headings); links to anything else in the repository point at GitHub. Mermaid blocks become
SVG diagrams (site_diagrams). No account data or application code is read.
"""
import html
import posixpath
import re
from urllib.parse import unquote

import markdown

if __package__:
    from . import site_diagrams
else:
    import site_diagrams

FENCE = re.compile(r"^( {0,8})(`{3,}|~{3,})([^\n`]*)\n(.*?)^\1\2[ \t]*$", re.S | re.M)
INLINE_CODE = re.compile(r"(`+)(.+?)\1", re.S)
HTML_TAGS = {"a", "abbr", "b", "blockquote", "br", "code", "details", "div", "em", "i", "img", "kbd", "li", "ol", "p", "pre",
             "span", "strong", "sub", "summary", "sup", "table", "tbody", "td", "th", "thead", "tr", "ul"}
SLOT = "WIKISLOT{}X"
NEWLINE = "\n"


def github_slug(value, separator="-"):
    """GitHub's heading anchors: lower case, punctuation dropped, spaces become hyphens."""
    value = html.unescape(re.sub(r"<[^>]+>", "", value)).strip().lower()
    return re.sub(r"[^\w\- ]", "", value).replace(" ", "-")


def escape_pseudo_tags(text):
    """<id>, <version> and similar placeholders in prose are text, not HTML (as on GitHub)."""
    def outside_code(part):
        return re.sub(r"<(/?)([A-Za-z][\w .:-]*)>",
                      lambda m: m.group(0) if m.group(2).split()[0].lower() in HTML_TAGS
                      else "&lt;" + m.group(1) + m.group(2) + "&gt;", part)
    pieces, last = [], 0
    for match in INLINE_CODE.finditer(text):
        pieces += [outside_code(text[last:match.start()]), match.group(0)]
        last = match.end()
    return "".join(pieces + [outside_code(text[last:])])


def indent_lists(text):
    """Python-Markdown nests list content at four spaces; the docs use GitHub's two or three."""
    out, unit = [], None
    for line in text.split(NEWLINE):
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        if indent == 0 and stripped:
            unit = 2 if re.match(r"[-*+] ", stripped) else 3 if re.match(r"\d+\. ", stripped) else None
            out.append(line)
        elif unit and stripped:
            out.append(" " * (4 * -(-indent // unit)) + stripped)
        else:
            out.append(line)
    return NEWLINE.join(out)


MATH_SYMBOLS = {r"\ge": "≥", r"\le": "≤", r"\cap": "∩", r"\cup": "∪", r"\sigma": "σ", r"\Delta": "Δ",
                r"\cdot": "·", r"\times": "×", r"\qquad": "\u2003\u2003", r"\quad": "\u2003"}


def math(expression):
    """The small LaTeX subset the docs use (operator names, sub- and superscripts, fractions,
    a few symbols) as HTML; the docs show it with GitHub's math on GitHub."""
    text = re.sub(r"\\(?:operatorname|mathrm|text)\{([^{}]*)\}", r"\1", " ".join(expression.split()))
    for name, symbol in sorted(MATH_SYMBOLS.items(), key=lambda item: -len(item[0])):
        text = text.replace(name, symbol)
    text = re.sub(r"\\frac\{([^{}]*)\}\{([^{}]*)\}", r"\1 / \2", text)
    text = html.escape(text, quote=False)
    text = re.sub(r"_\{([^{}]*)\}|_(\w)", lambda m: "<sub>" + (m.group(1) or m.group(2)) + "</sub>", text)
    text = re.sub(r"\^\{([^{}]*)\}|\^(\w)", lambda m: "<sup>" + (m.group(1) or m.group(2)) + "</sup>", text)
    return text


def prepare(text, number_start, labels=None):
    """Code blocks and diagrams out first (Python-Markdown cannot fence code inside list items)."""
    blocks = []

    def keep(match):
        indent, language, body = match.group(1), match.group(3).strip(), match.group(4)
        body = NEWLINE.join(line[len(indent):] if line.startswith(indent) else line for line in body.split(NEWLINE))
        if language == "mermaid":
            rendered = site_diagrams.render(body, number_start + sum(1 for b in blocks if "data-diagram" in b), labels)
        else:
            cls = f' class="language-{html.escape(language, quote=True)}"' if language else ""
            rendered = f"<pre><code{cls}>{html.escape(body.rstrip(NEWLINE))}</code></pre>"
        blocks.append(rendered)
        return indent + SLOT.format(len(blocks) - 1)
    text = FENCE.sub(keep, text)

    def formula(match):
        rendered = math(match.group(1))
        label = html.escape(re.sub(r"<[^>]+>", "", rendered), quote=True)
        blocks.append(f'<div class="formula wiki-formula" translate="no" role="math" aria-label="{label}">{rendered}</div>')
        return SLOT.format(len(blocks) - 1)
    text = re.sub(r"^\$\$\n(.*?)\n\$\$[ \t]*$", formula, text, flags=re.S | re.M)

    def inline(part):
        def piece(match):
            blocks.append(f'<span class="math" translate="no">{math(match.group(1))}</span>')
            return SLOT.format(len(blocks) - 1)
        return re.sub(r"(?<![\w$`])\$([^$\n`]+?)\$(?![\w$])", piece, part)
    pieces, last = [], 0
    for match in INLINE_CODE.finditer(text):
        pieces += [inline(text[last:match.start()]), match.group(0)]
        last = match.end()
    text = "".join(pieces + [inline(text[last:])])
    return escape_pseudo_tags(indent_lists(text)), blocks


def markup(text, number_start=1, labels=None):
    """Markdown body to HTML in which code blocks and diagrams are still WIKISLOT tokens.
    This is the form that is translated: the tokens and heading ids pass through unchanged."""
    text, blocks = prepare(text.replace("\r\n", NEWLINE), number_start, labels)
    body = markdown.markdown(text, extensions=["tables", "sane_lists", "toc"],
                             extension_configs={"toc": {"slugify": github_slug, "toc_depth": "2-4"}})
    return body, blocks


def finish(body, blocks, words=None):
    """Put code blocks and diagrams back and add the page furniture."""
    for index, block in enumerate(blocks):
        body = re.sub(r"<p>\s*" + SLOT.format(index) + r"\s*</p>", lambda m, b=block: b, body)
        body = body.replace(SLOT.format(index), block)
    body = re.sub(r"<table>", '<div class="table-wrap" tabindex="0"><table>', body).replace("</table>", "</table></div>")
    body = re.sub(r"<blockquote>", '<blockquote class="callout">', body)
    label = html.escape((words or {}).get("Link to this section", "Link to this section"), quote=True)

    return re.sub(r'<(h[234]) id="([^"]+)">(.*?)</\1>',
                  lambda m: f'<{m.group(1)} id="{m.group(2)}">{m.group(3)}<a class="anchor" href="#{m.group(2)}" '
                            f'aria-label="{label}">#</a></{m.group(1)}>', body, flags=re.S)


def to_html(text, number_start=1, labels=None, translate=None, words=None):
    """Markdown body (without its title) to HTML. translate(html) -> (html, blocks left in English).
    Returns the HTML, the number of diagrams and the number of untranslated blocks."""
    body, blocks = markup(text, number_start, labels)
    missing = 0
    if translate:
        body, missing = translate(body)
    return finish(body, blocks, words), sum(1 for b in blocks if "data-diagram" in b), missing


def diagram_sources(text):
    """The Mermaid sources of a Markdown document."""
    return [m.group(4) for m in FENCE.finditer(text.replace("\r\n", NEWLINE)) if m.group(3).strip() == "mermaid"]


def split_title(text):
    """The first H1 is the page title; anything before it (a list of translations) stays in the body."""
    text = text.replace("\r\n", NEWLINE)
    match = re.search(r"^#\s+(.+?)[ \t]*\n", text, re.M)
    if not match or "```" in text[:match.start()]:
        return None, text
    return match.group(1), text[:match.start()] + text[match.end():]


def ids(body):
    return set(re.findall(r'\sid="([^"]+)"', body))


def rewrite_links(body, source, page_path, pages, page_ids, relative, repo_url, branch, assets, root):
    """pages: repository path -> site path of rendered documents. assets: collects images to copy."""
    directory = posixpath.dirname(source)

    def target_of(value):
        if re.match(r"^[a-z][a-z0-9+.-]*:", value, re.I) or value.startswith(("#", "//")):
            return None
        path, _, anchor = value.partition("#")
        resolved = posixpath.normpath(posixpath.join(directory, unquote(path)))
        return resolved, anchor

    def link(match):
        attribute, value = match.group(1), html.unescape(match.group(2))
        found = target_of(value)
        if not found:
            return match.group(0)
        resolved, anchor = found
        if attribute == "src":
            name = "assets/" + posixpath.basename(resolved)
            assets[name] = resolved
            return f'src="{html.escape(relative(page_path, name), quote=True)}"'
        if resolved in pages:
            target = pages[resolved]
            fragment = "#" + anchor if anchor and anchor in page_ids.get(target, set()) else ""
            url = "./" if target == page_path else relative(page_path, target).rstrip("/") + "/"
            return f'href="{html.escape(url + fragment, quote=True)}"'
        if resolved in ("LICENSE", "NOTICE"):
            return f'href="{html.escape(relative(page_path, resolved), quote=True)}"'
        kind = "tree" if (root / resolved).is_dir() else "blob"
        url = f"{repo_url}/{kind}/{branch}/{resolved}" + ("#" + anchor if anchor else "")
        return f'href="{html.escape(url, quote=True)}"'
    return re.sub(r'\b(href|src)="([^"]*)"', link, body)


def plain(body):
    text = re.sub(r"<(script|style|svg)[^>]*>.*?</\1>", " ", body, flags=re.S)
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", text))).strip()
