import html
import re
from urllib.parse import urljoin, urlsplit

if __package__:
    from .site_i18n import _Tree
else:
    from site_i18n import _Tree


def markdown_path(path):
    return path + "index.md" if path.endswith("/") or not path else path.removesuffix(".html") + ".md"


def nodes(node):
    yield node
    for child in node.children:
        yield from nodes(child)


def markdown(source, url):
    tree = _Tree(source)
    all_nodes = list(nodes(tree.root))
    code_blocks = []
    article = next((n for n in all_nodes if n.tag == "article" and "guide-content" in n.attrs.get("class", "")), None)
    if article is None:
        article = next((n for n in all_nodes if n.tag == "main"), tree.root)

    def raw(node):
        return html.unescape(re.sub(r"<[^>]*>", "", source[node.open_end:node.close_start]))

    def address(value):
        value = html.unescape(value or "")
        target = urljoin(url, value)
        if urlsplit(target).scheme not in {"http", "https", "mailto"}:
            return ""
        return target.replace(" ", "%20").replace("(", "%28").replace(")", "%29")

    def inside(node):
        parts, position = [], node.open_end
        for child in node.children:
            parts += [text(source[position:child.open_start]), emit(child)]
            position = child.close_end
        parts.append(text(source[position:node.close_start]))
        return "".join(parts)

    def text(value):
        value = html.unescape(re.sub(r"<!--.*?-->", "", value, flags=re.S))
        return re.sub(r"\s+", " ", value)

    def emit(node):
        tag, attrs = node.tag, node.attrs
        classes = set(attrs.get("class", "").split())
        if (tag in {"script", "style", "nav", "footer", "button", "input", "select", "textarea"}
                or attrs.get("aria-hidden") == "true"
                or "data-workflow-controls" in attrs or "data-workflow-choices" in attrs
                or "data-hub-controls" in attrs or "data-hub-status" in attrs
                or classes & {"eyebrow", "card-number", "search", "lab-controls", "copy-button", "language-notice", "anchor", "project-context"}):
            return ""
        if tag == "svg":
            labels = [raw(n).strip() for n in nodes(node) if n.tag in {"title", "desc", "text"}]
            return "\n\n" + " · ".join(filter(None, labels)) + "\n\n" if labels else ""
        if tag == "pre":
            code = raw(node).strip("\n")
            fence = "`" * max(3, 1 + max((len(m) for m in re.findall(r"`+", code)), default=0))
            code_blocks.append(f"{fence}\n{code}\n{fence}")
            return f"\n\nTGW_CODE_BLOCK_{len(code_blocks) - 1}\n\n"
        if tag in {"code", "kbd"}:
            code = raw(node).strip()
            fence = "`" * (1 + max((len(m) for m in re.findall(r"`+", code)), default=0))
            return f"{fence} {code} {fence}" if "`" in code else f"{fence}{code}{fence}"
        if tag == "img":
            label, target = attrs.get("alt", "").strip(), address(attrs.get("src"))
            return f"![{label}]({target})" if label and target else ""
        if tag in {"ul", "ol"}:
            rows = []
            for i, child in enumerate(c for c in node.children if c.tag == "li"):
                marker = f"{i + 1}. " if tag == "ol" else "- "
                value = inside(child).strip()
                rows.append(marker + value.replace("\n", "\n" + " " * len(marker)))
            return "\n\n" + "\n".join(rows) + "\n\n"
        if tag == "table":
            rows = []
            for row in (n for n in nodes(node) if n.tag == "tr"):
                cells = [re.sub(r"\s+", " ", inside(cell)).strip().replace("|", r"\|")
                         for cell in row.children if cell.tag in {"th", "td"}]
                if cells:
                    rows.append(cells)
            if not rows:
                return ""
            width = max(map(len, rows))
            rendered = ["| " + " | ".join(row + [""] * (width - len(row))) + " |" for row in rows]
            rendered.insert(1, "| " + " | ".join(["---"] * width) + " |")
            return "\n\n" + "\n".join(rendered) + "\n\n"
        value = inside(node)
        if tag == "a":
            target = address(attrs.get("href"))
            label = re.sub(r"\s+", " ", value).strip()
            return f"[{label}]({target})" if target and label else value
        if tag in {"strong", "b", "summary"}:
            return "**" + value.strip() + "**"
        if tag in {"em", "i"}:
            return "*" + value.strip() + "*"
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            return "\n\n" + "#" * int(tag[1]) + " " + value.strip() + "\n\n"
        if tag == "blockquote":
            return "\n\n" + "\n".join("> " + line for line in value.strip().splitlines()) + "\n\n"
        if tag in {"br", "hr"}:
            return "\n"
        if tag in {"p", "div", "section", "article", "main", "figure", "figcaption", "details", "dl", "dt", "dd", "aside"}:
            return "\n\n" + value.strip() + "\n\n"
        return value

    content = emit(article).strip()
    content = "\n".join(line.rstrip(" \t") for line in content.split("\n"))
    content = re.sub(r"\n{3,}", "\n\n", content)
    content = re.sub(r"(?m)^([ \t]*)TGW_CODE_BLOCK_(\d+)[ \t]*$",
                     lambda m: "\n".join(m[1] + line if line else "" for line in code_blocks[int(m[2])].split("\n")), content)
    title = next((raw(n).strip() for n in all_nodes if n.tag == "h1"), "TgWitness")
    if not re.search(r"^# ", content, re.M):
        content = "# " + title + "\n\n" + content
    elif not content.startswith("# "):
        leading, content = re.split(r"(?=^# )", content, maxsplit=1, flags=re.M)
        first, _, rest = content.partition("\n")
        content = first + "\n\n" + leading.strip() + "\n\n" + rest.strip()
    heading, _, body = content.partition("\n")
    canonical = next((n.attrs["href"] for n in all_nodes if n.tag == "link" and n.attrs.get("rel") == "canonical"), url)
    context = [f"Canonical page: {canonical}"]
    description = next((n.attrs.get("content") for n in all_nodes
                        if n.tag == "meta" and n.attrs.get("name") == "description"), None)
    if description:
        context.append(description)
    for rel, label in (("help", "Project context and measured scale"), ("describedby", "Documentation index")):
        target = next((n.attrs.get("href") for n in all_nodes if n.tag == "link" and n.attrs.get("rel") == rel), None)
        if target:
            context.append(f"[{label}]({address(target)})")
    if any("language-notice" in n.attrs.get("class", "").split() for n in all_nodes):
        context.append("Translation coverage: this edition includes material from the English original.")
    return heading + "\n\n" + "\n\n".join(context) + "\n\n" + body.strip() + "\n"


def index(base_url, repo_url, branch, version, guides, references):
    def link(path, title, description):
        return f"- [{title}]({base_url}/{markdown_path(path)}): {description}"

    sections = [
        "# TgWitness",
        "> Open-source Telegram investigation software. Export chat history, preserve observed edits and deletion notices, "
        "follow people across chats, and hand over a signed archive that a recipient can verify.",
        "TgWitness runs on your own computer or server. PhishDestroy maintains the project under the MIT License. "
        "The website is documentation; the browser demo contains synthetic records and does not connect to Telegram.",
        "Start with one command: the installer includes Python and dependencies. Connect a Telegram account, select "
        "a chat or account scope and export. GitHub Actions capture offers temporary hosted collection with an "
        "encrypted archive and workflow provenance; it requires a fork, authorization and an archive password. "
        "Ongoing observation and investigation settings are available for tasks that need them. Basic collection "
        "does not require Docker, a GPU, an LLM or a separately deployed witness.",
        "The project's purpose is to preserve observed material and context regardless of whose position they support. "
        "Source observations, known gaps and analytical conclusions remain distinguishable. A signature checks "
        "integrity under a key; it does not make a message's claims true. Scope, access and disclosure settings "
        "support different requirements; a selected profile does not itself establish legal compliance.",
        "Signed exports let recipients verify file integrity and the signing key offline. A hash-linked journal preserves "
        "the sequence of saved observations; independently retained checkpoints provide an earlier comparison point. "
        "Reports combine readable history, source references and verification results in the same package.",
        "The panel brings together isolated account workspaces, supported session imports, parallel chat export, "
        "cross-chat people profiles, observed name changes, bot-button interaction receipts, saved attachments and "
        "offline HTML/JSON evidence. Case Board keeps team annotations linked to saved records. The report studio "
        "offers eight designs, content choices and a data preview; minimized sharing copies control what recipients receive. "
        "Optional witnesses, timestamps and encrypted off-site copies add records outside the local journal. "
        "Archive search, AI analysis, OCR, transcription, MCP and signed webhooks work "
        "with the records you have collected.",
        f"These guides track the `{branch}` source branch. The project version is `{version}`; check the changelog and "
        "release notes before assuming a source feature is included in a downloaded package.",
        "Maturity is described per workflow and tested revision. The preview release label coexists with implemented "
        "collection, signed exports and measured workloads. Published results include a 1 November 2026 inventory "
        "of 1,610,818 journal events (900,232 new-message events), a 5 November search benchmark on 1,000,000 "
        "synthetic messages, and two real exports totalling 56,329 messages on 6 November. These measure inventory, "
        "search and export respectively, each with its own method and revision. "
        "The overview links the methods and results.",
        "Choose an entry below for the exact workflow, commands and limits. Each guide has a Markdown edition; "
        "its canonical HTML page retains diagrams, animations and interactive examples. Translated pages also expose "
        "Markdown through `rel=alternate` links.",
        "## Start here",
        link("docs/reference/overview/", *references["overview"][:2]),
        link("docs/reference/installation/", *references["installation"][:2]),
        link("docs/start/", *guides["start"][:2]),
        link("docs/capture/", *guides["capture"][:2]),
        link("docs/dedicated-account/", *guides["dedicated-account"][:2]),
        link("docs/accounts/", *guides["accounts"][:2]),
        link("guides/modes.html", "Collection modes and evidence levels", "Compare one-off export, observation, investigation and independent verification."),
        f"- [Read-only browser demo]({base_url}/demo/): Explore the panel with fictional accounts and messages.",
        "## Investigate and preserve",
        link("docs/cases/", *guides["cases"][:2]),
        link("docs/case-board/", *guides["case-board"][:2]),
        link("docs/groups/", *guides["groups"][:2]),
        link("docs/reference/collection/", *references["collection"][:2]),
        link("docs/reference/history/", *references["history"][:2]),
        link("docs/exports/", *guides["exports"][:2]),
        link("docs/reports/", *guides["reports"][:2]),
        link("docs/handover/", *guides["handover"][:2]),
        link("docs/reference/case-board/", *references["case-board"][:2]),
        link("docs/reference/case-reports/", *references["case-reports"][:2]),
        link("docs/reference/evidence/", *references["evidence"][:2]),
        "## Search the archive and connect AI tools",
        link("docs/archive/", *guides["archive"][:2]),
        link("docs/reference/analysis/", *references["analysis"][:2]),
        link("docs/reference/search/", *references["search"][:2]),
        link("docs/reference/mcp/", *references["mcp"][:2]),
        link("docs/reference/cli/", *references["cli"][:2]),
        link("docs/reference/media-analysis/", *references["media-analysis"][:2]),
        link("docs/reference/webhooks/", *references["webhooks"][:2]),
        "## Deploy, share and verify",
        link("docs/server/", *guides["server"][:2]),
        link("docs/capture/", *guides["capture"][:2]),
        link("docs/proxies/", *guides["proxies"][:2]),
        link("docs/access/", *guides["access"][:2]),
        link("docs/concepts/", *guides["concepts"][:2]),
        link("docs/witness/", *guides["witness"][:2]),
        link("docs/reference/timestamp/", *references["timestamp"][:2]),
        link("docs/reference/security/", *references["security"][:2]),
        "## Verification and scope",
        "The journal records what the authorized account observed, subject to its access and Telegram rate limits. "
        "Saved content remains after a later deletion; content deleted before capture is unavailable. Deletion notices "
        "and unsuccessful rechecks remain distinct observations. Integrity verification establishes the relationship "
        "between supplied files, the signing key and retained checkpoints. The archive includes source identifiers, "
        "captured versions and coverage information for review. GitHub Actions capture adds an attestation binding "
        "the archive to an approved hosted workflow and collector version.",
        "The connection reference explains IP modes, fallback and external-request routing. MCP provides read-only "
        "access to selected saved records through a separate scoped token; Telegram actions and configuration changes "
        "are outside that interface. Archived messages remain untrusted source material for an AI client.",
        link("docs/reference/features/", *references["features"][:2]),
        link("docs/reference/verification/", *references["verification"][:2]),
        link("docs/reference/changelog/", *references["changelog"][:2]),
        "## Optional",
        f"- [Complete English handbook as text]({base_url}/llms-full.txt): The same guide and reference content in a single text download.",
        f"- [Complete English handbook]({base_url}/llms-full.md): Public guide and reference articles in one Markdown file, including source URLs.",
        f"- [Documentation hub]({base_url}/docs/): Browse the illustrated handbook and its language editions.",
        f"- [Source code]({repo_url}): Implementation, documentation and issue templates.",
        f"- [Releases]({repo_url}/releases): Packages and their release notes.",
        f"- [MIT License]({base_url}/LICENSE): Software license.",
        link("docs/reference/notice/", *references["notice"][:2]),
    ]
    return "\n\n".join(sections) + "\n"


def full(index_text, documents):
    return (index_text + "\n---\n\n" + "\n\n---\n\n".join(documents)).rstrip("\n") + "\n"


def directory(base_url, guides, references, base=""):
    sections = ["\n## Complete documentation map\n"]
    for heading, folder, entries in (("Guides", "docs/", guides), ("Reference", "docs/reference/", references)):
        sections.append("### " + heading + "\n")
        sections.extend(f"- [{title}]({base_url}/{base}{folder}{slug}/index.md): {description}"
                        for slug, (title, description, *_) in entries.items())
        sections.append("")
    return "\n".join(sections)


def localized_index(base_url, base, language, repo_url, branch, version, guides, references):
    context = ("ru/" if base == "ru/" else "") + "docs/reference/overview/index.md"
    sections = [
        "# TgWitness · " + language,
        f"> Documentation edition: {language}. Project version: `{version}`. Source branch: `{branch}`.",
        "This index links the Markdown editions of the public pages. The complete handbook is built from the same "
        "page content, including source URLs. Untranslated sections retain the English original; a language edition "
        "is not a claim that every section has been translated.",
        f"- [Project context, installation, measured scale and verification limits]({base_url}/{context})",
        f"- [English project summary]({base_url}/llms.txt)",
        f"- [Complete handbook · {language}]({base_url}/{base}llms-full.txt)",
        f"- [Complete handbook as Markdown · {language}]({base_url}/{base}llms-full.md)",
        f"- [Source code and release history]({repo_url})",
        f"- [Collection modes and evidence levels]({base_url}/{base}guides/modes.md)",
        f"- [Published checks and measurements]({base_url}/{'ru/' if base == 'ru/' else ''}docs/validation/index.md)",
        directory(base_url, guides, references, base),
    ]
    return "\n\n".join(sections).rstrip() + "\n"
