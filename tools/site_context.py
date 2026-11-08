import html
import posixpath

if __package__:
    from . import site_i18n, site_validation
    from .site_content import GUIDES, LABELS
else:
    import site_i18n
    import site_validation
    from site_content import GUIDES, LABELS


SUMMARY = ("Start with one command and a Telegram account. Add investigation tools when you need them; "
           "preserve the source record, its context and known gaps.")
OVERVIEW = "Start, scale and evidence"
MEASUREMENTS = "Published checks and measurements"


def render(path, lang, data, version):
    parent = posixpath.dirname(path)
    base = "" if lang == "en" else lang + "/"
    full_base = base if lang in site_i18n.LANGUAGES else ""
    evidence_base = "ru/" if lang == "ru" else ""

    def text(value):
        return html.escape(site_i18n.text(data, value))

    def link(target, label, language=None):
        address = posixpath.relpath(target, parent or ".")
        if target.endswith("/"):
            address = address.rstrip("/") + "/"
        mark = f' hreflang="{language}"' if language else ""
        return f'<a href="{html.escape(address, quote=True)}"{mark}>{label}</a>'

    routes = [
        link(full_base + "docs/start/", text(GUIDES["start"][0])),
        link(full_base + "docs/capture/", text(GUIDES["capture"][0])),
        link(evidence_base + "docs/reference/overview/", text(OVERVIEW), "ru" if lang == "ru" else "en"),
        link(full_base + "docs/exports/", text(GUIDES["exports"][0])),
        link(evidence_base + site_validation.PATH, text(MEASUREMENTS), "ru" if lang == "ru" else "en"),
    ]
    formats = [
        link(path.removesuffix(".html") + ".md", "Markdown"),
        link(base + "llms.txt", "llms.txt"),
        link(base + "llms-full.txt", "llms-full.txt"),
    ]
    return ('<aside class="project-context" aria-label="TgWitness">'
            f'<p class="project-context-heading"><strong>TgWitness</strong><span>v{html.escape(version)}</span></p>'
            f'<p>{text(SUMMARY)}</p><nav aria-label="{text(LABELS["nav"])}">' + "".join(routes) + '</nav>'
            '<nav class="project-context-formats" aria-label="Markdown / LLM">' + "".join(formats) + '</nav></aside>')
