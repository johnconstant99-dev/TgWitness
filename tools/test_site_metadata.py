from collections import Counter
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import build_site, site_i18n, site_llms, site_modes
from tools.site_content import GROUPS, GUIDES, NEXT, REFERENCE, REFERENCE_GROUPS

BASE = "https://example.test/TgWitness"
NEW_GUIDES = ("case-board", "reports", "handover", "groups")
NEW_REFERENCE = ("case-board", "case-reports")


def parse(source):
    return list(site_llms.nodes(site_i18n._Tree(source).root))


def link_map(nodes, rel):
    result = [n.attrs for n in nodes if n.tag == "link" and n.attrs.get("rel") == rel]
    if rel == "alternate":
        result = [attrs for attrs in result if "hreflang" in attrs]
        keys = [attrs["hreflang"] for attrs in result]
        assert len(keys) == len(set(keys)), "Duplicate language alternate"
        return {attrs["hreflang"]: attrs["href"] for attrs in result}
    assert len(result) == 1
    return result[0]["href"]


def graph(source, nodes):
    scripts = [n for n in nodes if n.tag == "script" and n.attrs.get("type") == "application/ld+json"]
    assert len(scripts) == 1
    node = scripts[0]
    return json.loads(source[node.open_end:node.close_start])["@graph"]


def test_complete_navigation_and_unique_metadata():
    assert Counter(slug for _, _, keys in GROUPS for slug in keys) == Counter(GUIDES.keys())
    assert Counter(slug for _, keys in REFERENCE_GROUPS for slug in keys) == Counter(REFERENCE.keys())
    assert set(NEXT) == set(GUIDES)
    assert set(NEXT.values()) <= set(GUIDES)
    assert all(NEXT[slug] != slug for slug in GUIDES)
    entries = [*GUIDES.values(), *REFERENCE.values()]
    assert len({entry[0] for entry in entries}) == len(entries), "Repeated page title"
    assert len({entry[1] for entry in entries}) == len(entries), "Repeated page description"
    assert all((ROOT / entry[3]).is_file() for entry in entries)
    assert set(NEW_GUIDES) <= set(GUIDES)
    assert set(NEW_REFERENCE) <= set(REFERENCE)


def test_collapsible_reference_renders_links_tables_and_code():
    from tools import site_wiki

    source = '''<details>
<summary>Recorded deployment</summary>

[Read the evidence](EVIDENCE.md)

| Check | Result |
| --- | --- |
| Signature | **PASS** |

```sh
verify --source "<archive>"
```

<details open>
<summary>Scope</summary>

- No Telegram account was connected.

</details>
</details>
'''
    result = site_wiki.to_html(source)[0]
    assert '<a href="EVIDENCE.md">Read the evidence</a>' in result
    assert '<table>' in result and '<strong>PASS</strong>' in result
    assert '<li>No Telegram account was connected.</li>' in result
    assert 'verify --source &quot;&lt;archive&gt;&quot;' in result
    assert result.count('<details') == 2
    assert 'markdown="1"' not in result
    assert 'WIKISLOT' not in result


def test_collapsible_markup_in_code_remains_literal():
    from tools import site_wiki

    source = '```html\n<details>\n<summary>Example</summary>\n</details>\n```'
    result = site_wiki.to_html(source)[0]
    assert '&lt;details&gt;' in result
    assert '<details' not in result
    assert 'markdown=' not in result


def test_reference_images_are_in_the_public_site_allowlist():
    from tools import site_wiki

    images = {}
    sources = {entry[3] for entry in REFERENCE.values()} | set(build_site.CAPTURE_DOCS.values())
    for source in sorted(sources):
        body = site_wiki.to_html((ROOT / source).read_text(encoding="utf-8"))[0]
        site_wiki.rewrite_links(body, source, "docs/reference/", {}, {},
                               build_site.relative, "https://github.com/phishdestroy/TgWitness",
                               "main", images, ROOT)
    assert images
    for target, source in images.items():
        assert build_site.WIKI_ASSETS.get(target) == source, source
        assert build_site.STATIC.get(target) == source, source
        assert (ROOT / source).is_file(), source


def test_metadata_tracks_localized_page_and_visible_hierarchy():
    local = "docs/reports/"
    path = "pt/" + local
    crumbs = [("Home", "pt/"), ("Documentation", "pt/docs/"), ("Design a report", path)]
    alternates = [("pt", path), ("en", local)]
    source = build_site.seo(BASE, path, "Design a report | TgWitness", "Preview a signed report.",
                            "pt", alternates, crumbs=crumbs)
    nodes = parse(source)
    assert link_map(nodes, "canonical") == BASE + "/" + path
    assert link_map(nodes, "alternate") == {
        "en": BASE + "/" + local, "pt-BR": BASE + "/" + path, "x-default": BASE + "/" + local}
    data = graph(source, nodes)
    webpage = next(item for item in data if item["@type"] == "WebPage")
    breadcrumb = next(item for item in data if item["@type"] == "BreadcrumbList")
    assert webpage["inLanguage"] == "pt-BR"
    assert webpage["breadcrumb"] == {"@id": breadcrumb["@id"]}
    assert [(item["position"], item["name"], item["item"]) for item in breadcrumb["itemListElement"]] == [
        (i + 1, name, BASE + "/" + target) for i, (name, target) in enumerate(crumbs)]
    assert not any(item["@type"] in {"Review", "AggregateRating"} for item in data)


def test_untranslated_reference_consolidates_without_false_alternates():
    local = "docs/reference/changelog/"
    source = build_site.seo(BASE, "de/" + local, "Translated navigation", "Translated navigation",
                            "de", [(lang, build_site.prefix(lang) + local) for lang in site_i18n.LANGUAGES])
    nodes = parse(source)
    assert link_map(nodes, "canonical") == BASE + "/" + local
    assert link_map(nodes, "alternate") == {"en": BASE + "/" + local, "x-default": BASE + "/" + local}
    assert graph(source, nodes)[0]["inLanguage"] == "en"


def test_markdown_preserves_content_and_limits_without_site_controls():
    source = '''<html><head><link rel="canonical" href="https://example.test/TgWitness/docs/reports/"></head>
      <body><nav>Repeated navigation</nav><main><nav>Breadcrumb</nav>
      <article class="guide-content"><p class="eyebrow">Guide 01</p><h1>Reports</h1>
      <p>Signatures verify the exported bytes. They do not establish Telegram authorship.</p>
      <section data-workflow="reports"><ol class="workflow-steps"><li data-workflow-step="0">Choose records.</li></ol>
      <div class="workflow-scene"><p>Message #42: meet at 11:00.</p></div>
      <div data-workflow-controls hidden><button>Play</button><span>Step 1 of 4</span></div>
      <fieldset data-workflow-choices="design" hidden><legend>Choose design</legend><button>Classic</button></fieldset></section>
      <p><a href="../handover/">Sharing copy</a> keeps explicit limits.</p>
      <pre><code>verify --public-key trusted.pem\n# do not edit evidence</code></pre>
      <table><tr><th>Field</th><th>Included</th></tr><tr><td>Name</td><td>No</td></tr></table>
      <p class="language-notice">Translation notice</p></article>
      <footer>Repeated verification footer</footer></main></body></html>'''
    result = site_llms.markdown(source, BASE + "/docs/reports/")
    assert result.startswith("# Reports\n\nCanonical page: " + BASE + "/docs/reports/")
    assert "They do not establish Telegram authorship." in result
    assert "1. Choose records." in result and "Message #42: meet at 11:00." in result
    assert "[Sharing copy](" + BASE + "/docs/handover/)" in result
    assert "verify --public-key trusted.pem\n# do not edit evidence" in result
    assert "| Name | No |" in result
    assert all(value not in result for value in ("Repeated", "Breadcrumb", "Guide 01", "Play", "Step 1 of 4", "Choose design", "Translation notice"))


def test_llms_index_leads_with_workflows_and_verification():
    content = site_llms.index(BASE, "https://github.com/example/TgWitness", "main", "0.0.0", GUIDES, REFERENCE)
    intro = content.split("## Start here", 1)[0]
    assert "Signed exports let recipients verify file integrity" in intro
    assert "eight designs" in intro and "Case Board" in intro
    assert all(f"/docs/{slug}/index.md" in content for slug in NEW_GUIDES)
    assert "GitHub Actions capture adds an attestation" in content
    assert "signing key and retained checkpoints" in content
    assert "content deleted before capture is unavailable" in content
    assert "llms-full.md" in content


def check_built_site(output):
    output = Path(output)
    ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9", "x": "http://www.w3.org/1999/xhtml"}
    sitemap = ET.parse(output / "sitemap.xml").getroot()
    home_source = (output / "index.html").read_text(encoding="utf-8")
    base = link_map(parse(home_source), "canonical").rstrip("/")
    expected_paths = {build_site.prefix(lang) + local for lang, local in build_site.PAGE_LOCALES
                      if build_site.canonical_path(build_site.prefix(lang) + local) == build_site.prefix(lang) + local}
    expected_paths.update(build_site.MODES_PAGES)
    entries = {entry.findtext("s:loc", namespaces=ns): entry for entry in sitemap.findall("s:url", ns)}
    assert len(entries) == len(sitemap), "Duplicate sitemap URL"
    assert set(entries) == {base + "/" + path for path in expected_paths}
    titles, descriptions = {}, {}
    for lang, local in build_site.PAGE_LOCALES:
        path = build_site.prefix(lang) + local
        source = (output / path / "index.html").read_text(encoding="utf-8")
        nodes = parse(source)
        canonical = base + "/" + build_site.canonical_path(path)
        assert link_map(nodes, "canonical") == canonical, path
        all_titles = [build_site.PlainText(source[n.open_end:n.close_start]).text for n in nodes if n.tag == "title" and not n.svg]
        all_descriptions = [n.attrs.get("content", "") for n in nodes if n.tag == "meta" and n.attrs.get("name") == "description"]
        assert len(all_titles) == len(all_descriptions) == 1 and all_titles[0] and all_descriptions[0], path
        assert sum(n.tag == "h1" for n in nodes) == 1, path
        if path == build_site.canonical_path(path):
            assert all_titles[0] not in titles.setdefault(lang, set()), (path, "duplicate title")
            assert all_descriptions[0] not in descriptions.setdefault(lang, set()), (path, "duplicate description")
            titles[lang].add(all_titles[0])
            descriptions[lang].add(all_descriptions[0])
        languages = build_site.page_languages(local)
        english_only = local in {build_site.WIKI_HUB + slug + "/" for slug in site_i18n.ENGLISH_ONLY}
        expected_alternates = {info[1]: base + "/" + build_site.prefix(code) + local
                               for code, info in languages.items() if not english_only or code == "en"}
        expected_alternates["x-default"] = base + "/" + local
        assert link_map(nodes, "alternate") == expected_alternates, path
        entry = entries[canonical]
        sitemap_links = entry.findall("x:link", ns)
        assert len(sitemap_links) == len(expected_alternates), path
        assert {n.attrib["hreflang"]: n.attrib["href"] for n in sitemap_links} == expected_alternates, path
        data = graph(source, nodes)
        webpage = next(item for item in data if item["@type"] == "WebPage")
        assert webpage["url"] == canonical
        assert webpage["inLanguage"] == ("en" if english_only else languages[lang][1]), path
        if local:
            crumbs = next(item for item in data if item["@type"] == "BreadcrumbList")
            items = crumbs["itemListElement"]
            assert webpage["breadcrumb"] == {"@id": crumbs["@id"]}
            assert [item["position"] for item in items] == list(range(1, len(items) + 1))
            assert items[-1]["item"] == base + "/" + path
            assert all(item["name"] and item["item"].startswith(base + "/") for item in items)
    for lang, info in site_modes.LANGUAGES.items():
        path = build_site.prefix(lang) + site_modes.LOCAL
        source = (output / path).read_text(encoding="utf-8")
        nodes = parse(source)
        canonical = base + "/" + path
        assert link_map(nodes, "canonical") == canonical, path
        expected_alternates = {values[1]: base + "/" + build_site.prefix(code) + site_modes.LOCAL
                               for code, values in site_modes.LANGUAGES.items()}
        expected_alternates["x-default"] = base + "/" + site_modes.LOCAL
        assert link_map(nodes, "alternate") == expected_alternates, path
        links = entries[canonical].findall("x:link", ns)
        assert len(links) == len(expected_alternates)
        assert {n.attrib["hreflang"]: n.attrib["href"] for n in links} == expected_alternates
        assert graph(source, nodes)[0]["inLanguage"] == info[1]
    for lang in build_site.NOTICE_LANGUAGES:
        prefix = build_site.prefix(lang)
        search = json.loads((output / prefix / "docs/search.json").read_text(encoding="utf-8"))
        pages = search["pages"]
        assert len({item["url"] for item in pages}) == len(pages), lang
        expected = {"reference/" + slug + "/" for slug in (REFERENCE if lang in build_site.LANGS else build_site.NOTICE_SLUGS)}
        expected.add("../" + site_modes.LOCAL)
        expected.add(build_site.relative(prefix + "docs/", build_site.site_export_clinic.PATH))
        validation_prefix = prefix if lang in build_site.site_validation.LANGUAGES else ""
        expected.add(build_site.relative(prefix + "docs/", validation_prefix + build_site.site_validation.PATH))
        if lang in build_site.LANGS:
            expected.update(slug + "/" for slug in GUIDES)
        assert {item["url"] for item in pages} == expected, lang
        assert all(item["title"] and item["description"] and item["text"] for item in pages)
    handbook = (output / "llms-full.md").read_text(encoding="utf-8")
    assert (output / "llms-full.txt").read_text(encoding="utf-8") == handbook
    urls = re.findall(r"^Canonical page: (.+)$", handbook, re.M)
    articles = {base + "/docs/" + slug + "/" for slug in GUIDES}
    articles.update(base + "/" + build_site.WIKI_HUB + slug + "/" for slug in REFERENCE)
    articles.add(base + "/" + site_modes.LOCAL)
    articles.add(base + "/" + build_site.site_export_clinic.PATH)
    articles.add(base + "/" + build_site.site_validation.PATH)
    assert Counter(urls) == Counter(articles), "Missing or repeated handbook article"
    for slug in NEW_GUIDES:
        page = (output / "docs" / slug / "index.html").read_text(encoding="utf-8")
        if "data-workflow=" in page:
            assert "workflows.js" in page and "workflows.css" in page
        assert (output / "docs" / slug / "index.md").is_file()
    for name in ("workflows.js", "workflows.css", "assets/case-board.png", "assets/dossier-en.png", "assets/dossier-pdf.png"):
        assert (output / name).read_bytes() == (ROOT / build_site.STATIC[name]).read_bytes()
    assert not urlsplit(base).query
    return {"pages_checked": len(build_site.PAGE_LOCALES) + len(site_modes.FILES), "sitemap_urls": len(entries),
            "search_languages": len(build_site.NOTICE_LANGUAGES), "handbook_articles": len(urls)}


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--site":
        print(json.dumps(check_built_site(sys.argv[2]), indent=2))
    else:
        test_complete_navigation_and_unique_metadata()
        test_metadata_tracks_localized_page_and_visible_hierarchy()
        test_untranslated_reference_consolidates_without_false_alternates()
        test_markdown_preserves_content_and_limits_without_site_controls()
        test_llms_index_leads_with_workflows_and_verification()
        print("5 metadata and Markdown checks passed.")
        print(json.dumps(check_built_site(ROOT / "dist/site"), indent=2))
