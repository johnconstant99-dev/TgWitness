"""Publication boundary checks: the Pages artifact must never include live data."""
import shutil
import json
import re
from collections import Counter
from html import unescape
from html.parser import HTMLParser
from urllib.parse import unquote, urljoin, urlsplit
import xml.etree.ElementTree as ET

import pytest

from tools.build_site import (DEMO_GUIDE_LOCALES, DEMO_LOCALES, DEMO_PAGES, DEMO_STATIC, INPUTS, LANGS, LOCAL_PAGES, MODES_PAGES,
                              NOTICE_LANGUAGES, NOTICE_PAGES, PAGES, ROOT, SEARCH_FILES,
                              STATIC, TRANSLATIONS, build_site, page_languages)
from tools import site_modes
from tools import site_i18n
from tools.build_site import inventory


def test_translated_site_blocks_preserve_commands_and_link_targets():
    _, fragments, _ = inventory(ROOT)
    blocks = {site_i18n.digest(text): text for fragment in fragments.values()
              for text in site_i18n.unit_texts(fragment)}
    protected = lambda text: Counter(unescape(value) for value in re.findall(
        r'<(?:code|kbd|pre)[^>]*>(.*?)</(?:code|kbd|pre)>', text, re.S))
    links = lambda text: Counter(re.findall(r'(?:href|src)="([^"]*)"', text))
    for lang in LANGS:
        if lang == 'en':
            continue
        catalogue = json.loads((ROOT / 'website/i18n' / (lang + '.json')).read_text(encoding='utf-8'))
        for key, source in blocks.items():
            value = catalogue['blocks'][key]
            assert protected(value) == protected(source), (lang, key, 'command changed')
            assert links(value) == links(source), (lang, key, 'link changed or duplicated')


@pytest.fixture
def site_root(tmp_path):
    for name in ("pyproject.toml", *INPUTS, *TRANSLATIONS):
        if name in TRANSLATIONS and not (ROOT / name).exists():
            continue  # a language not translated yet falls back to English
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    return tmp_path


def test_pages_uses_only_presentation_files_and_project_relative_assets(site_root):
    for name in ("data/live/panel-token.txt", "website/credentials.enc", "docs/assets/account.session"):
        path = site_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic-private-data", encoding="utf-8")
    output = build_site(site_root, repository="example/Journal")
    assert {p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()} == {
        *(page + "index.html" for page in PAGES), *SEARCH_FILES, *STATIC, ".nojekyll", "sitemap.xml", "robots.txt",
        *DEMO_STATIC, *DEMO_PAGES, *DEMO_LOCALES, *DEMO_GUIDE_LOCALES, *MODES_PAGES,
    }
    content = (output / "index.html").read_text(encoding="utf-8")
    assert "https://example.github.io/Journal/" in content
    assert 'src="assets/workspace.png"' in content
    assert 'src="../assets/workspace.png"' in (output / "ru/index.html").read_text(encoding="utf-8")
    assert "https://github.com/example/Journal.git" in content
    assert "@@" not in content
    assert all(b"synthetic-private-data" not in p.read_bytes() for p in output.rglob("*") if p.is_file())


def test_existing_unexpected_output_blocks_publication(site_root):
    output = build_site(site_root)
    (output / "account.session").write_text("synthetic", encoding="utf-8")
    with pytest.raises(ValueError, match="Unexpected file"):
        build_site(site_root)


def test_setup_and_account_guides_publish_all_26_language_catalogs(site_root):
    output = build_site(site_root)
    assert set(DEMO_GUIDE_LOCALES.values()) == set(site_modes.LANGUAGES)
    for name, lang in DEMO_GUIDE_LOCALES.items():
        body = (output / name).read_text(encoding="utf-8")
        assert body.startswith('window.TGW_SCOPE="guide";window.TGW_LANG=' + json.dumps(lang) + ';')
        words = json.loads(body.split("window.TGW_DICT=", 1)[1].strip().removesuffix(";"))
        if lang != "en":
            assert words["From account connection to a verifiable journal"] != "From account connection to a verifiable journal"
    for name in ("guide.html", "dedicated-account.html"):
        body = (output / "demo" / name).read_text(encoding="utf-8")
        assert 'guide-locales/' in body and 'guide-locale.js' not in body
    for lang in site_modes.EXTRA_LANGUAGES:
        body = (output / lang / "guides/modes.html").read_text(encoding="utf-8")
        assert 'demo/guide.html?lang=' + lang in body


def test_missing_guide_translation_blocks_publication(site_root):
    path = site_root / "tgwitness/locales/de.json"
    words = json.loads(path.read_text(encoding="utf-8"))
    words.pop("From account connection to a verifiable journal")
    path.write_text(json.dumps(words), encoding="utf-8")
    with pytest.raises(ValueError, match="Incomplete setup-guide translation: de"):
        build_site(site_root)


def test_site_rejects_linked_source(site_root, tmp_path):
    asset = site_root / "docs/assets/workspace.png"
    secret = tmp_path / "private.txt"
    secret.write_text("synthetic", encoding="utf-8")
    asset.unlink()
    try:
        asset.symlink_to(secret)
    except OSError:
        pytest.skip("Filesystem cannot create symlinks")
    with pytest.raises(ValueError, match="ordinary repository file"):
        build_site(site_root)


@pytest.mark.parametrize("repository", ["../private", "owner/repo/extra", 'owner/repo\"', "owner/repo?x"])
def test_invalid_repository_cannot_generate_links(site_root, repository):
    with pytest.raises(ValueError, match="OWNER/REPOSITORY"):
        build_site(site_root, repository=repository)


def test_custom_domain_and_user_pages_have_correct_canonical(site_root):
    output = build_site(site_root, repository="example/example.github.io")
    assert '<loc>https://example.github.io/</loc>' in (output / "sitemap.xml").read_text()
    output = build_site(site_root, base_url="https://watch.example.org")
    assert 'href="https://watch.example.org/"' in (output / "index.html").read_text(encoding="utf-8")


@pytest.mark.parametrize("base_url", ["javascript:alert(1)", "https://user:pass@example.org", "https://example.org/?token=private"])
def test_invalid_site_url_is_rejected(site_root, base_url):
    with pytest.raises(ValueError, match="HTTPS site URL"):
        build_site(site_root, base_url=base_url)


class Page(HTMLParser):
    def __init__(self, path):
        super().__init__()
        self.tags = []
        self.scripts = []
        self.ids = []
        self.title = ""
        self.h1 = ""
        self.active = None
        self.script = ""
        self.feed(path.read_text(encoding="utf-8"))

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if tag in ("title", "h1"):
            self.active = tag
        if tag == "script" and attrs.get("type") in ("application/ld+json", "application/json"):
            self.active, self.script = "json", ""

    def handle_data(self, data):
        if self.active == "json":
            self.script += data
        elif self.active:
            setattr(self, self.active, getattr(self, self.active) + data)

    def handle_endtag(self, tag):
        if tag == "script" and self.active == "json":
            self.scripts.append(json.loads(self.script))
            self.active = None
        elif tag == self.active:
            self.active = None

    def find(self, tag, **attrs):
        return [data for name, data in self.tags if tag == name and all(data.get(k) == v for k, v in attrs.items())]


@pytest.mark.parametrize("base_url", ["https://example.github.io/Journal", "https://watch.example.org"])
def test_every_page_has_distinct_metadata_and_valid_links(site_root, base_url):
    output = build_site(site_root, repository="example/Journal", base_url=base_url)
    pages = {base_url + "/" + path: Page(output / path / "index.html") for path in PAGES}
    assert len(pages) == len(PAGES) == len(LANGS) * len(LOCAL_PAGES) + len(site_modes.EXTRA_LANGUAGES) * len(NOTICE_PAGES)
    pages.update({base_url + "/" + path: Page(output / path) for path in MODES_PAGES})
    for lang in LANGS:
        prefix = "" if lang == "en" else lang + "/"
        local = [pages[base_url + "/" + prefix + path] for path in LOCAL_PAGES]
        assert len({page.title for page in local}) == len(local), lang
        assert len({page.find("meta", name="description")[0]["content"] for page in local}) == len(local), lang
    for url, page in pages.items():
        path = url.removeprefix(base_url + "/")
        lang = path.split("/")[0] if path.split("/")[0] in NOTICE_LANGUAGES and "/" in path else "en"
        local = path.removeprefix(lang + "/") if lang != "en" else path
        languages = site_modes.LANGUAGES if path in MODES_PAGES else page_languages(local)
        assert page.h1, url
        assert len(page.find("h1")) == 1, url
        assert len(page.ids) == len(set(page.ids)), url
        assert page.find("link", rel="canonical") == [{"rel": "canonical", "href": url}]
        assert page.find("meta", property="og:url")[0]["content"] == url
        html_tag = page.find("html")[0]
        assert html_tag["lang"] == languages[lang][1] and html_tag["dir"] == languages[lang][2], url
        # Every page names all of its language versions, and each of them exists.
        alternates = {a["hreflang"]: a["href"] for a in page.find("link", rel="alternate")}
        assert set(alternates) == {value[1] for value in languages.values()} | {"x-default"}, url
        assert alternates["x-default"] == base_url + "/" + local
        assert all(href in pages for href in alternates.values()), url
        graphs = [script["@graph"] for script in page.scripts if "@graph" in script]
        assert len(graphs) == 1
        assert graphs[0][0]["@id"] == url
        for item in graphs[0]:
            assert "aggregateRating" not in item and "review" not in item
            for crumb in item.get("itemListElement", []):
                assert crumb["item"] in pages
        for tag, attrs in page.tags:
            for attr in ("href", "src"):
                href = attrs.get(attr)
                if not href:
                    continue
                resolved = urlsplit(urljoin(url, href))
                if resolved.netloc != urlsplit(base_url).netloc:
                    # Passive assets must stay local, even if navigation is external.
                    assert tag not in ("script", "img", "iframe")
                    continue
                target_url = resolved._replace(fragment="", query="").geturl()
                if target_url in pages:
                    if resolved.fragment:
                        assert unquote(resolved.fragment) in pages[target_url].ids, (url, href)
                else:
                    relative = resolved.path.removeprefix(urlsplit(base_url).path + "/")
                    if relative.endswith("/"):
                        relative += "index.html"  # a directory such as the online demo
                    assert (output / relative).is_file(), (url, href)
    for name in SEARCH_FILES:
        index = json.loads((output / name).read_text(encoding="utf-8"))
        hub = base_url + "/" + name.removesuffix("search.json")
        assert len(index["pages"]) == (3 if name.split('/')[0] in site_modes.EXTRA_LANGUAGES else 31)
        for entry in index["pages"]:
            assert urljoin(hub, entry["url"]) in pages
            # Short notices, especially in CJK languages, are valid search content.
            assert entry["text"].strip(), entry["url"]
    sitemap = ET.parse(output / "sitemap.xml")
    assert {node.text for node in sitemap.findall(".//{*}loc")} == set(pages)


def test_unlisted_guide_is_not_published(site_root):
    private = site_root / "website/guides/en/private.html"
    private.write_text("synthetic-private-guide", encoding="utf-8")
    output = build_site(site_root)
    assert all(b"synthetic-private-guide" not in p.read_bytes() for p in output.rglob("*") if p.is_file())


def test_reference_source_links_open_the_document_on_github(site_root):
    """Audit A10: the footer must lead to GitHub, never back to the same rendered page."""
    from tools.build_site import REFERENCE, WIKI_HUB
    output = build_site(site_root, repository="example/Journal")
    checked = 0
    for lang in LANGS:
        prefix = "" if lang == "en" else lang + "/"
        for slug, (_, _, _, source) in REFERENCE.items():
            page = Page(output / (prefix + WIKI_HUB + slug + "/") / "index.html")
            links = [a["href"] for a in page.find("a", **{"class": "reference"})]
            assert links == ["https://github.com/example/Journal/edit/main/" + source], (lang, slug, links)
            checked += 1
    assert checked == len(LANGS) * len(REFERENCE)


def test_attributed_html_quote_closes_before_following_markdown():
    """A closing quote must not become placeholder text and swallow the rest of the page."""
    from tools.site_wiki import to_html
    source = ('<blockquote lang="en" dir="ltr" translate="no">\n'
              '<p>A maintainer statement.</p>\n</blockquote>\n\n'
              '## Context\n\nA separate [reference](../LICENSE) and an <id> placeholder.\n')
    body, _, _ = to_html(source)
    assert '</blockquote>' in body and '&lt;/blockquote&gt;' not in body
    assert body.index('</blockquote>') < body.index('<h2 id="context">')
    assert '<a href="../LICENSE">reference</a>' in body
    assert '&lt;id&gt;' in body


@pytest.mark.parametrize('lang', ['ru', 'fr', 'he', 'am'])
def test_notices_cannot_silently_fall_back_to_english(site_root, lang):
    from tools import site_i18n, site_wiki
    from tools.build_site import REFERENCE
    body = site_wiki.split_title((site_root / REFERENCE['notice'][3]).read_text(encoding='utf-8'))[1]
    fragment = site_wiki.markup(body)[0]
    assert 'translate="no"' not in fragment
    path = site_root / f'website/i18n/{lang}.json'
    data = json.loads(path.read_text(encoding='utf-8'))
    data['blocks'].pop(site_i18n.digest(site_i18n.unit_texts(fragment)[0]))
    path.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
    with pytest.raises(ValueError, match=f'Incomplete notice translation: {lang}/notice'):
        build_site(site_root)


def test_notice_navigation_cannot_silently_fall_back_to_english(site_root):
    path = site_root / 'website/i18n/he.json'
    data = json.loads(path.read_text(encoding='utf-8'))
    del data['strings']['Search the documentation']
    path.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
    with pytest.raises(ValueError, match='Incomplete site labels: he'):
        build_site(site_root)


def test_cases_cannot_be_published_with_a_missing_german_translation(site_root):
    from tools import site_i18n
    path = site_root / 'website/i18n/de.json'
    data = json.loads(path.read_text(encoding='utf-8'))
    fragment = (site_root / 'website/guides/en/cases.html').read_text(encoding='utf-8')
    first = site_i18n.unit_texts(fragment)[0]
    del data['blocks'][site_i18n.digest(first)]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
    with pytest.raises(ValueError, match='Incomplete site translation: de/guide:cases'):
        build_site(site_root)


def test_translated_notice_documents_match_the_site_catalogues():
    from tools.sync_notice_translations import outputs
    translated = outputs(ROOT)
    assert len(translated) == 62  # Two documents in 25 languages, plus the 12 existing translated READMEs.
    for name, text in translated.items():
        assert (ROOT / name).read_text(encoding='utf-8') == text, name


def test_online_demo_is_read_only_relative_and_translated(site_root):
    output = build_site(site_root, repository="example/Journal")
    panel = (output / "demo/index.html").read_text(encoding="utf-8")
    assert '<script src="mock.js"></script>' in panel and 'name="robots" content="noindex"' in panel
    assert not __import__("re").search(r'(src|href)="/[A-Za-z]', panel)  # works under the Pages project path
    assert panel.index("mock.js") < panel.index('src="app.js')
    mock = (output / "demo/mock.js").read_text(encoding="utf-8")
    assert 'if (method !== "GET") return json(403' in mock
    answers = json.loads((output / "demo/fixtures.json").read_text(encoding="utf-8"))
    assert answers and all(key.startswith(("/api/", "/profiles/")) for key in answers)
    assert json.loads(answers["/api/demo-access"]["text"]) == {"available": True, "token": "online-demo"}
    assert json.loads(answers["/api/status"]["text"])["demo"] is True
    russian = (output / "demo/locales/ru.js").read_text(encoding="utf-8")
    assert russian.startswith('window.TGW_LANG="ru";window.TGW_DICT={') and "Журнал" in russian
    assert 'href="../demo/?lang=ru"' in (output / "ru/index.html").read_text(encoding="utf-8")


def test_modes_requires_complete_catalogues_and_escapes_translations():
    from tools.build_site import render, seo, THEME_SCRIPT
    reader = lambda name: (ROOT / name).read_bytes()
    english = site_modes.catalogue(reader, "en")
    for lang in site_modes.LANGUAGES:
        assert set(site_modes.catalogue(reader, lang, english)) == set(english)
    with pytest.raises(ValueError, match="Incomplete modes catalogue"):
        site_modes.catalogue(lambda _: json.dumps({"modes": {}}).encode(), "ru", english)
    attack = '<img src=x onerror=alert(1)>'
    translated = {**english, "modes.title": attack}
    _, page = site_modes.render_page(reader(site_modes.SOURCE).decode(), translated, lang="en",
        base_url="https://example.github.io/Journal", values={"REPO_URL":"https://github.com/example/Journal", "BRANCH":"main", "VERSION":"0.6.1"},
        dictionary={}, render=render, seo=seo, theme_script=THEME_SCRIPT)
    assert attack not in page and "&lt;img src=x onerror=alert(1)&gt;" in page
    assert "{{modes." not in page
