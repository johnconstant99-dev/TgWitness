import html
from html.parser import HTMLParser
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import site_seo


class Head(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.in_head = False
        self.in_title = False
        self.title = ''
        self.meta = {}
        self.links = []
        self.scripts = []
        self.in_json = False
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'head':
            self.in_head = True
        if self.in_head:
            if tag == 'title':
                self.in_title = True
            if tag == 'meta':
                self.meta[attrs.get('name', attrs.get('property'))] = attrs.get('content')
            if tag == 'link':
                self.links.append(attrs)
            if tag == 'script' and attrs.get('type') == 'application/ld+json':
                self.in_json = True
                self.scripts.append('')

    def handle_endtag(self, tag):
        if tag == 'head':
            self.in_head = False
        if tag == 'title':
            self.in_title = False
        if tag == 'script':
            self.in_json = False

    def handle_data(self, text):
        if self.in_title:
            self.title += text
        if self.in_json:
            self.scripts[-1] += text


def sample(lang='en', title='Export and verify | TgWitness', description='Captured records.', canonical='https://example.test/TgWitness/docs/exports/'):
    graph = {'@context': 'https://schema.org', '@graph': [
        {'@type': 'WebPage', '@id': canonical, 'url': canonical, 'name': title,
         'description': description, 'inLanguage': lang,
         'breadcrumb': {'@id': canonical + '#breadcrumb'}},
        {'@type': 'BreadcrumbList', '@id': canonical + '#breadcrumb', 'itemListElement': []}]}
    return ('<!doctype html><html lang="' + lang + '"><head><title>' + html.escape(title) + '</title>'
            '<meta name="description" content="' + html.escape(description, quote=True) + '">'
            '<meta property="og:title" content="Old title"><meta property="og:description" content="Different summary">'
            '<link rel="canonical" href="' + canonical + '"><link rel="alternate" hreflang="en" href="' + canonical + '">'
            '<script type="application/ld+json">' + json.dumps(graph).replace('<', '\\u003c') + '</script></head>'
            '<body><h1 id="topic">Export and verify</h1><svg><title>Diagram title</title></svg>'
            '<pre><code>verify --fingerprint TRUSTED_KEY --path "A &amp; B"</code></pre>'
            '<a href="https://example.test/?a=1&amp;b=2">Original link</a><footer>Project footer</footer></body></html>')


class PageSearchMetadata(unittest.TestCase):
    def test_head_social_and_schema_agree_without_touching_evidence_examples(self):
        source = sample()
        result = site_seo.enrich(source, 'docs/exports/index.html')
        head = Head(result)
        self.assertEqual(head.title, 'Export Telegram Chats & Verify Signed Evidence | TgWitness')
        self.assertEqual(head.meta['og:title'], head.title)
        self.assertEqual(head.meta['twitter:title'], head.title)
        self.assertEqual(head.meta['description'], head.meta['og:description'])
        self.assertEqual(head.meta['description'], head.meta['twitter:description'])
        page = json.loads(head.scripts[0])['@graph'][0]
        self.assertEqual(page['name'], head.title)
        self.assertEqual(page['description'], head.meta['description'])
        self.assertEqual(page['keywords'], ['export Telegram chats'])
        self.assertEqual([link for link in head.links if link.get('rel') in {'canonical', 'alternate'}], Head(source).links)
        self.assertIn({'rel': 'stylesheet', 'href': '../../discovery.css'}, head.links)
        self.assertEqual(page['breadcrumb'], json.loads(Head(source).scripts[0])['@graph'][0]['breadcrumb'])
        self.assertIn('<svg><title>Diagram title</title></svg>', result)
        self.assertIn('<pre><code>verify --fingerprint TRUSTED_KEY --path "A &amp; B"</code></pre>', result)
        self.assertIn('href="https://example.test/?a=1&amp;b=2"', result)
        self.assertIn('href="../../llms-full.txt"', result)
        self.assertIn('class="machine-doc-footer"', result)
        self.assertIn('class="machine-doc-links"', result)
        self.assertEqual(site_seo.enrich(result, 'docs/exports/index.html'), result)

    def test_russian_metadata_and_relative_discovery(self):
        result = site_seo.enrich(sample('ru', 'Экспорт ｜ TgWitness', 'Архив，подпись и проверка．'), 'ru/docs/exports/index.html')
        head = Head(result)
        self.assertEqual(head.title, 'Экспорт чатов Telegram и проверка подписанного архива | TgWitness')
        self.assertEqual(head.meta['description'], 'Архив, подпись и проверка.')
        self.assertIn('href="../../../llms.txt"', result)

    def test_cjk_punctuation_and_localized_labels_are_retained(self):
        result = site_seo.enrich(sample('zh-Hans', '导出和验证 | TgWitness', '导出记录，检查签名。'), 'zh/docs/exports/index.html')
        head = Head(result)
        self.assertEqual(head.title, 'Telegram · 导出和验证 | TgWitness')
        self.assertEqual(head.meta['description'], '导出记录，检查签名。')

    def test_fullwidth_translated_brand_separator_is_not_duplicated(self):
        for lang, original, expected in (
            ('es', 'Exportar Telegram ｜ TgWitness', 'Exportar Telegram | TgWitness'),
            ('ja', 'Telegram のエクスポート ｜ TgWitness', 'Telegram のエクスポート | TgWitness'),
            ('fa', 'Telegram ｜ تی‌جی‌وییتنس', 'Telegram | TgWitness'),
        ):
            with self.subTest(language=lang):
                result = site_seo.enrich(sample(lang, original), lang + '/index.html')
                self.assertEqual(Head(result).title, expected)

    def test_metadata_is_escaped_and_no_unmapped_page_is_silently_published(self):
        value = '<script>alert("sample")</script>'
        result = site_seo.enrich(sample('de', 'Export | TgWitness', value), 'de/docs/exports/index.html')
        self.assertNotIn(value, result)
        self.assertEqual(Head(result).meta['description'], value)
        with self.assertRaisesRegex(ValueError, 'Missing page search intent'):
            site_seo.enrich(sample(), 'docs/new-workflow/index.html')

    def test_homepage_design_and_english_canonical_copy_are_preserved(self):
        home = sample(canonical='https://example.test/TgWitness/')
        result = site_seo.enrich(home, 'index.html')
        self.assertIn('<h1 id="topic">Export and verify</h1>', result)
        self.assertEqual(Head(result).title, 'Telegram Chat Export & OSINT Evidence | TgWitness')
        copy = site_seo.enrich(sample(canonical='https://example.test/TgWitness/docs/reference/changelog/'), 'ru/docs/reference/changelog/index.html')
        self.assertEqual(Head(copy).title, 'TgWitness Changelog & Release Notes | TgWitness')
        self.assertEqual(json.loads(Head(copy).scripts[0])['@graph'][0]['inLanguage'], 'en')


if __name__ == '__main__':
    unittest.main()
