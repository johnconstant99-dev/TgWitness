"""Check homepage typography without changing executable or copyable content."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import site_i18n, site_typography


class HomepageTypography(unittest.TestCase):
    def test_requested_punctuation(self):
        self.assertEqual(site_typography.prose(site_typography.ASCII),
                         "？！：；，．／＼（）［］｛｝＂＇＠＃＄％＆＊＋－＝～＿｜")
        self.assertEqual(site_typography.prose('“Saved” — it’s retained, 1–10.'),
                         '＂Saved＂ ， it＇s retained， 1－10．')

    def test_addresses_versions_and_substitutions(self):
        text = ('Open https://example.org/a?q=one&v=two, my.telegram.org, '
                '127.0.0.1:8787, v0.9.0, Python 3.11+, AUTH_KEY_DUPLICATED, '
                'tgwitness-evidence.zip; enlarge: {name}.')
        self.assertEqual(site_typography.prose(text),
                         'Open https://example.org/a?q=one&v=two， my.telegram.org， '
                         '127.0.0.1:8787， v0.9.0， Python 3.11+， AUTH_KEY_DUPLICATED， '
                         'tgwitness-evidence.zip； enlarge： {name}．')

    def test_markup_attributes_and_entities(self):
        source = ('<!doctype html><html><head><meta name="description" content="Edits &amp; files.">'
                  '<meta property="og:url" content="https://example.org/a?b=1&amp;c=2"></head><body>'
                  '<a id="a-b" href="https://example.org/a?b=1&amp;c=2" aria-label="Open: &quot;A&quot;!">'
                  'Files &amp; edits &#8212; saved.</a><svg viewBox="0 0 12 12"><text x="1">A: B.</text></svg>'
                  '<!-- keep : this. --></body></html>')
        result = site_typography.homepage(source)
        self.assertIn('content="Edits ＆ files．"', result)
        self.assertIn('content="https://example.org/a?b=1&amp;c=2"', result)
        self.assertIn('id="a-b" href="https://example.org/a?b=1&amp;c=2" aria-label="Open： ＂A＂！"', result)
        self.assertIn('Files ＆ edits ， saved．</a>', result)
        self.assertIn('<svg viewBox="0 0 12 12"><text x="1">A： B．</text></svg>', result)
        self.assertIn('<!-- keep : this. -->', result)
        self.assertEqual(site_typography.homepage(result), result)

    def test_entities_inside_copyable_urls(self):
        source = '<p>Open https://example.org/a?x=1&amp;y=2, then check.</p>'
        self.assertEqual(site_typography.homepage(source),
                         '<p>Open https://example.org/a?x=1&amp;y=2， then check．</p>')

    def test_literal_subtrees_and_scripts_are_unchanged(self):
        literal = ('<pre><code>curl -fsSL https://example.org/a | sh\n{ "x": [1, 2] }</code></pre>'
                   '<script>const a = {x: "a&b"}; if (a.x !== "") a.x += "!";</script>'
                   '<style>.test { color: #fff; }</style><textarea>--raw &amp; data</textarea>'
                   '<span data-typography="literal"><b title="file.json">file.json</b> + {raw}</span>')
        self.assertEqual(site_typography.homepage(literal + '<p>Next, done.</p>'),
                         literal + '<p>Next， done．</p>')

    def test_all_built_homepages_and_dynamic_strings(self):
        for lang in site_i18n.LANGUAGES:
            with self.subTest(language=lang):
                prefix = '' if lang == 'en' else lang
                path = ROOT / 'dist/site' / prefix / 'index.html'
                self.assertTrue(path.exists(), 'Build the site before this check')
                source = path.read_text(encoding='utf-8')
                self.assertEqual(site_typography.homepage(source), source)
                self.assertNotIn('@@', source)
                self.assertIn('git clone https://github.com/phishdestroy/TgWitness.git', source)
                self.assertIn('.\\Start.cmd', source)
                self.assertIn('docker compose up -d --build --wait', source)
                self.assertIn('href="http://127.0.0.1:8787"', source)
                self.assertIn('my.telegram.org</a>', source)
                tree = site_i18n._Tree(source)
                def nodes(node):
                    yield node
                    for child in node.children:
                        yield from nodes(child)
                node = next(n for n in nodes(tree.root) if n.attrs.get('id') == 'site-dict')
                dictionary = json.loads(source[node.open_end:node.close_start])
                for key, value in dictionary.items():
                    self.assertEqual(site_typography.prose(value), value, key)
                self.assertIn('{name}', dictionary['Enlarge: {name}'])
                self.assertNotIn('—', dictionary['When the message disappears, its captured history remains.'])


if __name__ == '__main__':
    unittest.main()
