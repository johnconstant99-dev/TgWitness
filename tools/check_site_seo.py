from collections import defaultdict
import html
import json
from pathlib import Path
import re
import sys
from urllib.parse import urljoin, urlsplit
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import site_i18n, site_seo


def check(output):
    sitemap = ET.parse(output / 'sitemap.xml').getroot()
    urls = [n.findtext('{http://www.sitemaps.org/schemas/sitemap/0.9}loc') for n in sitemap]
    home = (output / 'index.html').read_text(encoding='utf-8')
    tree = site_i18n._Tree(home)
    base = next(n.attrs['href'] for n in site_seo.nodes(tree.root) if n.tag == 'link' and n.attrs.get('rel') == 'canonical')
    titles, descriptions = defaultdict(list), defaultdict(list)
    records = []
    assert len(urls) == len(set(urls)), 'Duplicate sitemap URL'
    for url in urls:
        assert url.startswith(base), url
        route = url[len(base):]
        file = output / (route + 'index.html' if route.endswith('/') or not route else route)
        source = file.read_text(encoding='utf-8')
        root = site_i18n._Tree(source).root
        nodes = list(site_seo.nodes(root))
        head = next(n for n in nodes if n.tag == 'head')
        headers = list(site_seo.nodes(head))
        title_nodes = [n for n in headers if n.tag == 'title']
        assert len(title_nodes) == 1, (route, 'head title count')
        node = title_nodes[0]
        title = source[node.open_end:node.close_start]
        title = html.unescape(title)
        assert not re.search(r'[|｜]\s*TgWitness\s*[|｜]\s*TgWitness', title), route
        meta = defaultdict(list)
        for n in headers:
            if n.tag == 'meta':
                meta[n.attrs.get('name', n.attrs.get('property'))].append(n.attrs.get('content'))
        for name in ('description', 'og:title', 'og:description', 'twitter:title', 'twitter:description'):
            assert len(meta[name]) == 1 and meta[name][0], (route, name)
        description = meta['description'][0]
        assert meta['og:title'] == meta['twitter:title'] == [title], route
        assert meta['og:description'] == meta['twitter:description'] == [description], route
        assert not any('noindex' in value for value in meta['robots']), route
        canonicals = [n.attrs['href'] for n in headers if n.tag == 'link' and n.attrs.get('rel') == 'canonical']
        assert canonicals == [url], (route, canonicals)
        scripts = [n for n in headers if n.tag == 'script' and n.attrs.get('type') == 'application/ld+json']
        assert len(scripts) == 1, route
        script = scripts[0]
        graph = json.loads(source[script.open_end:script.close_start])['@graph']
        page = next(n for n in graph if n['@type'] == 'WebPage')
        lang = page['inLanguage']
        assert page['name'] == title and page['description'] == description, route
        assert page['keywords'] and all(isinstance(v, str) and v for v in page['keywords']), route
        assert len([n for n in nodes if n.tag == 'h1']) == 1, route
        assert (output / 'discovery.css').is_file()
        assert any(n.tag == 'link' and n.attrs.get('rel') == 'stylesheet' and urljoin(url, n.attrs.get('href', '')) == base + 'discovery.css' for n in headers), route
        if lang not in {'zh', 'zh-Hans', 'zh-Hant', 'ja', 'ko'}:
            assert not re.search('[\uff01-\uff5e]', title + description), route
        for name in ('llms.txt', 'llms-full.txt', 'sitemap.xml'):
            assert any(n.tag == 'a' and urljoin(url, n.attrs.get('href', '')) == base + name for n in nodes), (route, name)
            assert (output / name).is_file(), name
        for n in headers:
            if n.tag != 'link' or 'hreflang' not in n.attrs:
                continue
            target = n.attrs['href']
            assert target.startswith(base), target
            target_route = target[len(base):]
            target_file = target_route + 'index.html' if target_route.endswith('/') or not target_route else target_route
            assert (output / target_file).is_file(), (route, target_route)
        titles[(lang, title)].append(route)
        descriptions[(lang, description)].append(route)
        records.append({'url': url, 'language': lang, 'title': title,
                        'description': description, 'primary_query': page['keywords'][0]})
    for entries in (titles, descriptions):
        assert all(len(paths) == 1 for paths in entries.values()), [paths for paths in entries.values() if len(paths) > 1]
    for name in ('llms.txt', 'llms-full.txt', 'llms-full.md'):
        body = (output / name).read_text(encoding='utf-8')
        assert body.startswith('# TgWitness') and len(body) > 1000, name
        for target in re.findall(r'\]\((https?://[^\s)]+)\)', body):
            if target.startswith(base):
                local = urlsplit(target[len(base):]).path
                local += 'index.html' if local.endswith('/') or not local else ''
                assert (output / local).is_file(), (name, target)
    report = ROOT / 'test-results/site/seo.json'
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({'pages': records}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {'indexed_pages': len(records), 'languages': len({r['language'] for r in records}),
            'unique_titles_and_descriptions': True, 'llms_links_checked': True}


if __name__ == '__main__':
    print(json.dumps(check(ROOT / 'dist/site')))
