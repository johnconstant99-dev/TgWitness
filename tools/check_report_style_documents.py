"""Check complete signed report layouts, exact figures and offline reading."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import math
from pathlib import Path
import sys
import tempfile

from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.build_report_styles import build
from tools.check_browser import launch_browser
from tgwitness import report_charts, report_design
from tgwitness.verify import verify_report


def table_values(table):
    return table.locator('tbody tr').evaluate_all('(rows)=>rows.map(row=>[...row.cells].map(cell=>cell.textContent.trim()))')


def exact_figures(page, data):
    analytics = data['analytics']
    assert [int(value) for value in page.locator('.analytics-totals b').all_text_contents()] == [
        analytics['totals'][kind] for kind in report_charts.KINDS]
    figures = page.locator('.analytics-figure')
    expect(figures).to_have_count(5)
    daily = report_charts.activity_bins(analytics['activity']['rows'])
    daily_table = table_values(figures.nth(0).locator('.analytics-table table'))
    assert [(row[0], int(row[1])) for row in daily_table] == [(row['period'], row['total']) for row in daily]
    assert sum(int(row[1]) for row in daily_table) == analytics['activity']['counted_events']
    assert figures.nth(0).locator('svg g > title').all_text_contents() == [
        row['period'] + ' · ' + str(row['total']) for row in daily]
    hours = table_values(figures.nth(1).locator('.analytics-table table'))
    assert [int(row[1]) for row in hours] == [value for row in analytics['hourly']['rows'] for value in row]
    for index, key in ((2, 'participants'), (3, 'chats')):
        expected = analytics[key]['rows']
        exact_rank(figures.nth(index), expected)
        assert sum(row['total'] for row in expected) == analytics[key]['counted_events']
    composition = [{'label': report_charts.KINDS[kind], 'total': value}
                   for kind, value in analytics['composition'].items()]
    exact_rank(figures.nth(4), composition)
    assert sum(row['total'] for row in composition) == analytics['activity_events']


def exact_rank(figure, rows):
    labels = [row['label'].format(**row.get('label_values', {})) for row in rows]
    assert figure.locator('.rank-label').all_text_contents() == labels
    assert [int(value) for value in figure.locator('.rank-row > strong').all_text_contents()] == [
        row['total'] for row in rows]
    values = table_values(figure.locator('.analytics-table table'))
    expected = [[label + ' · ' + str(row['total']),
                 '#' + str(row['first_seq']) if row.get('first_seq') else '—',
                 '#' + str(row['last_seq']) if row.get('last_seq') else '—']
                for label, row in zip(labels, rows)]
    assert values == expected, (values, expected)
    maximum = max((row['total'] for row in rows), default=0) or 1
    widths = figure.locator('.rank-row .chart-bar').evaluate_all('(bars)=>bars.map(bar=>Number(bar.getAttribute("width")))')
    assert len(widths) == len(rows)
    assert all(math.isclose(width, 800 * row['total'] / maximum) for width, row in zip(widths, rows))


def preserved_context(page, data):
    edited = [item for item in data['changes']['messages'] if len(item['versions']) > 1]
    gone = [item for item in data['changes']['messages'] if item['gone']]
    assert edited and gone, 'The fixture must exercise both edits and deletion notices'
    compare = page.locator('#changes .version-compare').first
    expect(compare).to_be_visible()
    expect(compare.locator('> div').nth(0)).to_contain_text(edited[0]['versions'][0]['text'])
    expect(compare.locator('> div').nth(1)).to_contain_text(edited[0]['versions'][1]['text'])
    retained = page.locator('#changes .retained-message').first
    expect(retained).to_be_visible()
    previous = [version for version in gone[0]['versions'] if version['seq'] < gone[0]['gone'][0]['seq']][-1]
    expect(retained).to_contain_text(previous['text'])


def geometry(page):
    return page.evaluate("""()=>{
      const pick=selector=>{const el=document.querySelector(selector),r=el.getBoundingClientRect(),s=getComputedStyle(el);
        return {x:Math.round(r.x),width:Math.round(r.width),height:Math.round(r.height),
          font:s.fontFamily,fontSize:s.fontSize,padding:s.padding,columns:s.gridTemplateColumns};};
      return Object.fromEntries(['main','.hero','.hero h1','.hero .facts','.tiles','section.card','.report-analytics'].map(key=>[key,pick(key)]));
    }""")


def screen_identity(page, design):
    cover = page.locator('.hero').evaluate("""el=>{
      const css=getComputedStyle(el);
      return {leadingBorder:css.borderInlineStartWidth,topBorderStyle:css.borderTopStyle,
        topBorderWidth:css.borderTopWidth,background:css.backgroundImage};
    }""")
    if design == 'meridian':
        assert cover['leadingBorder'] == '14px', ('Meridian spine', cover)
    elif design == 'atlas':
        assert cover['background'] != 'none', ('Atlas grid', cover)
        assert cover['background'].count('linear-gradient') == 2, ('Atlas grid axes', cover)
    elif design == 'quire':
        assert cover['topBorderStyle'] == 'double' and cover['topBorderWidth'] == '4px', ('Quire frame', cover)
    contrast = page.locator('.hero h1, .hero .facts b, .hero .facts time, .hero .facts>div>span').evaluate_all("""elements=>{
      const rgba=value=>{const n=value.match(/[\\d.]+/g).map(Number);return [n[0],n[1],n[2],n[3]??1];};
      const blend=(front,back)=>front.slice(0,3).map((v,i)=>v*front[3]+back[i]*(1-front[3]));
      const background=el=>{
        const layers=[];
        for(let node=el;node;node=node.parentElement)layers.unshift(rgba(getComputedStyle(node).backgroundColor));
        return layers.reduce((back,front)=>blend(front,back),[255,255,255]);
      };
      const luminance=rgb=>rgb.map(v=>v/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4)
        .reduce((sum,v,i)=>sum+v*[.2126,.7152,.0722][i],0);
      return elements.filter(el=>el.textContent.trim()).map(el=>{
        const css=getComputedStyle(el),bg=background(el),ink=blend(rgba(css.color),bg);
        const a=luminance(ink),b=luminance(bg),ratio=(Math.max(a,b)+.05)/(Math.min(a,b)+.05);
        const size=parseFloat(css.fontSize),large=size>=24||(size>=18.66&&Number(css.fontWeight)>=700);
        return {text:el.textContent.trim(),color:css.color,background:bg,ratio,minimum:large?3:4.5};
      });
    }""")
    assert all(item['ratio'] >= item['minimum'] for item in contrast), (design + ' cover contrast', contrast)


def overflow(page):
    return page.evaluate("""()=>({width:innerWidth,total:document.documentElement.scrollWidth,
      offenders:[...document.querySelectorAll('body *')].filter(el=>el.checkVisibility()&&el.getBoundingClientRect().right>innerWidth+2)
        .slice(0,12).map(el=>({tag:el.tagName,id:el.id,cls:el.className?.baseVal??el.className,right:Math.round(el.getBoundingClientRect().right)}))})""")


def check(examples, designs, output):
    receipts = json.loads((examples / 'examples.json').read_text(encoding='utf-8'))
    failures, errors, outbound, layouts, geometries = [], [], [], [], {}
    original = None
    with sync_playwright() as playwright:
        browser = launch_browser(playwright)
        page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.on('request', lambda request: outbound.append(request.url)
                if request.url.startswith(('https:', 'http:')) else None)
        nojs = browser.new_page(java_script_enabled=False, viewport={'width': 390, 'height': 844})
        nojs.on('request', lambda request: outbound.append(request.url)
                if request.url.startswith(('https:', 'http:')) else None)
        for design in designs:
            print('Checking signed report:', design, flush=True)
            folder = examples / design
            data = json.loads((folder / 'report.json').read_text(encoding='utf-8'))['report']
            source = (folder / 'events.jsonl').read_bytes()
            facts = {key: data[key] for key in ('summary', 'analytics', 'changes', 'examination')}
            if original is None:
                original = source, facts
            assert (source, facts) == original, design + ': a design changed the source or report facts'
            assert data['analytics']['source']['sha256'] == hashlib.sha256(source).hexdigest()
            for suffix in ('html', 'json', 'pdf'):
                verify_report(folder / ('report.' + suffix), receipts[design]['fingerprint'])
            uri = (folder / 'report.html').as_uri()
            page.goto(uri)
            expect(page.locator('html')).to_have_attribute('data-report-design', design)
            exact_figures(page, data)
            preserved_context(page, data)
            for width in (320, 390, 768, 1440):
                page.set_viewport_size({'width': width, 'height': 1000})
                for theme, scheme in (('light', 'light'), ('dark', 'dark'), ('auto', 'light'), ('auto', 'dark')):
                    page.emulate_media(media='screen', color_scheme=scheme)
                    for direction in ('ltr', 'rtl'):
                        page.evaluate('({theme,direction})=>{document.documentElement.dataset.theme=theme;document.documentElement.dir=direction;}',
                                      {'theme': theme, 'direction': direction})
                        if width == 1440:
                            screen_identity(page, design)
                        measure = overflow(page)
                        key = [design, width, theme, scheme, direction]
                        layouts.append(key)
                        if measure['total'] > width + 1:
                            failures.append({'layout': key, 'overflow': measure})
            page.emulate_media(media='screen', color_scheme='light')
            page.set_viewport_size({'width': 1440, 'height': 1000})
            page.evaluate("()=>{document.documentElement.dataset.theme='light';document.documentElement.dir='ltr';scrollTo(0,0);}")
            geometries[design] = geometry(page)
            page.screenshot(path=str(output / (design + '-cover.png')))
            page.locator('#changes').scroll_into_view_if_needed()
            page.screenshot(path=str(output / (design + '-changes.png')))
            page.set_viewport_size({'width': 390, 'height': 844})
            page.evaluate('scrollTo(0,0)')
            page.screenshot(path=str(output / (design + '-mobile.png')))

            nojs.emulate_media(media='screen', color_scheme='light')
            nojs.goto(uri)
            preserved_context(nojs, data)
            expect(nojs.locator('#report-analytics')).to_be_visible()
            nojs.locator('.analytics-table').first.locator('summary').click()
            expect(nojs.locator('.analytics-table table').first).to_be_visible()
            measure = overflow(nojs)
            if measure['total'] > 391:
                failures.append({'layout': [design, 390, 'no-javascript'], 'overflow': measure})
            nojs.emulate_media(media='print', color_scheme='light')
            for table in nojs.locator('.analytics-print-data table').all():
                expect(table).to_be_visible()
            for closed in nojs.locator('.analytics-table').all():
                expect(closed).to_be_hidden()
            preserved_context(nojs, data)
            nojs.pdf(path=str(output / (design + '-browser-print.pdf')), format='A4', print_background=True)
        browser.close()
    for index, design in enumerate(designs):
        for other in designs[:index]:
            differing = [key for key, value in geometries[design].items() if value != geometries[other][key]]
            if len(differing) < 2:
                failures.append({'same_geometry': [design, other], 'differing_blocks': differing})
    result = {'designs': designs, 'layout_checks': len(layouts), 'exact_counts': True,
              'preserved_context': True, 'signed_formats': ['html', 'json', 'pdf'],
              'offline': not outbound, 'no_javascript': True, 'print_tables': True,
              'failures': failures, 'page_errors': errors, 'outbound_requests': outbound,
              'geometry': geometries}
    (output / 'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    if failures or errors or outbound:
        print(json.dumps({'failures': failures, 'errors': errors, 'outbound': outbound}, ensure_ascii=False, indent=2))
        raise SystemExit(1)
    print(json.dumps({key: value for key, value in result.items() if key != 'geometry'}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--examples', type=Path, help='Existing signed gallery; skip rebuilding')
    parser.add_argument('--design', action='append', choices=report_design.DESIGNS)
    parser.add_argument('--output', type=Path, default=Path('test-results/report-style-documents'))
    args = parser.parse_args()
    designs = tuple(args.design or report_design.DESIGNS)
    args.output.mkdir(parents=True, exist_ok=True)
    with ExitStack() as stack:
        examples = args.examples
        if examples is None:
            examples = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='report-style-documents-'))) / 'examples'
            print('Building complete signed examples.', flush=True)
            build(examples, designs=designs)
        check(examples.resolve(), designs, args.output)


if __name__ == '__main__':
    main()
