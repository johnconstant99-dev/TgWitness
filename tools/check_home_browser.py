"""Homepage actions, translated narrow layouts and actual text contrast."""
import json
from urllib.parse import urljoin

from playwright.sync_api import expect

try:
    from .site_i18n import LANGUAGES
except ImportError:
    from site_i18n import LANGUAGES


def check_home(browser, url, output, route_request, errors):
    cases = [(lang, 320, theme, False) for lang in LANGUAGES for theme in ('light', 'dark')]
    cases += [('en', 1440, theme, True) for theme in ('light', 'dark')]
    checks = []
    for lang, width, theme, javascript in cases:
        context = browser.new_context(viewport={'width': width, 'height': 1000}, color_scheme=theme,
                                      reduced_motion='reduce', java_script_enabled=javascript)
        context.route('**/*', route_request)
        page = context.new_page()
        page.on('pageerror', lambda error: errors.append('home: ' + str(error)))
        prefix = '' if lang == 'en' else lang + '/'
        page.goto(url + prefix, wait_until='networkidle')
        assert page.locator('video, #films').count() == 0
        expect(page.locator('#s3')).to_be_visible()
        assert page.locator('#s3 .button').get_attribute('href') == 'docs/exports/#s3'
        expect(page.locator('#s3 img')).to_be_visible()
        assert page.locator('.hero-retention-link').get_attribute('href') == '#s3'
        capture = page.locator('[data-home-action="sealed"]')
        expect(capture).to_be_visible()
        assert urljoin(page.url, capture.get_attribute('href')) == url + prefix + 'docs/capture/'
        assert not page.evaluate('document.documentElement.scrollWidth > innerWidth'), (lang, width, theme)
        for action, path in [('demo', 'demo/'), ('setup', 'demo/guide.html')]:
            button = page.locator(f'[data-home-action="{action}"]')
            expect(button).to_be_visible()
            assert urljoin(page.url, button.get_attribute('href')) == url + path + '?lang=' + lang
            assert button.bounding_box()['height'] >= 48
        routes = page.locator('.workflow a')
        assert routes.count() == 4
        assert urljoin(page.url, routes.nth(0).get_attribute('href')) == url + prefix + 'guides/modes.html'
        assert urljoin(page.url, routes.nth(3).get_attribute('href')) == url + prefix + 'docs/exports/'

        page.locator('.lang-menu>summary').click()
        expect(page.locator('.lang-list')).to_be_visible()
        assert not page.evaluate('document.documentElement.scrollWidth > innerWidth'), (lang, 'language menu')
        for item in page.locator('.lang-list a').all():
            box = item.bounding_box()
            assert box and box['x'] >= -1 and box['x'] + box['width'] <= width + 1
        page.locator('.lang-menu>summary').click()
        issues = page.evaluate('''() => {
          const rgb=s=>s.match(/[\\d.]+/g).map(Number);
          const lum=c=>c.slice(0,3).map(x=>{x/=255;return x<=.04045?x/12.92:((x+.055)/1.055)**2.4}).reduce((a,x,i)=>a+x*[.2126,.7152,.0722][i],0);
          const background=el=>{
            let colors=[];for(let node=el;node;node=node.parentElement)colors.push(rgb(getComputedStyle(node).backgroundColor));
            return colors.reverse().reduce((under,over)=>{const a=over.length===4?over[3]:1;return over.slice(0,3).map((v,i)=>v*a+under[i]*(1-a))},[255,255,255]);
          };
          return [...document.querySelectorAll('body *')].flatMap(el=>{
            if(!el.getClientRects().length || el.closest('svg,pre,.sr-only,[aria-hidden=true]') || ![...el.childNodes].some(n=>n.nodeType===3&&n.textContent.trim()))return [];
            const cs=getComputedStyle(el),a=lum(rgb(cs.color)),b=lum(background(el));
            const ratio=(Math.max(a,b)+.05)/(Math.min(a,b)+.05);
            const large=parseFloat(cs.fontSize)>=24 || parseFloat(cs.fontSize)>=18.66&&parseInt(cs.fontWeight)>=700;
            return ratio+0.01<(large?3:4.5)?[{text:el.textContent.trim().slice(0,70),ratio}]:[];
          });
        }''')
        assert not issues, (lang, width, theme, issues[:8])
        if javascript:
            page.locator('#s3 .button').click()
            expect(page).to_have_url(url + 'docs/exports/#s3')
            expect(page.locator('h2#s3')).to_be_visible()
            expect(page.locator('img[src$="off-site-copy.png"]')).to_be_visible()
            assert 'python -m tgwitness.replica restore' in page.locator('main').inner_text()
            page.go_back(wait_until='networkidle')
            page.locator('#s3 .screenshot-open').click()
            expect(page.locator('.screenshot-dialog')).to_be_visible()
            page.keyboard.press('Escape')
            primary = page.locator('[data-home-action="demo"]')
            page.keyboard.press('Tab')
            primary.focus()
            expect(primary).to_be_focused()
            assert primary.evaluate('el=>getComputedStyle(el).outlineStyle') == 'solid'
            primary.press('Enter')
            expect(page).to_have_url(url + 'demo/?lang=en')
            page.go_back(wait_until='networkidle')
            page.locator('[data-home-action="setup"]').click()
            expect(page).to_have_url(url + 'demo/guide.html?lang=en')
            page.go_back(wait_until='networkidle')
            page.screenshot(path=str(output / f'home-{theme}-{width}.png'))
        elif lang in ('en', 'ru', 'ar') and theme == 'dark':
            page.evaluate('scrollTo(0,0)')
            page.screenshot(path=str(output / f'home-{lang}-{theme}-{width}-no-js.png'))
        checks.append({'language': lang, 'width': width, 'theme': theme, 'javascript': javascript, 'passed': True})
        context.close()
        print(f'Home: {lang}, {width}px, {theme}, JS={javascript} passed', flush=True)
    (output / 'home-checks.json').write_text(json.dumps(checks, indent=2) + '\n', encoding='utf-8')
