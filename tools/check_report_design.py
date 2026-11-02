"""Offline dossier navigation, coverage semantics, narrow layouts and signed formats."""
import json
from pathlib import Path
import tempfile

from playwright.sync_api import expect, sync_playwright

from build_dossier_example import build
from check_browser import launch_browser
from tgwitness import report
from tgwitness.verify import verify_report


def main():
    coverage = {'continuous':[{'from':'2026-11-01T10:00:00+01:00','to':'2026-11-01T09:10:00Z'}],
                'gaps':[{'from':'2026-11-01T09:10:00Z','to':'2026-11-01T09:20:00Z'}]}
    plot = report.coverage_plot(coverage)
    assert plot['rows'] == [[(0, .5)], [(.5, .5)]]
    assert report.coverage_plot({}) is None
    for start, end in (('not a time','2026-11-01T09:10:00Z'),
                       ('2026-11-01T09:00:00','2026-11-01T09:10:00'),
                       ('2026-11-01T09:10:00Z','2026-11-01T09:00:00Z')):
        assert report.coverage_plot({'continuous':[{'from':start,'to':end}]}) is None
    output = Path('test-results/report-design')
    output.mkdir(parents=True, exist_ok=True)
    errors, outbound = [], []
    with tempfile.TemporaryDirectory(prefix='dossier-browser-') as scratch:
        root = Path(scratch)
        receipt = build(root)
        for lang in receipt:
            for suffix in ('html', 'json', 'pdf'):
                verify_report(root / lang / ('report.' + suffix), receipt[lang]['fingerprint'])
        with sync_playwright() as p:
            browser = launch_browser(p)
            page = browser.new_page(viewport={'width':1440,'height':1000}, reduced_motion='reduce')
            page.on('pageerror', lambda e: errors.append(str(e)))
            page.on('request', lambda r: outbound.append(r.url) if r.url.startswith(('https:','http:')) else None)
            for lang in ('en','ru','de'):
                page.goto((root/lang/'report.html').as_uri())
                expect(page.locator('.assessment-overview li')).to_have_count(6)
                page.locator('.assessment-overview a[href="#assessment-coverage"]').click()
                expect(page.locator('#assessment-coverage h3')).to_be_in_viewport()
                assert page.locator('#assessment-coverage .assessment-state').inner_text() == report.Words(lang)(report.case_assessment.STATUSES['recorded'])
                expect(page.locator('.coverage-figure')).to_have_count(1)
                expect(page.locator('.coverage-span-0')).to_have_count(2)
                # Includes the zero-duration stop at the final record; the table retains it.
                expect(page.locator('.coverage-span-1')).to_have_count(2)
                for width in (320,390,768,1440):
                    page.set_viewport_size({'width':width,'height':1000})
                    for theme in ('light','dark'):
                        page.evaluate('(theme)=>document.documentElement.dataset.theme=theme', theme)
                        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth+1'), (lang,width,theme)
                page.set_viewport_size({'width':1440,'height':1000})
                page.evaluate("document.documentElement.dataset.theme='light';scrollTo(0,0)")
                page.screenshot(path=str(output/(lang+'-cover.png')))
            page.goto((root/'ru/report.html').as_uri())
            page.locator('.assessment-overview').scroll_into_view_if_needed()
            page.screenshot(path=str(output/'ru-assessment.png'))
            page.locator('#coverage').scroll_into_view_if_needed()
            page.screenshot(path=str(output/'ru-coverage.png'))
            page.set_viewport_size({'width':390,'height':844})
            page.evaluate('scrollTo(0,0)')
            page.screenshot(path=str(output/'ru-mobile.png'))
            nojs = browser.new_page(java_script_enabled=False, viewport={'width':390,'height':844})
            nojs.goto((root/'ru/report.html').as_uri())
            expect(nojs.locator('.assessment-overview')).to_be_visible()
            nojs.locator('a[href="#assessment-integrity"]').click()
            expect(nojs.locator('#assessment-integrity h3')).to_be_in_viewport()
            nojs.emulate_media(media='print')
            expect(nojs.locator('.assessment-overview')).to_be_visible()
            expect(nojs.locator('.coverage-figure')).to_be_visible()
            nojs.pdf(path=str(output/'browser-print.pdf'), format='A4')
            browser.close()
    assert not errors and not outbound, (errors, outbound)
    print(json.dumps({'passed':True,'languages':['ru','en','de'],'widths':[320,390,768,1440],
                      'signed_formats':['HTML','JSON','PDF'],'offline':True,'no_javascript':True,
                      'coverage_preserves_unknown_intervals':True}))


if __name__ == '__main__':
    main()
