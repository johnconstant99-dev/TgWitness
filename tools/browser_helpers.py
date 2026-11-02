"""Playwright helpers shared by static-site and live-application checks."""
import os

from playwright.sync_api import expect


def launch_browser(p):
    return p.chromium.launch(headless=True, channel=os.environ.get("TGWITNESS_BROWSER_CHANNEL") or None)


def answer_panel_dialog(page, accept=True, text=None):
    dialog = page.locator("dialog.panel-dialog[open]")
    expect(dialog).to_have_count(1)
    field = dialog.locator("input")
    if accept and field.count():
        if text is not None:
            field.fill(text)
        elif not field.input_value():
            field.fill(field.get_attribute("placeholder") or "")
    dialog.locator("button[type=submit]" if accept else "button.secondary").click()
    expect(dialog).to_have_count(0)


def check_layout(page, connection=False):
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), page.evaluate("""()=>({width:innerWidth,overflow:[...document.querySelectorAll('body *')].filter(e=>e.checkVisibility()&&e.getBoundingClientRect().right>innerWidth+1).map(e=>[e.tagName,e.id,e.className,e.getBoundingClientRect().right]).slice(0,20)})""")
    for button in page.locator(".sidebar .nav:visible").all():
        bounds = button.bounding_box()
        assert bounds and bounds["x"] >= 0 and bounds["x"] + bounds["width"] <= page.viewport_size["width"] + 1
    if connection:
        for selector in ("#phone", "#auth-continue"):
            bounds = page.locator(selector).bounding_box()
            assert bounds and bounds["y"]+bounds["height"] <= page.viewport_size["height"], "Phone login requires initial scrolling"
    if page.locator("#view-observations").is_visible() and page.locator("#events-body tr").count():
        row = page.locator("#events-body tr").first
        assert row.locator("td").nth(2).is_visible() or row.locator(".event-mobile-meta").is_visible(), \
            "Timeline timestamps disappeared at this width"


    failures = page.evaluate("""() => {
      const rgba=s=>(s.match(/[\\d.]+/g)||[]).map(Number);
      const blend=(fg,bg)=>fg.slice(0,3).map((v,i)=>v*(fg[3]??1)+bg[i]*(1-(fg[3]??1)));
      const luminance=c=>c.map(v=>{v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4}).reduce((s,v,i)=>s+v*[.2126,.7152,.0722][i],0);
      const result=[];
      for(const el of document.querySelectorAll('body *')){
        if(![...el.childNodes].some(n=>n.nodeType===3&&n.textContent.trim())||!el.checkVisibility({checkVisibilityCSS:true})||el.closest('[disabled]'))continue;
        const cs=getComputedStyle(el);if(cs.visibility!=='visible')continue;
        let chain=[],n=el,skip=false;
        while(n){const s=getComputedStyle(n);chain.unshift(s);if(Number(s.opacity)<1||/url\\(/.test(s.backgroundImage))skip=true;n=n.parentElement;}
        if(skip)continue;
        let bg=[255,255,255];for(const s of chain)bg=blend(rgba(s.backgroundColor),bg);
        const color=blend(rgba(cs.color),bg), a=luminance(color),b=luminance(bg),ratio=(Math.max(a,b)+.05)/(Math.min(a,b)+.05);
        const large=parseFloat(cs.fontSize)>=24||(parseFloat(cs.fontSize)>=18.66&&Number(cs.fontWeight)>=700);
        if(ratio<(large?3:4.5))result.push({text:el.textContent.trim().slice(0,65),selector:el.id||el.className,ratio:+ratio.toFixed(2),color:cs.color});
      }
      return result;
    }""")
    assert not failures, failures
