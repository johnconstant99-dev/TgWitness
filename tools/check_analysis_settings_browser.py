"""Provider form races with deferred local promises; no network/provider calls."""
from pathlib import Path
import os
import re


def check_settings(browser):
    root = Path(__file__).resolve().parents[1]
    html = (root / 'tgwitness/static/index.html').read_text(encoding='utf-8')
    html = re.sub(r'<script\b[^>]*>.*?</script>', '', html, flags=re.S)
    page = browser.new_page()
    page.set_content(html)
    page.evaluate("""()=>{
      window.$=id=>document.getElementById(id);window.show=(id,on)=>$(id).hidden=!on;
      window.tr=text=>text;window.toast=()=>{};
      window.state={profile:'default',me:{admin:true},status:{analysis:{enabled:true,media_available:false}}};
      window.providerData={enabled:true,provider:'ollama',model:'baseline',endpoint:'http://127.0.0.1:11434',
        local_endpoint:'http://127.0.0.1:11434',route:'direct',context_chars:6000,output_tokens:800,
        timeout_seconds:60,daily_requests:30,input_per_million:null,output_per_million:null,currency:'USD',has_key:false};
      window.busy=(button,fn)=>{
        if(button)button.disabled=true;
        const job=Promise.resolve().then(fn);window.testBusy=job;
        return job.finally(()=>{if(button)button.disabled=false;});
      };
      window.refreshStatus=async()=>{
        state.status.analysis.enabled=providerData.enabled;TgWitnessAnalysis.syncStatus();
      };
      window.json=async(path,body)=>{
        if(!path.startsWith('analysis/provider?workspace_id='))throw Error('Unexpected request');
        if(body){
          window.submitted=structuredClone(body);
          if(window.holdPost)await new Promise(resolve=>window.releasePost=resolve);
          Object.assign(providerData,body);delete providerData.api_key;
          return structuredClone(providerData);
        }
        const response=structuredClone(providerData);
        if(window.holdGet)await new Promise(resolve=>window.releaseGet=resolve);
        return response;
      };
      window.change=(id,value)=>{const input=$(id);if(input.type==='checkbox')input.checked=value;else input.value=value;
        input.dispatchEvent(new Event('input',{bubbles:true}));input.dispatchEvent(new Event('change',{bubbles:true}));};
      window.submit=()=>{$('ai-settings-form').dispatchEvent(new SubmitEvent('submit',{
        bubbles:true,cancelable:true,submitter:$('ai-settings-form').querySelector('button[type=submit]')}));};
    }""")
    page.add_script_tag(path=str(root / 'tgwitness/static/analysis.js'))
    page.evaluate('()=>TgWitnessAnalysis.loadSettings()')
    page.evaluate("""()=>{providerData.model='fresh-server-model';window.holdGet=true;
      window.reading=TgWitnessAnalysis.loadSettings();}""")
    page.wait_for_function('()=>typeof releaseGet==="function"')
    page.evaluate("()=>change('ai-enabled',false)")
    page.evaluate('async()=>{holdGet=false;releaseGet();await reading;}')
    assert not page.locator('#ai-enabled').is_checked(), 'Late provider read overwrote the unchecked enable switch'
    assert page.locator('#ai-model').input_value() == 'fresh-server-model', 'Untouched fields did not refresh'
    page.evaluate('async()=>{submit();await testBusy;}')
    assert page.evaluate('()=>submitted.enabled===false&&submitted.model==="fresh-server-model"')

    page.evaluate("""()=>{change('ai-model','submitted-model');change('ai-key','synthetic-first');
      window.holdPost=true;submit();}""")
    page.wait_for_function('()=>typeof releasePost==="function"')
    page.evaluate("()=>{change('ai-model','newer-unsaved-model');change('ai-key','synthetic-next');}")
    page.evaluate('async()=>{holdPost=false;releasePost();await testBusy;}')
    assert page.locator('#ai-model').input_value() == 'newer-unsaved-model', 'Save response erased newer edits'
    assert page.locator('#ai-key').input_value() == 'synthetic-next', 'Save response erased a newer key draft'
    page.evaluate('()=>TgWitnessAnalysis.loadSettings()')
    assert page.locator('#ai-model').input_value() == 'newer-unsaved-model', 'Refresh erased an unsaved model'
    assert page.locator('#ai-key').input_value() == 'synthetic-next'

    page.evaluate('()=>{window.holdGet=true;window.reading=TgWitnessAnalysis.loadSettings();}')
    page.wait_for_function('()=>typeof releaseGet==="function"')
    page.evaluate("()=>{state.profile='second';state.me=null;TgWitnessAnalysis.clear();}")
    page.evaluate('async()=>{holdGet=false;releaseGet();await reading;}')
    assert page.locator('#ai-model').input_value() == ''
    assert page.locator('#ai-key').input_value() == ''
    assert page.locator('#ai-settings-form').evaluate('element=>element.inert')
    page.close()
    print('Provider settings: deferred reads, untouched fields, save drafts, key drafts and lock passed.', flush=True)


if __name__ == '__main__':
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, channel=os.environ.get("TGWITNESS_BROWSER_CHANNEL") or None)
        check_settings(browser)
        browser.close()
