"""Analyst workflow acceptance against a local synthetic journal. No Telegram traffic."""
import hashlib
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace as NS

from PIL import Image, ImageDraw
from playwright.sync_api import expect, sync_playwright

from check_browser import ROOT, RunningApp, hold_api_response, launch_browser, release_api_response, unlock
from tools.browser_fixtures import CHAT, FakeClient, saved_session


OTHER = -1000000000456
NEW = -1000000000789


class AnalystClient(FakeClient):
    async def iter_dialogs(self, limit):
        for cid, title in ((CHAT, "Harbor review"), (OTHER, "Private case"), (NEW, "New research")):
            yield NS(id=cid, name=title, is_group=True, is_channel=True,
                     entity=NS(id=-cid - 1000000000000, megagroup=True))


def seed(server):
    store, vault = server.app.state.store, server.app.state.vault
    vault.save("credentials", {"api_id": 123, "api_hash": "a" * 32, "session": saved_session()})
    vault.save("network", {"kind": "direct"})
    store.set_setting("account", {"id": 44, "username": "synthetic"})
    store.set_target(CHAT, "Harbor review", "supergroup", True)
    store.set_target(OTHER, "Private case", "supergroup", True)
    before = {"text": "Send 25 USDT to confirm the invoice. Keep the original receipt.", "sender_id": 44,
              "sender_observation": {"id": 44, "display_name": "Example operator"},
              "raw": {"entities": [{"_": "MessageEntityTextUrl", "offset": 0, "length": 4,
                                     "url": "https://old.example/invoice"}],
                      "reply_markup": {"_": "ReplyInlineMarkup", "rows": [{"_": "KeyboardButtonRow", "buttons": [
                          {"_": "KeyboardButtonUrl", "text": "Invoice", "url": "https://old.example/pay"}]}]}}}
    after = {**before, "text": "Send 250 USDT to review the invoice. Keep the original receipt.",
             "raw": {"entities": [{"_": "MessageEntityTextUrl", "offset": 0, "length": 4,
                                    "url": "https://new.example/invoice"}],
                     "reply_markup": {"_": "ReplyInlineMarkup", "rows": [{"_": "KeyboardButtonRow", "buttons": [
                         {"_": "KeyboardButtonUrl", "text": "Invoice", "url": "https://new.example/pay"}]}]}}}
    store.append("message.new", before, CHAT, 10, 44)
    edited = store.append("message.edited", after, CHAT, 10)
    store.append("message.new", {"text": "Private case material", "sender_id": 55}, OTHER, 20, 55)
    store.append("message.new", {"text": "Saved invoice image. Synthetic test fixture.", "sender_id": 44,
                                 "has_media": True}, CHAT, 11, 44)
    directory = store.root / "media"
    directory.mkdir(exist_ok=True)
    image = Image.new("RGB", (640, 320), "#111b2c")
    drawing = ImageDraw.Draw(image)
    drawing.rounded_rectangle((24, 24, 616, 296), 14, fill="#203047", outline="#6b9cc8", width=2)
    drawing.text((52, 55), "HARBOR / CAPTURED INVOICE", fill="#d4e4f4", font_size=25)
    drawing.text((52, 110), "Synthetic browser fixture", fill="#90b2d1", font_size=20)
    drawing.line((52, 160, 585, 160), fill="#5e86aa", width=2)
    drawing.text((52, 195), "Original file stays attached to its record.", fill="#d4e4f4", font_size=20)
    temp = directory / "fixture.png"
    image.save(temp)
    digest = hashlib.sha256(temp.read_bytes()).hexdigest()
    temp.replace(directory / digest)
    media = store.append("media.saved", {"media_sha256": digest, "mime_type": "image/png",
                                        "original_name": "invoice.png", "size": (directory / digest).stat().st_size}, CHAT, 11)
    return {"edited": edited, "media": media, "digest": digest, "before": before, "after": after}


def diff_checks(page, fixture):
    result = page.evaluate(r"""() => {
      const samples=[['',''],['a',''],['','a'],['same','same'],['pay 25','pay 250'],
        ['Привет 👋\nשלום','Привет 🧾\nשלום'],['x '.repeat(7000),'y '.repeat(7000)],
        ['a'.repeat(200000),'b'.repeat(200000)]];
      let seed=61;const next=()=>{seed=(seed*1664525+1013904223)>>>0;return seed;};
      const alphabet=['a','b',' ','\n','<','>','🧾','שלום','Ж'];
      for(let n=0;n<100;n++){
        const text=()=>Array.from({length:next()%50},()=>alphabet[next()%alphabet.length]).join('');
        samples.push([text(),text()]);
      }
      const start=performance.now();
      for(const [before,after] of samples){const parts=TgWitnessReview.diff(before,after);
        if(parts.filter(([k])=>k!=='ins').map(([,v])=>v).join('')!==before)throw Error('lost old text');
        if(parts.filter(([k])=>k!=='del').map(([,v])=>v).join('')!==after)throw Error('lost new text');
      }
      return {samples:samples.length,milliseconds:performance.now()-start};
    }""")
    assert result["milliseconds"] < 5000, result
    page.evaluate("""({before,after})=>{
      const box=document.createElement('div');box.id='review-fixture';document.body.append(box);
      box.append(TgWitnessReview.compare(before,after,s=>s));
    }""", fixture)
    comparison = page.locator("#review-fixture")
    expect(comparison.get_by_text("Hidden links changed", exact=True)).to_be_visible()
    expect(comparison.get_by_text("Buttons changed", exact=True)).to_be_visible()
    comparison.get_by_role("button", name="Side by side").click()
    expect(comparison.locator(".review-split pre").first).to_have_text(fixture["before"]["text"])
    comparison.get_by_role("button", name="Raw", exact=True).click()
    expect(comparison.locator("pre").first).to_contain_text("MessageEntityTextUrl")
    page.evaluate("""()=>{
      const payload={text:'<img src=x onerror="window.reviewXss=1"><script>window.reviewXss=2</script>',
        entities:[{type:'url',url:'javascript:window.reviewXss=3'}],buttons:{text:'<svg onload=alert(1)>'}};
      document.querySelector('#review-fixture').replaceChildren(TgWitnessReview.compare({text:''},payload,s=>s));
    }""")
    expect(comparison.locator("img,script,svg,a")).to_have_count(0)
    assert page.evaluate("window.reviewXss===undefined")
    cases = [
        ({"buttons": {"rows": [[{"type": "callback", "text": "Pay", "data_base64": "YQ=="}]]}},
         {"buttons": {"rows": [[{"type": "callback", "text": "Pay", "data_base64": "Yg=="}]]}}, "Buttons changed"),
        ({"buttons": {"rows": [[{"type": "copy", "text": "Copy", "copy_text": "old wallet"}]]}},
         {"buttons": {"rows": [[{"type": "copy", "text": "Copy", "copy_text": "new wallet"}]]}}, "Buttons changed"),
        ({"raw": {"reply_markup": {"rows": [{"buttons": [{"text": "Pay", "type": {
            "_": "InlineButtonTypeUrl", "url": "https://old.example"}}]}]}}},
         {"raw": {"reply_markup": {"rows": [{"buttons": [{"text": "Pay", "type": {
             "_": "InlineButtonTypeUrl", "url": "https://new.example"}}]}]}}}, "Buttons changed"),
        ({"raw": {"entities": [{"_": "MessageEntityMentionName", "offset": 0, "length": 3, "user_id": 11}]}},
         {"raw": {"entities": [{"_": "MessageEntityMentionName", "offset": 0, "length": 3, "user_id": 22}]}},
         "Hidden links changed"),
        ({"entities": [{"offset": 0, "length": 4, "url": "https://same.example"}]},
         {"entities": [{"offset": 5, "length": 4, "url": "https://same.example"}]}, "Hidden links changed"),
        ({"buttons": {"rows": [[{"type": "url", "text": "Open", "url": "https://same.example"}]]}},
         {"buttons": {"rows": [[{"type": "web_app", "text": "Open", "url": "https://same.example"}]]}},
         "Buttons changed"),
    ]
    for before, after, label in cases:
        page.evaluate("""({before,after})=>document.querySelector('#review-fixture').replaceChildren(
          TgWitnessReview.compare({text:'same text',...before},{text:'same text',...after},s=>s))""",
                      {"before": before, "after": after})
        expect(comparison.get_by_text(label, exact=True)).to_be_visible()
    result["destination_cases"] = len(cases)
    comparison.evaluate("n=>n.remove()")
    return result


def review_drawer(page, fixture, output):
    page.evaluate("navigate('observations')")
    page.evaluate("seq=>openRecord(seq)", fixture["edited"]["seq"])
    drawer = page.locator("#detail-drawer")
    expect(drawer.locator(".review-diff")).to_be_visible()
    expect(drawer.get_by_text("Hidden links changed", exact=True)).to_be_visible()
    expect(drawer.get_by_text("Buttons changed", exact=True)).to_be_visible()
    for width in (1440, 390):
        page.set_viewport_size({"width": width, "height": 960 if width > 600 else 844})
        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
        page.screenshot(path=str(output / f"diff-{width}.png"))
    page.set_viewport_size({"width": 1440, "height": 960})
    drawer.get_by_role("button", name="SHA-256", exact=True).click()
    assert page.evaluate("navigator.clipboard.readText()") == fixture["edited"]["hash"]
    drawer.get_by_role("button", name="Link to this record", exact=True).click()
    copied = page.evaluate("navigator.clipboard.readText()")
    assert "/journal/event/" + str(fixture["edited"]["seq"]) in copied and "ws=default" in copied
    current = fixture["edited"]["seq"]
    next_seq = page.evaluate("state.events[state.events.findIndex(e=>e.seq===state.drawerSeq)+1].seq")
    page.keyboard.press("j")
    page.wait_for_function("seq=>state.drawerSeq===seq", arg=next_seq)
    page.keyboard.press("k")
    page.wait_for_function("seq=>state.drawerSeq===seq", arg=current)
    page.evaluate("""()=>{const input=document.createElement('input');input.id='typing-guard';
      document.querySelector('#detail-content').append(input);input.focus();}""")
    page.keyboard.press("j")
    expect(page.locator("#typing-guard")).to_have_value("j")
    assert page.evaluate("state.drawerSeq") == current
    page.locator("#typing-guard").evaluate("n=>n.remove()")
    page.keyboard.press("Escape")
    expect(drawer).to_be_hidden()


def media_checks(page, server, fixture, output):
    page.evaluate("seq=>openRecord(seq)", fixture["media"]["seq"])
    drawer = page.locator("#detail-drawer")
    expect(drawer.locator(".review-preview img")).to_be_visible()
    drawer.locator(".review-image-button").click()
    lightbox = page.locator(".media-lightbox")
    expect(lightbox).to_be_visible()
    expect(lightbox.get_by_role("button", name="Close", exact=True)).to_be_focused()
    lightbox.get_by_role("button", name="Zoom", exact=True).click()
    expect(lightbox).to_have_class("media-lightbox zoomed")
    page.screenshot(path=str(output / "media-1440.png"))
    page.keyboard.press("Escape")
    expect(lightbox).to_have_count(0)
    expect(drawer.locator(".review-image-button")).to_be_focused()
    page.keyboard.press("Escape")
    expect(drawer).to_be_hidden()

    result = page.evaluate("""async()=>{
      const box=document.createElement('div');box.id='preview-fixture';document.body.append(box);
      let calls=0,cancelled=0;
      const config={api:async()=>{calls++;return new Response('<svg onload=alert(1)>',{headers:{'content-type':'image/svg+xml'}});},
        tr:s=>s,download:async()=>{},busy:async(button,fn)=>fn()};
      const el=TgWitnessReview.attachment({sha256:'f'.repeat(64)},config);box.append(el);el.querySelector('button').click();
      await new Promise(resolve=>setTimeout(resolve,40));
      const unsafeBlocked=!el.querySelector('img,iframe,svg')&&el.textContent.includes('Preview unavailable');
      config.api=async()=>new Response(new ReadableStream({pull(controller){controller.enqueue(new Uint8Array(1024*1024));},cancel(){cancelled++;}}),{headers:{'content-type':'image/png'}});
      const huge=TgWitnessReview.attachment({sha256:'e'.repeat(64)},config);box.append(huge);huge.querySelector('button').click();
      for(let i=0;i<100&&!cancelled;i++)await new Promise(resolve=>setTimeout(resolve,10));
      box.remove();return {unsafeBlocked,cancelled,calls};
    }""")
    assert result == {"unsafeBlocked": True, "cancelled": 1, "calls": 1}, result
    page.evaluate("TgWitnessReview.clear()")
    lifecycle = page.evaluate("""async digest=>{
      const response=await api('media/'+digest+'?inline=1'),bytes=await response.arrayBuffer();
      const picture=()=>new Response(bytes.slice(0),{headers:{'content-type':'image/png'}});
      const box=document.createElement('div');box.id='preview-lifecycle';document.body.append(box);
      const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
      const until=async test=>{for(let i=0;i<200&&!test();i++)await sleep(10);if(!test())throw Error('preview fixture timed out');};
      const config={api:async()=>picture(),tr:s=>s,download:async()=>{},busy:async(button,fn)=>fn()};
      let calls=0;
      const flaky=TgWitnessReview.attachment({sha256:'d'.repeat(64)},
        {...config,api:async()=>{if(++calls===1)throw Error('transient');return picture();}});
      box.append(flaky);flaky.querySelector('button').click();await until(()=>flaky.textContent.includes('Preview unavailable'));
      flaky.querySelector('button').click();await until(()=>flaky.querySelector('img'));
      const retryRecovered=calls===2;
      const items=[];
      for(let i=1;i<=42;i++){
        const item=TgWitnessReview.attachment({sha256:i.toString(16).padStart(64,'0')},config);
        box.append(item);item.querySelector('button').click();
        await until(()=>item.querySelector('img')||item.textContent.includes('Preview unavailable'));items.push(item);
      }
      const bounded=box.querySelectorAll('img').length<=40;
      items[0].querySelector('.review-image-button').click();
      await until(()=>document.querySelector('.media-lightbox img')?.naturalWidth>0);
      const evictedImageReopened=true;document.querySelector('.media-lightbox').close();
      flaky.remove();items.slice(0,10).forEach(item=>item.remove());
      if(!items.at(-1).querySelector('img'))items.at(-1).querySelector('button').click();
      await until(()=>items.at(-1).querySelector('img'));
      let release;
      const pending=TgWitnessReview.attachment({sha256:'c'.repeat(64)},
        {...config,api:()=>new Promise(resolve=>release=resolve)});
      box.append(pending);pending.querySelector('button').click();await until(()=>release);
      TgWitnessReview.clear();release(picture());await sleep(40);
      const staleBlocked=!pending.querySelector('img');box.remove();
      return {retryRecovered,evictedImageReopened,staleBlocked,bounded};
    }""", fixture["digest"])
    assert lifecycle == {"retryRecovered": True, "evictedImageReopened": True, "staleBlocked": True,
                         "bounded": True}, lifecycle


def source_checks(page, server, output):
    page.evaluate("navigate('sources')")
    page.locator("#sources-tab-chats").click()
    expect(page.locator("#target-list .target-row")).to_have_count(2)
    page.locator("#target-search").fill("Harbor")
    expect(page.locator("#target-list .target-row")).to_have_count(1)
    page.locator("#target-list .source-select").check()
    page.locator("#target-bulk-action").select_option("pause")
    page.locator("#target-bulk-apply").click()
    expect(page.locator("#target-list .source-state")).to_have_text("Paused")
    assert not server.app.state.store.targets()[0]["enabled"]
    page.locator("#target-filter").select_option("paused")
    expect(page.locator("#target-list .target-row")).to_have_count(1)
    page.locator("#target-search").fill("")
    page.locator("#target-filter").select_option("")
    page.locator("#load-dialogs").click()
    expect(page.locator("#dialog-list .target-row")).to_have_count(3)
    page.locator("#dialog-search").fill("New research")
    page.locator("#dialog-bulk-actions").get_by_role("button", name="Add all matching").click()
    expect(page.locator("#target-list .target-row")).to_have_count(3)
    page.locator("#finish-source-selection").click()
    page.locator("#target-list .source-select").first.check()
    for width in (1440, 390):
        page.set_viewport_size({"width": width, "height": 960 if width > 600 else 844})
        page.locator("#target-list").evaluate("""n=>window.scrollTo(0,
          n.closest('.card').getBoundingClientRect().top+scrollY-(innerWidth>600?74:14))""")
        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
        for row in page.locator("#target-list .target-row").all():
            check, heading = row.locator(".source-select").bounding_box(), row.locator("strong").bounding_box()
            assert heading["x"] - check["x"] - check["width"] < 36, "Source title floats away from its checkbox"
        page.screenshot(path=str(output / f"sources-{width}.png"))
    page.set_viewport_size({"width": 1440, "height": 960})


def palette_checks(page):
    page.keyboard.press("Control+k")
    page.locator("#quick-search").fill("Harbor")
    page.locator(f"#quick-option-chat-{CHAT}").click()
    expect(page.locator("#chat-name")).to_contain_text("Harbor")
    page.keyboard.press("Control+k")
    page.locator("#quick-search").fill("invoice")
    page.locator("#quick-option-journal").click()
    expect(page.locator("#event-search")).to_have_value("invoice")
    expect(page.locator("#events-body tr").first).to_be_visible()
    child = page.evaluate("""async()=>{const child=await json('profiles',{label:'Second investigation'},{root:true});
      await loadProfiles();return child.id;}""")
    page.keyboard.press("Control+k")
    page.locator("#quick-search").fill("Second investigation")
    page.locator("#quick-option-workspace-" + child).click()
    expect(page.locator("#profile-select")).to_have_value(child)
    page.wait_for_function("()=>!document.querySelector('#workspace').inert")
    page.keyboard.press("Control+k")
    page.locator("#quick-search").fill("Main account")
    expect(page.locator("#quick-option-workspace-default")).to_be_visible()
    page.locator("#quick-option-workspace-default").click()
    expect(page.locator("#profile-select")).to_have_value("default")
    # Wait for the final syncLive before installing the synthetic stream.
    page.wait_for_function("()=>state.profile==='default'&&!document.querySelector('#workspace').inert")


def live_checks(page):
    result = page.evaluate(r"""async()=>{
      TgWitnessLive.stop();
      let refreshes=0,release=null,active=0,maxActive=0;
      const streams=[],sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
      const until=async test=>{for(let i=0;i<200&&!test();i++)await sleep(10);if(!test())throw Error('live fixture timed out');};
      const api=async(path,body,{signal})=>new Response(new ReadableStream({start(controller){
        active++;maxActive=Math.max(maxActive,active);streams.push(controller);
        signal.addEventListener('abort',()=>{active--;try{controller.error(new DOMException('Aborted','AbortError'));}catch{}});
      }}),{headers:{'content-type':'text/event-stream'}});
      const send=seq=>streams.at(-1).enqueue(new TextEncoder().encode('event: journal\ndata: '+JSON.stringify([{seq}])+'\n\n'));
      TgWitnessLive.start({key:'fixture',head:0,api,tr:(s,v)=>v?s.replace('{n}',v.n):s,
        accessEnded:()=>{},canRefresh:()=>true,refresh:async()=>{refreshes++;if(refreshes===1)await new Promise(resolve=>release=resolve);}});
      await until(()=>streams.length===1);send(1);await until(()=>release);
      send(2);await sleep(300);release();await until(()=>refreshes===2);
      document.dispatchEvent(new Event('visibilitychange'));await sleep(30);
      document.dispatchEvent(new Event('visibilitychange'));await sleep(30);
      const singleConnection=active===1&&maxActive===1;
      TgWitnessLive.stop();await sleep(30);
      return {refreshes,singleConnection,activeAfterStop:active};
    }""")
    assert result == {"refreshes": 2, "singleConnection": True, "activeAfterStop": 0}, result
    page.evaluate("syncLive()")


def stream_and_scope(page, context, server, fixture):
    page.evaluate("""async()=>{state.search='';document.querySelector('#event-search').value='';
      navigate('observations');await refreshEvents();}""")
    toggle = page.locator(".journal .live-toggle")
    expect(toggle).to_have_attribute("aria-pressed", "true")
    toggle.click()
    expect(toggle).to_have_attribute("aria-pressed", "false")
    saved = server.app.state.store.append("message.new", {"text": "Fresh invoice notification", "sender_id": 44}, CHAT, 90, 44)
    expect(page.locator(".journal .live-new")).to_be_visible(timeout=10000)
    assert not page.evaluate("seq=>state.events.some(e=>e.seq===seq)", saved["seq"])
    page.locator(".journal .live-new").click()
    page.wait_for_function("seq=>state.events.some(e=>e.seq===seq)", arg=saved["seq"])
    toggle.click()

    grant = page.evaluate("""chat=>json('access/grants',{label:'Scoped analyst',permissions:['view'],
      workspaces:{default:[chat]}},{root:true})""", CHAT)
    viewer = context.new_page()
    viewer.goto(server.url)
    viewer.locator("#panel-token").fill(grant["token"])
    viewer.get_by_role("button", name="Open workspace").click()
    expect(viewer.locator("#workspace")).to_be_visible()
    expect(viewer.locator("#chats-list")).not_to_contain_text("Private case")
    head = server.app.state.store.stats()["head"]["seq"]
    hidden = server.app.state.store.append("message.new", {"text": "Hidden new data"}, OTHER, 91)
    visible = server.app.state.store.append("message.new", {"text": "Visible new data"}, CHAT, 92)
    records = viewer.evaluate(r"""async head=>{
      const control=new AbortController(),response=await api('stream?after='+head,undefined,{signal:control.signal});
      const reader=response.body.getReader(),decode=new TextDecoder();let text='';
      try{for(let n=0;n<20;n++){const result=await reader.read();text+=decode.decode(result.value||new Uint8Array());
        const line=text.split('\n').find(line=>line.startsWith('data: '));if(line)return JSON.parse(line.slice(6));}
      }finally{control.abort();await reader.cancel().catch(()=>{});reader.releaseLock();}
      throw Error('No journal frame');
    }""", head)
    assert [record["seq"] for record in records] == [visible["seq"]]
    assert hidden["seq"] not in [record["seq"] for record in records]
    other_data = b"<html>hidden scope attachment</html>"
    digest = hashlib.sha256(other_data).hexdigest()
    (server.app.state.store.root / "media" / digest).write_bytes(other_data)
    server.app.state.store.append("media.saved", {"media_sha256": digest}, OTHER, 91)
    assert viewer.evaluate("""async digest=>{try{await api('media/'+digest+'?inline=1');return 200;}
      catch(error){return error.status;}}""", digest) == 404
    assert viewer.evaluate("async digest=>(await api('media/'+digest+'?inline=1')).status", fixture["digest"]) == 200
    page.evaluate("id=>api('access/grants/'+id,undefined,{root:true,method:'DELETE'})", grant["id"])
    expect(viewer.locator("#gate")).to_be_visible(timeout=10000)
    assert not viewer.evaluate("TgWitnessLive.active()")
    viewer.close()


def batch_lock(page):
    page.evaluate("navigate('sources')")
    page.locator("#sources-tab-chats").click()
    page.locator("#target-list .source-select").first.check()
    hold_api_response(page, "/targets/batch")
    page.locator("#target-bulk-action").select_option("pause")
    page.locator("#target-bulk-apply").click()
    expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
    for button in page.locator("#target-bulk-actions button").all():
        expect(button).to_be_disabled()
    page.evaluate("lock()")
    release_api_response(page)
    expect(page.locator("#gate")).to_be_visible()
    expect(page.locator("#workspace")).to_be_hidden()
    expect(page.locator("#target-list .source-select")).to_have_count(0)
    expect(page.locator("#target-bulk-actions")).to_be_hidden()


def main():
    output = ROOT / "test-results/analyst-browser"
    output.mkdir(parents=True, exist_ok=True)
    errors, external = [], []
    with tempfile.TemporaryDirectory(prefix="analyst-browser-") as scratch:
        server = RunningApp(Path(scratch), client_factory=AnalystClient)
        with server, sync_playwright() as p:
            fixture = seed(server)
            browser = launch_browser(p)
            context = browser.new_context(viewport={"width": 1440, "height": 960}, reduced_motion="reduce",
                                          permissions=["clipboard-read", "clipboard-write"])
            context.on("page", lambda opened: opened.on("pageerror", lambda error: errors.append(str(error))))
            page = context.new_page()

            def local(route):
                if route.request.url.startswith(server.url + "/"):
                    route.continue_()
                else:
                    external.append(route.request.url)
                    route.abort()

            context.route("**/*", local)
            unlock(page, server)
            result = diff_checks(page, fixture)
            review_drawer(page, fixture, output)
            media_checks(page, server, fixture, output)
            source_checks(page, server, output)
            palette_checks(page)
            live_checks(page)
            stream_and_scope(page, context, server, fixture)
            batch_lock(page)
            expect(page.locator("#gate")).to_be_visible()
            expect(page.locator(".media-lightbox")).to_have_count(0)
            assert not page.evaluate("TgWitnessLive.active()")
            assert not errors, errors
            assert not external, external
            browser.close()
    receipt = {"passed": True, "diff": result, "errors": errors, "external": external}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
