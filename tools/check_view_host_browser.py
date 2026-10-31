"""View lifecycle checks in a real DOM, using no accounts or application APIs."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
from threading import Thread

from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_browser import launch_browser


class Assets(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/fixture":
            body = b"<!doctype html><html><title>View lifecycle fixture</title><body></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def log_message(self, *args):
        pass


def main():
    static = Path(__file__).resolve().parents[1] / "tgwitness" / "static"
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Assets, directory=str(static)))
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(f"http://127.0.0.1:{server.server_port}/fixture")
            result = page.evaluate("""async()=>{
              const {createViewHost}=await import('/core/view-host.js');
              const assert=(value,label)=>{if(!value)throw new Error(label);};
              const deferred=()=>{let resolve;const promise=new Promise(done=>resolve=done);return {promise,resolve};};
              const roots={},counts={},last={},reported=[];
              let workspace='A';
              const host=createViewHost({getSession:()=>({workspace}),onError:error=>reported.push(error.message)});
              for(const name of ['chats','journal','settings']){
                const root=document.createElement('section');root.id='view-'+name;
                root.innerHTML='<input id="draft:'+name+'"><button>Save</button><output></output>';
                document.body.append(root);roots[name]=root;
                counts[name]={mount:0,leave:0,status:0,reset:0,destroy:0,click:0};
                host.register(name,root,{
                  mount(){counts[name].mount++;root.querySelector('button').addEventListener('click',()=>counts[name].click++);},
                  async enter(context){
                    last[name]=context;
                    if(context.params.wait)await context.params.wait;
                    if(context.current())root.querySelector('output').textContent=context.session.workspace;
                  },
                  updateStatus(status,context){
                    assert(context.current(),'status context must still be current');
                    counts[name].status++;root.dataset.status=status.phase;
                    if(status.fail)throw new Error('expected status failure');
                  },
                  leave(){counts[name].leave++;},
                  resetSession(){counts[name].reset++;root.querySelector('input').value='';root.querySelector('output').textContent='';},
                  destroy(){counts[name].destroy++;},
                });
              }
              const refs=host.references('settings');
              assert(refs.byId('draft:settings')===roots.settings.querySelector('input'),'escaped ids are scoped to their root');
              assert(refs.byId('view-settings')===roots.settings,'root lookup');
              assert(refs.queryAll('button').length===1,'scoped query list');
              assert(host.references('missing')===null,'unknown refs');
              assert(await host.activate('chats'),'initial activation');
              assert(host.active==='chats'&&document.querySelectorAll('section').length===1,'only active view remains attached');
              host.updateStatus({phase:'recording'});
              assert(counts.chats.status===1&&counts.journal.status===0&&counts.settings.status===0,'inactive views are not rendered');
              await host.activate('settings');
              refs.byId('draft:settings').value='unsaved note';
              refs.query('button').click();
              await host.activate('journal');
              assert(!roots.settings.isConnected&&refs.byId('draft:settings').value==='unsaved note','draft survives detachment');
              await host.activate('settings');
              await host.activate('settings');
              refs.query('button').click();
              assert(counts.settings.mount===1&&counts.settings.click===2,'listeners bind once across reentry');
              assert(refs.byId('draft:settings').value==='unsaved note','same view does not reset draft');
              assert(Object.isFrozen(last.settings.session),'session snapshot is immutable');

              const aborted=new AbortController();aborted.abort();
              const previousContext=last.settings;
              assert(!await host.activate('journal',{signal:aborted.signal}),'cancelled navigation returns false');
              assert(host.active==='settings'&&previousContext.current(),'cancelled navigation preserves active work');

              const delayed=deferred();
              const slow=host.activate('chats',{params:{wait:delayed.promise}});
              const oldContext=last.chats;
              await host.activate('journal');
              assert(oldContext.signal.aborted&&!oldContext.current(),'leaving aborts stale work');
              delayed.resolve();assert(!await slow,'late completion cannot win');
              assert(host.active==='journal'&&roots.journal.querySelector('output').textContent==='A','new view remains active');

              const parentSignal=new AbortController();
              await host.activate('chats',{signal:parentSignal.signal});
              const statusBefore=counts.chats.status;
              parentSignal.abort();host.updateStatus({phase:'paused'});
              assert(!last.chats.current()&&counts.chats.status===statusBefore,'external cancellation stops updates');
              await host.activate('journal');
              host.updateStatus({phase:'error',fail:true});
              assert(reported.join(',')==='expected status failure','status errors are reported');

              const pending=deferred();
              const previousSession=host.activate('chats',{params:{wait:pending.promise}});
              host.resetSession();workspace='B';
              assert(host.active===null&&document.querySelectorAll('section').length===0,'workspace reset detaches every view');
              for(const name of Object.keys(roots)){
                assert(counts[name].reset===1,'all view state resets, including detached '+name);
                assert(roots[name].querySelector('input').value===''&&roots[name].querySelector('output').textContent==='','private data cleared '+name);
              }
              await host.activate('journal');pending.resolve();
              assert(!await previousSession,'old workspace completion is ignored');
              assert(roots.journal.querySelector('output').textContent==='B','new workspace data stays visible');
              assert(roots.chats.querySelector('output').textContent==='','old workspace did not repopulate detached view');
              assert(counts.journal.mount===1,'reset retains one-time bindings');

              const bad=document.createElement('section');document.body.append(bad);
              let attempts=0;
              host.register('bad',bad,{mount(){if(++attempts===1)throw new Error('expected mount failure');}});
              try{await host.activate('bad');throw new Error('mount must fail');}catch(error){assert(error.message==='expected mount failure','mount error propagates');}
              assert(host.active===null&&!bad.isConnected,'failed mount leaves no active broken view');
              assert(await host.activate('bad')&&attempts===2,'mount can retry after failure');
              await host.activate('settings');
              const dying=deferred();const dyingView=host.activate('chats',{params:{wait:dying.promise}});
              host.destroy();host.destroy();dying.resolve();
              assert(!await dyingView,'destroy aborts pending work');
              assert(host.active===null&&document.body.childNodes.length===0,'destroy removes roots and anchors');
              assert(Object.values(counts).every(count=>count.destroy===1),'destroy called exactly once');
              assert(host.references('chats')===null&&!host.isMounted('chats'),'disposed refs removed');
              return {views:Object.keys(roots).length,checks:'detach, drafts, active status, cancellation, workspace reset, mount retry, disposal'};
            }""")
            assert not errors, errors
            browser.close()
            print("View host passed:", result["checks"])
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


if __name__ == "__main__":
    main()
