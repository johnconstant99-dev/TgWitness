/** Download receipts and progress; report drafts remain owned by their form. */
export function createExports({root, tr, json, getSession, fmtTime, toast}) {
  const find = id => root.querySelector('#'+id), tabs = [...root.querySelectorAll('[data-export-tab]')];
  let session = getSession(), request = 0, transfer = 0, selected = 'downloads', entries = [];
  const bytes = size => size < 1024 ? tr('{n} B',{n:size}) : size < 1048576
    ? tr('{n} KiB',{n:(size/1024).toFixed(1)}) : tr('{n} MiB',{n:(size/1048576).toFixed(1)});
  const make = (tag, text='', cls='') => {
    const el = document.createElement(tag);el.textContent=text;if(cls)el.className=cls;return el;
  };
  function renderTimes() {
    for(const time of root.querySelectorAll('.export-receipt time')){
      time.textContent=fmtTime(time.dateTime);time.title=time.textContent;
    }
    find('exports-last').textContent=entries.length?tr('Latest: {size} · {time}',{
      size:bytes(entries[0].bytes),time:fmtTime(entries[0].created_at)}):'';
  }
  window.addEventListener('tgwitness:time-zone',renderTimes);
  function select(name, focus=false) {
    selected = name === 'settings' ? 'settings' : 'downloads';
    for (const button of tabs) {
      const active = button.dataset.exportTab === selected;
      button.setAttribute('aria-selected',String(active));button.tabIndex=active?0:-1;
      if(active&&focus)button.focus();
    }
    find('exports-downloads').hidden=selected!=='downloads';find('report-form').hidden=selected!=='settings';
  }
  for(const button of tabs) {
    button.addEventListener('click',()=>select(button.dataset.exportTab));
    button.addEventListener('keydown',event=>{
      if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;
      event.preventDefault();select(event.key==='Home'?'downloads':event.key==='End'?'settings':selected==='downloads'?'settings':'downloads',true);
    });
  }
  async function load(options={}) {
    const mine=++request, owner=getSession();
    find('exports-history-refresh').disabled=true;
    try {
      const result=await json('exports/history',undefined,options);
      if(owner!==getSession()||mine!==request)return;
      const list=find('exports-history-list');entries=result.exports||[];
      const stamp=JSON.stringify(entries);
      if(list.dataset.stamp!==stamp) {
        const rows=entries.map(entry=>{
          const row=make('div','','export-receipt'),label=make('strong',entry.format.toUpperCase());
          const time=make('time');time.dateTime=entry.created_at;
          row.append(label,make('span',entry.encrypted?tr('Encrypted'):tr('Plain file'),'hint'),
            time,make('span',bytes(entry.bytes)));
          const hash=make('code',entry.sha256),copy=make('button',tr('Copy SHA-256'),'quiet');
          copy.type='button';copy.addEventListener('click',async()=>{
            try{await navigator.clipboard.writeText(entry.sha256);toast(tr('Hash copied.'));}catch{toast(tr('Could not copy. Select and copy the hash.'),true);}
          });
          const detail=make('details'),summary=make('summary',tr('SHA-256'));detail.append(summary,hash,copy);row.append(detail);return row;
        });
        list.replaceChildren(...rows);list.dataset.stamp=stamp;
      }
      renderTimes();
      find('exports-history-status').textContent=entries.length?'':tr('No exports prepared yet. Choose a format above.');
    }catch(error){
      if(owner===getSession()&&mine===request&&!['AbortError','StaleView'].includes(error.name))find('exports-history-status').textContent=error.message;
    }finally{if(owner===getSession()&&mine===request)find('exports-history-refresh').disabled=false;}
  }
  find('exports-history-refresh').addEventListener('click',()=>load());
  function begin() {
    const owner=getSession(), mine=++transfer;
    select('downloads');find('exports-progress').hidden=false;
    find('exports-progress-label').textContent=tr('Checking journal integrity and preparing the export…');
    find('exports-progress-bar').removeAttribute('value');find('exports-progress-bytes').textContent='';
    return update=>{
      if(owner!==getSession()||mine!==transfer)return;
      const labels={saving:tr('Saving export…'),done:tr('Export saved.'),cancelled:tr('Download cancelled.'),failed:tr('Download failed. Retry the export.')};
      if(labels[update.phase])find('exports-progress-label').textContent=labels[update.phase];
      if(update.total!==undefined)find('exports-progress-bytes').textContent=update.expected
        ? tr('{saved} of {total}',{saved:bytes(update.total),total:bytes(update.expected)}):bytes(update.total);
      const bar=find('exports-progress-bar');
      if(update.expected){bar.max=update.expected;bar.value=update.total||0;}
      if(update.phase==='done'){bar.max=1;bar.value=1;void load();}
      if(['failed','cancelled'].includes(update.phase)){bar.hidden=true;if(update.error)find('exports-progress-bytes').textContent=update.error;}
      else bar.hidden=false;
    };
  }
  return {load,select,begin,leave(){request++;find('exports-history-refresh').disabled=false;},resetSession(){
    session=getSession();request++;transfer++;entries=[];select('downloads');find('exports-progress').hidden=true;
    find('exports-history-list').replaceChildren();delete find('exports-history-list').dataset.stamp;
    find('exports-last').textContent=find('exports-history-status').textContent='';
  },destroy(){window.removeEventListener('tgwitness:time-zone',renderTimes);},
    enter(options){if(session!==getSession())this.resetSession();return load(options);}};
}
