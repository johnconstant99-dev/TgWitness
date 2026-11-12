export function createExports({root, tr, json, getSession, fmtTime, toast,downloadAgain,onTab}) {
  const find = id => root.querySelector('#'+id), tabs = [...root.querySelectorAll('[data-export-tab]')];
  let session = getSession(), request = 0, transfer = 0, selected = 'downloads', entries = [];
  const bytes = size => size < 1024 ? tr('{n} B',{n:size}) : size < 1048576
    ? tr('{n} KiB',{n:(size/1024).toFixed(1)}) : tr('{n} MiB',{n:(size/1048576).toFixed(1)});
  const make = (tag, text='', cls='') => {
    const el = document.createElement(tag);el.textContent=text;if(cls)el.className=cls;return el;
  };
  const encryptionLabel=make('label',tr('Password encryption')),encryption=make('select'),encryptionHint=make('p','','hint');
  encryption.id='export-encryption';encryptionLabel.htmlFor=encryption.id;
  encryption.append(new Option(tr('ZIP (7-Zip / WinRAR)'),'zip'),
    new Option(tr('Stronger encryption (scrypt + AES-GCM, requires verify.py to open)'),'tgwpw'));
  encryptionHint.id='export-encryption-hint';encryption.setAttribute('aria-describedby',encryptionHint.id);
  const encryptionText=()=>{encryptionHint.textContent=tr(encryption.value==='tgwpw'
    ? 'Open with an independently obtained verify.py: python verify.py unseal-password export.tgwpw --out output-file. Then verify the decrypted evidence.'
    : 'ZIP password protection uses WinZip AES (weak key stretching). Use a long random passphrase of 20+ characters, or sealed delivery for sensitive exports.');};
  encryption.addEventListener('change',encryptionText);encryptionText();
  find('export-password-field').append(encryptionLabel,encryption,encryptionHint);
  const retryButton=make('button',tr('Retry export'),'secondary');retryButton.type='button';retryButton.hidden=true;
  retryButton.id='exports-retry';find('exports-progress').append(retryButton);
  function renderTimes() {
    for(const time of root.querySelectorAll('.export-receipt time')){
      time.textContent=fmtTime(time.dateTime);time.title=time.textContent;
    }
    find('exports-last').textContent=entries.length?tr('Latest: {size} · {time}',{
      size:bytes(entries[0].bytes),time:fmtTime(entries[0].created_at)}):'';
  }
  window.addEventListener('tgwitness:time-zone',renderTimes);
  function select(name, focus=false, {history=true}={}) {
    selected = name === 'settings' ? 'settings' : 'downloads';
    for (const button of tabs) {
      const active = button.dataset.exportTab === selected;
      button.setAttribute('aria-selected',String(active));button.tabIndex=active?0:-1;
      if(active&&focus)button.focus();
    }
    find('exports-downloads').hidden=selected!=='downloads';find('report-form').hidden=selected!=='settings';
    if(history)onTab?.(selected);
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
          const detail=make('details'),summary=make('summary',tr('SHA-256'));detail.append(summary,hash,copy);row.append(detail);
          if(entry.cache_warning)row.append(make('p',tr(entry.cache_warning),'hint'));
          if(entry.available&&entry.id){const again=make('button',tr('Download again'),'secondary');again.type='button';
            again.addEventListener('click',async()=>{again.disabled=true;try{await downloadAgain(entry);}catch(error){toast(error.message,true);}finally{again.disabled=false;}});row.append(again);}
          return row;
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
  function begin({format='zip',encrypted=false,encryption='zip',retry=null}={}) {
    const owner=getSession(), mine=++transfer;
    retryButton.hidden=true;retryButton.onclick=()=>{if(owner===getSession()&&mine===transfer)retry?.();};
    select('downloads');find('exports-progress').hidden=false;
    find('exports-next').hidden=true;
    find('exports-progress-bar').hidden=false;
    find('exports-progress-label').textContent=tr('Confirm');
    find('exports-progress-bar').removeAttribute('value');find('exports-progress-bytes').textContent='';
    return update=>{
      if(owner!==getSession()||mine!==transfer)return;
      const labels={preparing:tr('Checking journal integrity and preparing the export…'),saving:tr('Saving export…'),done:tr('Export saved.'),browser:tr('Download started. Check your browser’s downloads.'),cancelled:tr('Download cancelled.'),failed:tr('Download failed. Retry the export.')};
      if(labels[update.phase])find('exports-progress-label').textContent=labels[update.phase];
      if(update.total!==undefined)find('exports-progress-bytes').textContent=update.expected
        ? tr('{saved} of {total}',{saved:bytes(update.total),total:bytes(update.expected)}):bytes(update.total);
      const bar=find('exports-progress-bar');
      if(update.expected){bar.max=update.expected;bar.value=update.total||0;}
      if(['done','browser'].includes(update.phase)){
        bar.max=1;bar.value=1;void load();
        find('exports-next-copy').textContent=tr(format==='zip'
          ? 'Extract the ZIP and open report.html. Review coverage gaps and personal information. README.txt explains how to check integrity with an independently obtained signing-key fingerprint.'
          : format==='html'
          ? 'Open the HTML report in your browser. Review coverage gaps and personal information before sending the unchanged file.'
          : 'Review this data file in a compatible tool. Download the signed ZIP when your recipient also needs the readable report and verification tools.');
        find('exports-next-encrypted').textContent=tr(encryption==='tgwpw'
          ? 'Open with an independently obtained verify.py: python verify.py unseal-password export.tgwpw --out output-file. Then verify the decrypted evidence.'
          : 'Open the encrypted ZIP with 7-Zip or WinRAR and the password. Keep the password separate from the file.');
        find('exports-next-encrypted').hidden=!encrypted;find('exports-next').hidden=false;
      }
      if(['failed','cancelled'].includes(update.phase)){bar.hidden=true;if(update.error)find('exports-progress-bytes').textContent=update.error;void load();}
      else bar.hidden=false;
      retryButton.hidden=update.phase!=='failed'||!retry;
    };
  }
  return {load,select,begin,get tab(){return selected;},leave(){request++;find('exports-history-refresh').disabled=false;},resetSession(){
    session=getSession();request++;transfer++;entries=[];select('downloads',false,{history:false});find('exports-progress').hidden=true;find('exports-next').hidden=true;
    retryButton.hidden=true;retryButton.onclick=null;
    find('exports-history-list').replaceChildren();delete find('exports-history-list').dataset.stamp;
    find('exports-last').textContent=find('exports-history-status').textContent='';
  },destroy(){window.removeEventListener('tgwitness:time-zone',renderTimes);},
    enter(options){if(session!==getSession())this.resetSession();return load(options);}};
}
