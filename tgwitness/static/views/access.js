const rights={reviewer:['view'],analyst:['view','export'],operator:['view','export','sources','settings']};

export function createAccessView({root,tr,navigate,localInput,getState}) {
  const find=id=>root.querySelector('#'+id),listeners=new AbortController();
  const on=(node,event,fn)=>node.addEventListener(event,fn,{signal:listeners.signal});
  const tabs=[...root.querySelectorAll('[data-access-tab]')];
  let current='grants';
  function showTab(name,focus=false){
    if(name==='console'){navigate('system-log');return;}
    if(!['grants','sessions','limits'].includes(name))name='grants';
    current=name;
    for(const tab of tabs){const selected=tab.dataset.accessTab===name;tab.setAttribute('aria-selected',String(selected));tab.tabIndex=selected?0:-1;if(focus&&selected)tab.focus();}
    for(const panel of root.querySelectorAll('[data-access-panel]'))panel.hidden=panel.dataset.accessPanel!==name;
  }
  function workspaceFilter(){
    const query=find('access-workspace-search').value.trim().toLowerCase(),only=find('access-workspace-picked').checked;
    let selected=0,shown=0,total=0;
    for(const row of find('access-workspaces').children){
      const input=row.querySelector('[data-workspace]');if(!input)continue;total++;
      if(input.checked)selected++;
      row.hidden=(!row.querySelector('.check-label').textContent.toLowerCase().includes(query)&&!input.dataset.workspace.includes(query))||(only&&!input.checked);
      if(!row.hidden)shown++;
    }
    find('access-workspace-count').textContent=find('access-all').checked?tr('All current and future workspaces'):
      tr('{selected} selected · {shown} of {total} shown',{selected,shown,total});
    find('access-workspace-empty').hidden=shown>0;
  }
  function syncRights(){
    const selected=[...find('access-permissions').querySelectorAll('input:checked')].map(n=>n.value).sort();
    find('access-preset').value=Object.keys(rights).find(key=>JSON.stringify([...rights[key]].sort())===JSON.stringify(selected))||'custom';
  }
  function syncForm(){
    syncRights();find('access-expiry-preset').value=find('access-expires').value?'custom':'none';workspaceFilter();
  }
  for(const tab of tabs){
    on(tab,'click',()=>showTab(tab.dataset.accessTab));
    on(tab,'keydown',event=>{
      if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;
      event.preventDefault();let index=tabs.indexOf(tab);
      index=event.key==='Home'?0:event.key==='End'?tabs.length-1:(index+(event.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;
      if(tabs[index].dataset.accessTab==='console'){tabs[index].focus();return;}
      showTab(tabs[index].dataset.accessTab,true);
    });
  }
  on(find('access-console-open'),'click',event=>{
    if(event.button!==0||event.ctrlKey||event.metaKey||event.shiftKey||event.altKey)return;
    event.preventDefault();navigate('system-log');
  });
  on(find('access-preset'),'change',()=>{
    if(!getState().me?.admin)return;
    const selected=rights[find('access-preset').value];if(!selected)return;
    for(const input of find('access-permissions').querySelectorAll('input'))input.checked=selected.includes(input.value);
    find('access-permissions').dispatchEvent(new Event('change',{bubbles:true}));
  });
  on(find('access-permissions'),'change',syncRights);
  on(find('access-expiry-preset'),'change',()=>{
    if(!getState().me?.admin)return;
    const value=find('access-expiry-preset').value;if(value==='custom'){find('access-expires').focus();return;}
    find('access-expires').value=value==='none'?'':localInput(Date.now()/1000+Number(value)*86400);
    find('access-expires').dispatchEvent(new Event('input',{bubbles:true}));
  });
  on(find('access-expires'),'change',()=>{find('access-expiry-preset').value=find('access-expires').value?'custom':'none';});
  on(find('access-workspace-search'),'input',workspaceFilter);
  on(find('access-workspace-picked'),'change',workspaceFilter);
  on(find('access-workspaces'),'change',workspaceFilter);
  on(find('access-all'),'change',workspaceFilter);
  return {showTab,syncForm,workspaceFilter,enter(){showTab(current);workspaceFilter();},
    updateStatus(){},leave(){},resetSession(){current='grants';find('access-workspace-search').value='';find('access-workspace-picked').checked=false;showTab(current);},
    destroy(){listeners.abort();}};
}
