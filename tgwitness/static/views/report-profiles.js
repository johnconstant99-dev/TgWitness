export function createReportProfiles({root, tr, json, owner, ready, draft, apply, run}) {
  const get=id=>root.querySelector('#'+id), list=get('report-profile-list'), status=get('report-profile-status');
  let bound=null, rows=[], fields=[], pending=false;
  const current=key=>bound===key&&owner()===key.owner;
  const selected=()=>rows.find(row=>row.id===list.value);
  function controls(){
    for(const id of ['apply','export','delete'])get('report-profile-'+id).disabled=pending||!selected();
    get('report-profile-save').disabled=pending;
    get('report-profile-import').disabled=pending;
  }
  function render(id=list.value){
    list.replaceChildren(new Option(tr('Choose a configuration'),''));
    for(const row of rows)list.append(new Option(row.name,row.id));
    list.value=rows.some(row=>row.id===id)?id:'';controls();
  }
  function reset(){bound=null;rows=[];fields=[];pending=false;get('report-profile-name').value='';status.textContent='';render();}
  async function load(){
    if(bound?.owner===owner())return;
    reset();const key={owner:owner()};bound=key;pending=true;controls();
    try{const data=await json('report-profiles');if(!current(key))return;rows=data.profiles;fields=data.fields;render();}
    catch(error){if(current(key)){bound=null;pending=false;controls();status.textContent=error.message;}}
    finally{if(current(key)){pending=false;controls();}}
  }
  async function operation(fn){
    if(!ready()||pending||bound?.owner!==owner())return;
    const key=bound;pending=true;controls();
    try{await fn(key);}finally{if(current(key)){pending=false;controls();}}
  }
  async function save(value,key){
    const row=await json('report-profiles',value);if(!current(key))return;
    rows=rows.filter(item=>item.id!==row.id).concat(row);render(row.id);get('report-profile-name').value=row.name;
    status.textContent=tr('Configuration saved. Report settings have not been changed.');
  }
  list.addEventListener('change',()=>{get('report-profile-name').value=selected()?.name||'';controls();});
  get('report-profile-apply').addEventListener('click',()=>{
    if(!ready()||pending||bound?.owner!==owner()||!selected())return;
    apply(selected().options);status.textContent=tr('Configuration applied to the draft. Review and save report settings before exporting.');
  });
  get('report-profile-save').addEventListener('click',event=>run(event.currentTarget,()=>operation(async key=>{
    const name=get('report-profile-name').value.trim();if(!name)throw new Error(tr('Enter a configuration name.'));
    const options=draft();await save({name,options:Object.fromEntries(fields.map(field=>[field,options[field]]))},key);
  })));
  get('report-profile-delete').addEventListener('click',event=>run(event.currentTarget,()=>operation(async key=>{
    const row=selected();if(!row)return;
    await json('report-profiles/'+encodeURIComponent(row.id),undefined,{method:'DELETE'});if(!current(key))return;
    rows=rows.filter(item=>item.id!==row.id);render();get('report-profile-name').value='';
    status.textContent=tr('Configuration removed. The current report and collected records are unchanged.');
  })));
  get('report-profile-export').addEventListener('click',()=>{
    if(!ready()||pending||bound?.owner!==owner()||!selected())return;
    const {name,options}=selected(),blob=new Blob([JSON.stringify({format:'tgwitness-report-profile-v1',name,options},null,2)],{type:'application/json'});
    const url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download='tgwitness-report-profile.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  });
  get('report-profile-import').addEventListener('change',event=>{
    const input=event.currentTarget,file=input.files[0];if(!file)return;
    run(null,()=>operation(async key=>{
      try{
        if(file.size>65536)throw new Error(tr('Report configuration files must be smaller than 64 KiB.'));
        let value;try{value=JSON.parse(await file.text());}catch{throw new Error(tr('Choose a valid report configuration JSON file.'));}
        if(!current(key))return;
        if(!value||value.format!=='tgwitness-report-profile-v1'||Object.keys(value).some(k=>!['format','name','options'].includes(k)))throw new Error(tr('Choose a valid report configuration JSON file.'));
        await save({name:value.name,options:value.options},key);
      }finally{if(current(key))input.value='';}
    }));
  });
  reset();return {load,reset};
}
