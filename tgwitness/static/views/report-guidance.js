export function createReportGuidance({root, tr}) {
  const get=id=>root.querySelector('#report-guidance-'+id);
  let profiles=[], detailKey=null;
  const paragraph=text=>{const p=document.createElement('p');p.className='hint';p.textContent=text;return p;};
  function read(){
    return {jurisdiction:get('country').value,procedure:get('procedure').value,
      include_in_report:get('include').checked,local_note:get('local').checked,include_methods:get('methods').checked};
  }
  function sync(){
    const value=read(), profile=profiles.find(p=>p.code===value.jurisdiction), active=!!profile&&value.include_in_report;
    get('procedure').disabled=!profile;
    get('include').disabled=!profile;
    get('local').disabled=get('methods').disabled=!active;
    const key=value.jurisdiction+':'+value.procedure;
    if(detailKey===key)return active;
    detailKey=key;
    const detail=get('detail');detail.replaceChildren();
    if(!profile)return;
    const criminal=value.procedure==='criminal';
    const status=criminal?profile.criminal_status:'research_draft';
    detail.append(paragraph(profile.scope),paragraph('Research date: '+profile.reviewed_on+' · '+status.replaceAll('_',' ')),
      paragraph(criminal?profile.criminal:profile.basis));
    const links=document.createElement('ul');
    for(const source of criminal?profile.criminal_sources:profile.sources){
      const item=document.createElement('li'),link=document.createElement('a');
      link.href=source.url;link.target='_blank';link.rel='noopener noreferrer';link.textContent=source.title;
      item.append(link);links.append(item);
    }
    detail.append(links);
    return active;
  }
  function reset(){
    profiles=[];detailKey=null;root.open=false;
    get('country').replaceChildren(new Option(tr('Not selected'),''));
    get('procedure').value='civil';get('include').checked=true;
    get('local').checked=get('methods').checked=false;sync();
  }
  function load(value={}, catalog){
    profiles=catalog.profiles;detailKey=null;
    get('country').replaceChildren(new Option(tr('Not selected'),''),...profiles.map(p=>new Option(p.name,p.code)));
    get('country').value=value.jurisdiction||'';get('procedure').value=value.procedure||'civil';
    get('include').checked=value.include_in_report!==false;get('local').checked=!!value.local_note;get('methods').checked=!!value.include_methods;
    root.open=!!value.jurisdiction;sync();
  }
  reset();return {read,load,reset,sync};
}
