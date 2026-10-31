/** Local drafts only: no storage, credentials, or automatic writes. */
export function createFormControls({forms, roots, tr, getSession, toast}) {
  const records=new Map(), listeners=new AbortController(), signal=listeners.signal;
  const fields=form=>[...form.querySelectorAll('input,textarea,select')].filter(field=>
    field.type!=='file'&&field.id&&!field.closest('.alerts-builder'));
  const read=field=>['checkbox','radio'].includes(field.type)?field.checked:field.value;
  const snapshot=form=>new Map(fields(form).map(field=>[field.id,read(field)]));
  const different=(a,b)=>[...new Set([...a.keys(),...b.keys()])].filter(key=>a.get(key)!==b.get(key)).length;
  const visible=form=>form.isConnected&&!form.closest('[hidden]')&&form.getClientRects().length;
  function update(entry) {
    const count=entry.baseline?different(snapshot(entry.form),entry.baseline):0;
    entry.bar.hidden=false;entry.form.dataset.dirty=String(!!count);
    entry.label.textContent=tr('Unsaved changes: {n}',{n:count});
    entry.label.hidden=entry.button.hidden=!count;entry.button.disabled=!count;
  }
  for(const {form,setDirty} of forms) {
    const bar=document.createElement('div'),label=document.createElement('span'),button=document.createElement('button');
    bar.className='form-draft-bar';bar.hidden=true;label.setAttribute('role','status');
    button.type='button';button.className='quiet';button.textContent=tr('Discard changes');
    // Move the existing action, keeping its label, listeners and disabled fieldset.
    // Some actions (Check now) also make sense without a settings change.
    const save=form.querySelector('button[type=submit]')||document.createElement('button');
    const owner=save.closest('fieldset')||form;
    if(!save.textContent){save.type='submit';save.className='primary';save.textContent=tr('Save changes');}
    bar.append(label,save,button);owner.append(bar);
    const entry={form,bar,label,button,setDirty,baseline:null};records.set(form.id,entry);
    form.addEventListener('focusin',()=>{if(!entry.baseline)entry.baseline=snapshot(form);},{signal});
    for(const type of ['input','change'])form.addEventListener(type,()=>update(entry),{signal});
    button.addEventListener('click',()=>{
      if(!entry.baseline)return;
      for(const field of fields(form))if(entry.baseline.has(field.id)){
        const value=entry.baseline.get(field.id);if(['checkbox','radio'].includes(field.type))field.checked=value;else field.value=value;
        field.dispatchEvent(new Event('change',{bubbles:true}));
      }
      setDirty(false);update(entry);form.querySelector('.form-error')?.remove();toast(tr('Unsaved changes discarded.'));
    },{signal});
  }
  function loaded(id) {const entry=records.get(id);if(entry){entry.baseline=snapshot(entry.form);update(entry);}}
  function capture(id) {const entry=records.get(id);return entry?{id,session:getSession(),values:snapshot(entry.form)}:null;}
  function changed(ticket) {const entry=ticket&&records.get(ticket.id);return !!entry&&different(snapshot(entry.form),ticket.values)>0;}
  function accepted(ticket,preserve=changed(ticket)) {
    const entry=ticket&&records.get(ticket.id);if(!entry||ticket.session!==getSession())return;
    entry.baseline=preserve?ticket.values:snapshot(entry.form);update(entry);
  }
  document.addEventListener('keydown',event=>{
    if(event.defaultPrevented||event.isComposing||event.altKey||!(event.ctrlKey||event.metaKey)||event.key.toLowerCase()!=='s')return;
    const candidates=[...records.values()].filter(entry=>visible(entry.form)&&entry.form.dataset.dirty==='true').map(entry=>entry.form);
    const native=[...document.querySelectorAll('#parameters-form,#recording-form,#scope-form,#access-admin-form')].filter(visible);
    let form=event.target.closest?.('form');
    if(!form||!records.has(form.id)&&!native.includes(form))form=candidates.length===1?candidates[0]:native.length===1?native[0]:null;
    if(!form)return;
    event.preventDefault();const submit=form.querySelector('button[type=submit]:not(:disabled),button:not([type]):not(:disabled)');
    if(submit&&!submit.closest('fieldset:disabled'))form.requestSubmit(submit);
  },{signal});
  function labelButtons(root) {
    for(const button of root.querySelectorAll('button,[role=button]')) {
      if(button.textContent.trim())continue;
      const label=button.getAttribute('aria-label')||button.getAttribute('title');
      if(label){if(!button.hasAttribute('title'))button.title=label;if(!button.hasAttribute('aria-label'))button.setAttribute('aria-label',label);}
    }
  }
  for(const root of roots)labelButtons(root);
  const observer=new MutationObserver(changes=>{
    for(const change of changes)for(const node of change.addedNodes)if(node.nodeType===1){
      if(node.matches('button,[role=button]')&&!node.textContent.trim()){
        const label=node.getAttribute('aria-label')||node.title;
        if(label){node.title=label;node.setAttribute('aria-label',label);}
      }
      labelButtons(node);
    }
  });
  for(const root of roots)observer.observe(root,{childList:true,subtree:true});
  return {loaded,capture,changed,accepted,clearSubmitted(ticket,ids){
    const entry=ticket&&records.get(ticket.id);if(!entry||ticket.session!==getSession())return;
    for(const field of fields(entry.form))if(ids.includes(field.id)){
      if(read(field)===ticket.values.get(field.id))field.value='';ticket.values.set(field.id,'');
    }
  },reset(){for(const entry of records.values()){
    entry.baseline=null;entry.bar.hidden=true;delete entry.form.dataset.dirty;
  }},destroy(){observer.disconnect();listeners.abort();}};
}
