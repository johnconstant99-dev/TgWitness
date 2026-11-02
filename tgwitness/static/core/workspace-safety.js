/** URL, selector and loaded account must agree before any workspace request. */
export function createWorkspaceSafety({state,find,tr,avatar,switchProfile,refreshStatus,confirm}) {
  const bar=document.createElement('aside'),copy=document.createElement('p'),resolve=document.createElement('button');
  bar.id='workspace-context-alert';bar.className='workspace-context-alert';bar.hidden=true;bar.setAttribute('role','alert');
  resolve.type='button';resolve.className='secondary';resolve.textContent=tr('Switch to the account in this link');bar.append(copy,resolve);
  document.querySelector('.topbar').after(bar);
  const identity=document.createElement('div');identity.id='workspace-identity';identity.className='workspace-identity';
  document.querySelector('.profile-switch').append(identity);
  let statusMismatch='',avatarKey='';
  const urlWorkspace=()=>{const q=new URL(location.href).searchParams;return q.get('ws')||q.get('workspace')||'default';};
  const name=id=>{
    const p=id===state.profile?state.status:state.profiles.find(p=>p.id===id),a=p?.collector?.account;
    return a?.username?'@'+a.username:a?.id?'ID '+a.id:state.profiles.find(p=>p.id===id)?.label||id;
  };
  function sync(){
    if(!state.me||find('workspace').hidden){bar.hidden=true;document.querySelector('.content').inert=false;return true;}
    const wanted=urlWorkspace(),selected=find('profile-select').value;
    const mismatch=statusMismatch||wanted!==state.profile||selected!==state.profile||
      (!!state.status?.workspace_id&&state.status.workspace_id!==wanted);
    bar.hidden=!mismatch;document.querySelector('.content').inert=mismatch;
    if(mismatch){copy.textContent=tr('You are viewing {shown}, but {selected} is selected. Actions are paused until the account is confirmed.',
      {shown:name(statusMismatch||state.status?.workspace_id||state.profile),selected:name(selected!==state.profile?selected:wanted)})+' '+
      tr('Account in this link: {account}.',{account:name(wanted)});return false;}
    const account=state.status?.collector?.account,key=state.profile+':'+(account?.id||'')+':'+(account?.username||'');
    if(key!==avatarKey){
      avatarKey=key;const label=document.createElement('span');label.textContent=name(state.profile);
      label.title=account?.id?'ID '+account.id:tr('No account connected');
      identity.replaceChildren(avatar(account?.id,account?.username||name(state.profile),'sm',state.profile),label);
    }
    return true;
  }
  function assert(){if(!sync())throw new Error(tr('Confirm the workspace above before continuing.'));}
  function acceptStatus(result){
    statusMismatch=result.workspace_id&&result.workspace_id!==urlWorkspace()?result.workspace_id:'';
    if(statusMismatch){sync();throw new Error(tr('The server returned another workspace. Reload the selected account.'));}
  }
  resolve.addEventListener('click',async()=>{
    resolve.disabled=true;
    try{
      const wanted=urlWorkspace();
      if(!state.profiles.some(p=>p.id===wanted&&!p.error_type))throw new Error(tr('Unknown workspace.'));
      statusMismatch='';
      if(wanted!==state.profile)await switchProfile(wanted,{history:false});
      else{find('profile-select').value=wanted;state.status=null;await refreshStatus();}
      sync();
    }catch(error){copy.textContent=error.message;}finally{resolve.disabled=false;}
  });
  for(const event of ['tgwitness:route','tgwitness:lock','popstate'])window.addEventListener(event,sync);
  find('profile-select').addEventListener('change',()=>queueMicrotask(sync));
  async function confirmExport(){
    assert();const owner=state.profile,revision=state.workspaceRevision;
    const accepted=await confirm(tr('Export records from {account}?',{account:name(owner)}),{confirmText:tr('Prepare export')});
    assert();return accepted&&owner===state.profile&&revision===state.workspaceRevision;
  }
  return {sync,assert,acceptStatus,urlWorkspace,name,confirmExport};
}
