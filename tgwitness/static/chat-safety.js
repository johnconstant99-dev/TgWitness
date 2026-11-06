(function () {
  'use strict';
  function create({context, root, tr, changed, warn, audit}) {
    let writeScope = null, observedScope = null, approvedUntil = 0, dialog = null, cancelDialog = null, pending = false;
    const key = () => {const c = context(); return [c.profile, c.revision, c.chat, c.account?.id].join(':');};
    const identity = () => {const a = context().account; return a?.username ? '@'+a.username : a?.id ? 'ID '+a.id : tr('this account');};
    const writable = () => writeScope === key() && !!context().allowed;
    function reset() {writeScope = null; approvedUntil = 0; cancelDialog?.();}
    function sync() {
      if (observedScope !== key()) {reset(); observedScope = key();}
      const host = root(); if (!host) return;
      let bar = host.querySelector('.chat-safety');
      if (!bar) {
        bar = document.createElement('div'); bar.className = 'chat-safety';
        const make = (id, title) => {const label = document.createElement('label'), box = document.createElement('input'), name = document.createElement('span'); box.type = 'checkbox'; box.id = id; name.textContent = tr(title); label.append(box, name); bar.append(label); return box;};
        const read = make('chat-read-only', 'Read-only'); read.title = tr('Allow sending and bot actions in this chat');
        read.addEventListener('change', () => {writeScope = read.checked ? null : key(); approvedUntil = 0; cancelDialog?.(); changed();});
        const mask = make('chat-mask-secrets', 'Mask secrets'); mask.title = tr('Only the panel display changes. Original records and exports stay unchanged.');
        mask.addEventListener('change', async () => {
          const scope=key(),value=mask.checked; mask.disabled=true;
          try {if(!value)await audit(); if(scope!==key())return; window.TgWitnessPrivacy.setEnabled(value); changed();}
          catch(error) {mask.checked=window.TgWitnessPrivacy.enabled; warn(error.message);}
          finally {mask.disabled=false;}
        });
        const hint = document.createElement('span'); hint.className = 'chat-safety-hint'; hint.setAttribute('role', 'status'); bar.append(hint);
        host.querySelector('.chat-toolbar').after(bar);
      }
      const read = bar.querySelector('#chat-read-only'); read.checked = !writable(); read.disabled = !context().allowed;
      bar.querySelector('#chat-mask-secrets').checked = window.TgWitnessPrivacy?.enabled !== false;
      bar.querySelector('.chat-safety-hint').textContent = tr(context().evidence ? 'Sending is off for the Evidence for a case goal' : context().readOnly ? 'This account is read-only. Turn it off on the account page.' : writable() ? 'Sending is enabled for this chat.' : 'Messages and bot buttons are read-only.');
      bar.classList.toggle('can-send', writable());
    }
    async function confirm(action) {
      const canAct=()=>action==='open'?!!context().allowed:writable();
      if (!canAct()) {warn(tr('Turn off Read-only before acting from this account.')); return false;}
      if (pending) return false;
      if (action!=='open'&&approvedUntil > Date.now()) return true;
      const scope = key(); pending = true;
      try {return await new Promise(resolve => {
        dialog = document.createElement('dialog'); dialog.className = 'chat-action-confirm'; dialog.setAttribute('aria-labelledby', 'chat-action-title');
        const title = document.createElement('h2'); title.id = 'chat-action-title'; title.textContent = tr(action === 'send' ? 'Send as {account}?' : action === 'press' ? 'Press this bot button as {account}?' : 'Open or join as {account}?', {account: identity()});
        const description = document.createElement('p'); description.textContent = tr('This acts on Telegram using the connected account and is recorded in the journal.');
        const rememberLabel = document.createElement('label'), remember = document.createElement('input'); remember.type = 'checkbox'; remember.id = 'chat-action-remember';
        rememberLabel.hidden=action==='open';
        rememberLabel.append(remember, document.createTextNode(tr('Do not ask again for 10 minutes in this chat')));
        const actions = document.createElement('div'); actions.className = 'dialog-actions';
        let answer=false;
        const finish = yes => {answer=!!yes; dialog?.close();};
        dialog.addEventListener('close', () => {
          const valid=answer&&scope===key()&&canAct();
          if(valid&&action!=='open'&&remember.checked)approvedUntil=Date.now()+600000;
          dialog?.remove();dialog=null;cancelDialog=null;resolve(valid);
        }, {once:true});
        for (const [label, yes] of [['Cancel', false], ['Confirm action', true]]) {const button = document.createElement('button'); button.type = 'button'; button.className = yes ? 'primary' : 'secondary'; button.textContent = tr(label); button.dataset.confirmAction = String(yes); button.addEventListener('click', () => finish(yes)); actions.append(button);}
        dialog.append(title, description, rememberLabel, actions); document.body.append(dialog); dialog.addEventListener('cancel', event => {event.preventDefault(); finish(false);}); cancelDialog = () => finish(false); dialog.showModal(); actions.firstElementChild.focus();
      });} finally {pending = false;}
    }
    window.addEventListener('tgwitness:lock', reset);
    return {writable, confirm, sync, reset, key: () => key()+':'+writable()+':'+window.TgWitnessPrivacy?.enabled};
  }
  window.TgWitnessChatSafety = {create};
})();
