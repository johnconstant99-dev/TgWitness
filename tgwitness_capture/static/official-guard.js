(() => {
  'use strict';
  let armed = false, reason = null;
  const dangerous = '[contenteditable="true"], .Composer, .composer, .ReactionSelector, .ReactionButton, .BotKeyboard, .InlineButtons';
  const visible = el => !!(el && el.getClientRects().length && getComputedStyle(el).visibility !== 'hidden');
  function inspect() {
    if (armed && !reason) {
      if (location.origin !== 'https://web.telegram.org' || !/^\/a\/?$/.test(location.pathname)) reason = 'UnexpectedOrigin';
      else if (Array.from(document.querySelectorAll('[id^="auth-"]')).some(visible)) reason = 'AuthorizationScreen';
      else if (Array.from(document.querySelectorAll('.Modal.open, [role="alertdialog"], .Menu.open')).some(visible)) reason = 'UnexpectedDialog';
    }
    if (armed && reason && document.body && !document.getElementById('tgwitness-stop-cover')) {
      const cover = document.createElement('div'); cover.id = 'tgwitness-stop-cover';
      cover.textContent = 'TgWitness: observation stopped';
      Object.assign(cover.style, {position:'fixed',inset:'0',zIndex:'2147483647',background:'#101827',color:'#fff',display:'grid',placeItems:'center',font:'24px system-ui'});
      document.body.append(cover);
    }
    if (armed) document.querySelectorAll(dangerous).forEach(el => {el.inert = true;});
    return {armed, reason};
  }
  for (const name of ['keydown','beforeinput','paste','drop','contextmenu','dblclick','pointerdown','mousedown','click']) {
    document.addEventListener(name, event => {
      if (armed && (reason || ['keydown','beforeinput','paste','drop','contextmenu','dblclick'].includes(name) || event.target.closest?.(dangerous))) {
        event.preventDefault(); event.stopImmediatePropagation();
      }
    }, true);
  }
  Object.defineProperty(window, '__tgwitnessGuard', {value:Object.freeze({
    arm() {armed = true; return inspect();}, inspect,
    disarmForLogout() {armed = false; document.getElementById('tgwitness-stop-cover')?.remove();}
  }), writable:false, configurable:false});
  new MutationObserver(inspect).observe(document, {subtree:true,childList:true});
})();
