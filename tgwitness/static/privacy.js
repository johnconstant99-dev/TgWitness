(function () {
  "use strict";
  let enabled = true;
  const activeReveals = new Set();
  const displays = new Set(), painters = new WeakMap();
  function tracked(root, paint) {
    for (const ref of displays) if (!ref.deref()) displays.delete(ref);
    displays.add(new WeakRef(root)); painters.set(root, paint); paint(); return root;
  }
  window.addEventListener('tgwitness:lock', () => {for (const hide of activeReveals) hide();});
  try { enabled = localStorage.getItem('tgwitness-mask-secrets') !== 'off'; } catch { }
  function luhn(value) {
    const digits = value.replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19 || /^(\d)\1+$/.test(digits)) return false;
    let sum = 0, twice = false;
    for (let i = digits.length - 1; i >= 0; i--) {let n = Number(digits[i]); if (twice && (n *= 2) > 9) n -= 9; sum += n; twice = !twice;}
    return sum % 10 === 0;
  }
  function ranges(value) {
    const text = String(value ?? ''), found = [];
    const add = (start, end) => { if (end > start) found.push({start, end}); };
    const patterns = [
      /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|$)/g,
      /\b(?:sk-(?:proj-|ant-api\d+-|or-v\d+-)?[A-Za-z0-9_-]{12,4096}|AIza[A-Za-z0-9_-]{25,64}|gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b/g,
      /\b\d{6,14}:[A-Za-z0-9_-]{25,128}\b/g,
      /\beyJ[A-Za-z0-9_-]{5,4096}\.[A-Za-z0-9_-]{5,4096}\.[A-Za-z0-9_-]{10,4096}\b/g,
      /\b1[A-Za-z0-9_-]{300,500}={0,2}/g,
      /\b[A-Fa-f0-9]{256,4096}\b/g,
    ];
    for (const pattern of patterns) for (const match of text.matchAll(pattern)) add(match.index, match.index + match[0].length);
    const labeled = /(?:\b(?:password|passwd|pwd|passphrase|secret|token|api[_ -]?key|api[_ -]?hash|app[_ -]?hash|auth[_ -]?key|authorization|bearer|string[_ -]?session|session[_ -]?string|twofa|2fa|login[_ -]?code|verification[_ -]?code)\b|пароль|токен|секрет|ключ\s+api|код\s+(?:входа|подтверждения))[\s"']{0,4}(?:[:=]|\bis\b|—|-)?\s{0,8}(?:Bearer\s+)?("[^"\r\n]{1,4096}"|'[^'\r\n]{1,4096}'|[^\s<>"'`,;]{3,4096})/gi;
    for (const match of text.matchAll(labeled)) {
      const raw = match[1], quote = /^["']/.test(raw) ? 1 : 0, start = match.index + match[0].lastIndexOf(raw) + quote;
      add(start, start + raw.length - quote * 2);
    }
    for (const match of text.matchAll(/(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g)) if (luhn(match[0])) add(match.index, match.index + match[0].length);
    found.sort((a, b) => a.start - b.start || b.end - a.end);
    const merged = [];
    for (const item of found) {const previous = merged.at(-1); if (previous && item.start <= previous.end) previous.end = Math.max(previous.end, item.end); else merged.push({...item});}
    return merged;
  }
  function mask(value) {
    const text = String(value ?? '');
    return text.slice(0, text.length >= 12 ? 4 : text.length >= 6 ? 2 : 0) + '•••••';
  }
  function preview(value) {
    const text = String(value ?? ''), found = ranges(text); let offset = 0, result = '';
    for (const item of found) {result += text.slice(offset, item.start) + mask(text.slice(item.start, item.end)); offset = item.end;}
    return result + text.slice(offset);
  }
  function revealButton(root, wrap, label, masked, secret, {tr, reveal, current}) {
    if (!reveal) return;
    const button = document.createElement('button'); button.type = 'button'; button.className = 'text-link secret-reveal';
    button.textContent = tr('Show'); button.title = tr('Revealing a secret is recorded in the journal.');
    let visible = false, timer, errorNotice = null;
    const hide = () => {visible = false; label.textContent = masked; button.textContent = tr('Show'); clearTimeout(timer); activeReveals.delete(hide);};
    button.addEventListener('click', async () => {
      if (visible) {hide(); return;} if (!current() || button.disabled) return;
      button.disabled = true;
      errorNotice?.remove();errorNotice=null;
      try {await reveal(); if (!current() || !root.isConnected) return; visible = true; label.textContent = secret; button.textContent = tr('Hide'); button.removeAttribute('aria-label'); activeReveals.add(hide); timer = setTimeout(hide, 30000);}
      catch {button.title = tr('Could not record this reveal. Try again.'); button.textContent=tr('Retry'); button.setAttribute('aria-label', button.title);
        errorNotice=document.createElement('span');errorNotice.className='secret-reveal-error';errorNotice.setAttribute('role','alert');errorNotice.textContent=button.title;wrap.append(errorNotice);}
      finally {button.disabled = false;}
    });
    wrap.append(button);
  }
  function render(value, {className = '', tr = x => x, reveal, current = () => true} = {}) {
    const text = String(value ?? ''), root = document.createElement('div'); root.className = className;
    return tracked(root, () => {
      root.replaceChildren();
      if (!enabled) {root.textContent = text; return;}
      const found = ranges(text); let offset = 0;
      for (const item of found) {
        root.append(document.createTextNode(text.slice(offset, item.start)));
        const secret = text.slice(item.start, item.end), wrap = document.createElement('span'), label = document.createElement('span');
        wrap.className = 'secret-mask'; label.textContent = mask(secret); label.title = tr('Possible secret'); wrap.append(label);
        revealButton(root, wrap, label, mask(secret), secret, {tr, reveal, current});
        root.append(wrap); offset = item.end;
      }
      root.append(document.createTextNode(text.slice(offset)));
    });
  }
  function recordPreview(value) {
    return JSON.stringify(value, (key, item) => {
      if (!enabled || typeof item !== 'string') return item;
      if (/^(?:hash|previous_hash|prev_hash|signature|public_key|media_sha256|sha256)$/.test(key)) return item;
      if (/^(?:password|passwd|secret|token|api_key|api_hash|app_hash|auth_key|session|string_session|session_string|twofa|2fa)$/i.test(key)) return mask(item);
      return preview(item);
    }, 2);
  }
  function renderRecord(value, {className = '', tr = x => x, reveal, current = () => true} = {}) {
    const root = document.createElement('div'); root.className = className;
    return tracked(root, () => {
      root.replaceChildren();const label = document.createElement('code');
      const masked = recordPreview(value), original = JSON.stringify(value, null, 2);
      label.textContent = masked; root.append(label);
      if (masked !== original) revealButton(root, root, label, masked, original, {tr, reveal, current});
    });
  }
  window.TgWitnessPrivacy = {ranges, preview, render, renderRecord, recordPreview, get enabled() {return enabled;},
    setEnabled(value) {
      enabled = !!value;
      for (const hide of activeReveals) hide();
      for (const ref of displays) {const root = ref.deref(); if (root) painters.get(root)?.(); else displays.delete(ref);}
      try {localStorage.setItem('tgwitness-mask-secrets', enabled ? 'on' : 'off');} catch { }
    },
  };
})();
