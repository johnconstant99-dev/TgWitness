

const DICT = (() => { try { return JSON.parse(document.getElementById('site-dict')?.textContent || '{}'); } catch { return {}; } })();
const T = (text, values = {}) => (DICT[text] || text).replace(/\{(\w+)\}/g, (match, key) => key in values ? values[key] : match);
document.querySelectorAll('[data-tabs]').forEach(group => {
  const list = group.querySelector('[data-tab-buttons]');
  const buttons = [...list.querySelectorAll('button')];
  const panels = [...group.querySelectorAll('[data-tab-panel]')];
  list.setAttribute('role', 'tablist');
  list.setAttribute('aria-label', group.getAttribute('aria-label'));
  buttons.forEach(button => button.setAttribute('role', 'tab'));
  panels.forEach(panel => { panel.setAttribute('role', 'tabpanel'); panel.tabIndex = 0; });
  function activate(index, focus = false) {
    buttons.forEach((button, i) => {
      button.setAttribute('aria-selected', String(i === index));
      button.tabIndex = i === index ? 0 : -1;
      document.getElementById(button.getAttribute('aria-controls')).hidden = i !== index;
    });
    if (focus) buttons[index].focus();
  }
  buttons.forEach((button, index) => {
    button.addEventListener('click', () => activate(index));
    button.addEventListener('keydown', event => {
      const offsets = {ArrowRight: 1, ArrowLeft: -1};
      let next;
      if (event.key in offsets) next = (index + offsets[event.key] + buttons.length) % buttons.length;
      else if (event.key === 'Home') next = 0;
      else if (event.key === 'End') next = buttons.length - 1;
      else return;
      event.preventDefault();
      activate(next, true);
    });
  });
  activate(0);
});

if (navigator.clipboard && window.isSecureContext) {
  document.querySelectorAll('[data-copy]').forEach(button => {
    button.hidden = false;
    let reset;
    button.addEventListener('click', async () => {
      const code = document.getElementById(button.dataset.copy);
      const status = document.getElementById('copy-status');
      try {
        await navigator.clipboard.writeText(code.textContent);
        button.textContent = T('Copied');
        status.textContent = T('Command copied to clipboard.');
      } catch {
        button.textContent = T('Select text');
        const range = document.createRange();
        range.selectNodeContents(code);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        status.textContent = T('Clipboard unavailable. Command selected; copy it manually.');
      }
      clearTimeout(reset);
      reset = setTimeout(() => { button.textContent = T('Copy'); }, 2500);
    });
  });
}



const motionPreference = window.matchMedia('(prefers-reduced-motion: reduce)');
const record = document.querySelector('.record');
if (record) {
  const controls = record.querySelector('.record-controls');
  const toggle = record.querySelector('.motion-toggle');
  const steps = [...record.querySelectorAll('[data-record-step]')];
  const events = [...record.querySelectorAll('.record-events li')];
  let stage = motionPreference.matches ? 2 : 0;
  let playing = !motionPreference.matches;
  let visible = true;
  let timer;
  function showStage(next) {
    stage = next;
    record.dataset.stage = String(stage);
    events.forEach((event, index) => {
      event.classList.toggle('is-active', stage === index);
      event.classList.toggle('is-recorded', stage >= index);
    });
    steps.forEach((step, index) => step.setAttribute('aria-pressed', String(stage === index)));
    record.querySelector('.record-caption').textContent = [
      T('A message arrives. The first observation is saved.'),
      T('The time changes. Both captured versions stay.'),
      T('The message disappears. The captured history remains.')
    ][stage];
  }
  function syncMotion() {
    clearTimeout(timer);
    const active = playing && !motionPreference.matches;
    toggle.hidden = motionPreference.matches;
    toggle.setAttribute('aria-label', active ? T('Pause example animation') : T('Play example animation'));
    toggle.textContent = active ? T('Pause') + ' Ⅱ' : T('Play') + ' ▷';
    record.classList.toggle('is-playing', active && visible && !document.hidden);
    if (active && visible && !document.hidden) {
      timer = setTimeout(() => { showStage((stage + 1) % steps.length); syncMotion(); }, 3200);
    }
  }
  controls.hidden = false;
  showStage(stage);
  steps.forEach((step, index) => step.addEventListener('click', () => {
    playing = false;
    showStage(index);
    syncMotion();
  }));
  toggle.addEventListener('click', () => { playing = !playing; syncMotion(); });
  document.addEventListener('visibilitychange', syncMotion);
  motionPreference.addEventListener('change', () => {
    playing = false;
    showStage(2);
    syncMotion();
  });
  if ('IntersectionObserver' in window) {
    new IntersectionObserver(entries => {
      visible = entries[0].isIntersecting;
      syncMotion();
    }, {threshold: .15}).observe(record);
  }
  syncMotion();
}



if ('HTMLDialogElement' in window && document.querySelector('.screen-frame > img')) {
  const dialog = document.createElement('dialog');
  dialog.className = 'screenshot-dialog';
  dialog.setAttribute('aria-label', T('Full-size workspace screenshot'));
  const bar = document.createElement('div');
  bar.className = 'dialog-toolbar';
  const title = document.createElement('p');
  title.textContent = T('Workspace screenshot · fictional data');
  const close = document.createElement('button');
  close.type = 'button';
  close.textContent = T('Close') + ' ×';
  close.setAttribute('aria-label', T('Close screenshot'));
  bar.append(title, close);
  const viewport = document.createElement('div');
  viewport.className = 'screenshot-viewport';
  viewport.tabIndex = 0;
  viewport.setAttribute('role', 'region');
  viewport.setAttribute('aria-label', T('Scrollable full-size screenshot'));
  const image = document.createElement('img');
  viewport.append(image);
  dialog.append(bar, viewport);
  document.body.append(dialog);
  close.addEventListener('click', () => dialog.close());
  dialog.addEventListener('click', event => { if (event.target === dialog) dialog.close(); });
  dialog.addEventListener('close', () => { document.body.classList.remove('image-open'); });
  document.querySelectorAll('.screen-frame > img').forEach(screenshot => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'screenshot-open';
    button.setAttribute('aria-label', T('Enlarge: {name}', {name:screenshot.alt}));
    button.dataset.label = T('View full size') + ' ↗';
    screenshot.before(button);
    button.append(screenshot);
    button.addEventListener('click', () => {
      image.src = screenshot.src;
      image.alt = screenshot.alt;
      document.body.classList.add('image-open');
      dialog.showModal();
      viewport.scrollTo(0, 0);
    });
  });
}


if ('IntersectionObserver' in window && !motionPreference.matches) {
  const reveal = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add('has-entered');
      reveal.unobserve(entry.target);
    });
  }, {threshold: .2});
  document.querySelectorAll('.section-heading, .principles article, .bundle, .closing').forEach(element => reveal.observe(element));
}


const themeToggle = document.querySelector('[data-theme-toggle]');
if (themeToggle) {
  const sync = () => themeToggle.setAttribute('aria-pressed', String(document.documentElement.dataset.theme === 'dark'));
  themeToggle.hidden = false;
  sync();
  themeToggle.addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.classList.add('theme-changing');
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('tgw-theme', next); } catch {                    }
    sync();
    setTimeout(() => document.documentElement.classList.remove('theme-changing'), 400);
  });
}

const languageMenu = document.querySelector('.lang-menu');
if (languageMenu) {
  document.addEventListener('click', event => { if (!languageMenu.contains(event.target)) languageMenu.open = false; });
  languageMenu.addEventListener('keydown', event => {
    if (event.key === 'Escape') { languageMenu.open = false; languageMenu.querySelector('summary').focus(); }
  });
}
