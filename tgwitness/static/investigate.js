(() => {
  'use strict';
  const LABELS = [['important', 'Important'], ['conclusion', 'Conclusion'], ['question', 'Open question'],
    ['decision', 'Decision and rationale'],
    ['adult', '18+'], ['obscene', 'Obscene language'], ['violence', 'Violence'], ['personal', 'Personal data']];
  const HIDING = ['adult', 'obscene', 'violence', 'personal'];
  const STATES = {recording: 'Recording', paused: 'Paused', stopped: 'Stopped'};
  const AFTER = {request: 'after the request', 'button press': 'after the button press', message: 'after the message'};
  const RISKS = {telegram_proxy: 'Telegram proxy link: opening it in a Telegram app contacts that server and reveals the IP address.',
    telegram_story: 'Story link: opening it from an account can record a view by that account.',
    mixed_script: 'The address mixes alphabets and may imitate another domain.'};
  const LOOK = [
    ['hashes', 'Record hashes', [['short', 'Short'], ['full', 'Full'], ['appendix', 'In an appendix']]],
    ['images', 'Screenshots', [['inline', 'In the report'], ['none', 'Files only']]],
    ['theme', 'Theme', [['light', 'Light, for printing'], ['dark', 'Dark']]],
    ['detail', 'Detail', [['full', 'Full'], ['compact', 'Compact']]],
    ['summary', 'Summary cards', [['true', 'Shown'], ['false', 'Hidden']]],
    ['found', 'Found in messages', [['true', 'Shown'], ['false', 'Hidden']]],
    ['subjects', 'Profile cards', [['true', 'Shown'], ['false', 'Hidden']]],
    ['notes', 'Notes in the timeline', [['true', 'Shown'], ['false', 'Hidden']]],
    ['conclusions', 'Conclusions section', [['true', 'Shown'], ['false', 'Hidden']]],
    ['translations', 'Machine translations', [['true', 'Shown'], ['false', 'Hidden']]],
    ['references', 'Journal references', [['true', 'Shown'], ['false', 'Hidden']]],
    ['limits', 'How to read this document', [['true', 'Shown'], ['false', 'Hidden']]]];
  const PRESETS = {
    court: {hashes: 'full', images: 'inline', theme: 'light', detail: 'full', summary: true, found: true, subjects: true,
      notes: true, conclusions: true, translations: true, references: true, limits: true},
    briefing: {hashes: 'short', images: 'inline', theme: 'light', detail: 'compact', summary: true, found: true, subjects: true,
      notes: false, conclusions: true, translations: true, references: false, limits: true},
    internal: {hashes: 'short', images: 'inline', theme: 'dark', detail: 'full', summary: true, found: true, subjects: true,
      notes: true, conclusions: true, translations: true, references: true, limits: false}};
  const PRESET_NAMES = [['custom', 'Custom'], ['court', 'For court: everything, full hashes'],
    ['briefing', 'Briefing: short, without working notes'], ['internal', 'Internal: full, dark']];
  const ICONS = {
    doc: 'M6 3h9l4 4v14H6zM14 3v5h5M9 12h6M9 16h6',
    note: 'M4 4h16v12H9l-5 4zM8 9h8M8 12h5',
    pause: 'M8 5v14M16 5v14',
    play: 'M7 5l12 7-12 7z',
    stop: 'M6 6h12v12H6z',
    seal: 'M12 3a9 9 0 100 18 9 9 0 000-18zM8 12l3 3 5-6',
    back: 'M15 5l-7 7 7 7',
    close: 'M6 6l12 12M18 6L6 18',
    expand: 'M4 9V4h5M20 15v5h-5M4 4l6 6M20 20l-6-6',
    collapse: 'M10 4v6H4M14 20v-6h6M4 10l6-6M20 14l-6 6',
    clock: 'M12 3a9 9 0 100 18 9 9 0 000-18zM12 7v5l3 3',
    chart: 'M4 20V11M10 20V5M16 20v-7M22 20H2',
    shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM9 12l2 2 4-4',
    download: 'M12 4v11M7 10l5 5 5-5M5 20h14',
    link: 'M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1',
    send: 'M4 12l16-8-6 16-3-7z',
    check: 'M5 12l4 4L19 6',
    alert: 'M12 3l10 18H2zM12 10v4M12 17v.5',
    eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 9a3 3 0 100 6 3 3 0 000-6z',
    trash: 'M5 7h14M10 7V5h4v2M7 7l1 13h8l1-13',
    lock: 'M6 11h12v9H6zM8 11V8a4 4 0 018 0v3',
    globe: 'M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18',
    image: 'M4 6h16v12H4zM8 14l3-3 4 4 2-2 3 3M9 9.5v.5',
    key: 'M8 14a4 4 0 110-8 4 4 0 010 8zM11.5 10H21M18 10v4M21 10v3',
    search: 'M11 4a7 7 0 100 14 7 7 0 000-14zM21 21l-5-5',
    edit: 'M4 20h4L19 9l-4-4L4 16zM14 6l4 4',
    user: 'M12 12a4 4 0 100-8 4 4 0 000 8zM4 21a8 8 0 0116 0',
    target: 'M12 3a9 9 0 100 18 9 9 0 000-18zM12 7a5 5 0 100 10 5 5 0 000-10zM12 11a1 1 0 100 2 1 1 0 000-2z',
    spark: 'M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8zM19 15l.8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8z',
    next: 'M9 5l7 7-7 7',
    up: 'M12 19V5M6 11l6-6 6 6',
    down: 'M12 5v14M6 13l6 6 6-6',
    copy: 'M9 9h11v11H9zM5 15H4V4h11v1',
    refresh: 'M20 12a8 8 0 11-2.3-5.6M20 4v5h-5',
    more: 'M5 12h.5M12 12h.5M19 12h.5'};
  const SYSTEM = {checked_link: 'link', requested: 'send', observing: 'eye', outcome: 'check', deleted: 'trash',
    not_listed: 'more', account_change: 'key', ai_draft: 'spark', search_recorded: 'search', qr_code: 'image',
    presence: 'clock', peer_settings: 'globe'};
  const SVG = 'http://www.w3.org/2000/svg';
  const may = permission => !!(state.me?.admin || (state.me?.permissions || []).includes(permission));
  const key = () => state.workspaceRevision + ':' + state.profile + ':' + state.token;
  const path = (...parts) => ['documentation', ...parts.map(encodeURIComponent)].join('/');
  const open = () => drawer && !drawer.hidden;
  const thumbnails = new Map();
  const analysisState = {chat: null, zone: null, data: null};
  let toggle = null, drawer = null, current = null, data = null, timer = null, owner = '', editing = null;
  let modules = null, homeList = null, shieldInfo = null, homeTab = 'documents', sessionTab = 'timeline';
  let wide = false, accountInfo = null, plans = null, plan = null, planTab = 'work';
  let accountDraft = {profile: {}, privacy: {}, global: {}, errors: {}}, avatarUrl = null, accountReport = null;
  let cover = null, presence = null, watchPattern = null;
  const AUTHORITY_ORDER = ['undercover_operation', 'chis', 'directed_surveillance', 'court_order', 'prosecutor_approval', 'other'];
  const PRESENCE_STATES = {online: 'online', offline: 'offline', recently: 'last seen recently',
    last_week: 'last seen within a week', last_month: 'last seen within a month', unknown: 'status not available'};
  const INTERVALS = [[60, 'Every minute'], [180, 'Every 3 minutes'], [300, 'Every 5 minutes'], [600, 'Every 10 minutes'],
    [1800, 'Every 30 minutes'], [3600, 'Every hour']];
  const openExceptions = new Set();
  const assist = {intent: '', goal: '', context: 60, variants: 3, preview: null, result: null};
  const GOAL_STATES = {open: 'Open', obtained: 'Obtained', dropped: 'Dropped'};
  const STEP_KINDS = [['question', 'Question'], ['answer', 'Answer'], ['emoji', 'Emoji or reaction'], ['follow_up', 'Follow-up'],
    ['other', 'Other']];
  const ZONES = [...Array.from({length: 27}, (_, i) => (i - 12) * 60), 210, 270, 330, 345, 390, 570].sort((a, b) => a - b);
  const WEEKDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const AUDIENCE = [['everybody', 'Everybody'], ['contacts', 'My contacts'], ['nobody', 'Nobody']];
  const AVATAR_TYPES = ['image/jpeg', 'image/png'];
  try {wide = localStorage.getItem('tgwitness.docWide') === '1';} catch (error) {wide = false;}

  function icon(name) {
    const svg = document.createElementNS(SVG, 'svg'), line = document.createElementNS(SVG, 'path');
    svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('class', 'doc-icon');
    svg.setAttribute('aria-hidden', 'true'); svg.setAttribute('focusable', 'false');
    line.setAttribute('d', ICONS[name] || ICONS.more); svg.append(line);
    return svg;
  }

  function el(tag, cls, ...kids) {
    const item = node(tag, cls);
    item.append(...kids.flat().filter(kid => kid !== null && kid !== undefined && kid !== '' && kid !== false));
    return item;
  }

  function button(text, cls, action, iconName, label) {
    const b = node('button', cls || 'secondary'); b.type = 'button'; b.dataset.key = text || label || '';
    if (iconName) b.append(icon(iconName));
    if (text) b.append(node('span', '', tr(text)));
    if (label) {b.setAttribute('aria-label', tr(label)); b.title = tr(label);}
    b.addEventListener('click', () => busy(b, action));
    return b;
  }

  const copy = value => Promise.resolve().then(() => navigator.clipboard.writeText(value)).then(() => toast(tr('Copied')));

  function copyChip(item) {
    const tag = chip(item.kind + ' · ' + item.value, 'ioc', 'search', tr('Copy'));
    tag.tabIndex = 0; tag.setAttribute('role', 'button');
    tag.setAttribute('aria-label', tr('Copy') + ': ' + item.value);
    tag.addEventListener('click', () => copy(item.value).catch(() => {}));
    tag.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {event.preventDefault(); copy(item.value).catch(() => {});}
    });
    return tag;
  }

  function short(text, size = 140) {
    text = String(text || '').replace(/\s+/g, ' ').trim();
    return text.length > size ? text.slice(0, size) + '…' : text;
  }

  const seconds = value => value < 10 ? String(Math.round(value * 10) / 10) : String(Math.round(value));
  const clock = value => (value || '').slice(11, 19);
  const labelName = value => tr((LABELS.find(item => item[0] === value) || [value, value])[1]);

  const duration = value => value === null || value === undefined ? '—'
    : value < 60 ? tr('{n} s', {n: Math.round(value)}) : value < 3600 ? tr('{n} min', {n: Math.round(value / 60)})
    : tr('{n} h', {n: (value / 3600).toFixed(1)});

  function describe(step) {
    if (step.hidden) return tr('Content hidden: {reasons}', {reasons: step.hidden.map(r => tr(r)).join(', ')});
    const who = step.sender?.display_name || (step.sender?.username ? '@' + step.sender.username : tr('The other side'));
    switch (step.type) {
      case 'checked_link': return tr('Checked the link {link}', {link: step.link || ''});
      case 'requested': return step.action === 'send' ? tr('Requested to send: {text}', {text: short(step.text)})
        : step.action === 'press' ? tr('Requested to press {button}', {button: step.button || ''}) : tr('Requested to open the link');
      case 'observing': return tr('Added {title} to observation', {title: step.title || ''});
      case 'sent': return tr('Sent #{id}: {text}', {id: step.message_id, text: short(step.text)});
      case 'sent_elsewhere': return tr('Sent #{id} from another app: {text}', {id: step.message_id, text: short(step.text)});
      case 'outcome': return tr('Outcome: {status}', {status: tr(step.status || '')}) + (step.answer ? ' · ' + short(step.answer) : '');
      case 'reply': return tr('{name}: {text}', {name: who, text: short(step.text) || tr('(attachment)')});
      case 'edited': return tr('{name} edited #{id}: {text}', {name: who, id: step.message_id, text: short(step.text)});
      case 'deleted': return tr('Deletion notice for #{id}', {id: step.message_id});
      case 'not_listed': return tr('{n} more messages not listed', {n: step.count});
      case 'self_check': return tr('Account check: {risks} risks, {notices} notices', {risks: (step.risks || []).length, notices: step.notices || 0});
      case 'visual': return tr('Isolated browser: {url}', {url: step.final_url || step.url || ''})
        + (step.http_status ? ' · HTTP ' + step.http_status : '') + (step.server_ip ? ' · ' + step.server_ip : '');
      case 'account_change': return accountChange(step);
      case 'subject': return tr('Profile snapshot: {title}', {title: step.title || ''});
      case 'qr_code': return tr('QR code in an image: {texts}', {texts: (step.codes || []).map(text => short(text, 90)).join('; ')});
      case 'search_recorded': return tr('Recorded search “{query}”: {n} results', {query: short(step.query, 80), n: step.matched || 0})
        + (step.note ? ' · ' + short(step.note, 80) : '');
      case 'ai_draft': return tr('AI drafts from {model}: {n} chat messages sent to the provider, {k} drafts suggested · {task}',
        {model: step.model || '?', n: step.messages_sent || 0, k: step.drafts || 0, task: short(step.intent, 80)});
      default: return step.type;
    }
  }

  function accountChange(step) {
    const value = text => text ? '“' + short(text, 40) + '”' : tr('(empty)');
    if (step.change === 'profile') return tr('Account profile changed: {list}', {list: (step.fields || []).map(item =>
      tr(item.field) + ' ' + value(item.before) + ' → ' + value(item.after)).join('; ')});
    if (step.change === 'privacy') return tr('Account privacy changed: {list}', {list: (step.settings || []).map(item =>
      tr(item.label) + ' ' + tr(item.before || '?') + ' → ' + tr(item.after || '?')).join('; ')})
      + ((step.failed || []).length ? ' · ' + tr('not applied: {list}', {list: step.failed.map(name => tr(name)).join(', ')}) : '');
    if (step.change === 'options') return tr('Account options changed: {list}', {list: (step.options || []).map(item =>
      tr(item.label) + ' ' + tr(item.before ? 'on' : 'off') + ' → ' + tr(item.after ? 'on' : 'off')).join('; ')});
    if (step.change === 'photo_set') return tr('New profile photo · SHA-256 {hash}', {hash: (step.sha256 || '').slice(0, 12) + '…'});
    return tr('Profile photo removed');
  }

  function setWide(value) {
    wide = value;
    drawer.classList.toggle('wide', wide);
    try {localStorage.setItem('tgwitness.docWide', wide ? '1' : '0');} catch (error) {wide = value;}
    current ? renderSession() : renderHome();
  }

  function updateToggle() {
    if (!toggle) return;
    toggle.classList.toggle('live', !!current && !current.fixed && current.state === 'recording');
  }

  function reset() {
    current = data = editing = homeList = shieldInfo = accountInfo = plans = plan = null;
    cover = presence = watchPattern = null;
    clearInterval(timer); timer = null;
    Object.assign(assist, {intent: '', goal: '', preview: null, result: null}); planTab = 'work';
    accountDraft = {profile: {}, privacy: {}, global: {}, errors: {}}; accountReport = null; openExceptions.clear();
    if (avatarUrl) {URL.revokeObjectURL(avatarUrl); avatarUrl = null;}
    for (const url of thumbnails.values()) URL.revokeObjectURL(url);
    thumbnails.clear();
    modules = null; homeTab = 'documents'; sessionTab = 'timeline';
    Object.assign(analysisState, {chat: null, data: null});
    if (drawer) {drawer.hidden = true; drawer.replaceChildren();}
    if (toggle) {toggle.hidden = !allowed(); updateToggle();}
  }

  function mount() {
    if (toggle) return;
    toggle = el('button', 'doc-toggle', icon('doc'), node('span', '', tr('Documentation')), node('span', 'doc-live-dot'));
    toggle.type = 'button'; toggle.setAttribute('aria-expanded', 'false');
    drawer = node('aside', 'doc-drawer' + (wide ? ' wide' : '')); drawer.hidden = true;
    drawer.setAttribute('aria-label', tr('Documentation'));
    toggle.addEventListener('click', () => (open() ? hide() : show()));
    document.body.append(toggle, drawer);
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && open()) {
        const composer = drawer.querySelector('.doc-mark');
        if (composer && composer.contains(document.activeElement)) {composer.remove(); editing = null; return;}
        if (drawer.contains(document.activeElement)) hide();
        return;
      }
      if (event.ctrlKey || event.metaKey || event.altKey || !['m', 'M', 'ь', 'Ь'].includes(event.key)) return;
      if (event.target.closest?.('input, textarea, select, [contenteditable="true"]')) return;
      if (!current || current.fixed || !state.token) return;
      event.preventDefault();
      (open() ? Promise.resolve() : show()).then(() => markForm()).catch(() => {});
    });
  }

  async function show() {
    if (owner !== key()) {owner = key(); reset();}
    drawer.hidden = false; toggle.setAttribute('aria-expanded', 'true');
    if (!modules) modules = await json('extensions').catch(() => ({loaded: [], goal: null}));
    clearInterval(timer);
    timer = setInterval(() => {if (open() && current && !current.fixed && !typing()) refresh().catch(() => {});}, 5000);
    current ? await refresh() : await listing();
  }

  function typing() {
    const active = document.activeElement;
    return !!drawer.querySelector('.doc-mark') || (drawer.contains(active) && active.matches('input, textarea, select'));
  }

  function hide() {
    drawer.hidden = true; toggle.setAttribute('aria-expanded', 'false'); clearInterval(timer); timer = null;
    toggle.focus();
  }

  function analysisAvailable() {
    return !!(state.status?.targets || []).length && modules?.goal !== 'evidence'
      && (modules?.loaded || []).some(m => m.id === 'analyzer');
  }

  function topRow(back, title, extra) {
    const row = node('div', 'doc-top');
    if (back) row.append(button('', 'ghost doc-icon-btn', back, 'back', 'Back'));
    row.append(el('div', 'doc-title', node('h2', '', title), extra || ''));
    const size = button('', 'ghost doc-icon-btn doc-wide-btn', async () => setWide(!wide), wide ? 'collapse' : 'expand',
      wide ? 'Narrow panel' : 'Wide panel');
    size.dataset.key = 'wide';
    row.append(size, button('', 'ghost doc-icon-btn', async () => hide(), 'close', 'Close'));
    return row;
  }

  function tabBar(tabs, active, choose) {
    const bar = node('div', 'doc-tabs'); bar.setAttribute('role', 'tablist');
    tabs.forEach(([id, label, iconName, count], index) => {
      const tab = el('button', 'doc-tab' + (id === active ? ' on' : ''), icon(iconName), node('span', '', tr(label)),
        count ? node('span', 'doc-count', String(count)) : '');
      tab.type = 'button'; tab.dataset.key = 'tab:' + id;
      tab.setAttribute('role', 'tab'); tab.setAttribute('aria-selected', String(id === active));
      tab.tabIndex = id === active ? 0 : -1;
      tab.addEventListener('click', () => choose(id));
      tab.addEventListener('keydown', event => {
        if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
        event.preventDefault();
        const next = tabs[(index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length][0];
        choose(next);
        requestAnimationFrame(() => drawer.querySelector('.doc-tab.on')?.focus());
      });
      bar.append(tab);
    });
    return bar;
  }

  function paint(head, body) {
    const old = drawer.querySelector('.doc-body'), active = document.activeElement;
    const focus = drawer.contains(active) ? active.dataset?.key : null;
    const composer = current && !current.fixed ? drawer.querySelector('.doc-mark') : null;
    const feed = body.dataset.view.endsWith(':timeline');
    const keep = old && old.dataset.view === body.dataset.view
      ? {top: old.scrollTop, bottom: old.scrollHeight - old.scrollTop - old.clientHeight < 48} : null;
    if (composer) body.prepend(composer); else editing = null;
    drawer.replaceChildren(head, body);
    if (keep) body.scrollTop = keep.bottom && feed ? body.scrollHeight : keep.top;
    else if (feed && !composer) body.scrollTop = body.scrollHeight;
    if (focus) drawer.querySelector('[data-key="' + CSS.escape(focus) + '"]')?.focus();
  }

  function section(iconName, title, ...content) {
    return el('section', 'doc-panel', el('h4', 'doc-section', icon(iconName), tr(title)), ...content);
  }

  function empty(iconName, title, text) {
    return el('div', 'doc-empty', icon(iconName), node('strong', '', title), text ? node('p', '', text) : '');
  }

  async function listing() {
    homeList = await json('documentation');
    renderHome();
  }

  function renderHome() {
    const tabs = [['documents', 'Documents', 'doc', homeList?.sessions.length],
      ...(may('interact') && modules?.goal !== 'evidence' ? [['plans', 'Plans', 'target', plans?.plans.length]] : []),
      ...(analysisAvailable() ? [['analysis', 'Analysis', 'chart']] : []),
      ...(may('collect') ? [['watch', 'Online watch', 'timer', presence?.watches.length]] : []),
      ...(may('account') ? [['protection', 'Protection', 'shield'], ['account', 'Account', 'user'],
        ['cover', 'Cover and authority', 'lock', (cover?.personas.length || 0) + (cover?.authorisations.length || 0)]] : [])];
    if (!tabs.some(tab => tab[0] === homeTab)) homeTab = 'documents';
    const head = el('header', 'doc-head', topRow(null, tr('Documentation')),
      tabs.length > 1 ? tabBar(tabs, homeTab, id => {homeTab = id; renderHome();}) : '');
    const body = node('div', 'doc-body');
    body.dataset.view = 'home:' + homeTab + (homeTab === 'plans' && plan ? ':' + plan.id + ':' + planTab : '');
    body.setAttribute('role', 'tabpanel');
    body.append(...(homeTab === 'analysis' ? analysisPanel() : homeTab === 'protection' ? protectionPanel()
      : homeTab === 'account' ? accountPanel() : homeTab === 'plans' ? plansPanel()
      : homeTab === 'cover' ? coverPanel() : homeTab === 'watch' ? watchPanel() : documentsPanel()));
    paint(head, body);
    updateToggle();
  }

  function documentsPanel() {
    const form = node('form', 'doc-start');
    const title = node('input'); title.required = true; title.maxLength = 200; title.placeholder = tr('What are you documenting?');
    title.setAttribute('aria-label', tr('What are you documenting?'));
    const purpose = node('textarea'); purpose.maxLength = 2000; purpose.rows = 2; purpose.placeholder = tr('Purpose (optional)');
    purpose.setAttribute('aria-label', tr('Purpose (optional)'));
    const start = el('button', 'primary', icon('play'), node('span', '', tr('Start documenting'))); start.type = 'submit';
    const chats = node('select'); chats.multiple = true; chats.size = 4; chats.setAttribute('aria-label', tr('Only these chats'));
    for (const target of state.status?.targets || []) chats.append(new Option(target.title || String(target.chat_id), String(target.chat_id)));
    const scope = el('label', 'doc-scope', tr('Only these chats (none selected: all chats)'), chats);
    form.append(title, purpose, ...(chats.options.length ? [scope] : []), start,
      node('p', 'hint', tr('A draft can be paused, restarted or deleted. Only a fixed document is signed.')));
    form.addEventListener('submit', event => {event.preventDefault(); busy(start, async () => {
      const session = await json('documentation', {title: title.value, purpose: purpose.value,
        chat_ids: [...chats.selectedOptions].map(option => Number(option.value))});
      current = session; sessionTab = 'timeline';
      for (const chat of session.chat_ids || []) await snapshot(chat, true).catch(error => toast(error.message, true));
      await refresh();
    });});
    const parts = [section('note', 'New investigation record', form)];
    const sessions = homeList?.sessions || [];
    if (!sessions.length) {
      parts.push(empty('doc', tr('No documents yet.'), tr('Start a record, act in Telegram, and the steps write themselves.')));
      return parts;
    }
    const list = node('ul', 'doc-list');
    for (const item of sessions) {
      const status = item.fixed ? 'fixed' : item.state;
      const card = el('button', 'doc-session', el('span', 'doc-session-main', node('strong', '', item.title),
        node('span', 'doc-sub', tr('{n} notes', {n: item.marks}) + (item.created_at ? ' · ' + item.created_at.slice(0, 10) : ''))),
        el('span', 'doc-pill ' + status, node('span', 'doc-dot'), item.fixed ? tr('Fixed') : tr(STATES[item.state] || item.state)));
      card.type = 'button';
      card.addEventListener('click', () => busy(card, async () => {current = {id: item.id}; sessionTab = 'timeline'; await refresh();}));
      list.append(el('li', '', card));
    }
    parts.push(section('doc', 'Documents', list));
    return parts;
  }

  async function refresh() {
    const result = await json(path(current.id));
    current = {...result.session, fixed: result.fixed}; data = result.document;
    renderSession();
  }

  async function act(action) {
    await json(path(current.id, action), {}); await refresh();
  }

  async function document_(suffix, recording = 1) {
    const response = await api(path(current.id, 'document.' + suffix) + (recording > 1 ? '?recording=' + recording : ''));
    const page = suffix === 'html' || suffix === 'slides';
    const types = {md: 'text/markdown', vtt: 'text/vtt', srt: 'application/x-subrip', json: 'application/json'};
    const blob = new Blob([await response.text()], {type: page ? 'text/html' : types[suffix] || 'application/octet-stream'});
    const name = 'tgwitness-documentation-' + current.id.slice(0, 8) + (recording > 1 ? '-recording-' + recording : '')
      + (suffix === 'slides' ? '-slides.html' : '.' + suffix);
    if (!page) return saveBlob(blob, name);
    const url = URL.createObjectURL(blob), opened = window.open(url, '_blank');
    if (!opened) saveBlob(blob, name);
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  async function fix() {
    if (await askConfirm(tr('Fix this document? It is signed and recorded in the journal; afterwards only a new revision can change it.'))) await act('fix');
  }

  function pill(session) {
    const status = session.fixed ? 'fixed' : session.state;
    return el('span', 'doc-pill ' + status, node('span', 'doc-dot'),
      session.fixed ? tr('Fixed') : tr(STATES[session.state] || session.state));
  }

  function actions() {
    const row = node('div', 'doc-actions');
    if (current.fixed) {
      row.append(button('New revision', 'primary', async () => {
        current = await json(path(current.id, 'revise'), {}); sessionTab = 'timeline'; await refresh();
      }, 'edit'), button('Export', 'secondary', async () => {sessionTab = 'export'; renderSession();}, 'download'));
      return row;
    }
    if (current.state === 'recording') row.append(button('Pause', 'secondary', () => act('pause'), 'pause'));
    if (current.state === 'paused') row.append(button('Resume', 'primary', () => act('resume'), 'play'));
    if (current.state !== 'stopped') row.append(button('Stop', 'secondary', () => act('stop'), 'stop'));
    const note = button('Note', 'primary', async () => markForm(), 'note');
    note.append(node('kbd', 'doc-kbd', 'M'));
    row.append(note, button('Fix document', 'secondary', fix, 'seal'));
    return row;
  }

  function renderSession() {
    const session = current, blocks = data?.blocks || [];
    const steps = blocks.filter(b => b.type === 'step').length, marks = blocks.filter(b => b.type === 'mark').length;
    const tabs = [['timeline', 'Timeline', 'clock', steps], ['notes', 'Notes', 'note', marks],
      ...(analysisAvailable() ? [['analysis', 'Analysis', 'chart']] : []),
      ...(may('account') && !session.fixed ? [['protection', 'Protection', 'shield']] : []), ['export', 'Export', 'download']];
    if (!tabs.some(tab => tab[0] === sessionTab)) sessionTab = 'timeline';
    const meta = node('div', 'doc-sub doc-head-meta', [tr('Revision {n}', {n: session.revision}),
      session.fixed ? 'SHA-256 ' + session.fixed.statement_sha256.slice(0, 12) + '…' : '',
      session.fixed?.sealed ? tr('{n} hidden records sealed', {n: session.fixed.sealed}) : ''].filter(Boolean).join(' · '));
    const head = el('header', 'doc-head',
      topRow(async () => {current = data = null; sessionTab = 'timeline'; await listing();}, session.title, pill(session)),
      meta, actions(), tabBar(tabs, sessionTab, id => {sessionTab = id; renderSession();}));
    const body = node('div', 'doc-body'); body.dataset.view = session.id + ':' + sessionTab;
    body.setAttribute('role', 'tabpanel');
    const build = {timeline: timelinePanel, notes: notesPanel, analysis: analysisPanel, protection: protectionPanel,
      export: exportPanel}[sessionTab];
    body.append(...build().filter(Boolean));
    paint(head, body);
    updateToggle();
  }

  function chip(text, cls, iconName, title) {
    const item = el('span', 'doc-chip-tag ' + (cls || ''), iconName ? icon(iconName) : '', text);
    if (title) item.title = title;
    return item;
  }

  function lagChips(step) {
    const found = [];
    if (typeof step.after_seconds === 'number')
      found.push(chip(tr('+{s} s', {s: seconds(step.after_seconds)}), 'lag', 'clock', tr(AFTER[step.after] || 'after the action')));
    if (typeof step.telegram_after_seconds === 'number')
      found.push(chip(tr('Telegram: +{s} s', {s: seconds(step.telegram_after_seconds)}), 'lag-server', '', tr('Telegram server time')));
    return found;
  }

  function timeChip(step) {
    const time = node('time', 'doc-time', clock(step.at));
    if (step.at) {time.dateTime = step.at; time.title = step.at;}
    if (!step.video) return time;
    const s = Math.floor(step.video.offset_seconds || 0), pad = n => String(n).padStart(2, '0');
    const video = chip(pad(Math.floor(s / 3600)) + ':' + pad(Math.floor(s / 60) % 60) + ':' + pad(s % 60)
      + (step.video.recording > 1 ? ' · #' + step.video.recording : ''), 'video', 'play', tr('Moment in the screen recording'));
    return el('span', 'doc-time-group', time, video);
  }

  function quick(block) {
    if (!state.me?.admin || current.fixed) return '';
    const step = block.step, row = node('div', 'doc-quick');
    const username = step.sender?.username;
    if (username && ['reply', 'edited'].includes(step.type))
      row.append(button('Telegram Web', 'ghost', () => isolate({telegram: '@' + username, chat_id: block.chat_id,
        title: step.sender.display_name || null, purpose: current.title}), 'globe'));
    const links = [step.type === 'checked_link' ? step.link : null,
      ...(step.indicators || []).filter(i => i.kind === 'url').map(i => i.value)].filter(Boolean).slice(0, 3);
    for (const link of links) {
      const b = button('Open in isolation', 'ghost', () => isolate({url: link, chat_id: block.chat_id, purpose: current.title}), 'globe');
      b.title = link; row.append(b);
    }
    return row.childElementCount ? row : '';
  }

  function extras(block) {
    const step = block.step, row = node('div', 'doc-chips');
    if (!step.hidden) {
      for (const link of step.risky_links || [])
        row.append(chip(tr(RISKS[link.risk] || 'Risky link.'), 'alert', 'alert', link.href || link.text || ''));
      for (const link of step.deceptive_links || [])
        row.append(chip(tr('The link text {text} opens {href}', {text: '“' + (link.text || '') + '”', href: link.href || ''}), 'alert', 'link'));
      for (const item of step.indicators || []) row.append(copyChip(item));
    }
    return [row.childElementCount ? row : '', quick(block)];
  }

  function bubble(block, outgoing) {
    const step = block.step;
    const who = outgoing ? (step.type === 'sent_elsewhere' ? tr('This account · another app') : tr('This account'))
      : step.sender?.display_name || (step.sender?.username ? '@' + step.sender.username : tr('The other side'));
    const box = el('div', 'doc-bubble', el('div', 'doc-who', node('span', 'doc-name', who),
      step.type === 'edited' ? node('span', 'doc-tag', tr('Edited')) : '',
      step.ai_draft ? el('span', 'doc-tag', icon('spark'), step.ai_draft.similarity >= 1
        ? tr('AI draft #{n}', {n: step.ai_draft.seq})
        : tr('Based on AI draft #{n} · {p}%', {n: step.ai_draft.seq, p: Math.round(step.ai_draft.similarity * 100)})) : '',
      step.message_id ? node('span', 'doc-id', '#' + step.message_id) : ''),
      step.text ? node('p', 'doc-text', step.text) : '');
    if (step.translation) box.append(el('div', 'doc-translation', node('small', '', tr('Machine translation {source} → {target} · {model}',
      {source: (step.translation.source_language || '?').toUpperCase(), target: (step.translation.target || '?').toUpperCase(),
        model: step.translation.model || '?'})), node('p', '', step.translation.text)));
    if (step.media) box.append(el('div', 'doc-media', icon('image'),
      node('span', '', [step.media.file_name || tr('(attachment)'), step.media.mime_type].filter(Boolean).join(' · '))));
    const keys = (step.buttons || []).filter(row => row.length);
    if (keys.length) box.append(el('div', 'doc-keys', ...keys.map(row => el('div', 'doc-key-row',
      ...row.map(label => node('span', 'doc-key', label))))));
    if (step.files?.length) box.append(node('div', 'doc-sub', tr('{n} files saved', {n: step.files.length})));
    return el('li', 'doc-msg ' + (outgoing ? 'out' : 'in'), box,
      el('div', 'doc-meta-line', timeChip(step), ...lagChips(step)), ...extras(block));
  }

  function captureCard(block) {
    const step = block.step, subject = step.subject || {};
    const who = [subject.title, subject.telegram, subject.chat_id !== undefined && subject.chat_id !== null ? 'ID ' + subject.chat_id : '']
      .filter(Boolean).join(' · ');
    const card = el('div', 'doc-card', el('div', 'doc-card-head', icon('globe'), node('strong', '', tr('Isolated browser')),
      step.http_status ? node('span', 'doc-tag', 'HTTP ' + step.http_status) : '',
      step.server_ip ? node('span', 'doc-tag', step.server_ip) : ''),
      node('div', 'doc-url', step.final_url || step.url || ''), step.title ? node('div', 'doc-sub', step.title) : '',
      thumbnail(step),
      who ? node('div', 'doc-sub', tr('Requested as the view of {who}; this caption comes from the workspace records, not from the screenshot.', {who})) : '');
    return el('li', 'doc-msg card', card, el('div', 'doc-meta-line', timeChip(step), ...lagChips(step)), ...extras(block));
  }

  function checkCard(block) {
    const step = block.step, risks = step.risks || [];
    const card = el('div', 'doc-card check', el('div', 'doc-card-head', icon('shield'), node('strong', '', tr('Account check')),
      node('span', 'doc-tag ' + (risks.length ? 'bad' : 'good'), tr('{n} risks', {n: risks.length}))),
      risks.length ? el('ul', 'doc-risks', ...risks.map(item => node('li', '', tr(item.label) + ': '
        + tr('visible to ' + item.visible_to) + ' → ' + tr('visible to ' + item.recommended)))) : node('div', 'doc-sub', tr('No risky privacy settings found.')));
    return el('li', 'doc-msg card', card, el('div', 'doc-meta-line', timeChip(step)));
  }

  function systemRow(block) {
    const step = block.step;
    const status = step.type === 'outcome' ? (step.status === 'succeeded' ? ' good' : step.status === 'rejected' ? ' bad' : '') : '';
    return el('li', 'doc-sys' + status, el('div', 'doc-sys-line', icon(step.type === 'outcome' && status === ' bad' ? 'alert' : SYSTEM[step.type] || 'more'),
      node('span', 'doc-sys-text', describe(step)), timeChip(step), ...lagChips(step)), ...extras(block));
  }

  function stepView(block) {
    const step = block.step;
    if (step.hidden) return el('li', 'doc-sys locked', el('div', 'doc-sys-line', icon('lock'),
      node('span', 'doc-sys-text', describe(step)), timeChip(step)));
    if (step.type === 'sent' || step.type === 'sent_elsewhere') return bubble(block, true);
    if (step.type === 'reply' || step.type === 'edited') return bubble(block, false);
    if (step.type === 'visual') return captureCard(block);
    if (step.type === 'self_check') return checkCard(block);
    if (step.type === 'subject') return subjectCard(block);
    return systemRow(block);
  }

  function divider(chat) {
    const episode = (data?.episodes || []).find(item => item.chat_id === chat);
    const title = episode?.title || (chat === null ? tr('Account check and isolated browser') : tr('Chat {id}', {id: chat}));
    const row = el('li', 'doc-divider', node('span', '', title));
    if (chat !== null && chat !== undefined && !current.fixed && may('collect')) {
      row.append(button('', 'ghost doc-icon-btn doc-snap', () => snapshot(chat), 'user', 'Snapshot the profile now'));
    }
    return row;
  }

  async function snapshot(chat, quiet) {
    const result = await json('subjects/' + encodeURIComponent(chat) + '/snapshot', {});
    if (!quiet) toast(result.snapshot?.changes?.length ? tr('Profile saved; {n} changes since the previous snapshot.', {n: result.snapshot.changes.length})
      : tr('Profile saved as journal record #{seq}.', {seq: result.event}));
    if (!quiet) await refresh();
    return result;
  }

  const avatars = new Map();

  function avatarImage(sha256, title) {
    const box = node('div', 'doc-subject-avatar');
    box.textContent = (title || '?').split(/\s+/).slice(0, 2).map(part => part[0] || '').join('').toUpperCase() || '?';
    if (!sha256) return box;
    const show = url => {const img = node('img'); img.alt = tr('Profile photo'); img.src = url; box.replaceChildren(img);};
    if (avatars.has(sha256)) show(avatars.get(sha256));
    else api('media/' + sha256).then(r => r.blob()).then(blob => {const url = URL.createObjectURL(blob); avatars.set(sha256, url); show(url);})
      .catch(() => {});
    return box;
  }

  const shownValue = value => Array.isArray(value) ? value.map(item => typeof item === 'object' ? '/' + item.command : item).join(', ') || '—'
    : value === null || value === undefined || value === '' ? '—' : String(value);

  function subjectCard(block) {
    const step = block.step, kinds = {bot: 'Bot', user: 'Person', channel: 'Channel', group: 'Group'};
    const photo = (step.files || []).find(item => item.role === 'avatar');
    const ident = step.user_id ?? step.chat_id;
    const flags = [node('span', 'doc-flag', tr(kinds[step.kind] || 'Chat')),
      ...(step.flags || []).filter(flag => flag !== 'bot').map(flag => node('span', 'doc-flag ' + flag, tr(flag).toUpperCase()))];
    const commands = (step.commands || []).map(command => {
      const item = node('span', '', '/' + command.command); item.title = command.description || ''; return item;
    });
    const card = el('div', 'doc-subject', el('div', 'doc-subject-head', avatarImage(photo?.sha256, step.title),
      el('div', 'doc-subject-id', node('strong', '', step.title || tr('Unnamed')),
        (step.usernames || []).length ? node('span', 'doc-subject-handles', step.usernames.map(name => '@' + name).join(' · ')) : '',
        ident !== undefined && ident !== null ? node('span', 'doc-sub', tr('Telegram ID {id}', {id: ident})) : '',
        el('div', 'doc-flags', ...flags))),
      step.about ? el('div', 'doc-subject-part', node('small', '', tr('Bio or description')), node('p', '', step.about)) : '',
      step.bot_description ? el('div', 'doc-subject-part', node('small', '', tr('Bot description')), node('p', '', step.bot_description)) : '',
      commands.length ? el('div', 'doc-subject-part', node('small', '', tr('Bot commands')), el('div', 'doc-commands', ...commands)) : '',
      step.participants ? node('span', 'doc-sub', tr('{n} members', {n: step.participants})) : '',
      (step.changes || []).length ? el('div', 'doc-subject-changes', node('small', '', tr('Changed since the previous snapshot')),
        ...step.changes.map(change => node('p', '', tr(change.field) + ': ' + shownValue(change.before) + ' → ' + shownValue(change.after)))) : '',
      el('div', 'doc-meta-line', timeChip(step), ...extras(block)));
    return el('li', 'doc-msg card', card);
  }

  function noteCard(mark) {
    const kind = ['conclusion', 'decision', 'important', 'question'].find(label => mark.labels.includes(label))
      || (mark.labels.some(label => HIDING.includes(label)) ? 'hiding' : 'plain');
    const card = el('li', 'doc-notecard ' + kind, el('div', 'doc-who', icon('note'),
      ...(mark.labels.length ? mark.labels.map(label => node('span', 'doc-tag l-' + label, labelName(label))) : [node('span', 'doc-tag', tr('Note'))]),
      node('time', 'doc-time', clock(mark.at))), node('p', 'doc-text', mark.text));
    if (mark.target_seq) card.append(node('div', 'doc-sub', tr('Tied to journal record #{seq}', {seq: mark.target_seq})));
    if (mark.video) {
      const s = Math.floor(mark.video.offset_seconds), pad = n => String(n).padStart(2, '0');
      card.append(chip(tr('Video ≈ {at}', {at: pad(Math.floor(s / 3600)) + ':' + pad(Math.floor(s / 60) % 60) + ':' + pad(s % 60)}), 'lag', 'play'));
    }
    if (!current.fixed) card.append(el('div', 'doc-row-actions', button('Edit', 'ghost', async () => markForm(mark), 'edit'),
      button('Remove', 'ghost', async () => {
        await api(path(current.id, 'marks', mark.id), undefined, {method: 'DELETE'}); await refresh();
      }, 'trash')));
    return card;
  }

  function foundRow() {
    const seen = new Map();
    for (const item of (data?.episodes || []).flatMap(episode => episode.summary?.indicators || []))
      if (!seen.has(item.kind + item.value)) seen.set(item.kind + item.value, item);
    if (!seen.size) return '';
    const row = el('div', 'doc-chips found', ...[...seen.values()].slice(0, 16).map(copyChip));
    return section('search', 'Found in messages', row);
  }

  function timelinePanel() {
    const parts = [];
    if (!current.fixed && state.me?.admin) parts.push(browserRow());
    parts.push(foundRow());
    if (!current.fixed && modules?.goal !== 'evidence') parts.push(translateRow());
    if (!current.fixed) parts.push(searchRow());
    if (!current.fixed) parts.push(qrRow());
    const blocks = data?.blocks || [], shown = blocks.slice(-80);
    if (!shown.length) {
      parts.push(empty('clock', tr('Nothing recorded yet'),
        tr('Steps appear here as the account acts and receives replies. Press M to add a note.')));
      return parts;
    }
    if (blocks.length > shown.length)
      parts.push(node('p', 'hint', tr('Showing the newest {n} of {total} entries. Open the report for everything.', {n: shown.length, total: blocks.length})));
    const list = node('ol', 'doc-feed');
    let chat;
    for (const block of shown) {
      if (block.type === 'step' && block.chat_id !== chat) {chat = block.chat_id; list.append(divider(chat));}
      list.append(block.type === 'mark' ? noteCard(block.mark) : stepView(block));
    }
    parts.push(list);
    if (data?.truncated) parts.push(node('p', 'hint', tr('This document is long; the newest records may be outside the shown range.')));
    return parts;
  }

  const MESSAGE_STEPS = ['reply', 'edited', 'sent', 'sent_elsewhere'];

  function targetLanguage() {
    const code = String(typeof LANG === 'string' ? LANG : 'en').slice(0, 2).toLowerCase();
    return /^[a-z]{2}$/.test(code) ? code : 'en';
  }

  function translateRow() {
    const pending = (data?.blocks || []).filter(b => b.type === 'step' && b.chat_id !== null && b.chat_id !== undefined
      && MESSAGE_STEPS.includes(b.step.type) && !b.step.hidden && !b.step.translation && b.step.ref?.seq && b.step.text);
    if (!pending.length) return '';
    const chats = new Map();
    for (const block of pending) chats.set(block.chat_id, [...(chats.get(block.chat_id) || []), block.step.ref.seq]);
    return el('div', 'doc-row-actions doc-translate-row', button('Translate messages', 'ghost', async () => {
      const target = targetLanguage();
      let done = 0;
      for (const [chatId, seqs] of chats) {
        let preview;
        try {
          preview = await json('translations/preview', {chat_id: chatId, seqs: seqs.slice(-100), target});
        } catch (error) {
          if (error.status === 409) continue;
          throw error;
        }
        if (!preview.enabled) throw new Error(tr('AI is off for this workspace. The main administrator can connect a model in Settings → AI.'));
        const ask = tr('Send {n} messages to {model} at {endpoint} for machine translation into {language}? The originals stay unchanged and the translation is recorded in the journal.',
          {n: preview.messages, model: preview.provider.model || '?', endpoint: preview.provider.endpoint, language: preview.target_name});
        if (!await askConfirm(ask)) return;
        const result = await json('translations', {preview_id: preview.preview_id, consent: true});
        done += result.items.length;
      }
      toast(done ? tr('{n} messages translated.', {n: done}) : tr('Nothing to translate: the messages are already in your language.'));
      await refresh();
    }, 'globe'), node('span', 'hint', tr('Machine translation appears under the original and is labelled as such.')));
  }

  function qrRow() {
    const chats = (current.chat_ids || []).length ? current.chat_ids : (data?.episodes || [])
      .map(episode => episode.chat_id).filter(chat => chat !== null && chat !== undefined);
    if (!chats.length) return '';
    return el('div', 'doc-row-actions', button('Read QR codes in saved images', 'ghost', async () => {
      let codes = 0, images = 0;
      for (const chat of chats) {
        const result = await json('qr/scan?chat_id=' + encodeURIComponent(chat), {});
        codes += result.codes; images += result.scanned;
      }
      toast(codes ? tr('{n} codes read from {k} images.', {n: codes, k: images})
        : tr('No codes found in {k} images.', {k: images}));
      await refresh();
    }, 'image'), node('span', 'hint', tr('Payment and link codes on screenshots become indicators tied to their message.')));
  }

  function searchRow() {
    const query = node('input'), source = node('select'), note = node('input'), go = el('button', 'secondary', icon('search'),
      node('span', '', tr('Search and record')));
    query.maxLength = 500; query.placeholder = tr('What are you looking for?'); query.dataset.key = 'record:query';
    query.setAttribute('aria-label', tr('Search query'));
    for (const [value, label] of [['messages', 'Messages'], ['all', 'Messages and recognised text'], ['ocr', 'Text in images'],
      ['transcription', 'Speech transcripts']]) source.append(new Option(tr(label), value));
    note.maxLength = 1000; note.placeholder = tr('Why this search (optional)'); go.type = 'submit';
    const form = el('form', 'doc-search-record', query, source, note, go,
      node('p', 'hint', tr('The query, its scope and the number of results are recorded in the journal and the document, including searches that find nothing.')));
    form.addEventListener('submit', event => {event.preventDefault(); busy(go, async () => {
      if (!query.value.trim()) {query.focus(); return;}
      const result = await json('search/record', {query: query.value.trim(), source: source.value, note: note.value,
        chat_ids: current.chat_ids || []});
      toast(result.matched ? tr('{n} results · recorded as record #{seq}', {n: result.matched, seq: result.event})
        : tr('No results · recorded as record #{seq}', {seq: result.event}));
      await refresh();
    });});
    return el('details', 'doc-how', node('summary', '', tr('Record a search')), form);
  }

  function notesPanel() {
    const marks = (data?.blocks || []).filter(b => b.type === 'mark').map(b => b.mark), parts = [];
    if (!current.fixed) {
      const add = button('Add note', 'primary', async () => markForm(), 'note');
      add.append(node('kbd', 'doc-kbd', 'M'));
      parts.push(el('div', 'doc-row-actions', add, node('span', 'hint', tr('Press M anywhere in the panel to add a note.'))));
    }
    if (!marks.length) {
      parts.push(empty('note', tr('No notes yet'), tr('Notes and conclusions are your statements. They stay separate from Telegram observations.')));
      return parts;
    }
    const groupOf = mark => ['conclusion', 'decision', 'important', 'question'].find(label => mark.labels.includes(label)) || 'other';
    for (const [group, title, iconName] of [['conclusion', 'Conclusions', 'seal'], ['decision', 'Decisions and rationale', 'check'],
      ['important', 'Important', 'alert'], ['question', 'Open questions', 'search'], ['other', 'Other notes', 'note']]) {
      const items = marks.filter(mark => groupOf(mark) === group);
      if (items.length) parts.push(section(iconName, title, el('ol', 'doc-feed', ...items.map(noteCard))));
    }
    return parts;
  }

  function packageForm() {
    const box = node('div', 'doc-package'), mode = node('select'), own = node('input'), result = node('div', 'doc-package-result');
    mode.setAttribute('aria-label', tr('Case package (ZIP)'));
    for (const [value, text] of [['none', 'Case package (ZIP)'], ['generated', 'Encrypted, with a generated passphrase'],
      ['own', 'Encrypted, with my passphrase']]) mode.append(new Option(tr(text), value));
    own.type = 'password'; own.placeholder = tr('Passphrase, at least 20 characters'); own.hidden = true;
    own.autocomplete = 'new-password'; own.setAttribute('aria-label', tr('Passphrase, at least 20 characters'));
    mode.addEventListener('change', () => {own.hidden = mode.value !== 'own';});
    const go = button('Download', 'primary', async () => {
      const response = await api(path(current.id, 'package'), {encryption: mode.value,
        ...(mode.value === 'own' ? {passphrase: own.value} : {})});
      const secret = response.headers.get('X-TgWitness-Passphrase');
      saveBlob(await response.blob(), 'tgwitness-case-' + current.id.slice(0, 8) + (mode.value === 'none' ? '' : '.encrypted') + '.zip');
      own.value = '';
      if (secret) {
        const code = node('code', 'doc-secret', secret);
        result.replaceChildren(el('div', 'doc-callout warn', icon('alert'), node('p', '', tr('Write this passphrase down and keep it apart from the drive. It is shown only now; without it the package cannot be opened.'))),
          el('div', 'doc-secret-row', code, button('Copy', 'secondary', () => copy(secret), 'key')));
      } else result.replaceChildren(el('div', 'doc-callout good', icon('check'), node('p', '', tr('Saved. Open it with any ZIP tool; 7-Zip or WinRAR also open encrypted packages.'))));
    }, 'download');
    box.append(mode, go, own, result);
    return box;
  }

  function appearanceForm() {
    const saved = {offset_minutes: 0, hashes: 'short', images: 'inline', theme: 'light', detail: 'full', summary: true,
      found: true, preset: 'custom', subjects: true, notes: true, conclusions: true, translations: true, references: true,
      limits: true, ...(current.appearance || {})};
    const form = node('div', 'doc-look'), selects = {}, zone = node('select'), preset = node('select');
    for (const [value, text] of PRESET_NAMES) preset.append(new Option(tr(text), value));
    preset.value = saved.preset || 'custom'; selects.preset = preset;
    form.append(el('label', 'doc-look-preset', tr('Preset'), preset));
    for (let minutes = -720; minutes <= 840; minutes += 60)
      zone.append(new Option(minutes ? 'UTC' + (minutes < 0 ? '−' : '+') + Math.abs(minutes / 60) : 'UTC', String(minutes)));
    zone.value = String(saved.offset_minutes); selects.offset_minutes = zone;
    form.append(el('label', '', tr('Times'), zone));
    for (const [name, label, choices] of LOOK) {
      const select = node('select');
      for (const [value, text] of choices) select.append(new Option(tr(text), value));
      select.value = String(saved[name]); selects[name] = select;
      form.append(el('label', '', tr(label), select));
    }
    const save = async () => {
      const body = Object.fromEntries(Object.entries(selects).map(([k, s]) => [k, k === 'offset_minutes' ? Number(s.value)
        : s.value === 'true' ? true : s.value === 'false' ? false : s.value]));
      current.appearance = await api(path(current.id, 'appearance'), body, {method: 'PUT'}).then(r => r.json());
    };
    const lock = () => {
      for (const name of ['limits', 'references']) selects[name].disabled = preset.value === 'court';
    };
    preset.addEventListener('change', () => {
      for (const [name, value] of Object.entries(PRESETS[preset.value] || {})) if (selects[name]) selects[name].value = String(value);
      lock(); busy(null, save);
    });
    for (const [name, select] of Object.entries(selects)) {
      if (name === 'preset') continue;
      select.addEventListener('change', () => {preset.value = 'custom'; lock(); busy(null, save);});
    }
    lock();
    return [form, el('div', 'doc-row-actions', button('Preview', 'secondary', () => document_('html'), 'eye'),
      button('Presentation', 'secondary', () => document_('slides'), 'play')),
      node('p', 'hint', tr('Appearance does not change the signed content. It applies to the page, Markdown and the case package.'))];
  }

  function exportPanel() {
    const parts = [section('doc', 'Open the record', el('div', 'doc-grid', button('Open', 'secondary', () => document_('html'), 'doc'),
      button('Presentation', 'secondary', () => document_('slides'), 'play'),
      button('Markdown', 'secondary', () => document_('md'), 'download'), button('JSON', 'secondary', () => document_('json'), 'download'))),
      ...((data?.recordings || []).length ? [section('play', 'Screen recording', node('p', 'hint',
        tr('Subtitles with step captions and notes, aligned to the recorder video. Open them in a player next to the video, or burn them in with FFmpeg.')),
        el('div', 'doc-grid', ...data.recordings.flatMap((item, index) => [
          button(tr('Recording {n}: subtitles VTT', {n: index + 1}), 'secondary', () => document_('vtt', index + 1), 'download'),
          button(tr('Recording {n}: subtitles SRT', {n: index + 1}), 'secondary', () => document_('srt', index + 1), 'download')])))] : [])];
    if (current.fixed) parts.push(section('download', 'Case package',
      node('p', 'hint', tr('A BagIt folder with the report, presentation, checks, files and found indicators.')), packageForm()));
    else parts.push(section('seal', 'Case package', node('p', 'hint', tr('Fix the document to export a signed case package.')),
      button('Fix document', 'primary', fix, 'seal')));
    if (current.fixed?.sealed && may('board.manage')) parts.push(section('key', 'Keys to hidden content',
      node('p', 'hint', tr('{n} hidden records sealed', {n: current.fixed.sealed})),
      button('Keys to hidden content', 'secondary', async () => {
        if (!await askConfirm(tr('Release the keys to hidden content? Hand them over separately from the document; the release is recorded in the journal.'))) return;
        const response = await api(path(current.id, 'keys.json'));
        saveBlob(await response.blob(), 'tgwitness-documentation-' + current.id.slice(0, 8) + '-keys.json');
      }, 'key')));
    parts.push(section('eye', 'Report appearance', appearanceForm()));
    parts.push(section('trash', 'Manage', el('div', 'doc-row-actions',
      current.fixed ? '' : button('Start over', 'ghost', async () => {
        if (await askConfirm(tr('Start this draft over? Its notes are removed; Telegram observations stay unchanged.'))) await act('restart');
      }, 'clock'),
      button('Delete', 'ghost danger', async () => {
        const text = current.fixed ? 'Delete this local copy? The fixed digest stays in the journal; download the document first.'
          : 'Delete this draft completely? Telegram observations stay unchanged.';
        if (!await askConfirm(tr(text))) return;
        await api(path(current.id), undefined, {method: 'DELETE'}); current = data = null; await listing();
      }, 'trash'))));
    return parts;
  }

  function protectionPanel() {
    const box = node('div', 'doc-protect');
    const fill = () => {
      const info = shieldInfo, latest = info.latest, parts = [];
      parts.push(el('div', 'doc-callout good', icon('shield'),
        node('p', '', tr('Read receipts are always blocked for this collector: it never marks messages or stories as read.'))));
      if (latest) {
        const risks = latest.findings.filter(f => f.level === 'risk'), notices = latest.findings.filter(f => f.level === 'notice');
        parts.push(section('shield', 'Account check', node('p', 'doc-sub', tr('Last check: {at}', {at: (latest.event?.observed_at || '').slice(0, 19).replace('T', ' ')})),
          risks.length ? el('ul', 'doc-risks', ...risks.map(item => el('li', 'bad', icon('alert'), tr(item.label) + ': '
            + tr('visible to ' + item.visible_to) + ' → ' + tr('visible to ' + item.recommended))))
            : el('div', 'doc-callout good', icon('check'), node('p', '', tr('No risky privacy settings found.'))),
          notices.length ? el('ul', 'doc-risks', ...notices.map(item => el('li', '', icon('more'), tr(item.label)))) : ''));
        const view = latest.bot_view || {};
        parts.push(section('user', 'What a bot you message sees', el('dl', 'doc-kv',
          ...Object.entries(view).flatMap(([k, v]) => [node('dt', '', k), node('dd', '', String(v))]))));
      } else parts.push(empty('shield', tr('This account has not been checked yet.'),
        tr('The check reads privacy settings only; it changes nothing in Telegram.')));
      parts.push(el('div', 'doc-row-actions', button('Check my account', 'primary', async () => {
        await json('opsec/check', {}); shieldInfo = await json('opsec'); fill();
      }, 'search')));
      if (may('settings')) {
        const label = node('label', 'doc-switch'), input = node('input'); input.type = 'checkbox';
        input.checked = !!info.settings.hide_online_after_actions;
        label.append(input, node('span', 'doc-switch-track'), node('span', '', tr('Go offline right after each panel action')));
        input.addEventListener('change', () => busy(null, async () => {
          await json('opsec/settings', {hide_online_after_actions: input.checked});
          shieldInfo.settings.hide_online_after_actions = input.checked;
        }));
        parts.push(section('eye', 'Presence', label,
          node('p', 'hint', tr('A quick switch from online to offline can itself be noticed. Hiding last seen in privacy settings is stronger.'))));
      }
      box.replaceChildren(...parts);
    };
    if (!may('account')) return [empty('lock', tr('Not available for this access.'))];
    if (shieldInfo) fill();
    else {
      box.append(node('p', 'hint', tr('Loading…')));
      json('opsec').then(info => {shieldInfo = info; fill();}).catch(error => box.replaceChildren(el('div', 'doc-callout warn', icon('alert'), node('p', '', error.message))));
    }
    return [box];
  }

  const draftNow = () => ({profile: {}, privacy: {}, global: {}, errors: {}});
  const PRIVACY_GROUPS = [['profile', 'Who sees my profile', 'eye'], ['contact', 'Who can reach me', 'send']];
  const FIELD_NAMES = {first_name: 'First name', last_name: 'Last name', username: 'Username', about: 'Bio'};

  function coverPanel() {
    if (!may('account')) return [empty('lock', tr('Not available for this access.'))];
    const box = node('div', 'doc-account');
    if (cover) fillCover(box);
    else {
      box.append(node('p', 'hint', tr('Loading…')));
      json('undercover').then(info => {cover = info; if (box.isConnected) fillCover(box);})
        .catch(error => box.replaceChildren(el('div', 'doc-callout warn', icon('alert'), node('p', '', error.message))));
    }
    return [box];
  }

  async function reloadCover(box) {
    cover = await json('undercover');
    fillCover(box);
  }

  function fillCover(box) {
    box.replaceChildren(
      el('div', 'doc-callout', icon('lock'), node('p', '', tr('What is recorded here goes into the undercover activity record: who the account pretends to be, under which authority, and who sent each message. TgWitness records and flags; it does not decide whether an authorisation was needed.'))),
      personaSection(box), authoritySection(box),
      el('div', 'doc-row-actions', current ? button('Open the undercover record', 'secondary', () => document_('undercover'), 'doc') : '',
        button('Reload', 'ghost', () => reloadCover(box), 'refresh')));
  }

  function personaSection(box) {
    const list = node('ul', 'doc-goals');
    cover.personas.forEach(persona => {
      const row = el('li', 'doc-goal ' + (persona.status === 'retired' ? 'dropped' : 'obtained'),
        node('span', 'doc-goal-status ' + (persona.status === 'retired' ? 'dropped' : 'obtained'),
          tr(persona.status === 'retired' ? 'Retired' : 'Active')),
        el('div', 'doc-goal-main', node('span', 'doc-goal-text', persona.label),
          node('span', 'doc-sub', [persona.telegram_id ? tr('Telegram ID {id}', {id: persona.telegram_id}) : '',
            persona.controlled_by ? tr('controlled by {who}', {who: persona.controlled_by}) : ''].filter(Boolean).join(' · ')),
          persona.legend ? node('p', 'doc-text', persona.legend) : ''),
        el('div', 'doc-row-actions doc-goal-tools', button('', 'ghost doc-icon-btn', async () => {
          row.replaceWith(personaForm(box, persona));
        }, 'edit', 'Edit')));
      list.append(row);
    });
    return section('user', 'Personas', node('p', 'hint', tr('The account as the other side sees it, and who controls it.')),
      cover.personas.length ? list : node('p', 'hint', tr('None recorded.')),
      el('details', 'doc-how', node('summary', '', tr('Add a persona')), personaForm(box, null)));
  }

  function personaForm(box, persona) {
    const label = node('input'), ident = node('input'), controller = node('input'), legend = node('textarea'), status = node('select');
    label.maxLength = 120; label.value = persona?.label || ''; label.placeholder = tr('Short name of the legend');
    ident.type = 'number'; ident.value = persona?.telegram_id ?? '';
    controller.maxLength = 200; controller.value = persona?.controlled_by || '';
    legend.maxLength = 4000; legend.rows = 3; legend.value = persona?.legend || '';
    for (const [value, text] of [['active', 'Active'], ['retired', 'Retired']]) status.append(new Option(tr(text), value));
    status.value = persona?.status || 'active';
    const save = button(persona ? 'Save' : 'Add persona', 'primary', async () => {
      if (!label.value.trim()) {label.focus(); throw new Error(tr('Give the persona a short name.'));}
      const body = {label: label.value.trim(), telegram_id: ident.value ? Number(ident.value) : null,
        controlled_by: controller.value.trim(), legend: legend.value, status: status.value};
      if (persona) await api('undercover/personas/' + persona.id, body, {method: 'PUT'});
      else await json('undercover/personas', body);
      await reloadCover(box);
    }, 'check');
    const fields = el('div', 'doc-fields',
      el('label', 'doc-field', node('span', '', tr('Label')), label),
      el('label', 'doc-field', node('span', '', tr('Telegram ID')), ident),
      el('label', 'doc-field', node('span', '', tr('Controlled by')), controller),
      el('label', 'doc-field', node('span', '', tr('Status')), status),
      el('label', 'doc-field wide', node('span', '', tr('Legend')), legend));
    const actions = el('div', 'doc-row-actions', save, persona ? button('Cancel', 'ghost', () => reloadCover(box)) : '');
    return persona ? el('li', 'doc-goal editing', fields, actions) : el('div', '', fields, actions);
  }

  function authoritySection(box) {
    const names = cover.kinds || {}, list = node('ul', 'doc-goals');
    for (const item of cover.authorisations) {
      const spent = item.withdrawn_at || (item.valid_to && Date.parse(item.valid_to) < Date.now());
      list.append(el('li', 'doc-goal ' + (spent ? 'dropped' : 'obtained'),
        node('span', 'doc-goal-status ' + (spent ? 'dropped' : 'obtained'), tr(spent ? 'Closed' : 'In force')),
        el('div', 'doc-goal-main', node('span', 'doc-goal-text', item.reference + ' · ' + tr(names[item.kind] || item.kind)),
          node('span', 'doc-sub', [item.authority, (item.valid_from || '').slice(0, 16).replace('T', ' ') + ' – '
            + (item.valid_to ? item.valid_to.slice(0, 16).replace('T', ' ') : tr('open')),
            item.chat_ids?.length ? tr('{n} chats', {n: item.chat_ids.length}) : tr('all chats'),
            item.withdrawn_at ? tr('withdrawn {at}', {at: item.withdrawn_at.slice(0, 16).replace('T', ' ')}) : ''].filter(Boolean).join(' · ')),
          item.notes ? node('p', 'doc-text', item.notes) : '',
          item.document_sha256 ? node('span', 'doc-sub', 'SHA-256 ' + item.document_sha256.slice(0, 16) + '…') : ''),
        el('div', 'doc-row-actions doc-goal-tools', item.withdrawn_at ? '' :
          button('', 'ghost doc-icon-btn danger', async () => {
            if (!await askConfirm(tr('Record that authorisation {ref} was withdrawn? Activity after this moment is flagged as outside it.', {ref: item.reference}))) return;
            await json('undercover/authorisations/' + item.id + '/withdraw', {});
            await reloadCover(box);
          }, 'close', 'Record as withdrawn'))));
    }
    return section('shield', 'Authorisations', node('p', 'hint',
      tr('Reference numbers of the approvals that cover this work. Messages outside their time or chats are flagged in the record.')),
      cover.authorisations.length ? list : el('div', 'doc-callout warn', icon('alert'),
        node('p', '', tr('None recorded. The undercover record will say so.'))),
      el('details', 'doc-how', node('summary', '', tr('Add an authorisation')), authorityForm(box, names)));
  }

  function authorityForm(box, names) {
    const reference = node('input'), kind = node('select'), authority = node('input');
    const from = node('input'), to = node('input'), chats = node('select'), digest = node('input'), notes = node('textarea');
    reference.maxLength = 200; reference.placeholder = tr('Reference number');
    for (const value of AUTHORITY_ORDER) kind.append(new Option(tr(names[value] || value), value));
    authority.maxLength = 200;
    from.type = 'datetime-local'; to.type = 'datetime-local';
    chats.multiple = true; chats.size = 4;
    for (const target of state.status?.targets || []) chats.append(new Option(target.title || String(target.chat_id), String(target.chat_id)));
    digest.maxLength = 64; digest.placeholder = tr('64 hexadecimal characters');
    notes.maxLength = 2000; notes.rows = 2;
    const save = button('Add authorisation', 'primary', async () => {
      if (!reference.value.trim()) {reference.focus(); throw new Error(tr('Enter the reference number.'));}
      if (!from.value) {from.focus(); throw new Error(tr('Enter when the authorisation starts.'));}
      if (digest.value.trim() && !/^[a-f0-9]{64}$/.test(digest.value.trim())) {
        digest.focus(); throw new Error(tr('The document hash must be 64 hexadecimal characters.'));
      }
      const stamp = value => value ? new Date(value).toISOString() : null;
      await json('undercover/authorisations', {reference: reference.value.trim(), kind: kind.value,
        authority: authority.value.trim(), valid_from: stamp(from.value), valid_to: stamp(to.value),
        chat_ids: [...chats.selectedOptions].map(option => Number(option.value)),
        document_sha256: digest.value.trim() || null, notes: notes.value});
      await reloadCover(box);
    }, 'check');
    return el('div', '', el('div', 'doc-fields',
      el('label', 'doc-field', node('span', '', tr('Reference')), reference),
      el('label', 'doc-field', node('span', '', tr('Type')), kind),
      el('label', 'doc-field', node('span', '', tr('Issuing authority')), authority),
      el('label', 'doc-field', node('span', '', tr('Document SHA-256')), digest),
      el('label', 'doc-field', node('span', '', tr('Valid from')), from),
      el('label', 'doc-field', node('span', '', tr('Valid to')), to),
      el('label', 'doc-field wide', node('span', '', tr('Chats (none selected: all chats)')), chats),
      el('label', 'doc-field wide', node('span', '', tr('Notes')), notes)),
      el('div', 'doc-row-actions', save));
  }

  function watchPanel() {
    if (!may('collect')) return [empty('lock', tr('Not available for this access.'))];
    const box = node('div', 'doc-account');
    if (presence) fillWatch(box);
    else {
      box.append(node('p', 'hint', tr('Loading…')));
      json('presence').then(info => {presence = info; if (box.isConnected) fillWatch(box);})
        .catch(error => box.replaceChildren(el('div', 'doc-callout warn', icon('alert'), node('p', '', error.message))));
    }
    return [box];
  }

  async function reloadWatch(box) {
    presence = await json('presence');
    fillWatch(box);
  }

  function stateChip(status) {
    if (!status) return chip(tr('not checked yet'), 'quiet', 'clock');
    const state = status.state || 'unknown';
    return chip(tr(PRESENCE_STATES[state] || state), state === 'online' ? 'good' : state === 'offline' ? '' : 'quiet',
      state === 'online' ? 'eye' : 'clock');
  }

  function fillWatch(box) {
    const config = presence.settings, running = node('input'), every = node('select'), all = node('input');
    running.type = 'checkbox'; running.checked = config.enabled;
    all.type = 'checkbox'; all.checked = config.record_unchanged;
    for (const [value, text] of INTERVALS) every.append(new Option(tr(text), String(value)));
    every.value = String(config.interval_seconds);
    const apply = () => busy(null, async () => {
      presence.settings = await json('presence/settings', {enabled: running.checked,
        interval_seconds: Number(every.value), record_unchanged: all.checked});
    });
    for (const control of [running, every, all]) control.addEventListener('change', apply);
    const switchRow = (input, label, hint) => {
      const row = node('label', 'doc-switch doc-option');
      row.append(input, node('span', 'doc-switch-track'), el('span', 'doc-option-text', node('span', '', tr(label)),
        node('small', '', tr(hint))));
      return row;
    };
    const list = node('ul', 'doc-goals');
    for (const item of presence.watches) {
      const who = item.label || (item.username ? '@' + item.username : tr('Telegram ID {id}', {id: item.user_id}));
      list.append(el('li', 'doc-goal ' + (item.enabled ? '' : 'dropped'),
        el('div', 'doc-goal-main', node('span', 'doc-goal-text', who),
          node('span', 'doc-sub', [item.user_id ? tr('Telegram ID {id}', {id: item.user_id}) : tr('not resolved yet'),
            item.username && item.label ? '@' + item.username : '',
            item.last_checked_at ? tr('checked {at}', {at: clock(item.last_checked_at)}) : ''].filter(Boolean).join(' · ')),
          el('div', 'doc-chips', stateChip(item.last_state),
            item.last_state?.was_online ? chip(tr('last online {at}', {at: clock(item.last_state.was_online)}), 'quiet', 'clock') : ''),
          item.note ? node('p', 'doc-sub', item.note) : ''),
        el('div', 'doc-row-actions doc-goal-tools',
          item.user_id ? button('', 'ghost doc-icon-btn', () => showPattern(box, item), 'chart', 'Show the daily pattern') : '',
          button('', 'ghost doc-icon-btn', () => busy(null, async () => {
            await api('presence/watches/' + item.id, {user_id: item.user_id, username: item.username, label: item.label,
              note: item.note, enabled: !item.enabled}, {method: 'PUT'});
            await reloadWatch(box);
          }), item.enabled ? 'pause' : 'play', item.enabled ? 'Pause' : 'Resume'),
          button('', 'ghost doc-icon-btn danger', async () => {
            if (!await askConfirm(tr('Stop watching {who}? Records already made stay in the journal.', {who}))) return;
            await api('presence/watches/' + item.id, undefined, {method: 'DELETE'});
            await reloadWatch(box);
          }, 'trash', 'Remove'))));
    }
    const target = node('input'), label = node('input'), note = node('input');
    target.maxLength = 33; target.placeholder = tr('@username or numeric ID');
    label.maxLength = 120; label.placeholder = tr('Label (optional)');
    note.maxLength = 1000; note.placeholder = tr('Why (optional)');
    const add = el('button', 'secondary', icon('eye'), node('span', '', tr('Watch this account'))); add.type = 'submit';
    const form = el('form', 'doc-inline-add doc-watch-add', target, label, note, add);
    form.addEventListener('submit', event => {event.preventDefault(); busy(add, async () => {
      const value = target.value.trim();
      if (!value) {target.focus(); return;}
      const numeric = /^\d+$/.test(value);
      await json('presence/watches', {user_id: numeric ? Number(value) : null, username: numeric ? null : value,
        label: label.value.trim(), note: note.value.trim()});
      target.value = label.value = note.value = '';
      await reloadWatch(box);
    });});
    box.replaceChildren(
      el('div', 'doc-callout', icon('timer'), node('p', '', tr('The workspace asks Telegram for the status of these accounts on a schedule and records every change. Asking is an action by this account. A person who hides last seen shows only a coarse state.'))),
      section('timer', 'Checking', el('div', 'doc-fields',
        el('label', 'doc-field', node('span', '', tr('How often')), every)),
        switchRow(running, 'Watch while observation runs', 'The schedule only runs while the collector is running.'),
        switchRow(all, 'Record every check, not only changes', 'Off by default: only changes are written to the journal.'),
        el('div', 'doc-row-actions', button('Check now', 'primary', () => busy(null, async () => {
          const result = await json('presence/check', {});
          toast(result.changes ? tr('{n} changes recorded.', {n: result.changes}) : tr('No changes since the last check.'));
          await reloadWatch(box);
        }), 'refresh'))),
      section('eye', 'Watched accounts', presence.watches.length ? list
        : node('p', 'hint', tr('None yet. Add an account by @username or numeric ID.')), form),
      watchPattern ? patternCard(box) : '');
  }

  async function showPattern(box, item) {
    watchPattern = {...await json('presence/pattern?user_id=' + item.user_id + '&offset_minutes=' + (watchPattern?.offset || 0)),
      who: item.label || (item.username ? '@' + item.username : String(item.user_id)), offset: watchPattern?.offset || 0,
      user_id: item.user_id};
    fillWatch(box);
  }

  function patternCard(box) {
    const found = watchPattern, zone = node('select'), hours = Array.from({length: 24}, (_, h) => String(h).padStart(2, '0'));
    for (const value of ZONES) zone.append(new Option(zoneName(value), String(value)));
    zone.value = String(found.offset || 0);
    zone.addEventListener('change', () => busy(null, async () => {
      watchPattern.offset = Number(zone.value);
      await showPattern(box, {user_id: found.user_id, label: found.who});
    }));
    const states = Object.entries(found.states || {});
    return section('chart', 'Daily pattern', node('p', 'doc-sub', found.who + ' · ' + tr('{n} checks', {n: found.checks})),
      el('div', 'doc-plan-zone', node('span', 'doc-sub', tr('Times shown in')), zone),
      states.length ? el('div', 'doc-stats', ...states.map(([state, count]) =>
        el('div', 'doc-stat', node('b', '', String(count)), tr(PRESENCE_STATES[state] || state)))) : '',
      node('h5', 'doc-minor', tr('Seen online by hour')), bars(found.hours || [], hours, 'doc-hours'),
      node('h5', 'doc-minor', tr('By weekday')), bars(found.weekdays || [], WEEKDAYS.map(day => tr(day)), 'doc-week'),
      (found.sessions || []).length ? el('div', '', node('h5', 'doc-minor', tr('Recent online stretches')),
        el('ul', 'doc-risks', ...found.sessions.slice(-10).reverse().map(item => el('li', '', icon('clock'),
          zoned(item.from, found.offset, true) + ' → ' + zoned(item.to, found.offset, true) + ' · ' + span(item.seconds))))) : '',
      node('p', 'hint', tr(found.meaning || '')),
      el('div', 'doc-row-actions', button('Close', 'ghost', async () => {watchPattern = null; fillWatch(box);})));
  }

  function accountPanel() {
    if (!may('account')) return [empty('lock', tr('Not available for this access.'))];
    const box = node('div', 'doc-account');
    if (accountInfo) fillAccount(box);
    else {box.append(node('p', 'hint', tr('Loading…'))); loadAccount(box);}
    return [box];
  }

  async function loadAccount(box) {
    try {
      accountInfo = await json('account/profile');
      accountDraft = draftNow();
      if (avatarUrl) {URL.revokeObjectURL(avatarUrl); avatarUrl = null;}
      if (accountInfo.has_photo) {
        avatarUrl = await api('account/avatar').then(r => r.blob()).then(blob => URL.createObjectURL(blob)).catch(() => null);
      }
    } catch (error) {
      box.replaceChildren(el('div', 'doc-callout warn', icon('alert'), node('p', '', error.message)),
        el('div', 'doc-row-actions', button('Try again', 'secondary', () => loadAccount(box), 'refresh')));
      return;
    }
    if (box.isConnected) fillAccount(box);
  }

  function changeCount() {
    return Object.keys(accountDraft.profile).length + Object.keys(accountDraft.privacy).length
      + Object.keys(accountDraft.global).length;
  }

  function fillAccount(box) {
    const info = accountInfo, locked = modules?.goal === 'evidence';
    const bar = el('div', 'doc-applybar');
    const sync = () => {
      const count = changeCount(), blocked = Object.keys(accountDraft.errors).length > 0;
      bar.hidden = !count;
      bar.replaceChildren(el('span', 'doc-applybar-count', node('b', '', String(count)),
        tr(count === 1 ? 'unsaved change' : 'unsaved changes')),
        button('Discard', 'ghost', async () => {accountDraft = draftNow(); fillAccount(box);}),
        button('Review and apply', 'primary', () => applyAccount(box), 'check'));
      bar.lastChild.disabled = blocked || locked;
      if (blocked) bar.lastChild.title = tr('Fix the highlighted fields first.');
    };
    box.replaceChildren(
      locked ? el('div', 'doc-callout warn', icon('lock'),
        node('p', '', tr('Telegram actions from the panel are off for the Evidence for a case goal.'))) : '',
      accountReport ? accountReport : '',
      profileCard(info, locked, sync), privacyBlock(info, locked, sync), globalBlock(info, locked, sync),
      el('div', 'doc-account-foot', node('p', 'hint', tr('Nothing changes in Telegram until you apply. Every change is recorded in the journal with the values before and after.')),
        button('Reload from Telegram', 'ghost', async () => {accountInfo = null; accountReport = null; box.replaceChildren(
          node('p', 'hint', tr('Loading…'))); await loadAccount(box);}, 'refresh')),
      bar);
    sync();
  }

  function audienceName(value) {
    return tr((AUDIENCE.find(item => item[0] === value) || [value, value])[1]);
  }

  function describeChanges() {
    const lines = [];
    for (const [name, value] of Object.entries(accountDraft.profile)) {
      lines.push(tr(FIELD_NAMES[name]) + ': ' + (value ? (name === 'username' ? '@' : '') + short(value, 60) : tr('(empty)')));
    }
    for (const [name, rule] of Object.entries(accountDraft.privacy)) {
      const entry = accountInfo.privacy[name], parts = [audienceName(rule.visible_to)];
      if (rule.allow) parts.push(tr('always: {n}', {n: rule.allow.length}));
      if (rule.deny) parts.push(tr('never: {n}', {n: rule.deny.length}));
      lines.push(tr(entry.label) + ': ' + parts.join(', '));
    }
    for (const [name, value] of Object.entries(accountDraft.global)) {
      lines.push(tr(accountInfo.global[name].label) + ': ' + tr(value ? 'on' : 'off'));
    }
    return lines;
  }

  async function applyAccount(box) {
    const lines = describeChanges();
    if (!lines.length) return;
    if (!await askConfirm(tr('Apply these changes in Telegram?') + ' ' + lines.join('; '))) return;
    const problems = [], done = [];
    if (Object.keys(accountDraft.profile).length) {
      try {
        const result = await json('account/profile', accountDraft.profile);
        done.push(tr('Profile: {n} fields', {n: result.changed.length}));
      } catch (error) {problems.push([tr('Profile'), error.message]);}
    }
    if (Object.keys(accountDraft.privacy).length) {
      const rules = Object.fromEntries(Object.entries(accountDraft.privacy).map(([name, rule]) => [name, {
        visible_to: rule.visible_to,
        ...(rule.allow ? {allow_users: rule.allow.map(p => p.id ?? '@' + p.username)} : {}),
        ...(rule.deny ? {deny_users: rule.deny.map(p => p.id ?? '@' + p.username)} : {})}]));
      try {
        const result = await json('account/privacy', {rules});
        if (Object.keys(result.applied).length) done.push(tr('Privacy: {n} settings', {n: Object.keys(result.applied).length}));
        for (const [name, reason] of Object.entries(result.failed)) problems.push([tr(accountInfo.privacy[name].label), failure(reason)]);
      } catch (error) {problems.push([tr('Privacy'), error.message]);}
    }
    if (Object.keys(accountDraft.global).length) {
      try {
        const result = await json('account/global-privacy', {settings: accountDraft.global});
        done.push(tr('Account options: {n}', {n: result.changed.length}));
      } catch (error) {problems.push([tr('Account options'), error.message]);}
    }
    accountReport = problems.length ? el('div', 'doc-callout warn', icon('alert'), el('div', '',
      node('p', '', tr('Some changes were not applied:')),
      el('ul', 'doc-risks', ...problems.map(([what, why]) => el('li', '', what + ' — ' + why))),
      done.length ? node('p', 'doc-sub', tr('Applied: {list}', {list: done.join(', ')})) : ''))
      : el('div', 'doc-callout good', icon('check'), node('p', '', tr('Applied in Telegram and recorded in the journal: {list}', {list: done.join(', ')})));
    accountInfo = null; box.replaceChildren(node('p', 'hint', tr('Loading…')));
    await loadAccount(box);
  }

  function failure(reason) {
    if (reason === 'exceptions_unavailable') return tr('some exceptions set in Telegram could not be kept; edit them here or in the Telegram app');
    if (reason === 'unsupported') return tr('not supported by this Telegram version');
    if (reason.startsWith('unknown_user:')) return tr('could not find {who}', {who: reason.slice(13)});
    if (reason === 'PremiumAccountRequiredError') return tr('needs Telegram Premium');
    return tr('Telegram rejected the request: {error}', {error: reason});
  }

  function initials(profile) {
    return ((profile.first_name || '').trim()[0] || '') + ((profile.last_name || '').trim()[0] || '') || '?';
  }

  function avatarBlock(info, locked) {
    const picker = node('input'), preview = node('div', 'doc-avatar'), status = node('span', 'doc-sub');
    let chosen = null;
    picker.type = 'file'; picker.accept = AVATAR_TYPES.join(','); picker.hidden = true;
    const image = url => {const img = node('img'); img.alt = tr('Profile photo'); img.src = url; return img;};
    const showCurrent = () => {
      preview.classList.toggle('none', !info.has_photo); preview.classList.remove('chosen');
      preview.replaceChildren(info.has_photo && avatarUrl ? image(avatarUrl)
        : info.has_photo ? icon('image') : node('span', 'doc-initials', initials(info.profile)));
      status.textContent = tr(info.has_photo ? 'Current profile photo' : 'No profile photo');
      choose.hidden = remove.hidden = false; remove.hidden = !info.has_photo; upload.hidden = cancel.hidden = true;
    };
    const upload = button('Set as profile photo', 'primary', async () => {
      if (!chosen) return;
      if (!await askConfirm(tr('Set this image as the profile photo in Telegram? It is uploaded as it is and recorded in the journal.'))) return;
      const encoded = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result).split(',', 2)[1] || '');
        reader.onerror = () => reject(new Error(tr('The file could not be read.')));
        reader.readAsDataURL(chosen);
      });
      const result = await json('account/avatar', {image_base64: encoded});
      if (avatarUrl) URL.revokeObjectURL(avatarUrl);
      avatarUrl = URL.createObjectURL(chosen); info.has_photo = true; chosen = null; picker.value = '';
      showCurrent(); toast(tr('Profile photo updated · SHA-256 {hash}', {hash: result.sha256.slice(0, 12) + '…'}));
    }, 'check');
    const cancel = button('Cancel', 'ghost', async () => {chosen = null; picker.value = ''; showCurrent();});
    picker.addEventListener('change', () => {
      const file = picker.files?.[0];
      if (!file) return;
      if (!AVATAR_TYPES.includes(file.type)) {toast(tr('Use a JPEG or PNG image.'), true); picker.value = ''; return;}
      if (file.size > 5 * 1024 * 1024) {toast(tr('The image is larger than 5 MB.'), true); picker.value = ''; return;}
      chosen = file;
      const url = URL.createObjectURL(file), img = image(url);
      img.addEventListener('load', () => URL.revokeObjectURL(url), {once: true});
      preview.classList.remove('none'); preview.classList.add('chosen'); preview.replaceChildren(img);
      status.textContent = tr('New photo, not applied yet') + ' · ' + Math.ceil(file.size / 1024) + ' KB';
      choose.hidden = remove.hidden = true; upload.hidden = cancel.hidden = false;
    });
    const choose = button('Change photo', 'secondary', async () => picker.click(), 'image');
    const remove = button('', 'ghost doc-icon-btn danger', async () => {
      if (!await askConfirm(tr('Remove the current profile photo in Telegram? If older photos exist, the previous one becomes current.'))) return;
      await api('account/avatar', undefined, {method: 'DELETE'});
      accountInfo = null; toast(tr('Profile photo removed.'));
      const box = preview.closest('.doc-account');
      box.replaceChildren(node('p', 'hint', tr('Loading…'))); await loadAccount(box);
    }, 'trash', 'Remove photo');
    for (const control of [choose, upload, remove]) control.disabled = locked;
    showCurrent();
    return {preview, controls: el('div', 'doc-avatar-side', status, el('div', 'doc-row-actions', choose, upload, cancel, remove),
      node('small', 'doc-sub', tr('JPEG or PNG, up to 5 MB.'))), picker};
  }

  function profileCard(info, locked, sync) {
    const profile = info.profile, avatar = avatarBlock(info, locked);
    const title = node('strong', 'doc-profile-name'), handle = node('span', 'doc-sub');
    const showName = () => {
      const value = name => accountDraft.profile[name] ?? profile[name] ?? '';
      title.textContent = [value('first_name'), value('last_name')].filter(Boolean).join(' ') || tr('No name');
      handle.textContent = value('username') ? '@' + value('username') : tr('No username');
    };
    const check = (name, value) => {
      if (name === 'first_name' && !value) return tr('The first name cannot be empty.');
      if (name === 'username' && value && !/^[A-Za-z][A-Za-z0-9_]{4,31}$/.test(value)) {
        return tr('Use 5–32 letters, digits or underscores, starting with a letter.');
      }
      if (name === 'about' && value.length > info.about_limit) return tr('The bio is longer than {n} characters.', {n: info.about_limit});
      return '';
    };
    const field = (name, setup) => {
      const input = node(name === 'about' ? 'textarea' : 'input'), message = node('small', 'doc-field-error');
      input.value = accountDraft.profile[name] ?? profile[name] ?? ''; input.dataset.key = 'account:' + name;
      input.disabled = locked; input.setAttribute('autocomplete', 'off'); input.spellcheck = name === 'about';
      setup?.(input);
      const wrap = el('label', 'doc-field' + (name === 'about' ? ' wide' : ''), node('span', '', tr(FIELD_NAMES[name])));
      wrap.append(name === 'username' ? el('span', 'doc-prefixed', node('span', 'doc-prefix', '@'), input) : input);
      const counter = name === 'about' ? node('small', 'doc-counter') : null;
      if (counter) wrap.append(counter);
      wrap.append(message);
      const update = () => {
        const value = name === 'username' ? input.value.trim().replace(/^@/, '') : input.value.trim();
        if (value === (profile[name] || '')) delete accountDraft.profile[name]; else accountDraft.profile[name] = value;
        const problem = check(name, value);
        message.textContent = problem; wrap.classList.toggle('invalid', !!problem);
        wrap.classList.toggle('changed', name in accountDraft.profile);
        if (problem) accountDraft.errors[name] = problem; else delete accountDraft.errors[name];
        if (counter) {
          counter.textContent = input.value.length + ' / ' + info.about_limit;
          counter.classList.toggle('over', input.value.length > info.about_limit);
        }
        showName(); sync();
      };
      input.addEventListener('input', update);
      update();
      return wrap;
    };
    showName();
    return el('section', 'doc-panel doc-profile-card',
      el('div', 'doc-profile-top', avatar.preview, el('div', 'doc-profile-id', title, handle,
        info.premium ? node('span', 'doc-tag good', tr('Premium')) : ''), avatar.picker),
      avatar.controls,
      el('div', 'doc-fields',
        field('first_name', input => {input.maxLength = 64;}),
        field('last_name', input => {input.maxLength = 64;}),
        field('username', input => {input.maxLength = 33; input.placeholder = tr('No username');}),
        field('about', input => {input.maxLength = 140; input.rows = 3; input.placeholder = tr('A few words about the account');})));
  }

  function effective(name) {
    const entry = accountInfo.privacy[name], draft = accountDraft.privacy[name];
    return {visible_to: draft?.visible_to ?? entry.visible_to ?? 'nobody', allow: draft?.allow ?? entry.allow_users ?? [],
      deny: draft?.deny ?? entry.deny_users ?? []};
  }

  function samePeople(a, b) {
    const ids = list => list.map(p => p.id ? 'id:' + p.id : 'u:' + p.username).sort().join(',');
    return ids(a) === ids(b);
  }

  function setPrivacy(name, next) {
    const entry = accountInfo.privacy[name], current = effective(name), value = {...current, ...next};
    const allowChanged = !samePeople(value.allow, entry.allow_users || []), denyChanged = !samePeople(value.deny, entry.deny_users || []);
    if (value.visible_to === entry.visible_to && !allowChanged && !denyChanged) {delete accountDraft.privacy[name]; return;}
    accountDraft.privacy[name] = {visible_to: value.visible_to, ...(allowChanged ? {allow: value.allow} : {}),
      ...(denyChanged ? {deny: value.deny} : {})};
  }

  function peopleList(name, field, title, locked, redraw) {
    const people = effective(name)[field], other = field === 'allow' ? 'deny' : 'allow';
    const input = node('input'); input.placeholder = tr('@username'); input.maxLength = 33;
    input.setAttribute('aria-label', tr(title) + ': ' + tr('add by username')); input.dataset.key = 'people:' + name + ':' + field;
    input.disabled = locked;
    const add = () => {
      const value = input.value.trim().replace(/^@/, '');
      if (!value) return;
      if (!/^[A-Za-z][A-Za-z0-9_]{3,31}$/.test(value)) {toast(tr('Enter a Telegram username, for example @name.'), true); return;}
      const lower = value.toLowerCase(), clash = person => (person.username || '').toLowerCase() === lower;
      if (people.some(clash)) {input.value = ''; return;}
      setPrivacy(name, {[field]: [...people, {username: value, name: '@' + value}],
        [other]: effective(name)[other].filter(person => !clash(person))});
      redraw(true);
    };
    input.addEventListener('keydown', event => {if (event.key === 'Enter') {event.preventDefault(); add();}});
    const chips = people.map(person => {
      const chipBox = el('span', 'doc-person' + (person.id ? '' : ' new'), node('span', '', person.name),
        person.username && person.name !== '@' + person.username ? node('small', '', '@' + person.username) : '');
      if (!locked) {
        const drop = button('', 'doc-person-x', async () => {
          setPrivacy(name, {[field]: people.filter(item => item !== person)}); redraw();
        }, 'close', 'Remove');
        chipBox.append(drop);
      }
      return chipBox;
    });
    return el('div', 'doc-people ' + field, node('span', 'doc-people-title', tr(title)),
      el('div', 'doc-people-list', ...chips, el('span', 'doc-people-add', input,
        button('', 'ghost doc-icon-btn', async () => add(), 'next', 'Add'))));
  }

  function privacyRow(name, locked, sync) {
    const entry = accountInfo.privacy[name];
    const row = node('div', 'doc-privacy-row');
    const redraw = focusAdd => {
      const fresh = privacyRow(name, locked, sync);
      row.replaceWith(fresh); sync();
      if (focusAdd) fresh.querySelector('.doc-people-add input')?.focus();
    };
    const value = effective(name), changed = name in accountDraft.privacy;
    row.classList.toggle('changed', changed); row.classList.toggle('off', !entry.available);
    const choice = node('div', 'doc-choice'); choice.setAttribute('role', 'radiogroup'); choice.setAttribute('aria-label', tr(entry.label));
    for (const [audience, label] of AUDIENCE) {
      const option = el('button', 'doc-choice-item' + (value.visible_to === audience ? ' on' : ''), tr(label));
      option.type = 'button'; option.setAttribute('role', 'radio'); option.setAttribute('aria-checked', String(value.visible_to === audience));
      option.dataset.key = 'privacy:' + name + ':' + audience; option.disabled = locked || !entry.available;
      option.addEventListener('click', () => {setPrivacy(name, {visible_to: audience}); redraw(); drawer.querySelector(
        '[data-key="privacy:' + name + ':' + audience + '"]')?.focus();});
      choice.append(option);
    }
    const fixed = [...(entry.allow_chats || []).map(chat => tr('Members of {title}', {title: chat.title}) + ' · ' + tr('always')),
      ...(entry.deny_chats || []).map(chat => tr('Members of {title}', {title: chat.title}) + ' · ' + tr('never')),
      ...(entry.special || []).map(item => tr({close_friends: 'Close friends', premium: 'Premium users', bots_allowed: 'Bots allowed',
        bots_denied: 'Bots not allowed', contacts_denied: 'Everyone except contacts'}[item] || item))];
    const extra = entry.available ? el('div', 'doc-exceptions',
      value.visible_to !== 'everybody' ? peopleList(name, 'allow', 'Always allow', locked, redraw) : '',
      value.visible_to !== 'nobody' ? peopleList(name, 'deny', 'Never allow', locked, redraw) : '',
      fixed.length ? el('div', 'doc-people fixed', node('span', 'doc-people-title', tr('Also set in Telegram, kept')),
        el('div', 'doc-people-list', ...fixed.map(text => node('span', 'doc-person quiet', text)))) : '') : '';
    const count = value.allow.length + value.deny.length + fixed.length;
    const details = el('details', 'doc-exceptions-box', node('summary', '', count ? tr('Exceptions: {n}', {n: count})
      : tr('Add exceptions')), extra);
    details.open = openExceptions.has(name);
    details.addEventListener('toggle', () => {if (details.open) openExceptions.add(name); else openExceptions.delete(name);});
    row.append(el('div', 'doc-privacy-head', el('div', 'doc-privacy-name', node('span', '', tr(entry.label)),
      node('small', '', !entry.available ? tr('Not available for this account') : tr(entry.description))), choice),
      entry.available ? details : '');
    return row;
  }

  function privacyBlock(info, locked, sync) {
    return el('section', 'doc-panel doc-privacy-block', el('h4', 'doc-section', icon('lock'), tr('Privacy')),
      node('p', 'hint', tr('Choose who sees each part of the profile. Exceptions work like in Telegram: always allow or never allow particular people.')),
      ...PRIVACY_GROUPS.map(([group, title, iconName]) => {
        const names = Object.keys(info.privacy).filter(name => info.privacy[name].group === group);
        return names.length ? el('div', 'doc-privacy-group', el('h5', 'doc-minor', icon(iconName), tr(title)),
          el('div', 'doc-privacy', ...names.map(name => privacyRow(name, locked, sync)))) : '';
      }));
  }

  function globalBlock(info, locked, sync) {
    if (!info.global) return '';
    return el('section', 'doc-panel', el('h4', 'doc-section', icon('shield'), tr('Account options')),
      el('div', 'doc-options', ...Object.entries(info.global).map(([name, option]) => {
        const label = node('label', 'doc-switch doc-option'), input = node('input');
        input.type = 'checkbox'; input.checked = accountDraft.global[name] ?? option.enabled; input.disabled = locked;
        input.dataset.key = 'global:' + name;
        input.addEventListener('change', () => {
          if (input.checked === option.enabled) delete accountDraft.global[name]; else accountDraft.global[name] = input.checked;
          label.classList.toggle('changed', name in accountDraft.global); sync();
        });
        label.classList.toggle('changed', name in accountDraft.global);
        label.append(input, node('span', 'doc-switch-track'), el('span', 'doc-option-text', node('span', '', tr(option.label)),
          node('small', '', tr(option.description))));
        return label;
      })));
  }

  const planPath = (...parts) => ['conversation', ...parts.map(encodeURIComponent)].join('/');
  const requestId = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), x => x.toString(16).padStart(2, '0')).join('');

  function span(value) {
    if (value === null || value === undefined) return '—';
    value = Math.max(0, Math.round(value));
    if (value < 60) return tr('{n} s', {n: value});
    if (value < 3600) return tr('{m} min {s} s', {m: Math.floor(value / 60), s: value % 60});
    if (value < 86400) return tr('{h} h {m} min', {h: Math.floor(value / 3600), m: Math.floor(value / 60) % 60});
    return tr('{d} d {h} h', {d: Math.floor(value / 86400), h: Math.floor(value / 3600) % 24});
  }

  function zoneName(offset) {
    const sign = offset < 0 ? '−' : '+', abs = Math.abs(offset);
    return 'UTC' + (offset ? sign + Math.floor(abs / 60) + (abs % 60 ? ':' + String(abs % 60).padStart(2, '0') : '') : '');
  }

  function zoned(value, offset, seconds) {
    if (!value) return '—';
    const shifted = new Date(Date.parse(value) + offset * 60000).toISOString();
    return shifted.slice(0, 10) + ' ' + shifted.slice(11, seconds ? 19 : 16);
  }

  async function loadPlans() {
    plans = await json('conversation');
    if (homeTab === 'plans') renderHome();
  }

  async function openPlan(id) {
    plan = await json(planPath(id));
    if (assist.planId !== id) {
      Object.assign(assist, {planId: id, intent: '', goal: '', preview: null, result: null});
      planTab = 'work';
    }
    renderHome();
  }

  async function planCall(parts, body, method, query = '') {
    const id = plan.id, target = planPath(id, ...parts) + '?revision=' + plan.revision + query;
    let response;
    try {
      response = method === 'DELETE' || method === 'PUT'
        ? await api(target, body, {method}).then(r => r.json()) : await json(target, body ?? {});
    } catch (error) {
      if (error.status === 409 && plan?.id === id) await openPlan(id).catch(() => {});
      throw error;
    }
    if (plan?.id !== id) return response;
    plan = response; renderHome();
    return response;
  }

  function plansPanel() {
    if (!plans) {
      loadPlans().catch(error => toast(error.message, true));
      return [node('p', 'hint', tr('Loading…'))];
    }
    return plan ? planView() : plansHome();
  }

  function plansHome() {
    const targets = state.status?.targets || [];
    const form = node('form', 'doc-start doc-plan-new');
    const chat = node('select'), template = node('select'), title = node('input');
    chat.setAttribute('aria-label', tr('Chat')); template.setAttribute('aria-label', tr('Template'));
    for (const target of targets) chat.append(new Option(target.title || String(target.chat_id), String(target.chat_id)));
    for (const [id, info] of Object.entries(plans.templates)) template.append(new Option(tr(info.title), id));
    template.value = 'payment';
    title.maxLength = 160; title.placeholder = tr('Title (optional)'); title.setAttribute('aria-label', tr('Title (optional)'));
    const goals = node('ul', 'doc-plan-preview');
    const showGoals = () => {
      const listed = plans.templates[template.value]?.goals || [];
      goals.replaceChildren(...(listed.length ? listed.map(text => el('li', '', icon('target'), tr(text)))
        : [el('li', 'muted', icon('edit'), tr('Start empty and add your own goals.'))]));
    };
    template.addEventListener('change', showGoals); showGoals();
    const start = el('button', 'primary', icon('play'), node('span', '', tr('Start plan'))); start.type = 'submit';
    form.append(el('div', 'doc-fields', el('label', 'doc-field', node('span', '', tr('Chat')), chat),
      el('label', 'doc-field', node('span', '', tr('Template')), template),
      el('label', 'doc-field wide', node('span', '', tr('Title')), title)), goals, start);
    form.addEventListener('submit', event => {event.preventDefault(); busy(start, async () => {
      if (!chat.value) throw new Error(tr('Add the chat to observation first.'));
      const created = await json('conversation', {chat_id: Number(chat.value), template: template.value, title: title.value});
      plans = null; await openPlan(created.id);
    });});
    const parts = [section('target', 'New conversation plan', node('p', 'hint',
      tr('Write down what you need to learn, prepare the messages, and see when the other side answers. Nothing is sent without your click.')),
      targets.length ? form : empty('target', tr('No chats yet.'), tr('Add a chat to observation, then plan the conversation here.')))];
    if (!plans.plans.length) return parts;
    const list = node('ul', 'doc-list');
    for (const item of plans.plans) {
      const progress = item.goals ? Math.round(item.obtained / item.goals * 100) : 0;
      const meter = el('span', 'doc-meter doc-plan-meter', node('span'));
      meter.firstChild.style.width = progress + '%';
      const card = el('button', 'doc-session', el('span', 'doc-session-main', node('strong', '', item.title),
        node('span', 'doc-sub', item.chat_title + ' · ' + tr('{n} of {total} goals', {n: item.obtained, total: item.goals})
          + ' · ' + tr('{n} messages', {n: item.steps})), meter), icon('next'));
      card.type = 'button'; card.classList.add('doc-plan-card');
      card.addEventListener('click', () => busy(card, () => openPlan(item.id)));
      list.append(el('li', '', card));
    }
    parts.push(section('note', 'Plans', list));
    return parts;
  }

  function planView() {
    const goals = plan.goals, obtained = goals.filter(g => g.status === 'obtained').length;
    const meter = el('div', 'doc-meter doc-plan-meter', node('span'));
    meter.firstChild.style.width = (goals.length ? Math.round(obtained / goals.length * 100) : 0) + '%';
    const head = el('div', 'doc-plan-head',
      button('', 'ghost doc-icon-btn', async () => {plan = null; plans = null; renderHome();}, 'back', 'All plans'),
      el('div', 'doc-plan-title', node('h3', '', plan.title),
        node('span', 'doc-sub', plan.chat_title + ' · ' + tr('{n} of {total} goals obtained', {n: obtained, total: goals.length})), meter),
      el('div', 'doc-row-actions',
        button('', 'ghost doc-icon-btn', () => openPlan(plan.id), 'refresh', 'Refresh'),
        button('', 'ghost doc-icon-btn', async () => {
          const name = await askText(tr('Plan title'), {value: plan.title});
          if (name && name.trim()) await planCall([], {title: name.trim(), offset_minutes: plan.offset_minutes || 0}, 'PUT');
        }, 'edit', 'Rename'),
        button('', 'ghost doc-icon-btn danger', async () => {
          if (!await askConfirm(tr('Delete this plan? Messages already sent and AI drafts stay in the journal.'))) return;
          await api(planPath(plan.id), undefined, {method: 'DELETE'}); plan = null; plans = null; renderHome();
        }, 'trash', 'Delete plan')));
    const sent = plan.steps.filter(step => step.sent).length;
    const tabs = segments([['work', 'Goals and messages', 'target', sent + '/' + plan.steps.length],
      ['assist', 'Write in their style', 'spark'], ['activity', 'Activity and style', 'clock', plan.activity.replies]],
    planTab, id => {planTab = id; renderHome();});
    const content = planTab === 'assist' ? [assistSection()] : planTab === 'activity' ? [activitySection(), styleSection()]
      : [goalsSection(), stepsSection()];
    return [head, tabs, ...content];
  }

  function segments(items, active, choose) {
    const bar = node('div', 'doc-segments'); bar.setAttribute('role', 'tablist');
    items.forEach(([id, label, iconName, count], index) => {
      const item = el('button', 'doc-segment' + (id === active ? ' on' : ''), icon(iconName), node('span', '', tr(label)),
        count ? node('span', 'doc-count', String(count)) : '');
      item.type = 'button'; item.dataset.key = 'segment:' + id; item.setAttribute('role', 'tab');
      item.setAttribute('aria-selected', String(id === active)); item.tabIndex = id === active ? 0 : -1;
      item.addEventListener('click', () => choose(id));
      item.addEventListener('keydown', event => {
        if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
        event.preventDefault();
        choose(items[(index + (event.key === 'ArrowRight' ? 1 : -1) + items.length) % items.length][0]);
        requestAnimationFrame(() => drawer.querySelector('.doc-segment.on')?.focus());
      });
      bar.append(item);
    });
    return bar;
  }

  function goalsSection() {
    const list = node('ul', 'doc-goals');
    for (const goal of plan.goals) {
      const next = {open: 'obtained', obtained: 'dropped', dropped: 'open'}[goal.status];
      const status = button(GOAL_STATES[goal.status], 'doc-goal-status ' + goal.status, () => planCall(['goals', goal.id],
        {text: goal.text, status: next, note: goal.note, evidence: goal.evidence}, 'PUT'), goal.status === 'obtained' ? 'check'
        : goal.status === 'dropped' ? 'close' : 'target');
      status.title = tr('Change status');
      const row = el('li', 'doc-goal ' + goal.status, status, el('div', 'doc-goal-main', node('span', 'doc-goal-text', goal.text),
        goal.note ? node('span', 'doc-sub', goal.note) : '',
        goal.evidence.length ? el('span', 'doc-chips', ...goal.evidence.map(seq => chip('#' + seq, 'ioc', 'link', tr('Journal record')))) : ''),
        el('div', 'doc-row-actions doc-goal-tools',
          button('', 'ghost doc-icon-btn', async () => row.replaceWith(goalEditor(goal)), 'edit', 'Edit'),
          button('', 'ghost doc-icon-btn', async () => {
            if (await askConfirm(tr('Remove this goal?'))) await planCall(['goals', goal.id], undefined, 'DELETE');
          }, 'trash', 'Remove')));
      list.append(row);
    }
    const input = node('input'); input.maxLength = 300; input.placeholder = tr('Add a goal: what do you need to learn or obtain?');
    input.setAttribute('aria-label', tr('New goal')); input.dataset.key = 'plan:new-goal';
    const add = el('form', 'doc-inline-add', input, el('button', 'secondary', icon('target'), node('span', '', tr('Add'))));
    add.lastChild.type = 'submit';
    add.addEventListener('submit', event => {event.preventDefault(); busy(add.lastChild, async () => {
      if (!input.value.trim()) return;
      await planCall(['goals'], {text: input.value.trim()});
    });});
    return section('target', 'Goals', plan.goals.length ? list : node('p', 'hint', tr('No goals yet.')), add);
  }

  function goalEditor(goal) {
    const text = node('input'), note = node('textarea'), evidence = node('input');
    text.value = goal.text; text.maxLength = 300; note.value = goal.note; note.maxLength = 1000; note.rows = 2;
    note.placeholder = tr('Note'); evidence.value = goal.evidence.join(', ');
    evidence.placeholder = tr('Journal record numbers, for example 120, 134');
    const save = button('Save', 'primary', async () => {
      const numbers = evidence.value.split(/[\s,;#]+/).filter(Boolean).map(Number);
      if (numbers.some(n => !Number.isInteger(n) || n < 1)) throw new Error(tr('Use journal record numbers.'));
      await planCall(['goals', goal.id], {text: text.value, status: goal.status, note: note.value, evidence: numbers}, 'PUT');
    }, 'check');
    return el('li', 'doc-goal editing', el('div', 'doc-fields',
      el('label', 'doc-field wide', node('span', '', tr('Goal')), text),
      el('label', 'doc-field wide', node('span', '', tr('Note')), note),
      el('label', 'doc-field wide', node('span', '', tr('Evidence in the journal')), evidence)),
      el('div', 'doc-row-actions', save, button('Cancel', 'ghost', async () => renderHome())));
  }

  function goalSelect(value, blank) {
    const select = node('select');
    select.append(new Option(tr(blank), ''));
    for (const goal of plan.goals) select.append(new Option(short(goal.text, 60), goal.id));
    select.value = value || '';
    return select;
  }

  const BASIS = {panel: 'Sent from the panel', text: 'Same text found in the chat', similar: 'Matched by similar text',
    linked: 'Linked by hand'};

  function stepStatus(step) {
    const offset = plan.offset_minutes || 0;
    if (step.sent) {
      const reply = step.sent.reply, sent = step.sent;
      return el('div', 'doc-step-status sent', el('span', 'doc-chip-tag good', icon('check'),
        tr('Sent {at}', {at: zoned(sent.sent_at, offset, true)})),
        reply ? el('span', 'doc-chip-tag lag', icon('clock'), tr('Reply after {time}', {time: span(reply.after_seconds)}))
          : el('span', 'doc-chip-tag', icon('clock'), tr('No reply yet')),
        el('span', 'doc-chip-tag ' + (sent.basis === 'similar' ? 'warn' : 'quiet'), icon(sent.basis === 'linked' ? 'link' : 'search'),
          tr(BASIS[sent.basis] || sent.basis) + (sent.message_id ? ' · #' + sent.message_id : '')),
        sent.text ? el('p', 'doc-step-actual', node('span', 'doc-sub', tr('Actually sent:')), node('span', '', sent.text)) : '',
        reply ? node('q', 'doc-step-reply', reply.text) : '');
    }
    return el('div', 'doc-step-status', step.state === 'skipped' ? chip(tr('Skipped'), '', 'close')
      : chip(tr('Planned'), '', 'more'));
  }

  function stepsSection() {
    const list = node('ol', 'doc-steps');
    plan.steps.forEach((step, index) => {
      const goal = plan.goals.find(g => g.id === step.goal);
      const kind = (STEP_KINDS.find(k => k[0] === step.kind) || [step.kind, step.kind])[1];
      const tools = el('div', 'doc-row-actions');
      if (!step.sent && step.state !== 'skipped' && may('interact')) tools.append(button('Send', 'primary', () => sendStep(step), 'send'));
      tools.append(button('', 'ghost doc-icon-btn', () => copy(step.text), 'copy', 'Copy'));
      if (!step.sent) {
        tools.append(button('', 'ghost doc-icon-btn', async () => item.replaceWith(stepEditor(step)), 'edit', 'Edit'),
          button('', 'ghost doc-icon-btn', () => planCall(['steps', step.id], {...stepBody(step),
            state: step.state === 'skipped' ? 'planned' : 'skipped'}, 'PUT'), step.state === 'skipped' ? 'play' : 'close',
          step.state === 'skipped' ? 'Restore' : 'Skip'));
        if (step.state !== 'skipped' && plan.unlinked.length) tools.append(button('', 'ghost doc-icon-btn', async () => {
          if (!item.querySelector('.doc-linker')) item.insertBefore(linker(step), tools);
        }, 'link', 'Link to a sent message'));
      } else if (step.sent.basis !== 'panel') {
        tools.append(button('', 'ghost doc-icon-btn', async () => {
          if (!item.querySelector('.doc-linker')) item.insertBefore(linker(step), tools);
        }, 'link', 'Link to another message'));
        if (step.message_id) tools.append(button('', 'ghost doc-icon-btn', () => planCall(['steps', step.id],
          {...stepBody(step), message_id: null}, 'PUT'), 'close', 'Remove the link'));
      }
      if (index > 0) tools.append(button('', 'ghost doc-icon-btn', () => moveStep(step, -1), 'up', 'Move up'));
      if (index < plan.steps.length - 1) tools.append(button('', 'ghost doc-icon-btn', () => moveStep(step, 1), 'down', 'Move down'));
      tools.append(button('', 'ghost doc-icon-btn', async () => {
        if (await askConfirm(tr('Remove this message from the plan?'))) await planCall(['steps', step.id], undefined, 'DELETE');
      }, 'trash', 'Remove'));
      const item = el('li', 'doc-step ' + (step.sent ? 'sent' : step.state),
        el('div', 'doc-step-top', node('span', 'doc-step-n', String(index + 1)), node('span', 'doc-tag', tr(kind)),
          goal ? el('span', 'doc-tag l-question', short(goal.text, 48)) : '',
          step.draft ? el('span', 'doc-tag', icon('spark'), tr('AI draft · record #{n}', {n: step.draft})) : ''),
        node('p', 'doc-step-text', step.text), stepStatus(step), tools);
      list.append(item);
    });
    return section('send', 'Messages', plan.steps.length ? list : node('p', 'hint', tr('No messages planned yet.')), stepForm(),
      plans?.ai ? el('div', 'doc-row-actions', button('Draft the next message with AI', 'ghost', async () => {
        planTab = 'assist'; renderHome();
      }, 'spark')) : '');
  }

  const stepBody = step => ({text: step.text, kind: step.kind, goal: step.goal, state: step.state, draft: step.draft,
    message_id: step.message_id || null, request_id: step.request_id || null});

  function linker(step) {
    const offset = plan.offset_minutes || 0, select = node('select');
    select.setAttribute('aria-label', tr('Sent message'));
    for (const message of plan.unlinked) {
      select.append(new Option(zoned(message.sent_at, offset) + ' · #' + message.message_id + ' · ' + short(message.text, 70),
        String(message.message_id)));
    }
    const box = el('div', 'doc-linker', node('span', 'doc-sub', tr('Which of your messages is this step? Reply times are counted from it.')),
      select, el('div', 'doc-row-actions',
        button('Link', 'primary', () => planCall(['steps', step.id], {...stepBody(step), message_id: Number(select.value)}, 'PUT'), 'link'),
        button('Cancel', 'ghost', async () => box.remove())));
    if (!plan.unlinked.length) box.replaceChildren(node('p', 'hint', tr('No unlinked messages of yours in this chat.')));
    return box;
  }

  async function moveStep(step, offset) {
    await planCall(['steps', step.id, 'move'], {}, undefined, '&offset=' + offset);
  }

  function stepFields(step) {
    const text = node('textarea'), kind = node('select'), goal = goalSelect(step?.goal, 'No goal');
    text.maxLength = 4096; text.rows = 3; text.value = step?.text || '';
    text.placeholder = tr('Message text, as it will be sent');
    for (const [value, label] of STEP_KINDS) kind.append(new Option(tr(label), value));
    kind.value = step?.kind || 'question';
    return {text, kind, goal, fields: el('div', 'doc-fields',
      el('label', 'doc-field wide', node('span', '', tr('Message')), text),
      el('label', 'doc-field', node('span', '', tr('Type')), kind), el('label', 'doc-field', node('span', '', tr('Goal')), goal))};
  }

  function stepForm() {
    const parts = stepFields(null), add = el('button', 'secondary', icon('note'), node('span', '', tr('Add message')));
    parts.text.dataset.key = 'plan:new-step'; add.type = 'submit';
    const form = el('form', 'doc-step-form', parts.fields, el('div', 'doc-row-actions', add));
    form.addEventListener('submit', event => {event.preventDefault(); busy(add, async () => {
      if (!parts.text.value.trim()) {parts.text.focus(); return;}
      await planCall(['steps'], {text: parts.text.value, kind: parts.kind.value, goal: parts.goal.value || null});
    });});
    return el('details', 'doc-how doc-add-step', node('summary', '', tr('Add a message to the plan')), form);
  }

  function stepEditor(step) {
    const parts = stepFields(step);
    return el('li', 'doc-step editing', parts.fields, el('div', 'doc-row-actions',
      button('Save', 'primary', () => planCall(['steps', step.id], {...stepBody(step), text: parts.text.value,
        kind: parts.kind.value, goal: parts.goal.value || null}, 'PUT'), 'check'),
      button('Cancel', 'ghost', async () => renderHome())));
  }

  async function sendStep(step) {
    if (!await askConfirm(tr('Send this message to {chat} from the account now?', {chat: plan.chat_title}) + ' “' + short(step.text, 240) + '”')) return;
    const rid = step.request_id || requestId();
    if (step.request_id !== rid) await planCall(['steps', step.id], {...stepBody(step), request_id: rid}, 'PUT');
    const result = await json('interactions', {request_id: rid, action: 'send', chat_id: plan.chat_id, text: step.text});
    toast(result.status === 'queued' ? tr('Queued. The account sends it at a safe pace; the plan updates when it appears.')
      : result.status === 'succeeded' ? tr('Sent. The plan marks it when the message is saved.') : tr('Status: {status}', {status: result.status}));
    const id = plan.id;
    setTimeout(() => {if (plan?.id === id && homeTab === 'plans' && open() && !typing()) openPlan(id).catch(() => {});}, 3000);
  }

  function assistSection() {
    if (!plans?.ai) return section('spark', 'Write in their style', el('div', 'doc-callout', icon('lock'),
      node('p', '', tr('AI is off for this workspace. The main administrator can connect a local or external model in Settings → AI.'))));
    const intent = node('textarea'), goal = goalSelect(assist.goal, 'Any goal'), context = node('select'), variants = node('select');
    intent.maxLength = 1000; intent.rows = 2; intent.value = assist.intent; intent.dataset.key = 'plan:intent';
    intent.placeholder = tr('What should the next message do? For example: ask for the wallet again without sounding pushy');
    for (const n of [30, 60, 120, 200]) context.append(new Option(tr('Last {n} messages', {n}), String(n)));
    for (const n of [1, 2, 3, 4, 5]) variants.append(new Option(String(n), String(n)));
    context.value = String(assist.context); variants.value = String(assist.variants);
    const remember = () => Object.assign(assist, {intent: intent.value, goal: goal.value, context: Number(context.value),
      variants: Number(variants.value)});
    const card = assist.preview ? transmissionCard() : null;
    for (const control of [intent, goal, context, variants]) control.addEventListener('input', () => {
      remember();
      if (assist.preview) {assist.preview = null; card?.remove();}
    });
    const previewButton = button('Preview what is sent', 'secondary', async () => {
      remember();
      if (!assist.intent.trim()) {intent.focus(); throw new Error(tr('Describe what the message should do.'));}
      assist.preview = await json(planPath(plan.id, 'assist', 'preview'), {intent: assist.intent, goal: assist.goal || null,
        context: assist.context, variants: assist.variants});
      assist.result = null; renderHome();
    }, 'eye');
    const parts = [node('p', 'hint', tr('The model reads the chat, learns their language, slang and emoji, and suggests messages. You see exactly what is sent before anything leaves.')),
      el('div', 'doc-fields', el('label', 'doc-field wide', node('span', '', tr('Task')), intent),
        el('label', 'doc-field', node('span', '', tr('Goal')), goal), el('label', 'doc-field', node('span', '', tr('Context')), context),
        el('label', 'doc-field', node('span', '', tr('Variants')), variants)),
      el('div', 'doc-row-actions', previewButton)];
    if (card) parts.push(card);
    if (assist.result) parts.push(draftsCard());
    return section('spark', 'Write in their style', ...parts);
  }

  function transmissionCard() {
    const preview = assist.preview, provider = preview.provider, consent = node('input');
    consent.type = 'checkbox';
    const label = el('label', 'doc-consent', consent, node('span', '', tr('Send these {n} messages to {model} at {endpoint}', {
      n: preview.messages, model: provider.model || '—', endpoint: provider.endpoint})));
    const generate = button('Generate drafts', 'primary', async () => {
      if (!consent.checked) {consent.focus(); throw new Error(tr('Confirm that this data may be sent to the AI provider.'));}
      assist.result = await json(planPath(plan.id, 'assist'), {preview_id: preview.preview_id, consent: true});
      assist.preview = null; renderHome();
    }, 'spark');
    const raw = node('pre', 'doc-transmission', JSON.stringify(preview.transmission.map(item => {
      try {return {...item, content: JSON.parse(item.content)};} catch (error) {return item;}
    }), null, 2));
    return el('div', 'doc-ai-card', el('div', 'doc-stats',
      el('div', 'doc-stat', node('b', '', String(preview.messages)), tr('messages')),
      el('div', 'doc-stat', node('b', '', Math.round(preview.characters / 100) / 10 + 'k'), tr('characters')),
      el('div', 'doc-stat', node('b', '', provider.processing === 'server-local' ? tr('Local') : tr('External')), tr('processing'))),
      provider.route_error ? el('div', 'doc-callout warn', icon('alert'), node('p', '', provider.route_error)) : '',
      el('details', 'doc-how', node('summary', '', tr('Exact data that will be sent')), raw), label,
      el('div', 'doc-row-actions', generate, button('Cancel', 'ghost', async () => {assist.preview = null; renderHome();})),
      node('p', 'hint', tr('The request, the model and the drafts are recorded in the journal. A draft becomes a message only if you send it.')));
  }

  function draftsCard() {
    const result = assist.result, found = result.style || {};
    const traits = [found.language, found.register, found.typical_length].filter(Boolean);
    const cards = result.drafts.map(draft => el('div', 'doc-draft', node('p', 'doc-step-text', draft.text),
      draft.why ? node('span', 'doc-sub', draft.why) : '',
      el('div', 'doc-row-actions',
        button('Add to plan', 'primary', async () => {
          await planCall(['steps'], {text: draft.text, kind: 'question', goal: assist.goal || null, draft: result.event});
          toast(tr('Added to the plan.'));
        }, 'note'),
        button('', 'ghost doc-icon-btn', () => copy(draft.text), 'copy', 'Copy'))));
    return el('div', 'doc-ai-card',
      traits.length || found.slang?.length || found.emoji?.length ? el('div', 'doc-style-line',
        ...traits.map(text => node('span', 'doc-tag', text)), ...(found.slang || []).map(text => node('span', 'doc-tag l-question', text)),
        ...(found.emoji || []).map(text => node('span', 'doc-tag', text))) : '',
      found.notes ? node('p', 'doc-sub', found.notes) : '',
      result.caution ? el('div', 'doc-callout warn', icon('alert'), node('p', '', result.caution)) : '',
      ...cards,
      node('p', 'hint', tr('Recorded in the journal as record #{n} · {model}', {n: result.event, model: result.generation?.model || ''})));
  }

  function activitySection() {
    const info = plan.activity, offset = plan.offset_minutes || 0, zone = node('select');
    for (const value of ZONES) zone.append(new Option(zoneName(value), String(value)));
    zone.value = String(offset); zone.setAttribute('aria-label', tr('Time zone'));
    zone.addEventListener('change', () => busy(null, () => planCall([], {title: plan.title, offset_minutes: Number(zone.value)}, 'PUT')));
    if (!info.messages) return section('clock', 'Their activity', empty('clock', tr('No saved messages in this chat yet.'),
      tr('Reply times appear as soon as the conversation is saved.')));
    const stat = (value, label, cls) => el('div', 'doc-stat ' + (cls || ''), node('b', '', value), tr(label));
    const hours = Array.from({length: 24}, (_, h) => String(h).padStart(2, '0'));
    const exchanges = info.exchanges.slice(0, 12).map(pair => el('li', 'doc-exchange',
      el('div', 'doc-exchange-ours', node('span', 'doc-sub', zoned(pair.sent_at, offset, true)), node('span', '', pair.ours)),
      el('span', 'doc-chip-tag lag', icon('clock'), span(pair.after_seconds)),
      el('div', 'doc-exchange-theirs', node('span', 'doc-sub', zoned(pair.replied_at, offset, true)), node('span', '', pair.reply))));
    return section('clock', 'Their activity',
      el('div', 'doc-plan-zone', node('span', 'doc-sub', tr('Times shown in')), zone),
      el('div', 'doc-stats', stat(String(info.replies), 'replies measured'), stat(span(info.median_seconds), 'typical reply'),
        stat(span(info.fastest_seconds), 'fastest'), stat(span(info.slowest_seconds), 'slowest'),
        stat(String(info.theirs), 'their messages')),
      node('p', 'doc-sub', tr('Last message from them: {at}', {at: zoned(info.last_theirs_at, offset) + ' ' + zoneName(offset)})),
      node('h5', 'doc-minor', tr('Their messages by hour')), bars(info.hours, hours, 'doc-hours'),
      node('h5', 'doc-minor', tr('By weekday')), bars(info.weekdays, WEEKDAYS.map(day => tr(day)), 'doc-week'),
      info.silences.length ? el('div', '', node('h5', 'doc-minor', tr('Longest silences')), el('ul', 'doc-risks',
        ...info.silences.map(gap => el('li', '', icon('pause'), span(gap.seconds) + ' · ' + zoned(gap.from, offset) + ' → ' + zoned(gap.to, offset))))) : '',
      exchanges.length ? el('div', '', node('h5', 'doc-minor', tr('Recent replies')), el('ul', 'doc-exchanges', ...exchanges)) : '',
      node('p', 'hint', tr(info.basis)));
  }

  function styleSection() {
    const found = plan.style;
    if (!found.messages) return section('user', 'Their style', node('p', 'hint', tr('Their style appears after they write.')));
    const percent = value => Math.round(value * 100) + '%';
    const scripts = Object.entries(found.scripts).map(([name, share]) => node('span', 'doc-tag', tr(name) + ' ' + percent(share)));
    return section('user', 'Their style',
      el('div', 'doc-stats', el('div', 'doc-stat', node('b', '', String(found.average_length)), tr('characters per message')),
        el('div', 'doc-stat', node('b', '', String(found.messages_in_a_row)), tr('messages in a row')),
        el('div', 'doc-stat', node('b', '', percent(found.with_emoji)), tr('with emoji')),
        el('div', 'doc-stat', node('b', '', percent(found.starts_lowercase)), tr('start lowercase')),
        el('div', 'doc-stat', node('b', '', percent(found.no_final_punctuation)), tr('no final punctuation'))),
      scripts.length ? el('div', 'doc-style-line', node('span', 'doc-sub', tr('Alphabet')), ...scripts) : '',
      found.emoji.length ? el('div', 'doc-style-line', node('span', 'doc-sub', tr('Emoji')),
        ...found.emoji.map(([symbol, count]) => node('span', 'doc-tag doc-emoji', symbol + ' ' + count))) : '',
      found.words.length ? el('div', 'doc-style-line', node('span', 'doc-sub', tr('Frequent words')),
        ...found.words.map(([word, count]) => el('span', 'doc-tag', word, node('small', '', ' ' + count)))) : '',
      node('p', 'hint', tr('Counted from their saved messages in this workspace; nothing is sent anywhere.')));
  }

  function bars(values, labels, cls) {
    const chart = node('div', 'doc-bars ' + (cls || '')), top = Math.max(1, ...values);
    values.forEach((value, index) => {
      const column = node('div', 'doc-bar'), fill = node('span');
      fill.style.height = Math.round(value / top * 100) + '%';
      column.title = labels[index] + ': ' + value;
      column.append(fill, node('small', '', labels[index]));
      chart.append(column);
    });
    return chart;
  }

  function rows(items) {
    const list = node('div', 'doc-rows'), top = Math.max(1, ...items.map(i => i.count));
    for (const item of items) {
      const row = node('div', 'doc-row'), meter = node('span', 'doc-meter'), fill = node('span');
      fill.style.width = Math.round(item.count / top * 100) + '%';
      meter.append(fill);
      row.append(node('span', '', tr(item.label)), meter, node('b', '', String(item.count)));
      list.append(row);
    }
    return list;
  }

  function insightsView(result) {
    const hours = [...Array(24).keys()].map(String), parts = [];
    const c = result.counts, r = result.replies, d = result.deletions;
    const stats = [[c.messages, 'messages'], [c.incoming, 'received'], [c.outgoing, 'sent'], [c.deletions, 'deletion notices'],
      [c.own_deletions, 'own messages deleted']];
    parts.push(el('div', 'doc-stats', ...stats.map(([value, label]) => el('div', 'doc-stat', node('b', '', String(value ?? 0)), node('span', '', tr(label))))));
    parts.push(section('chart', 'Activity by hour', node('p', 'hint', tr('Received messages; your time zone offset is applied.')),
      bars(result.hours.incoming, hours), node('p', 'hint', tr('Sent by this account')), bars(result.hours.outgoing, hours, 'muted-bars')));
    const reply = [node('p', 'doc-sub', tr('{count} replies · median {median} · fastest {min} · slowest {max} · {unanswered} messages without a reply',
      {count: r.count, median: duration(r.median), min: duration(r.min), max: duration(r.max), unanswered: r.unanswered})), rows(r.buckets)];
    if (r.by_hour.length) {
      const medians = hours.map(h => (r.by_hour.find(b => b.hour === Number(h)) || {}).median || 0);
      reply.push(node('p', 'hint', tr('Median reply time by the hour you wrote (seconds)')), bars(medians, hours));
    }
    parts.push(section('clock', 'Reply time', ...reply));
    const deleted = [node('p', 'doc-sub', tr('Median lifetime before deletion: {median}', {median: duration(d.median)})), rows(d.lifetimes)];
    if (d.waves.length) {
      const list = node('ol', 'doc-waves');
      for (const wave of d.waves.slice(-20).reverse()) {
        let text = tr('{time}: {count} deleted (#{first}–#{last}; this account {own}, others {other})',
          {time: (wave.start || '').slice(0, 19).replace('T', ' '), count: wave.count, first: wave.first_id, last: wave.last_id, own: wave.own, other: wave.other});
        if (wave.after) text += ' · ' + tr(wave.after.outgoing ? '{s} after your message #{id}' : '{s} after their message #{id}', {s: duration(wave.after.seconds), id: wave.after.message_id});
        if (wave.since_previous_wave) text += ' · ' + tr('{s} since the previous wave', {s: duration(wave.since_previous_wave)});
        list.append(node('li', '', text));
      }
      deleted.push(node('p', 'hint', tr('Deletion waves (newest first)')), list);
    }
    parts.push(section('trash', 'Deleted messages', ...deleted));
    for (const person of result.presence) {
      if (person.online.some(Boolean)) parts.push(el('section', 'doc-panel', el('h4', 'doc-section', icon('user'),
        tr('Seen online by hour: user {id}', {id: person.user_id})), bars(person.online, hours)));
    }
    const how = el('details', 'doc-how', node('summary', '', tr('How to read these figures')), ...result.limits.map(l => node('p', 'hint', tr(l))));
    parts.push(how);
    return parts;
  }

  function analysisPanel() {
    const targets = state.status?.targets || [];
    if (!analysisAvailable()) return [empty('chart', tr('Analysis is not available'),
      tr('It needs the analyzer module and is off while the workspace is set up as a witness.'))];
    const chat = node('select'), zone = node('select'), out = node('div', 'doc-insights');
    chat.setAttribute('aria-label', tr('Chat')); zone.setAttribute('aria-label', tr('Times'));
    for (const target of targets) chat.append(new Option(target.title || String(target.chat_id), String(target.chat_id)));
    for (let minutes = -720; minutes <= 840; minutes += 60) zone.append(new Option('UTC' + (minutes < 0 ? '−' : '+') + Math.abs(minutes / 60), String(minutes)));
    zone.value = analysisState.zone ?? String(-new Date().getTimezoneOffset() - (-new Date().getTimezoneOffset() % 60));
    if (analysisState.chat && [...chat.options].some(o => o.value === analysisState.chat)) chat.value = analysisState.chat;
    const go = button('Show', 'primary', async () => {
      const result = await json('analyzer/insights?chat_id=' + encodeURIComponent(chat.value) + '&offset_minutes=' + encodeURIComponent(zone.value));
      Object.assign(analysisState, {chat: chat.value, zone: zone.value, data: result});
      out.replaceChildren(...insightsView(result));
    }, 'chart');
    out.replaceChildren(...(analysisState.data ? insightsView(analysisState.data)
      : [empty('chart', tr('Choose a chat'), tr('Reply times, activity hours, deleted messages and presence for one chat.'))]));
    return [el('div', 'doc-toolbar', chat, zone, go), out];
  }

  async function isolate(target) {
    await json('capture/browser/open', target); await refresh();
  }

  function browserRow() {
    const form = node('form', 'doc-browser'), input = node('input');
    const go = el('button', 'secondary', icon('globe'), node('span', '', tr('Open in isolation')));
    input.placeholder = tr('https://… or @username'); input.maxLength = 2048; input.required = true; go.type = 'submit';
    input.setAttribute('aria-label', tr('Open in isolation'));
    form.append(input, go, node('p', 'hint', tr('Opens in the separate browser recorder, never with the observing account. Connect it in Extras → Independent capture.')));
    form.addEventListener('submit', event => {event.preventDefault(); busy(go, async () => {
      const value = input.value.trim();
      await isolate(/^https?:\/\//i.test(value) ? {url: value, purpose: current.title} : {telegram: value, purpose: current.title});
      input.value = '';
    });});
    return form;
  }

  function thumbnail(step) {
    const file = (step.files || []).find(f => f.mime_type === 'image/png');
    if (!file) return '';
    const image = node('img', 'doc-shot'); image.alt = tr('Screenshot {sha}', {sha: file.sha256.slice(0, 16)});
    image.loading = 'lazy';
    const known = thumbnails.get(file.sha256);
    if (known) image.src = known;
    else api('capture/browser/object/' + file.sha256).then(r => r.blob()).then(blob => {
      const url = URL.createObjectURL(blob); thumbnails.set(file.sha256, url); image.src = url;
    }).catch(() => image.replaceWith(node('code', 'doc-sub', 'SHA-256 ' + file.sha256)));
    return image;
  }

  function markForm(mark) {
    if (!current || current.fixed || !drawer) return;
    editing = mark || null;
    drawer.querySelector('.doc-mark')?.remove();
    const form = node('form', 'doc-mark'), text = node('textarea');
    form.setAttribute('aria-label', tr(mark ? 'Save note' : 'Add note'));
    text.rows = 3; text.maxLength = 5000; text.required = true; text.value = mark?.text || '';
    text.placeholder = tr('What matters here? Your note stays separate from Telegram observations.');
    text.setAttribute('aria-label', tr('Note'));
    const labels = node('div', 'doc-labels');
    for (const [value, label] of LABELS) {
      const box = node('label', 'doc-chip' + (HIDING.includes(value) ? ' hiding' : '')), input = node('input');
      input.type = 'checkbox'; input.value = value; input.checked = !!mark?.labels.includes(value);
      box.classList.toggle('on', input.checked);
      input.addEventListener('change', () => box.classList.toggle('on', input.checked));
      box.append(input, document.createTextNode(tr(label))); labels.append(box);
    }
    const target = node('select'); target.setAttribute('aria-label', tr('Not tied to a step'));
    target.append(new Option(tr('Not tied to a step'), ''));
    const steps = (data?.blocks || []).filter(b => b.type === 'step' && b.step.ref).slice(-30).reverse();
    for (const block of steps) target.append(new Option(short(clock(block.step.at) + ' · ' + describe(block.step), 90), String(block.step.ref.seq)));
    if (mark?.target_seq) target.value = String(mark.target_seq);
    const save = el('button', 'primary', icon('check'), node('span', '', tr(mark ? 'Save note' : 'Add note'))); save.type = 'submit';
    const cancel = button('Cancel', 'ghost', async () => {form.remove(); editing = null;}, 'close');
    form.append(el('div', 'doc-mark-head', icon('note'), node('strong', '', tr(mark ? 'Save note' : 'Add note'))), text, labels, target,
      node('p', 'hint', tr('18+, obscene language, violence and personal data hide the chosen step in the document; the journal keeps it.')),
      el('div', 'doc-row-actions', save, cancel));
    form.addEventListener('submit', event => {event.preventDefault(); busy(save, async () => {
      const body = {text: text.value, labels: [...labels.querySelectorAll('input:checked')].map(i => i.value),
        target_seq: target.value ? Number(target.value) : null};
      if (editing) await api(path(current.id, 'marks', editing.id), body, {method: 'PUT'});
      else await json(path(current.id, 'marks', 'new'), body);
      form.remove(); editing = null; await refresh();
    });});
    const body = drawer.querySelector('.doc-body');
    if (!body) return;
    body.prepend(form); body.scrollTop = 0; text.focus();
  }

  function allowed() {
    return !!state.token && (state.me?.admin || (state.me?.permissions || []).includes('board.read'));
  }

  function watch() {
    mount();
    if (owner && owner !== key()) {owner = key(); reset();}
    toggle.hidden = !allowed();
    if (toggle.hidden && open()) hide();
  }
  document.addEventListener('DOMContentLoaded', () => {watch(); setInterval(watch, 2000);});
})();
