const PLACES = {'extras:bot': 'witness', 'extras:evidence': 'timestamps_backup', 'wizard:timestamps': 'timestamps_backup',
  'extras:github': 'code_check', 'extras:cloud': 'cloud'};
export const EXTRA_FEATURES = {bot: 'witness', evidence: 'timestamps_backup', github: 'code_check', cloud: 'cloud'};

export function createModes({node, tr, json, may, status, query, go, toast}) {
  let data = null, key = '', loadedAt = 0, request = 0, selected = null, easyOpened = '', home = null;
  const isLocked = featureId => {
    if(document.documentElement.dataset.uiLevel)return false;
    const feature = data?.features.find(f => f.id === featureId);
    return !!(feature && data.mode && rank(data.mode) < rank(feature.mode));
  };
  const rank = id => data?.modes.find(m => m.id === id)?.rank ?? 0;
  const info = id => data?.modes.find(m => m.id === id);
  const label = m => m.emoji + ' ' + tr(m.name);
  const percent = () => data ? Math.round(100 * data.active / data.total) : 0;
  const button = (cls, text) => { const b = node('button', cls, text); b.type = 'button'; return b; };

  const switcher = button('mode-switch');
  switcher.id = 'mode-switch'; switcher.hidden = true;
  const switchDot = node('span', 'mode-switch-dot'), switchName = node('span', 'mode-switch-name'), switchLevel = node('span', 'mode-switch-level');
  switchDot.setAttribute('aria-hidden', 'true'); switcher.append(switchDot, switchName, switchLevel);
  document.getElementById('app-version').before(switcher);

  const onboarding = node('section', 'mode-onboarding card padded');
  onboarding.id = 'mode-onboarding'; onboarding.hidden = true; onboarding.setAttribute('aria-labelledby', 'mode-onboarding-title');
  document.getElementById('setup-card').before(onboarding);

  const dialog = node('dialog', 'mode-dialog');
  dialog.id = 'mode-dialog'; dialog.setAttribute('aria-labelledby', 'mode-dialog-title');
  const wizard = node('dialog', 'mode-dialog tsa-wizard');
  wizard.id = 'tsa-wizard'; wizard.setAttribute('aria-labelledby', 'tsa-wizard-title');
  document.body.append(dialog, wizard);

  const card = node('section', 'card padded protection-card');
  card.id = 'protection-card'; card.hidden = true; card.setAttribute('aria-labelledby', 'protection-card-title');
  query('#extras-overview .extras-intro')[0]?.after(card);

  function modeCards(host, {current, choose, compact}) {
    const grid = node('div', 'mode-cards' + (compact ? ' compact' : ''));
    for (const m of data.modes) {
      const item = node(choose ? 'button' : 'div', 'mode-card');
      if (choose) {
        item.type = 'button'; item.setAttribute('aria-pressed', String(m.id === (selected || current)));
        item.addEventListener('click', () => choose(m.id));
      }
      item.dataset.mode = m.id;
      if (m.id === current) item.classList.add('current');
      if (m.id === selected) item.classList.add('selected');
      const head = node('span', 'mode-card-head');
      head.append(node('span', 'mode-card-emoji', m.emoji), node('strong', '', tr(m.name)));
      if (m.id === current) head.append(node('span', 'mode-card-badge', tr('Current')));
      const facts = node('dl', 'mode-card-facts');
      for (const [term, text] of [[tr('For whom'), m.audience], [tr('What you get'), m.outcome], [tr('How hard'), m.effort]])
        facts.append(node('dt', '', term), node('dd', '', tr(text)));
      item.append(head, facts);
      grid.append(item);
    }
    host.append(grid);
  }

  function layerList(host) {
    const list = node('div', 'protection-layers');
    for (const m of data.modes) {
      const layers = data.layers.filter(layer => layer.mode === m.id);
      if (!layers.length) continue;
      const group = node('section', 'protection-group'), rows = node('ul', '');
      group.append(node('h4', '', label(m)));
      for (const layer of layers) {
        const row = node('li', 'protection-layer ' + layer.state);
        const mark = node('span', 'protection-mark', {on: '✓', pending: '…', off: '○'}[layer.state]);
        mark.setAttribute('aria-hidden', 'true');
        const text = node('span', 'protection-text');
        text.append(node('span', '', tr(layer.name)),
          node('small', '', layer.place ? tr({on: 'On', pending: 'Waiting for confirmation', off: 'Off'}[layer.state]) : tr('Built in')));
        row.append(mark, text);
        if (layer.place && layer.state !== 'on' && may('settings')) {
          const feature = data.features.find(f => f.id === PLACES[layer.place]), hidden = feature && isLocked(feature.id);
          const setup = button('quiet', hidden ? '🔓 ' + tr(info(feature.mode).name) : tr('Set up'));
          if (hidden) { setup.title = lockText(feature); setup.setAttribute('aria-label', lockText(feature)); }
          setup.addEventListener('click', () => {
            if (hidden) { show(feature.mode); return; }
            if (dialog.open) dialog.close();
            open(layer.place);
          });
          row.append(setup);
        }
        rows.append(row);
      }
      group.append(rows); list.append(group);
    }
    const later = node('p', 'hint protection-not-yet');
    later.textContent = tr('Not in this version: {list}.', {list: data.not_yet.map(text => tr(text)).join(' · ')});
    host.append(list, later);
  }

  function level(host) {
    const m = info(data.mode), bar = node('div', 'protection-bar'), fill = node('span', '');
    fill.style.width = percent() + '%'; bar.append(fill);
    bar.setAttribute('role', 'img');
    bar.setAttribute('aria-label', tr('{active} of {total} protection layers', {active: data.active, total: data.total}));
    host.append(node('p', 'protection-summary', (m ? label(m) + ' · ' : '') +
      tr('{active} of {total} layers ({percent}%)', {active: data.active, total: data.total, percent: percent()})), bar);
  }

  function featureNames(ids) { return ids.map(id => tr(data.features.find(f => f.id === id).name)); }
  function between(from, to) {
    const low = from ? rank(from) : data.modes.length, high = rank(to);
    return {
      shown: from ? data.features.filter(f => rank(from) < rank(f.mode) && rank(f.mode) <= high).map(f => f.id) : [],
      hidden: data.features.filter(f => high < rank(f.mode) && rank(f.mode) <= low).map(f => f.id),
    };
  }

  function renderDialog() {
    dialog.replaceChildren();
    if (!data) return;
    const head = node('div', 'mode-dialog-head'), title = node('h2', '', tr('Protection mode')), close = button('quiet', '×');
    title.id = 'mode-dialog-title'; close.setAttribute('aria-label', tr('Close'));
    close.addEventListener('click', () => dialog.close());
    head.append(title, close);
    dialog.append(head, node('p', 'hint', tr('A mode decides what the panel shows and suggests. Recording and signing are the same in every mode; a hidden section keeps working and nothing is deleted.')));
    modeCards(dialog, {current: data.mode, compact: true, choose: may('settings') ? id => {
      selected = id === data.mode ? null : id; renderDialog();
      dialog.querySelector('.mode-diff input, .mode-diff button.primary:not(:disabled)')?.focus();
    } : null});
    if (selected) dialog.append(diffBox(selected));
    const levelBox = node('section', 'mode-level');
    levelBox.append(node('h3', '', tr('Protection level')));
    level(levelBox); layerList(levelBox);
    dialog.append(levelBox);
  }

  function diffBox(target) {
    const lower = !!data.mode && rank(target) < rank(data.mode), box = node('section', 'mode-diff' + (lower ? ' lower' : '')), m = info(target);
    const {shown, hidden} = between(data.mode, target);
    box.append(node('h3', '', tr(lower ? 'Lower the mode to {mode}?' : 'Switch to {mode}?', {mode: label(m)})));
    if (shown.length) box.append(node('p', '', tr('Appears: {list}.', {list: featureNames(shown).join(' · ')})));
    if (hidden.length) box.append(node('p', '', tr('Hidden, still working: {list}.', {list: featureNames(hidden).join(' · ')})));
    if (!shown.length && !hidden.length) box.append(node('p', '', tr('The same sections stay visible.')));
    let confirm = null;
    if (lower) {
      const line = node('label', 'check-label');
      confirm = node('input'); confirm.type = 'checkbox';
      line.append(confirm, document.createTextNode(' ' + tr('I understand: hidden sections keep working and nothing is deleted.')));
      box.append(line);
    }
    const apply = button('primary', tr(lower ? 'Lower to {mode}' : 'Switch to {mode}', {mode: tr(m.name)}));
    apply.disabled = lower;
    confirm?.addEventListener('change', () => { apply.disabled = !confirm.checked; });
    apply.addEventListener('click', () => save(target, {confirm: lower, button: apply}));
    box.append(apply);
    return box;
  }

  function renderOnboarding() {
    const s = status(), wanted = !document.documentElement.dataset.uiLevel && !!data && data.mode === null && !s?.demo && !window.TGW_ONLINE_DEMO && may('settings');
    onboarding.hidden = !wanted;
    onboarding.dataset.session = String(!!s?.collector?.has_session);
    if (!wanted) { onboarding.replaceChildren(); return; }
    if (onboarding.childElementCount) return;
    const title = node('h2', '', tr('How much protection does this workspace need?'));
    title.id = 'mode-onboarding-title';
    onboarding.append(title,
      node('p', 'muted', tr('The mode decides which sections the panel shows. Every record is signed in every mode, and you can change the mode later next to the version number.')));
    modeCards(onboarding, {current: null, choose: id => save(id, {first: true})});
    const foot = node('div', 'mode-onboarding-foot'), later = button('secondary', tr('Change later'));
    later.addEventListener('click', () => save(data.default, {first: true, later: true, button: later}));
    foot.append(later, node('span', 'hint', tr('Until then the panel uses {mode}.', {mode: label(info(data.default))})));
    onboarding.append(foot);
  }

  function renderSwitcher() {
    switcher.hidden = !data;
    if (!data) return;
    const m = info(data.mode);
    switchDot.textContent = m ? m.emoji : '◌';
    switchName.textContent = m ? tr(m.name) : tr('All sections');
    switchLevel.textContent = data.active + '/' + data.total;
    const text = m ? tr('Protection mode: {mode}. {active} of {total} protection layers.', {mode: tr(m.name), active: data.active, total: data.total})
      : tr('No protection mode chosen yet. {active} of {total} protection layers.', {active: data.active, total: data.total});
    switcher.setAttribute('aria-label', text); switcher.title = text;
  }

  function renderCard() {
    card.hidden = !data;
    const signature = data ? JSON.stringify([data, may('settings')]) : '';
    if (!data || card.dataset.signature === signature) return;
    card.dataset.signature = signature;
    const m = info(data.mode), wasOpen = card.querySelector('details')?.open;
    card.replaceChildren();
    const head = node('div', 'card-heading compact'), title = node('h2', '', tr('Protection level'));
    title.id = 'protection-card-title';
    const change = button('secondary', tr('Change mode'));
    change.addEventListener('click', () => show());
    head.append(title, change);
    card.append(head);
    card.append(node('p', 'hint', tr('A mode changes the panel view. The status of each layer is below.')));
    level(card);
    const details = node('details', 'protection-details'), summary = node('summary', '', tr('The {total} protection layers', {total: data.total}));
    details.append(summary); layerList(details);
    details.open = wasOpen ?? data.mode === 'mossad';
    card.append(details);
    if (!m) card.append(node('p', 'hint', tr('No mode is chosen yet, so every section is shown.')));
  }

  function lockText(feature) {
    const m = info(feature.mode);
    return tr('🔓 Unlock in mode: {mode}', {mode: label(m)});
  }

  function applyGating() {
    if(document.documentElement.dataset.uiLevel){
      for(const el of query('[data-mode-locked]'))delete el.dataset.modeLocked;
      for(const el of query('.mode-lock'))el.hidden=true;
      return;
    }
    const current = data?.mode ? rank(data.mode) : Infinity, byId = new Map((data?.features || []).map(f => [f.id, f]));
    document.getElementById('workspace').dataset.protectionMode = data?.mode || '';
    for (const element of query('[data-mode-feature]')) {
      const feature = byId.get(element.dataset.modeFeature);
      const locked = !!feature && current < rank(feature.mode);
      if (locked) element.dataset.modeLocked = ''; else delete element.dataset.modeLocked;
      if (!element.hasAttribute('data-mode-anchor')) continue;
      const before = element.previousElementSibling;
      let lock = before?.dataset.lockFor === element.dataset.modeFeature ? before : null;
      if (!locked) { if (lock) lock.hidden = true; continue; }
      if (!lock) {
        const asCard = element.classList.contains('extra-card');
        lock = node(asCard ? 'article' : 'div', 'mode-lock' + (asCard ? ' extra-card' : ' card padded'));
        lock.dataset.lockFor = element.dataset.modeFeature;
        element.before(lock);
      }
      lock.hidden = false;
      const signature = JSON.stringify([data.mode, feature, may('settings')]);
      if (lock.dataset.signature === signature) continue;
      lock.dataset.signature = signature; lock.replaceChildren();
      const text = node('div', 'mode-lock-text');
      text.append(node('strong', '', tr(feature.name)),
        node('span', 'hint', feature.active ? tr('On and still working; hidden in this mode.') : tr('Hidden in this mode.')));
      const unlock = button('secondary', lockText(feature));
      unlock.disabled = !may('settings');
      unlock.addEventListener('click', () => show(feature.mode));
      lock.append(text, unlock);
    }
    const tools = query('#export-chat-tools')[0];
    if (tools) {
      home ??= tools.nextElementSibling;
      if (data?.mode === 'easy') {
        if (tools.parentElement.firstElementChild !== tools) tools.parentElement.prepend(tools);
        if (easyOpened !== key) { easyOpened = key; tools.open = true; }
      } else if (home && tools.nextElementSibling !== home) home.before(tools);
    }
  }

  function render() { renderSwitcher(); renderOnboarding(); renderCard(); applyGating(); if (dialog.open) renderDialog(); }

  async function load(force = false) {
    const s = status(), wanted = s ? key : '';
    if (!s || window.TGW_ONLINE_DEMO && !force) { data = null; render(); return; }
    const mine = ++request;
    try {
      const result = await json('mode');
      if (mine !== request || wanted !== key) return;
      data = result; loadedAt = Date.now();
    } catch {
      if (mine !== request) return;
      data = null;
    }
    render();
  }

  function reset() {
    wizardRun++; request++; selected = null;
    if (dialog.open) dialog.close();
    if (wizard.open) wizard.close();
  }

  function sync(sessionKey) {
    if (sessionKey !== key) { reset(); key = sessionKey; data = null; render(); void load(); return; }
    if (Date.now() - loadedAt > 60000) void load();
  }

  async function save(id, {confirm = false, first = false, later = false, button: control = null} = {}) {
    const before = data?.mode ?? null;
    if (control) control.disabled = true;
    try {
      const result = await json('mode', {mode: id, confirm_downgrade: confirm, reason: later ? 'later' : 'chosen'}, {method: 'PATCH'});
      data = result; loadedAt = Date.now(); selected = null;
      if (dialog.open) dialog.close();
      render();
      const m = info(id), up = before === null || rank(id) > rank(before);
      toast(tr('Protection mode: {mode}.', {mode: label(m)}));
      if (later || !up) return;
      if (id === 'easy') go(first ? 'setup' : 'chats');
      else if (id === 'witnessed') {
        go('extras:bot');
        const name = query('#witness-label')[0];
        if (name && !name.value) name.value = tr('Independent witness');
        toast(tr('Next: the independent witness. Step 2 saves witness.json for the second machine.'));
      }
      else if (id === 'court') openWizard();
      else if (id === 'mossad') {
        go('extras');
        requestAnimationFrame(() => { const details = card.querySelector('details'); if (details) details.open = true; card.scrollIntoView({block: 'start'}); });
      }
    } catch (error) {
      toast(error.message, true);
    } finally {
      if (control?.isConnected) control.disabled = false;
    }
  }

  function show(preselect = null) {
    if (!data) return;
    selected = preselect && preselect !== data.mode && may('settings') ? preselect : null;
    renderDialog();
    if (!dialog.open) dialog.showModal();
    void load().then(() => { if (dialog.open) renderDialog(); });
  }

  function open(place) {
    if (place === 'wizard:timestamps') openWizard(); else go(place);
  }

  let wizardRun = 0;
  async function openWizard() {
    const run = ++wizardRun;
    wizard.replaceChildren();
    const head = node('div', 'mode-dialog-head'), title = node('h2', '', tr('Turn on trusted timestamps')), close = button('quiet', '×');
    title.id = 'tsa-wizard-title'; close.setAttribute('aria-label', tr('Close'));
    close.addEventListener('click', () => wizard.close());
    head.append(title, close);
    const steps = node('ol', 'tsa-steps'), body = node('div', 'tsa-body'), result = node('div', 'tsa-result');
    result.setAttribute('role', 'status');
    for (const text of [tr('Choose the services'), tr('Turn on and timestamp the current checkpoint'), tr('Check the answer')])
      steps.append(node('li', '', text));
    wizard.append(head, steps, body, result);
    if (!wizard.open) wizard.showModal();
    const step = n => [...steps.children].forEach((item, i) => { item.classList.toggle('current', i === n); item.classList.toggle('complete', i < n); });
    step(0);
    if (status()?.demo) { body.append(node('p', 'hint', tr('Evidence mode works in a real workspace, not in the demo.'))); return; }
    let evidence;
    try { evidence = await json('evidence'); } catch (error) { body.append(node('p', 'form-error', error.message)); return; }
    if (run !== wizardRun) return;
    const saved = evidence.settings, settings = saved.tsa_urls.length || saved.ots_calendars.length ? saved : {...saved, ...evidence.defaults};
    body.append(node('p', 'muted', tr('Only the SHA-256 of each signed checkpoint is sent, through this workspace\'s connection route. The answers are kept with the checkpoints, travel in evidence exports and are checked by verify.py.')));
    const services = node('ul', 'tsa-services');
    for (const url of settings.tsa_urls) services.append(node('li', '', 'RFC 3161 · ' + url));
    for (const url of settings.ots_calendars) services.append(node('li', '', 'OpenTimestamps · ' + url));
    body.append(services);
    const actions = node('div', 'tsa-actions'), start = button('primary', tr(evidence.settings.enabled ? 'Timestamp the current checkpoint' : 'Turn on and timestamp')),
      edit = button('quiet', tr('Edit the services'));
    edit.addEventListener('click', () => { wizard.close(); go('extras:evidence'); });
    actions.append(start, edit); body.append(actions);
    if (evidence.route_problem) {
      start.disabled = true;
      const problem = node('p', 'form-error', tr(evidence.route_problem)), fix = button('secondary', tr('Open connection settings'));
      fix.addEventListener('click', () => { wizard.close(); go('connection'); });
      body.append(problem, fix);
      return;
    }
    start.addEventListener('click', async () => {
      start.disabled = true; step(1);
      try {
        if (evidence.settings.enabled) await json('evidence/anchor', {});
        else await json('evidence', {enabled: true, interval_minutes: settings.interval_minutes, tsa_urls: settings.tsa_urls, ots_calendars: settings.ots_calendars});
      } catch (error) { start.disabled = false; result.replaceChildren(node('p', 'form-error', error.message)); return; }
      result.replaceChildren(node('p', 'hint', tr('Sending the checkpoint hash to timestamp services…')));
      const deadline = Date.now() + 90000;
      while (run === wizardRun && wizard.open && Date.now() < deadline) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        let state;
        try { state = await json('evidence'); } catch { continue; }
        const health = state.health;
        if (state.busy || ['first_pending', 'sending', 'no_checkpoint'].includes(health.reason)) continue;
        step(2); showAnswer(result, state); void load(true);
        return;
      }
      if (run === wizardRun) result.replaceChildren(node('p', 'hint', tr('No answer yet. The timestamps keep running in the background; check Extras → Evidence later.')));
    });
  }

  function showAnswer(box, state) {
    const verified = (state.last?.results || []).filter(r => r.ok && r.kind === 'rfc3161');
    const pending = (state.last?.results || []).filter(r => r.ok && r.kind === 'opentimestamps');
    const failed = (state.last?.results || []).filter(r => !r.ok);
    box.replaceChildren();
    if (verified.length) box.append(node('p', 'tsa-ok', tr('Verified timestamps: {list}.', {list: verified.map(r => new URL(r.service).hostname).join(', ')})));
    if (pending.length) box.append(node('p', 'hint', tr('OpenTimestamps proofs received; Bitcoin confirms them within hours.')));
    if (failed.length) box.append(node('p', 'form-error', tr('No valid answer from: {list}.', {list: failed.map(r => new URL(r.service).hostname + ' — ' + r.error).join('; ')})));
    if (!verified.length && !pending.length && !failed.length) box.append(node('p', 'hint', tr('Every service has already answered for the latest checkpoint.')));
    const done = button('secondary', tr('Done'));
    done.addEventListener('click', () => wizard.close());
    box.append(done);
  }

  switcher.addEventListener('click', () => show());
  dialog.addEventListener('close', () => { selected = null; });

  return {sync, reset, refresh: () => load(), show, open, openWizard, mode: () => data?.mode ?? null, locked: isLocked,
    lockedExtra: name => !!EXTRA_FEATURES[name] && isLocked(EXTRA_FEATURES[name])};
}
