(() => {
  'use strict';
  const kinds = ['browser', 'ayugram', 'trusted'];
  const owner = () => state.workspaceRevision + ':' + state.profile + ':' + state.token;
  let bound = null, loading = false, generation = 0;
  const cards = new Map();
  function clear() {
    generation++; bound = null; loading = false; cards.clear();
    $('capture-connections').replaceChildren(); $('capture-load-message').textContent = '';
  }
  function field(form, label, type, id, value = '') {
    const box = node('label', '', tr(label)), input = node('input');
    input.type = type; input.id = id; input.autocomplete = 'off';
    if (type === 'checkbox') {box.className = 'capture-check'; input.checked = !!value; box.prepend(input);}
    else {input.value = value; box.append(input);}
    form.append(box); return input;
  }
  function make(kind, connection) {
    const base = 'capture-' + kind, card = node('article', 'card padded capture-recorder');
    card.id = base; card.append(node('h3', '', kind === 'trusted' ? 'Trusted Live (preview)' : kind === 'browser' ? tr('Browser recorder') : tr('AyuGram recorder')));
    const fieldset = node('fieldset'); card.append(fieldset);
    const setup = node('details'), summary = node('summary', '', tr('Connection settings'));
    setup.open = !connection.enabled; setup.append(summary); fieldset.append(setup);
    const form = node('form'); setup.append(form);
    const enabled = field(form, 'Allow this panel to control the recorder', 'checkbox', base + '-enabled', connection.enabled);
    const url = field(form, 'Recorder API origin', 'url', base + '-url', connection.url || '');
    url.placeholder = 'http://127.0.0.1:' + (kind === 'trusted' ? '8793' : kind === 'browser' ? '8791' : '8792'); url.required = true;
    const pin = field(form, 'Recorder key fingerprint (SHA-256)', 'text', base + '-pin', connection.fingerprint || '');
    pin.maxLength = 64; pin.minLength = 64; pin.required = true; pin.spellcheck = false;
    const token = field(form, 'Control token', 'password', base + '-token');
    token.placeholder = connection.configured ? tr('Saved in the encrypted workspace vault') : tr('Copy control-token.txt from this recorder');
    token.maxLength = 512;
    const screen = field(form, 'Client screen URL (optional)', 'url', base + '-screen', connection.screen_url || '');
    form.append(node('p', 'hint', tr('An empty token keeps the saved token only while the recorder address and fingerprint stay the same. Disabling this connection does not pause capture.')));
    const save = node('button', 'secondary', tr('Save connection')); save.type = 'submit'; form.append(save);
    const status = node('p', 'capture-status', tr(connection.enabled ? 'Connection saved. Check the recorder to load its current state.' : 'Connection disabled. No requests sent.'));
    status.id = base + '-status'; status.setAttribute('role', 'status'); fieldset.append(status);
    const top = node('div', 'independent-capture-actions'), check = node('button', 'secondary', tr('Check recorder'));
    check.id = base + '-check'; check.type = 'button'; check.disabled = !connection.enabled; top.append(check);
    const screenLink = node('a', 'secondary', tr('Open client screen ↗')); screenLink.target = '_blank'; screenLink.rel = 'noopener noreferrer';
    const clientScreen = () => connection.screen_url || (kind === 'trusted' ? connection.url : '');
    screenLink.hidden = !clientScreen(); if (clientScreen()) screenLink.href = clientScreen();
    top.append(screenLink); fieldset.append(top);
    const officialLink = node('a', 'secondary', LANG === 'ru' ? 'Открыть официальный клиент и настройки наблюдения ↗' : 'Open official client and observation settings ↗');
    officialLink.target = '_blank'; officialLink.rel = 'noopener noreferrer'; officialLink.hidden = true; top.append(officialLink);
    const controls = node('div', 'capture-fields'); controls.hidden = true; fieldset.append(controls);
    const flags = {};
    if (kind === 'browser') {
      flags.screenshots = field(controls, 'Viewport screenshots', 'checkbox', base + '-screenshots');
      flags.pages = field(controls, 'MHTML pages and extracted text', 'checkbox', base + '-pages');
    } else flags.database = field(controls, 'Consistent SQLite snapshots', 'checkbox', base + '-database');
    flags.video = field(controls, 'Optional procedure video (no audio)', 'checkbox', base + '-video');
    const videoHelp = node('p', 'hint'); controls.append(videoHelp);
    const tabs = node('div', 'capture-fields'), targets = node('select'); targets.id = base + '-targets';
    const targetLabel = node('label', '', tr('Browser tab to capture')); targetLabel.append(targets); tabs.append(targetLabel);
    tabs.hidden = kind !== 'browser'; controls.append(tabs);
    const actions = node('div', 'independent-capture-actions'); controls.append(actions);
    const checkpoint = node('p', 'capture-checkpoint'); controls.append(checkpoint);
    const events = node('ol', 'capture-events'); controls.append(events);
    const errorBox = node('p', 'form-error'); errorBox.setAttribute('role', 'alert'); card.append(errorBox);
    let remote = null, pending = false;
    const epoch = generation, who = owner();
    const current = () => epoch === generation && who === owner();
    const options = {profile: state.profile, token: state.token};
    const call = async (path, body) => {
      if (!current()) throw new StaleView();
      const result = await json('capture/' + kind + '/' + path, body, options);
      if (!current()) throw new StaleView();
      return result;
    };
    async function run(fn) {
      if (pending || !current()) return;
      pending = true; fieldset.disabled = true; errorBox.textContent = '';
      try {await fn();} catch (error) {
        if (current() && !(error instanceof StaleView)) {
          errorBox.textContent = error.message; controls.hidden = true; remote = null;
          status.textContent = tr('Recorder state unavailable. Check again before sending commands.');
        }
      } finally {pending = false; if (current()) fieldset.disabled = false;}
    }
    function button(parent, text, suffix, fn, primary = false) {
      const item = node('button', primary ? 'primary' : 'secondary', tr(text));
      item.type = 'button'; item.id = base + '-' + suffix; item.addEventListener('click', () => run(fn)); parent.append(item); return item;
    }
    const refreshTabs = button(tabs, 'Find browser tabs', 'find-tabs', async () => {
      const list = await call('targets'); targets.replaceChildren();
      for (const item of list) targets.append(new Option(item.url, item.target_id));
      if (remote?.selected_target) targets.value = remote.selected_target;
    });
    const selectTab = button(tabs, 'Use selected tab', 'select-tab', async () => {
      await call('target', {target_id: targets.value}); await refresh();
    });
    const selection = () => Object.fromEntries(Object.entries(flags).map(([key, input]) => [key, input.checked]));
    const saveOptions = button(actions, 'Save capture options', 'options', async () => {await call('settings', selection()); await refresh();});
    const toggle = button(actions, 'Start capture', 'toggle', async () => {
      await call('settings', remote.settings.enabled ? {enabled: false} : {...selection(), enabled: true}); await refresh();
    }, true);
    const snapshot = button(actions, 'Snapshot now', 'snapshot', async () => {await call('snapshot', {}); await refresh();});
    button(actions, 'Download checkpoint', 'checkpoint', async () => {
      await download('capture/' + kind + '/checkpoint', 'capture-' + kind + '-checkpoint.json', false, false, undefined, () => {}, {owner: {current}});
    });
    const zip = button(actions, 'Download verified ZIP', 'export', async () => {
      await download('capture/' + kind + '/export', 'capture-' + kind + '.zip', true, false, {}, () => {}, {owner: {current}});
      if (current()) await refresh();
    });
    async function refresh() {
      const data = await call('status'); remote = data.status; controls.hidden = false;
      if (kind === 'trusted') {
        controls.hidden = true;
        status.textContent = 'Trusted Live: ' + remote.phase + '\n' + connection.fingerprint + '\n' + (remote.last_error || remote.external_anchor);
        return;
      }
      status.dataset.state = remote.settings.enabled ? 'running' : 'paused';
      status.textContent = tr(remote.settings.enabled ? 'Capture running' : 'Capture paused') + '\n' + tr('Last saved snapshot') + ': ' +
        (remote.last_success || tr('None yet')) + (remote.last_error ? '\n' + remote.last_error : '');
      for (const [key, input] of Object.entries(flags)) input.checked = !!remote.settings[key];
      flags.video.disabled = !remote.video_available;
      const official = !!remote.official;
      officialLink.hidden = !official; officialLink.href = connection.url;
      tabs.hidden = kind !== 'browser' || official;
      for (const input of Object.values(flags)) input.parentElement.hidden = official;
      saveOptions.hidden = toggle.hidden = snapshot.hidden = official;
      videoHelp.textContent = tr(remote.video_available ? 'Video is available. It is recorded only while capture is running.' : 'Video is unavailable until an operator configures a screen source and FFmpeg.');
      if (official) videoHelp.textContent = LANG === 'ru' ? 'Этот рекордер управляет официальным Telegram Web．Откройте его панель для входа，выбора чата，темпа и завершения сессии，используйте токен управления рекордером．' : 'This recorder owns the official Telegram Web client．Open its panel to log in，select a chat，set the pace and finish the session，using the recorder control token．';
      toggle.textContent = tr(remote.settings.enabled ? 'Pause capture' : 'Start capture');
      snapshot.disabled = !remote.settings.enabled; zip.disabled = !!remote.settings.enabled;
      refreshTabs.disabled = selectTab.disabled = !!remote.settings.enabled;
      checkpoint.textContent = tr('Verified recorder key') + ': ' + connection.fingerprint + '\n#' + data.checkpoint.body.seq +
        ' · ' + data.checkpoint.body.head_hash + '\n' + tr('Operator-declared route') + ': ' + remote.route_label;
      const rows = await call('events'); events.replaceChildren();
      for (const event of rows.slice(-8).reverse()) events.append(node('li', '', '#' + event.seq + ' · ' + event.kind + ' · ' + event.observed_at));
    }
    check.addEventListener('click', () => run(refresh));
    form.addEventListener('submit', event => {event.preventDefault(); void run(async () => {
      const body = {enabled: enabled.checked, url: url.value.trim(), fingerprint: pin.value.trim(), token: token.value.trim(), screen_url: screen.value.trim()};
      token.value = '';
      const result = await call('connection', body); connection = result.connections[kind];
      check.disabled = !connection.enabled; controls.hidden = true; remote = null;
      screenLink.hidden = !clientScreen(); if (clientScreen()) screenLink.href = clientScreen();
      status.textContent = tr(connection.enabled ? 'Connection saved. Check the recorder to load its current state.' : 'Connection disabled. Recorder capture state has not changed.');
      if (connection.enabled) setup.open = false;
    });});
    if (kind === 'trusted') {
      fieldset.append(node('p', 'hint', 'Open the recorder screen to choose Desktop or Web, native export or visual capture, and the provisioned connector. This mode uses a separate official-client session.'));
    }
    cards.set(kind, card); return card;
  }
  async function select() {
    if (bound !== owner()) clear();
    if (state.extra !== 'capture' || loading || bound === owner()) return;
    loading = true; const who = owner(), epoch = generation;
    bound = who;
    try {
      const result = await json('capture');
      if (epoch !== generation || who !== owner()) return;
      $('capture-connections').replaceChildren(...kinds.map(kind => make(kind, result.connections[kind])));
      bound = who; $('capture-load-message').textContent = '';
    } catch (error) {
      if (epoch === generation && who === owner() && !(error instanceof StaleView)) {
        bound = null; $('capture-load-message').textContent = error.message;
      }
    } finally {if (epoch === generation) loading = false;}
  }
  window.TgWitnessIndependentCapture = {select, clear};
  window.addEventListener('tgwitness:lock', clear);
})();
