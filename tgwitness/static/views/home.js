const TASKS = {
  observation: ['Observing live updates', 'Loading older messages, chat and account exports, full history and connection changes', 'Reading saved messages, search, reports and signed exports of saved observations', 'Pause observation', 'collector/stop'],
  starting_observation: ['Starting observation', 'Other Telegram tasks until observation has started', 'Reading saved messages and reports', null, null],
  history: ['Loading full history', 'Observation, exports, loading older messages and connection changes', 'Reading saved messages and reports', 'Pause history', 'history/pause'],
  chat_export: ['Exporting a chat', 'Observation, other exports, full history and connection changes', 'Reading saved messages and reports', 'Cancel export', null],
  export: ['Running an account or multi-account export', 'Observation, other exports, full history and connection changes', 'Reading saved messages and reports', 'Open exports', null],
  loading_messages: ['Loading messages of a chat', 'Other Telegram tasks for a moment', 'Everything else', null, null],
  measuring_chat: ['Measuring a chat for export', 'Other Telegram tasks for a moment', 'Everything else', null, null],
  planning_export: ['Planning an export', 'Other Telegram tasks for a moment', 'Everything else', null, null],
  checking_export: ['Checking export settings', 'Other Telegram tasks for a moment', 'Everything else', null, null],
  profile_photo: ['Loading a profile photo', 'Other Telegram tasks for a moment', 'Everything else', null, null],
  panel_action: ['Running a panel action', 'Other Telegram tasks for a moment', 'Everything else', null, null],
  connection_change: ['Changing the connection', 'All Telegram tasks until the new connection is checked', 'Reading saved messages and reports', null, null],
  sign_in_required: ['Telegram signed this account out', 'All Telegram tasks until you sign in again', 'Reading saved messages, reports and exports of saved observations', 'Sign in', null],
};

export function taskInfo(activity) {
  const row = TASKS[activity?.task];
  return row ? {label: row[0], blocks: row[1], allows: row[2], action: row[3], path: row[4]} : null;
}

export function createHome({root, tr, node, getState, accountState, switchProfile, navigate, json, refresh, formatTime, busy, toast}) {
  let activity = null, loadedAt = 0, loading = false, loadedFor = null;
  const svgNS = 'http://www.w3.org/2000/svg';
  const svgNode = (tag, attributes) => {
    const element = document.createElementNS(svgNS, tag);
    for (const [key, value] of Object.entries(attributes || {})) element.setAttribute(key, value);
    return element;
  };

  async function loadActivity(profile) {
    if (loading || (loadedFor === profile && Date.now() - loadedAt < 60000)) return;
    loading = true;
    try {
      activity = await json('overview/activity');
      loadedAt = Date.now(); loadedFor = profile;
      render();
    } catch {
      activity = null;
    } finally {
      loading = false;
    }
  }

  function chart() {
    const box = node('section', 'home-card home-chart');
    const head = node('div', 'home-heading');
    head.append(node('h2', '', tr('Saved by day')), node('span', 'home-sub', tr('last {n} days, this account', {n: activity?.days || 60})));
    box.append(head);
    const days = activity?.days || 60, start = activity ? new Date(activity.since + 'T00:00:00Z') : new Date(Date.now() - (days - 1) * 86400000);
    const byDay = new Map((activity?.series || []).map(item => [item.day, item]));
    const values = [...Array(days).keys()].map(index => {
      const day = new Date(start.getTime() + index * 86400000).toISOString().slice(0, 10);
      return byDay.get(day) || {day, messages: 0, edits: 0, deletions: 0};
    });
    const total = values.reduce((sum, v) => sum + v.messages + v.edits + v.deletions, 0);
    if (!total) {
      box.append(node('p', 'home-empty', tr('Nothing saved in this period yet. Start observation, load history or run an export; saved messages, edits and deletions appear here by day.')));
      return box;
    }
    const peak = Math.max(1, ...values.map(v => v.messages)), changes = Math.max(1, ...values.map(v => v.edits + v.deletions));
    const width = 600, height = 140, step = width / days;
    const svg = svgNode('svg', {viewBox: `0 0 ${width} ${height + 40}`, class: 'home-svg', role: 'img', 'aria-label': tr('Saved by day')});
    svg.append(svgNode('path', {d: `M0 ${height}H${width}`, class: 'home-axis'}));
    values.forEach((v, index) => {
      const x = index * step + 1, w = Math.max(1, step - 2);
      const h = v.messages ? Math.max(2, v.messages / peak * (height - 10)) : 0;
      const bar = svgNode('rect', {x, y: height - h, width: w, height: h, rx: 2, class: 'home-bar'});
      const title = svgNode('title');
      title.textContent = v.day + ': ' + tr('{n} messages', {n: v.messages}) + ' · ' + tr('{n} edits', {n: v.edits}) + ' · ' + tr('{n} deletions', {n: v.deletions});
      bar.append(title);
      svg.append(bar);
      const lost = v.edits + v.deletions;
      if (lost) {
        const r = 2 + Math.round(lost / changes * 5);
        const dot = svgNode('circle', {cx: x + w / 2, cy: height + 18, r, class: v.deletions ? 'home-dot-loss' : 'home-dot-edit'});
        dot.append(title.cloneNode(true));
        svg.append(dot);
      }
    });
    box.append(svg);
    const legend = node('div', 'home-legend');
    legend.append(node('span', 'home-key messages', tr('Messages')), node('span', 'home-key deletions', tr('Deletions')), node('span', 'home-key edits', tr('Edits only')));
    box.append(legend, node('p', 'home-note', tr('By the day TgWitness saved them. Hover a day for exact numbers; Journal and Chats hold the records.')));
    return box;
  }
  const chip = (kind, text) => node('span', 'home-chip home-chip-' + kind, text);
  const progressOf = activity => {
    const d = activity?.detail;
    if (!d || !d.total || d.captured == null) return null;
    return Math.max(0, Math.min(100, Math.round(d.captured / d.total * 100)));
  };

  function activityLine(profile) {
    const activity = profile.collector?.activity, info = taskInfo(activity), wrap = node('div', 'home-activity');
    if (!info) {
      wrap.append(node('span', 'home-idle' + (profile.collector?.has_session ? '' : ' none'), tr(profile.collector?.has_session ? 'Idle: ready for any task' : 'No Telegram account connected')));
      return wrap;
    }
    const title = node('strong', '', tr(info.label));
    wrap.append(title);
    const d = activity.detail;
    if (activity.task === 'chat_export' && d) {
      const name = d.title || ('#' + d.chat_id);
      title.textContent = tr('Exporting {chat}', {chat: name});
      const percent = progressOf(activity);
      if (percent !== null) {
        const bar = node('div', 'home-progress'), fill = node('span');
        fill.style.width = percent + '%'; bar.append(fill);
        wrap.append(bar, node('small', '', tr('{done} of {total} messages', {done: d.captured.toLocaleString(), total: d.total.toLocaleString()})
          + (d.eta_seconds ? ' · ' + tr('about {minutes} min left', {minutes: Math.max(1, Math.round(d.eta_seconds / 60))}) : '')));
      }
    }
    wrap.append(node('small', 'home-blocked', tr('Not available now: {list}', {list: tr(info.blocks)})),
                node('small', 'home-allowed', tr('Still available: {list}', {list: tr(info.allows)})));
    return wrap;
  }

  function accountCard(profile, state) {
    const info = accountState(profile), collector = profile.collector || {}, account = collector.account || {};
    const card = node('article', 'home-account' + (profile.id === state.profile ? ' current' : ''));
    const head = node('div', 'home-account-head'), who = node('div', 'home-who');
    const initial = node('span', 'home-avatar', (profile.label || '?').trim().slice(0, 1).toUpperCase());
    who.append(node('strong', '', profile.label), node('small', '', account.username ? '@' + account.username : account.id ? 'ID ' + account.id : tr('No Telegram account yet')));
    head.append(initial, who, chip(info.kind, tr(info.label)));
    card.append(head, activityLine(profile));
    const pause = collector.activity?.telegram_pause_until;
    if (pause) card.append(node('p', 'home-warning', tr('Telegram asked to pause requests until {time}.', {time: formatTime(new Date(pause * 1000).toISOString())})));
    const actions = node('div', 'home-actions');
    const open = node('button', 'secondary', tr(profile.id === state.profile ? 'Open chats' : 'Open account'));
    open.type = 'button';
    open.addEventListener('click', () => busy(open, async () => {
      if (profile.id !== state.profile) await switchProfile(profile.id);
      navigate(info.needsSignIn || !info.hasSession ? 'connection' : 'chats');
    }));
    actions.append(open);
    const task = taskInfo(collector.activity);
    if (task?.action) {
      const act = node('button', 'quiet', tr(task.action));
      act.type = 'button';
      act.addEventListener('click', () => busy(act, async () => {
        if (task.path) {
          await json(task.path, {}, {profile: profile.id});
          toast(tr('Paused.'));
          await refresh();
        } else {
          if (profile.id !== state.profile) await switchProfile(profile.id);
          navigate(collector.activity.task === 'sign_in_required' ? 'connection' : 'evidence');
        }
      }));
      actions.append(act);
    }
    card.append(actions);
    return card;
  }

  function running(profiles) {
    const box = node('section', 'home-card home-running');
    box.append(node('h2', '', tr('Running now')));
    const items = profiles.filter(p => taskInfo(p.collector?.activity) && p.collector.activity.task !== 'sign_in_required');
    if (!items.length) {
      box.append(node('p', 'home-empty', tr('Nothing is running. Every connected account is free for a new task.')));
      return box;
    }
    const list = node('ul', 'home-process');
    for (const profile of items) {
      const activity = profile.collector.activity, info = taskInfo(activity), item = node('li');
      const percent = progressOf(activity);
      item.append(node('strong', '', profile.label), node('span', '', ' · ' + (activity.task === 'chat_export' && activity.detail
        ? tr('Exporting {chat}', {chat: activity.detail.title || ('#' + activity.detail.chat_id)}) : tr(info.label))));
      if (percent !== null) {
        const bar = node('div', 'home-progress'), fill = node('span');
        fill.style.width = percent + '%'; bar.append(fill); item.append(bar);
      }
      list.append(item);
    }
    box.append(list);
    return box;
  }

  function system(state) {
    const box = node('section', 'home-card home-system'), status = state.status || {}, collector = status.collector || {};
    box.append(node('h2', '', tr('System')));
    const facts = node('dl', 'home-facts');
    const health = status.health?.state;
    const rows = [
      [tr('Panel'), tr(health === 'ok' ? 'Working' : health ? 'Needs attention' : 'Checking…')],
      [tr('Accounts'), String((state.profiles || []).length || 1)],
      [tr('Saved records in this account'), (status.stats?.total || 0).toLocaleString()],
      [tr('Files waiting to download'), String(collector.media_pending || 0)],
    ];
    if (collector.disk_free_bytes != null) rows.push([tr('Free disk space'), (collector.disk_free_bytes / 1024 ** 3).toFixed(1) + ' GB']);
    for (const [label, value] of rows) facts.append(node('dt', '', label), node('dd', '', value));
    box.append(facts);
    if (state.me?.admin) {
      const map = node('button', 'text-link', tr('Open the system map'));
      map.type = 'button';
      map.addEventListener('click', () => navigate('system-map'));
      box.append(map);
    }
    return box;
  }

  function render() {
      const state = getState();
      if (!root || !state.status) return;
      loadActivity(state.profile);
      const profiles = (state.profiles && state.profiles.length) ? state.profiles
        : [{id: state.profile, label: tr('Main account'), collector: state.status.collector, health: state.status.health}];
      const accounts = node('section', 'home-card home-accounts');
      const heading = node('div', 'home-heading');
      heading.append(node('h2', '', tr('Accounts')), node('span', 'home-count', String(profiles.length)));
      const add = node('button', 'quiet', tr('Add account'));
      add.type = 'button';
      add.addEventListener('click', () => navigate('accounts'));
      heading.append(add);
      accounts.append(heading);
      const grid = node('div', 'home-account-grid');
      for (const profile of profiles) grid.append(accountCard(profile, state));
      accounts.append(grid);
      const side = node('div', 'home-side');
      side.append(running(profiles), system(state));
      const main = node('div', 'home-main');
      main.append(accounts, chart());
      const layout = node('div', 'home-layout');
      layout.append(main, side);
      root.replaceChildren(layout);
  }

  return {render};
}
