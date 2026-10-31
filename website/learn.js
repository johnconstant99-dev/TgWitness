'use strict';


(() => {

  const DICT = (() => { try { return JSON.parse(document.getElementById('site-dict')?.textContent || '{}'); } catch { return {}; } })();
  const T = (text, values = {}) => (DICT[text] || text).replace(/\{(\w+)\}/g, (match, key) => key in values ? values[key] : match);
  const motion = matchMedia('(prefers-reduced-motion: reduce)');
  const showControls = lab => lab.querySelectorAll('[data-enhanced]').forEach(node => { node.hidden = false; });
  const pressed = (lab, attribute, value) => lab.querySelectorAll(`[${attribute}]`).forEach(button => {
    button.setAttribute('aria-pressed', String(button.getAttribute(attribute) === value));
  });

  function journey(lab) {
    const play = lab.querySelector('[data-play]');
    const next = lab.querySelector('[data-next]');
    const states = [
      [T('Waiting for a message'), T('Step through a fictional send, edit and delete.'), T('No observations yet. Start the sequence or advance one event.')],
      [T('Meet at 10:00'), T('A new message is visible in the chat.'), T('Record 1 appended: the collector observed the original message.')],
      [T('Meet at 11:00'), T('The current text changes. The earlier observation stays.'), T('Record 2 appended: the edit is a new observation. Record 1 still holds the original text.')],
      [T('Message deleted'), T('The message has disappeared from the chat view.'), T('Record 3 appended: the deletion notice is retained alongside both observed versions.')],
    ];
    let step = 0;
    let timer;
    let playing = false;
    const render = () => {
      lab.dataset.step = String(step);
      lab.querySelector('[data-chat-message]').textContent = states[step][0];
      lab.querySelector('[data-chat-note]').textContent = states[step][1];
      lab.querySelector('[data-journey-status]').textContent = states[step][2];
      lab.querySelector('[data-record-count]').textContent = [T('0 records'), T('1 record'), T('2 records'), T('3 records')][step];
      lab.querySelector('[data-step-label]').textContent = step === 3 ? T('Complete / {n} of 3', {n:step}) : T('Step / {n} of 3', {n:step});
      lab.querySelectorAll('[data-event]').forEach(row => {
        const pending = Number(row.dataset.event) > step;
        row.classList.toggle('is-pending', pending);
        row.setAttribute('aria-hidden', String(pending));
      });
      play.textContent = playing ? T('Pause') : step === 3 ? T('Replay sequence') : T('Play sequence');
      next.disabled = step === 3;
      lab.classList.toggle('is-playing', playing);
    };
    const stop = () => { clearTimeout(timer); playing = false; render(); };
    const advance = () => {
      step = Math.min(step + 1, 3);
      if (step === 3) playing = false;
      render();
      if (playing) timer = setTimeout(advance, 1600);
    };
    play.addEventListener('click', () => {
      if (playing) { stop(); return; }
      if (motion.matches) { step = 3; render(); return; }
      if (step === 3) step = 0;
      playing = true;
      advance();
    });
    next.addEventListener('click', () => { stop(); advance(); });
    lab.querySelector('[data-reset]').addEventListener('click', () => { stop(); step = 0; render(); });
    document.addEventListener('visibilitychange', () => { if (document.hidden) stop(); });
    window.addEventListener('pagehide', stop);
    motion.addEventListener('change', stop);
    if ('IntersectionObserver' in window) {
      new IntersectionObserver(entries => { if (!entries[0].isIntersecting && playing) stop(); }).observe(lab);
    }
    showControls(lab);
    render();
  }



  const canonical = value => {
    if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
    if (value !== null && typeof value === 'object') {
      return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
    }
    return JSON.stringify(value);
  };
  const digest = async value => {
    const bytes = new TextEncoder().encode(canonical(value));
    return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), byte => byte.toString(16).padStart(2, '0')).join('');
  };
  const clone = value => JSON.parse(JSON.stringify(value));

  async function hashChain(lab) {
    const status = lab.querySelector('[data-hash-status]');
    if (!globalThis.crypto?.subtle) {
      status.textContent = T('The static example is available. To calculate hashes interactively, open this page over HTTPS or a localhost preview with Web Crypto support.');
      return;
    }
    const records = [
      {seq:1, observed_at:'2026-01-01T10:00:00.000+00:00', source_at:'2026-01-01T10:00:00+00:00', kind:'message.new', chat_id:-100123, message_id:42, actor_id:7, payload:{text:'Meet at 10:00'}, previous_hash:'0'.repeat(64)},
      {seq:2, observed_at:'2026-01-01T10:01:00.000+00:00', source_at:'2026-01-01T10:01:00+00:00', kind:'message.edited', chat_id:-100123, message_id:42, actor_id:null, payload:{text:'Meet at 11:00'}, previous_hash:''},
      {seq:3, observed_at:'2026-01-01T10:02:00.000+00:00', source_at:null, kind:'message.deleted', chat_id:-100123, message_id:42, actor_id:null, payload:{message_ids:[42]}, previous_hash:''},
    ];
    const saved = [];
    for (const event of records) {
      if (saved.length) event.previous_hash = saved.at(-1);
      saved.push(await digest(event));
    }
    const retained = lab.querySelector('[data-retained-head]');
    retained.textContent = saved[2].slice(0, 14) + '…';
    retained.title = saved[2];
    let revision = 0;
    const render = async mode => {
      const current = ++revision;
      const events = clone(records);
      const stored = [...saved];
      if (mode === 'edited' || mode === 'rebuilt') events[1].payload.text = 'Meet at 19:00';
      if (mode === 'truncated') { events.pop(); stored.pop(); }
      if (mode === 'rebuilt') {
        for (let i = 1; i < events.length; i++) {
          events[i].previous_hash = stored[i - 1];
          stored[i] = await digest(events[i]);
        }
      }
      const calculated = await Promise.all(events.map(digest));
      if (current !== revision) return;
      pressed(lab, 'data-hash-mode', mode);
      lab.dataset.hashMode = mode;
      lab.dataset.state = mode === 'original' ? 'ok' : 'error';
      lab.querySelector('[data-hash-text]').textContent = events[1].payload.text;
      lab.querySelectorAll('[data-hash-node]').forEach((node, index) => {
        const removed = index >= events.length;
        const matches = calculated[index] === stored[index];
        node.classList.toggle('is-removed', removed);
        node.classList.toggle('is-broken', !removed && !matches);
        node.classList.toggle('is-rebuilt', mode === 'rebuilt' && index > 0);
        const hash = node.querySelector('[data-hash-value]');
        hash.textContent = removed ? T('No record supplied') : calculated[index].slice(0, 14) + '…';
        hash.title = removed ? '' : calculated[index];
        node.querySelector('.hash-verdict').textContent = removed ? T('Tail removed') : !matches ? T('≠ saved hash') : mode === 'rebuilt' && index > 0 ? T('Rebuilt · different hash') : T('= saved hash');
      });
      const explanations = {
        original:[T('Same length and matching head.'), T('All three computed hashes match the saved hashes. This sample agrees with the retained three-record boundary.')],
        edited:[T('Same saved head; the journal prefix fails verification.'), T('Record 2 no longer matches its saved hash. Checking only the final stored head would miss this; the verifier checks every record.')],
        rebuilt:[T('Head differs from the retained checkpoint.'), T('The rebuilt hashes link together, but the final head has changed. The retained checkpoint rejects this history. Original signatures would also fail on changed records.')],
        truncated:[T('Too short: 2 supplied records < 3 retained records.'), T('The two remaining hashes still match. The retained checkpoint reveals the missing tail. Without that earlier boundary, this shorter prefix alone would not reveal the omission.')],
      };
      lab.querySelector('[data-boundary-verdict]').textContent = explanations[mode][0];
      status.textContent = explanations[mode][1];
      lab.querySelector('[data-canonical]').textContent = canonical(events[1]);
      lab.querySelector('[data-stored-digest]').textContent = stored[1];
      lab.querySelector('[data-calculated-digest]').textContent = calculated[1];
      lab.querySelector('[data-hash-detail]').hidden = false;
    };
    const failed = () => {
      status.textContent = T('Hash calculation is unavailable in this browser. The formulas and static explanation below remain available.');
      lab.querySelectorAll('[data-hash-mode]').forEach(button => { button.disabled = true; });
    };
    lab.querySelectorAll('[data-hash-mode]').forEach(button => {
      button.addEventListener('click', () => { render(button.dataset.hashMode).catch(failed); });
    });
    await render('original');
    showControls(lab);
  }

  function witness(lab) {
    const answers = {
      ok:[T('{n} records', {n:128}), T('head {hash}', {hash:'a4f2…'}), T('Accepted: the count grows, the signature verifies and the key matches. The witness retains this new boundary.')],
      rollback:[T('{n} records', {n:112}), T('head {hash}', {hash:'65be…'}), T('Rollback: the signed answer reports fewer records than the last accepted checkpoint. The witness records the problem and keeps the earlier accepted boundary.')],
      fork:[T('{n} records', {n:120}), T('head {hash}', {hash:'b8e1…'}), T('Fork: the count is unchanged but the head differs. The witness records the disagreement and keeps the earlier accepted boundary.')],
      offline:[T('No answer'), T('boundary unknown'), T('No response: the witness records the failed check. It cannot assert the collector’s current state. If the witness can still reach the Bot API and its publication policy permits, it can publish that failure.')],
    };
    lab.querySelectorAll('[data-witness-mode]').forEach(button => {
      button.addEventListener('click', () => {
        const mode = button.dataset.witnessMode;
        pressed(lab, 'data-witness-mode', mode);
        lab.dataset.state = mode === 'ok' ? 'ok' : mode === 'offline' ? 'warning' : 'error';
        lab.querySelector('[data-witness-count]').textContent = answers[mode][0];
        lab.querySelector('[data-witness-head]').textContent = answers[mode][1];
        lab.querySelector('[data-witness-status]').textContent = answers[mode][2];
      });
    });
    showControls(lab);
  }

  function delivery(lab) {
    const actions = [T('Send {n}', {n:1}), T('Edit {n}', {n:1}), T('Delete {n}', {n:1}), T('Send {n}', {n:2}), T('Edit {n}', {n:2}), T('Delete {n}', {n:2})];
    const a = [0.6, 0.8, 1.2, 0.7, 0.9, 1.4];
    const scenarios = {
      complete:[1.0, 1.2, 1.6, 0.9, 1.3, 1.8],
      delayed:[1.0, 1.2, 1.6, 6.8, 7.4, 1.8],
      missing:[1.0, 1.2, 1.6, 0.9, null, 1.8],
    };
    const notes = {
      complete:T('Both accounts captured all six expected observations in this example.'),
      delayed:T('Account B still captured 6 of 6. Two receipts took longer. Capture ratio and receipt delay answer different questions.'),
      missing:T('Account B captured 5 of 6 by the cutoff (83.3%). The missing edit has no measured delay. This result only describes the six controlled actions.'),
    };
    const svg = (tag, attrs) => {
      const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
      Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, value));
      return node;
    };
    const render = mode => {
      const b = scenarios[mode];
      pressed(lab, 'data-delivery-mode', mode);
      lab.dataset.state = mode === 'missing' ? 'error' : mode === 'delayed' ? 'warning' : 'ok';
      const group = lab.querySelector('[data-chart-points]');
      group.replaceChildren();
      [a, b].forEach((values, series) => {
        values.forEach((value, index) => {
          const x = 87 + index * 91 + (series ? 6 : -6);
          const y = value === null ? 244 : 244 - value * 27.5;
          const color = series ? 'point-b' : 'point-a';
          if (value !== null) group.append(svg('line', {x1:x, x2:x, y1:244, y2:y, class:'chart-stem ' + color}));
          const point = value === null
            ? svg('path', {d:`M${x-5} ${y-5}l10 10m0-10l-10 10`, class:'point-missing'})
            : series ? svg('path', {d:`M${x} ${y-6}l6 6-6 6-6-6z`, class:color})
              : svg('circle', {cx:x, cy:y, r:5, class:color});
          const title = svg('title', {});
          title.textContent = `${series ? 'B' : 'A'} · ${actions[index]} · ${value === null ? T('not observed by cutoff') : T('{s} seconds', {s:value.toFixed(1)})}`;
          point.append(title);
          group.append(point);
          if (!motion.matches) point.animate([{opacity:0}, {opacity:1}], {duration:220, easing:'ease-out'});
        });
      });
      const observed = b.filter(value => value !== null).length;
      const rate = observed === 6 ? '100%' : (100 * observed / 6).toFixed(1) + '%';
      lab.querySelector('[data-rate-b]').textContent = `${observed} / 6 · ${rate}`;
      lab.querySelector('[data-delivery-status]').textContent = notes[mode];
      lab.querySelector('#delivery-chart-desc').textContent = notes[mode] + ' ' + T('Exact values follow in the table.');
      const table = lab.querySelector('[data-delivery-table]');
      table.replaceChildren();
      actions.forEach((action, index) => {
        const row = document.createElement('tr');
        [action, T('{s} s', {s:a[index].toFixed(1)}), b[index] === null ? T('Not observed') : T('{s} s', {s:b[index].toFixed(1)})].forEach((value, column) => {
          const cell = document.createElement(column === 0 ? 'th' : 'td');
          if (column === 0) cell.scope = 'row';
          cell.textContent = value;
          row.append(cell);
        });
        table.append(row);
      });
    };
    lab.querySelectorAll('[data-delivery-mode]').forEach(button => button.addEventListener('click', () => render(button.dataset.deliveryMode)));
    showControls(lab);
    render('complete');
  }

  function investigation(lab) {
    const views = {
      all:{sources:['channel', 'group', 'bot', 'private'], text:T('Four chats contribute different observations. Follow the source records for every connection; do not assign the channel post to user 71001 without an attributed sender.')},
      person:{sources:['group', 'private'], text:T('Records #146 and #205 supply the same sender ID, 71001. That connects a Telegram account’s observed posts across two chats. It does not identify a real-world person or attribute the channel post.')},
      link:{sources:['channel', 'group', 'bot', 'private'], text:T('The destination pay.example.invalid/new appears in group record #146, bot keyboard #173, channel edit #188 and private message #205. A repeated destination connects the material; it does not prove common control of those accounts.')},
      file:{sources:['group', 'private'], text:T('Completed media receipts #151 and #209 have equal full SHA-256 values in this fictional case. Compare the actual bytes and their associated message records. The matching file does not identify its creator or prove who forwarded it.')},
    };
    lab.querySelectorAll('[data-case-mode]').forEach(button => {
      button.addEventListener('click', () => {
        const mode = button.dataset.caseMode;
        pressed(lab, 'data-case-mode', mode);
        lab.dataset.caseView = mode;
        lab.querySelectorAll('[data-case-node]').forEach(node => {
          const active = views[mode].sources.includes(node.dataset.caseNode);
          node.classList.toggle('is-muted', !active);
          node.classList.toggle('is-linked', active);
          if (active && !motion.matches) node.animate([{borderColor:'#bad9ff'}, {borderColor:'#689cd5'}], {duration:350});
        });
        lab.querySelector('[data-case-status]').textContent = views[mode].text;
      });
    });
    showControls(lab);
    lab.dataset.caseView = 'all';
  }

  function security(lab) {
    const names = {replica:T('the encrypted off-site copy'), alerts:T('notifications'), timestamp:T('checkpoint hashes for timestamps'),
                   witness:T('signed checkpoints for the witness')};
    const on = new Set();
    const render = () => {
      lab.querySelectorAll('[data-flow-toggle]').forEach(button => button.setAttribute('aria-pressed', String(on.has(button.dataset.flowToggle))));
      lab.querySelectorAll('.route[data-flow]').forEach(route => {
        const flow = route.dataset.flow;
        if (flow === 'telegram') return;
        const active = on.has(flow);
        route.classList.toggle('is-on', active);
        route.querySelector('[data-state-label]').textContent = active ? T('Switched on in this example') : T('Optional · off by default');
      });
      lab.dataset.flows = [...on].join(' ');
      lab.querySelector('[data-security-status]').textContent = on.size
        ? T('Leaving this machine: the Telegram connection and {list}. Nothing else.', {list:[...on].map(flow => names[flow]).join(', ')})
        : T('Default: only the Telegram connection leaves this machine.');
    };
    lab.querySelectorAll('[data-flow-toggle]').forEach(button => button.addEventListener('click', () => {
      const flow = button.dataset.flowToggle;
      if (on.has(flow)) on.delete(flow); else on.add(flow);
      render();
      const route = lab.querySelector(`.route[data-flow="${flow}"]`);
      if (on.has(flow) && !motion.matches) route.animate([{transform:'translateX(-6px)', opacity:.6}, {transform:'none', opacity:1}], {duration:320, easing:'cubic-bezier(.2,.8,.2,1)'});
    }));
    showControls(lab);
    render();
  }


  function hardening(lab) {
    const items = [...lab.querySelectorAll('.checklist-items li')];
    const count = lab.querySelector('[data-checklist-count]');
    const meter = lab.querySelector('.meter i');
    const update = () => {
      const done = items.filter(item => item.classList.contains('is-done')).length;
      count.textContent = T('{done} of {total} done', {done, total:items.length});
      meter.style.width = `${Math.round(done / items.length * 100)}%`;
      lab.classList.toggle('is-complete', done === items.length);
    };
    items.forEach((item, index) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'check-toggle';
      button.setAttribute('aria-pressed', 'false');
      button.setAttribute('aria-label', T('Mark step {n} as done', {n:index + 1}));
      button.dataset.enhanced = '';
      button.addEventListener('click', () => {
        const done = !item.classList.contains('is-done');
        item.classList.toggle('is-done', done);
        button.setAttribute('aria-pressed', String(done));
        update();
      });
      item.prepend(button);
    });
    showControls(lab);
    update();
  }


  async function modesHash(lab) {
    const status = lab.querySelector('[data-hash-status]');
    if (!globalThis.crypto?.subtle) {
      status.textContent = T('modes.hash.unavailable');
      return;
    }
    const input = lab.querySelector('[data-edit-record]');
    const original = input.value;
    const records = [1, 2, 3].map(seq => ({seq, observed_at:'2026-01-01T10:00:00.000+00:00',
      source_at:null, kind:seq === 1 ? 'message.new' : seq === 2 ? 'message.edited' : 'message.deleted',
      chat_id:-100123, message_id:42, actor_id:null,
      payload:seq === 3 ? {message_ids:[42]} : {text:seq === 2 ? original : 'Meet at 10:00'}, previous_hash:'0'.repeat(64)}));
    const saved = [];
    for (const event of records) {
      if (saved.length) event.previous_hash = saved.at(-1);
      saved.push(await digest(event));
    }
    saved.forEach((hash, index) => {
      const node = lab.querySelector(`[data-digest="${index + 1}"]`);
      node.textContent = hash.slice(0, 16) + '…';
      node.title = hash;
    });
    lab.querySelector('[data-stored]').textContent = saved[1];
    let revision = 0;
    const update = async () => {
      const current = ++revision;
      const event = clone(records[1]);
      event.payload.text = input.value;
      const calculated = await digest(event);
      if (current !== revision) return;
      const broken = calculated !== saved[1];
      lab.dataset.state = broken ? 'error' : 'ok';
      lab.querySelector('[data-calculated]').textContent = calculated;
      const node = lab.querySelector('[data-digest="2"]');
      node.textContent = calculated.slice(0, 16) + '…';
      node.title = calculated;
      status.textContent = T(broken ? 'modes.hash.changed' : 'modes.hash.ok');
    };
    input.addEventListener('input', () => update().catch(() => {
      status.textContent = T('modes.hash.unavailable');
    }));
    await update();
    showControls(lab);
  }

  const setups = {journey, hash:hashChain, witness, delivery, investigation, security, hardening, modesHash};
  document.querySelectorAll('[data-lab]').forEach(lab => {
    Promise.resolve().then(() => setups[lab.dataset.lab](lab)).catch(() => {
      lab.querySelectorAll('[data-enhanced]').forEach(node => { node.hidden = true; });
      const status = lab.querySelector('[role=status]');
      if (status) status.textContent = T(lab.dataset.lab === 'modesHash' ? 'modes.hash.unavailable' : 'Interactive controls are unavailable in this browser. The static explanation and formulas remain available.');
    });
  });
})();
