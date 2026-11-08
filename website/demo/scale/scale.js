'use strict';
(() => {
  const $ = id => document.getElementById(id), number = value => new Intl.NumberFormat('en-US').format(value);
  const hex = bytes => Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
  const decode = value => Uint8Array.from(atob(value), char => char.charCodeAt(0));
  const encoder = new TextEncoder();
  const snapshot = location.protocol === 'file:' || new URLSearchParams(location.search).get('snapshot') === '1';
  let run = null, checkedIdentity = '', checking = false, selectedIndex = 0, replayTimer = null, playing = false, replayStart = 0, replayElapsed = 0;
  const motion = matchMedia('(prefers-reduced-motion: reduce)');
  const identity = value => JSON.stringify(value);
  const count = value => Number.isSafeInteger(value) && value >= 0;
  const digestText = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
  const canonical = value => value === null || typeof value !== 'object' ? JSON.stringify(value) : Array.isArray(value) ? '[' + value.map(canonical).join(',') + ']' : '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  const duration = seconds => [Math.floor(seconds / 3600), Math.floor(seconds / 60) % 60, Math.floor(seconds) % 60].map(v => String(v).padStart(2, '0')).join(':');
  const stateClass = state => state === 'collecting' ? 'collecting' : state === 'complete' ? 'complete' : state === 'partial_verified' ? 'partial' : ['exporting', 'verifying', 'waiting_for_verification'].includes(state) ? 'exporting' : ['failed', 'rate_limited', 'paused', 'disk_limit'].includes(state) ? 'failed' : '';
  function error(message) { $('error').textContent = message; $('error').hidden = false; }
  function intervalRate(index) {
    if (index < 1) return null;
    const current = run.timeline[index].statement, previous = run.timeline[index - 1].statement;
    const seconds = current.elapsed_seconds - previous.elapsed_seconds;
    return seconds > 0 ? Math.max(0, (current.messages - previous.messages) / seconds) : null;
  }
  function chartX(index) {
    const first = run.timeline[0].statement.elapsed_seconds, last = run.timeline.at(-1).statement.elapsed_seconds;
    return 700 * (run.timeline[index].statement.elapsed_seconds - first) / Math.max(.001, last - first);
  }
  function playbackControls() {
    const available = Boolean(run && run.timeline.length > 1);
    $('replay').textContent = playing ? 'Pause replay' : selectedIndex === (run?.timeline.length || 1) - 1 ? 'Replay run' : 'Play from here';
    $('replay').disabled = !available || motion.matches;
    $('playback-speed').disabled = !available || motion.matches;
    $('replay-state').textContent = motion.matches ? 'Reduced motion · use the timeline to inspect samples' : playing ? 'Recorded replay · playing' : 'Recorded timeline · paused';
  }
  function pauseReplay() {
    clearTimeout(replayTimer); replayTimer = null; playing = false; playbackControls();
  }
  function renderMoment() {
    const selected = run.timeline[selectedIndex], current = selected.statement;
    $('messages').textContent = number(current.messages);
    $('events').textContent = number(current.events);
    $('duplicates').textContent = 'Duplicates excluded: ' + number(current.duplicate_records);
    $('rate').textContent = current.elapsed_seconds > 0 ? number(Number((current.messages / current.elapsed_seconds).toFixed(1))) : '—';
    $('elapsed').textContent = duration(current.elapsed_seconds);
    $('head').textContent = selected.hash;
    $('previous-head').textContent = current.previous_hash;
    $('hash-label').textContent = 'RECEIPT ' + current.seq + ' / ' + run.timeline.length + ' · SHA-256';
    $('copy').textContent = 'Copy full hash ↗';
    $('copy-previous').textContent = 'Copy previous hash ↗';
    $('sample-time').textContent = new Date(current.observed_at).toLocaleString('en-GB', {timeZone:'UTC', hour12:false}) + ' UTC';
    const rate = intervalRate(selectedIndex);
    $('interval-rate').textContent = rate === null ? 'No preceding interval' : number(Number(rate.toFixed(1))) + ' msg/s · selected interval';
    $('timeline').value = selectedIndex;
    $('timeline').setAttribute('aria-valuetext', 'Receipt ' + current.seq + ' of ' + run.timeline.length + ', elapsed ' + duration(current.elapsed_seconds) + ', ' + number(current.messages) + ' messages');
    $('timeline-position').textContent = duration(current.elapsed_seconds) + ' / ' + duration(run.timeline.at(-1).statement.elapsed_seconds);
    $('latest').disabled = selectedIndex === run.timeline.length - 1;
    $('chart-cursor').setAttribute('d', 'M' + chartX(selectedIndex).toFixed(2) + ' 0V125');
    $('worker-summary').textContent = current.workers.filter(w => w.verified).length + ' / ' + current.workers.length + ' archives verified · selected sample';
    const workers = document.createDocumentFragment();
    for (const row of current.workers) {
      const box = document.createElement('div'), top = document.createElement('div'), title = document.createElement('span'), dot = document.createElement('i'), total = document.createElement('strong'), status = document.createElement('small');
      box.className = 'worker'; top.className = 'worker-top'; title.textContent = row.alias; dot.className = stateClass(row.state);
      total.textContent = number(row.messages); status.textContent = row.state.replaceAll('_', ' ');
      top.append(title, dot); box.append(top, total, status); workers.append(box);
    }
    $('workers').replaceChildren(workers);
    playbackControls();
  }
  function seek(index) {
    pauseReplay(); selectedIndex = Math.max(0, Math.min(run.timeline.length - 1, index)); renderMoment();
  }
  function replayTick() {
    if (!playing) return;
    const elapsed = replayElapsed + (performance.now() - replayStart) / 1000 * Number($('playback-speed').value);
    let next = selectedIndex;
    while (next + 1 < run.timeline.length && run.timeline[next + 1].statement.elapsed_seconds <= elapsed) next++;
    if (next !== selectedIndex) { selectedIndex = next; renderMoment(); }
    if (next === run.timeline.length - 1) { pauseReplay(); return; }
    replayTimer = setTimeout(replayTick, 50);
  }
  async function copyHash(value, button) {
    try { await navigator.clipboard.writeText(value); button.textContent = 'Hash copied'; }
    catch { error('Copy the full hash displayed beside this button; clipboard access is unavailable.'); }
  }
  function render(value) {
    if (value?.format !== 'tgwitness-scale-demo-v1' || !Array.isArray(value.timeline) || !value.timeline.length) throw new Error('No valid measurement receipts are available.');
    if (window.TGWITNESS_SAMPLES) value.samples_receipt = window.TGWITNESS_SAMPLES;
    if (window.TGWITNESS_CAMPAIGN) value.campaign_receipt = window.TGWITNESS_CAMPAIGN;
    const previous = run;
    const atLatest = !run || !playing && selectedIndex === run.timeline.length - 1;
    if (run && (run.public_key !== value.public_key || run.timeline[selectedIndex]?.hash !== value.timeline[selectedIndex]?.hash)) pauseReplay();
    run = value;
    selectedIndex = atLatest ? run.timeline.length - 1 : Math.min(selectedIndex, run.timeline.length - 1);
    const last = run.timeline.at(-1), current = last.statement;
    if (!Number.isSafeInteger(current.messages) || current.messages < 0 || !Array.isArray(current.workers)) throw new Error('Invalid measurement counters.');
    const verified = current.workers.filter(w => w.verified).length;
    const stale = Date.now() - Date.parse(current.observed_at) > 45000;
    $('run-state').textContent = current.finished ? verified === current.workers.length ? 'Recorded run · verified archives' : 'Run stopped · review required' : snapshot ? 'Recorded snapshot · run still active' : stale ? 'Last recorded measurement · stale' : 'Live private test';
    $('receipt-summary').textContent = number(run.timeline.length) + ' signed receipts · ' + run.transport + ' route · attachments excluded';
    const campaign = run.campaign_receipt?.statement;
    $('campaign').hidden = !campaign;
    $('source-scope').textContent = 'PUBLIC BROADCASTS';
    if (campaign) {
      const displayed = campaign.runs.find(row => row.receipt.statement.receipt_chain_head === last.hash);
      if (displayed) $('source-scope').textContent = 'DETAIL · ' + displayed.id;
      $('campaign-messages').textContent = number(campaign.messages) + ' messages';
      $('campaign-detail').textContent = campaign.runs.length + ' runs · ' + number(campaign.overlapping_records) + ' overlapping records';
      const rows = document.createDocumentFragment();
      for (const row of campaign.runs) {
        const item = row.receipt.statement, tr = document.createElement('tr');
        for (const value of [row.id + (item.all_ranges_complete ? '' : ' · partial'), number(item.messages), duration(item.elapsed_seconds), number(Number((item.messages / item.elapsed_seconds).toFixed(1)))]) {
          const td = document.createElement('td'); td.textContent = value; tr.append(td);
        }
        rows.append(tr);
      }
      $('campaign-runs').replaceChildren(rows);
    }
    const selected = run.samples_receipt?.statement?.samples;
    $('excerpts').hidden = !Array.isArray(selected) || !selected.length;
    if (Array.isArray(selected) && identity(previous?.samples_receipt) !== identity(run.samples_receipt)) {
      const cards = document.createDocumentFragment();
      for (const sample of selected) {
        const card = document.createElement('article'), quote = document.createElement('blockquote'), label = document.createElement('div'), digest = document.createElement('code'), copy = document.createElement('button');
        quote.textContent = sample.excerpt + '…';
        label.className = 'hash-label'; label.textContent = 'ORIGINAL EVENT · SHA-256';
        digest.textContent = sample.original_event_hash;
        copy.className = 'copy'; copy.textContent = 'Copy event hash ↗'; copy.addEventListener('click', () => copyHash(sample.original_event_hash, copy));
        card.append(quote, label, digest, copy); cards.append(card);
      }
      $('excerpt-grid').replaceChildren(cards);
    }
    const rates = run.timeline.map((item, i) => intervalRate(i)), maximum = Math.max(1, ...rates.filter(v => v !== null));
    const points = rates.flatMap((rate, i) => rate === null ? [] : [[chartX(i), 112 - 100 * rate / maximum]]);
    const line = points.map((p, i) => (i ? 'L' : 'M') + p.map(v => v.toFixed(2)).join(' ')).join(' ');
    $('chart-line').setAttribute('d', line);
    $('chart-area').setAttribute('d', points.length ? line + ' L' + points.at(-1)[0].toFixed(2) + ' 125 L' + points[0][0].toFixed(2) + ' 125 Z' : '');
    $('chart-label').textContent = 'Peak interval · ' + number(Number(Math.max(0, ...rates).toFixed(1))) + ' msg/s';
    $('timeline').max = run.timeline.length - 1; $('timeline').disabled = run.timeline.length < 2;
    renderMoment();
    for (const id of ['copy', 'copy-previous', 'verify', 'download']) $(id).disabled = false;
    if (checkedIdentity !== identity(run)) { $('verify-state').textContent = 'Latest receipt not checked'; $('verify-light').className = 'status-light'; $('campaign-verification').textContent = 'Combined totals not checked'; }
  }
  async function verifyEnvelope(item, expectedKey) {
    if (!item || typeof item.statement_json !== 'string' || item.public_key !== expectedKey || !digestText(item.sha256)) throw new Error('Invalid summary signing identity.');
    const statement = JSON.parse(item.statement_json), bytes = encoder.encode(item.statement_json);
    const key = await crypto.subtle.importKey('raw', decode(expectedKey), {name:'Ed25519'}, false, ['verify']);
    if (canonical(statement) !== canonical(item.statement) || hex(await crypto.subtle.digest('SHA-256', bytes)) !== item.sha256 || !await crypto.subtle.verify({name:'Ed25519'}, key, decode(item.signature), bytes)) throw new Error('Summary content or signature does not match.');
    return statement;
  }
  async function verifyCampaign(value, head) {
    const summary = await verifyEnvelope(value.campaign_receipt, value.public_key);
    if (summary.format !== 'tgwitness-scale-summary-v1' || !count(summary.messages) || !count(summary.events) || summary.overlapping_records !== 0 || summary.disjoint_ranges_verified !== true || summary.recount_verified !== true || !Array.isArray(summary.runs) || !summary.runs.length || summary.runs.length > 16) throw new Error('Invalid combined measurement.');
    const ids = new Set(), receipts = new Set();
    let messages = 0, events = 0, archives = 0, primary = 0;
    for (const entry of summary.runs) {
      if (typeof entry.id !== 'string' || !entry.id || ids.has(entry.id) || receipts.has(entry.receipt?.sha256)) throw new Error('A run is counted more than once.');
      ids.add(entry.id); receipts.add(entry.receipt?.sha256);
      const result = await verifyEnvelope(entry.receipt, entry.receipt?.public_key);
      if (result.format !== 'tgwitness-scale-final-v1' || !count(result.messages) || !count(result.events) || result.duplicates !== 0 || !Number.isFinite(result.elapsed_seconds) || result.elapsed_seconds <= 0 || result.all_archives_verified !== true || typeof result.all_ranges_complete !== 'boolean' || result.disjoint_ranges_verified !== true || result.recount_verified !== true || !digestText(result.receipt_chain_head) || !Array.isArray(result.workers) || !result.workers.length || result.workers.length > 128) throw new Error('A run has no complete verification receipt.');
      if (new Set(result.workers.map(w => w.alias)).size !== result.workers.length) throw new Error('A worker is counted more than once.');
      for (const worker of result.workers) {
        if (!count(worker.messages) || !count(worker.events) || worker.journal_verified !== true || worker.checkpoint_verified !== true || worker.archive_verified !== true || typeof worker.range_complete !== 'boolean' || !digestText(worker.archive_sha256)) throw new Error('Incomplete worker verification.');
      }
      if (result.all_ranges_complete !== result.workers.every(w => w.range_complete)) throw new Error('Range completion differs from its workers.');
      if (result.workers.reduce((sum, w) => sum + w.messages, 0) !== result.messages || result.workers.reduce((sum, w) => sum + w.events, 0) !== result.events) throw new Error('Final run counters do not match its workers.');
      if (entry.receipt.public_key === value.public_key && result.receipt_chain_head === head) {
        const last = value.timeline.at(-1).statement;
        if (!last.finished || last.messages !== result.messages || last.events !== result.events || last.elapsed_seconds !== result.elapsed_seconds) throw new Error('Final measurement differs from its receipt chain.');
        primary++;
      }
      messages += result.messages; events += result.events; archives += result.workers.length;
    }
    if (primary !== 1 || !count(messages) || !count(events) || summary.messages !== messages || summary.events !== events || summary.verified_archives !== archives) throw new Error('Combined totals do not match the verified runs.');
  }
  async function verify(value) {
    if (!globalThis.crypto?.subtle) throw new Error('Cryptographic checks require a browser with Web Crypto support.');
    if (value?.format !== 'tgwitness-scale-demo-v1' || !Array.isArray(value.timeline) || !value.timeline.length || value.timeline.length > 10000) throw new Error('Invalid receipt collection.');
    const key = await crypto.subtle.importKey('raw', decode(value.public_key), {name:'Ed25519'}, false, ['verify']);
    const workerKeys = new Map(), lastWorkers = new Map();
    let previous = '0'.repeat(64), seq = 0, messages = 0, elapsed = -1;
    for (const item of value.timeline) {
      const statement = JSON.parse(item.statement_json);
      if (canonical(statement) !== canonical(item.statement)) throw new Error('Receipt display differs from signed data.');
      const bytes = encoder.encode(item.statement_json);
      if (statement.format !== 'tgwitness-scale-progress-v1' || !count(statement.messages) || !count(statement.events) || !count(statement.duplicate_records) || !Number.isFinite(statement.elapsed_seconds) || statement.seq !== ++seq || statement.previous_hash !== previous || statement.messages < messages || statement.elapsed_seconds < Math.max(0, elapsed)) throw new Error('Receipt sequence or counters are inconsistent.');
      if (!Array.isArray(statement.workers) || !statement.workers.length || statement.workers.length > 128 || new Set(statement.workers.map(w => w.alias)).size !== statement.workers.length) throw new Error('Invalid worker identities.');
      if (statement.messages !== statement.workers.reduce((sum, w) => sum + w.messages, 0)) throw new Error('Worker totals do not match the headline.');
      if (statement.events !== statement.workers.reduce((sum, w) => sum + w.events, 0) || statement.duplicate_records !== statement.workers.reduce((sum, w) => sum + w.duplicate_records, 0)) throw new Error('Worker event totals do not match.');
      const digest = hex(await crypto.subtle.digest('SHA-256', bytes));
      if (digest !== item.hash || !await crypto.subtle.verify({name:'Ed25519'}, key, decode(item.signature), bytes)) throw new Error('Receipt hash or signature does not match.');
      for (const worker of statement.workers) {
        const old = lastWorkers.get(worker.alias);
        if (!count(worker.messages) || !count(worker.events) || !count(worker.duplicate_records) || !digestText(worker.head_hash) || old && (worker.messages < old.messages || worker.events < old.events)) throw new Error('Worker counters are inconsistent.');
        const point = worker.checkpoint;
        if (point) {
          const anchor = point.statement;
          if (anchor?.format !== 'tgwitness-checkpoint-v1' || !count(anchor.event_count) || anchor.event_count < worker.events || !digestText(anchor.head_hash)) throw new Error('Invalid journal checkpoint.');
          const existing = workerKeys.get(worker.alias);
          if (existing && existing.publicKey !== anchor.public_key) throw new Error('Worker signing identity changed.');
          let pinned = existing;
          if (!pinned) {
            const raw = decode(anchor.public_key);
            pinned = {publicKey:anchor.public_key, fingerprint:hex(await crypto.subtle.digest('SHA-256',raw)), key:await crypto.subtle.importKey('raw',raw,{name:'Ed25519'},false,['verify'])};
            workerKeys.set(worker.alias,pinned);
          }
          if (point.fingerprint !== pinned.fingerprint || !await crypto.subtle.verify({name:'Ed25519'},pinned.key,decode(point.signature),encoder.encode(canonical(anchor)))) throw new Error('Journal checkpoint signature does not match.');
          if (pinned.count !== undefined && (anchor.event_count < pinned.count || anchor.event_count === pinned.count && anchor.head_hash !== pinned.hash)) throw new Error('Journal checkpoint continuity changed.');
          pinned.count = anchor.event_count; pinned.hash = anchor.head_hash;
          if (anchor.event_count === worker.events && anchor.head_hash !== worker.head_hash) throw new Error('Worker head differs from its checkpoint.');
        }
        lastWorkers.set(worker.alias, worker);
      }
      previous = digest; messages = statement.messages; elapsed = statement.elapsed_seconds;
    }
    if (value.samples_receipt) {
      const item = value.samples_receipt, bytes = encoder.encode(item.statement_json), statement = JSON.parse(item.statement_json);
      if (item.public_key !== value.public_key || canonical(statement) !== canonical(item.statement) || statement.run_started_at !== value.timeline[0].statement.started_at || !await crypto.subtle.verify({name:'Ed25519'}, key, decode(item.signature), bytes)) throw new Error('Excerpt receipt does not match this run or signature.');
    }
    if (value.campaign_receipt) await verifyCampaign(value, previous);
    return previous;
  }
  $('verify').addEventListener('click', async () => {
    if (!run || checking) return;
    checking = true; $('verify').disabled = true; $('verify-state').textContent = 'Checking hashes and signatures…';
    const selected = run;
    try { await verify(selected); checkedIdentity = identity(selected); $('verify-state').textContent = checkedIdentity === identity(run) ? 'Receipts and checkpoints verified' : 'Earlier receipts verified; a newer receipt arrived'; $('campaign-verification').textContent = checkedIdentity === identity(run) && run.campaign_receipt ? 'Summary signatures and totals verified' : 'Combined totals not checked'; $('verify-light').className = 'status-light good'; $('error').hidden = true; }
    catch (e) { checkedIdentity = ''; $('verify-state').textContent = 'Verification failed'; $('campaign-verification').textContent = 'Combined totals not verified'; $('verify-light').className = 'status-light bad'; error(e.message); }
    finally { checking = false; $('verify').disabled = false; }
  });
  $('copy').addEventListener('click', () => copyHash(run.timeline[selectedIndex].hash, $('copy')));
  $('copy-previous').addEventListener('click', () => copyHash(run.timeline[selectedIndex].statement.previous_hash, $('copy-previous')));
  $('timeline').addEventListener('input', event => seek(Number(event.target.value)));
  $('latest').addEventListener('click', () => seek(run.timeline.length - 1));
  $('chart').addEventListener('click', event => {
    if (!run) return;
    const bounds = $('chart').getBoundingClientRect(), position = 700 * (event.clientX - bounds.left) / bounds.width;
    let nearest = 0;
    for (let i = 1; i < run.timeline.length; i++) if (Math.abs(chartX(i) - position) < Math.abs(chartX(nearest) - position)) nearest = i;
    seek(nearest);
  });
  $('replay').addEventListener('click', () => {
    if (playing) { pauseReplay(); return; }
    if (!run || run.timeline.length < 2 || motion.matches) return;
    if (selectedIndex === run.timeline.length - 1) selectedIndex = 0;
    replayElapsed = run.timeline[selectedIndex].statement.elapsed_seconds; replayStart = performance.now(); playing = true; renderMoment(); replayTick();
  });
  $('playback-speed').addEventListener('change', pauseReplay);
  motion.addEventListener('change', pauseReplay);
  document.addEventListener('visibilitychange', () => { if (document.hidden) pauseReplay(); });
  $('download').addEventListener('click', () => { const url = URL.createObjectURL(new Blob([JSON.stringify(run, null, 2)], {type:'application/json'})), link = document.createElement('a'); link.href = url; link.download = 'tgwitness-public-receipts.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); });
  $('theme').addEventListener('click', () => { document.documentElement.dataset.theme = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light'; });
  if (matchMedia('(prefers-color-scheme: light)').matches) document.documentElement.dataset.theme = 'light';
  if (window.TGWITNESS_RUN) { try { render(window.TGWITNESS_RUN); } catch (e) { error(e.message); } }
  async function refresh() {
    if (snapshot || !['http:', 'https:'].includes(location.protocol)) return;
    try { const response = await fetch('run.json', {cache:'no-store', credentials:'omit'}); if (!response.ok) throw new Error('Measurements could not be loaded.'); render(await response.json()); }
    catch (e) { error(e.message); if (run && !run.timeline.at(-1).statement.finished) $('run-state').textContent = 'Last recorded measurement · disconnected'; }
  }
  refresh(); setInterval(refresh, 10000);
  window.TgWitnessScale = Object.freeze({verify});
})();
