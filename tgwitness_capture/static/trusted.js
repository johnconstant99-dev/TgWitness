(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let token = '', status = null, busy = false, frameURL = '', transcriptURL = '', frameHash = '';
  let queue = Promise.resolve(), pending = 0;
  async function request(path, body) {
    const response = await fetch('/api/' + path, {method: body === undefined ? 'GET' : 'POST',
      headers: {Authorization: 'Bearer ' + token, ...(body === undefined ? {} : {'Content-Type': 'application/json'})},
      body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store', redirect: 'error'});
    if (!response.ok) {const error = await response.json().catch(() => ({})); throw new Error(typeof error.detail === 'string' ? error.detail : 'Request refused: ' + response.status);}
    return response;
  }
  function run(work) {
    pending++; busy = true;
    const action = queue.then(async () => {
      $('error').textContent = '';
      try {await work();} catch (error) {$('error').textContent = error.message;}
      finally {if (token) await refresh().catch(error => {$('error').textContent = error.message;});}
    }).finally(() => {pending--; busy = pending > 0;});
    queue = action.catch(() => {});
    return action;
  }
  async function refresh() {
    status = await (await request('status')).json();
    $('login').hidden = true; $('workspace').hidden = false;
    const phase = status.phase.replaceAll('_', ' ');
    $('phase').textContent = phase.charAt(0).toUpperCase() + phase.slice(1);
    $('health').textContent = status.last_error || (status.video_running ? 'Procedure video is recording.' : 'Procedure video is stopped.');
    $('fingerprint').textContent = 'Recorder key SHA-256: ' + status.fingerprint;
    $('anchor').textContent = status.external_anchor;
    $('limits').replaceChildren(...status.limits.map(value => {const li = document.createElement('li'); li.textContent = value; return li;}));
    if (!$('connector').options.length) for (const [id, connector] of Object.entries(status.connectors)) {
      $('connector').add(new Option(connector.label + ' · ' + connector.mode, id));
    }
    const live = status.phase === 'collecting', manual = ['setup', 'paused'].includes(status.phase);
    $('choices').hidden = status.phase !== 'configured';
    $('screen-section').hidden = !live && !manual;
    $('manual').hidden = !manual;
    $('screen-mode').textContent = live ? 'Capture guard: scroll only. Keyboard and clicks are blocked.' : 'Manual setup: input is enabled. These screen frames are not preserved.';
    $('start').disabled = !manual; $('pause').disabled = !live;
    $('up').disabled = $('down').disabled = !live || status.choice?.method === 'export';
    $('annotation').hidden = !status.choice || status.choice.method === 'export';
    $('export-section').hidden = !status.choice || status.choice.method === 'visual';
    $('import').disabled = !['collecting', 'paused'].includes(status.phase);
    $('stop').disabled = !live && !manual;
    $('finish').disabled = ['configured', 'completed', 'archived'].includes(status.phase);
    $('download').disabled = !['paused', 'completed', 'failed', 'cleanup_pending', 'archived'].includes(status.phase);
    const events = await (await request('events')).json();
    $('events').replaceChildren(...events.slice(-15).reverse().map(event => {const li = document.createElement('li'); li.textContent = '#' + event.seq + ' · ' + event.kind + ' · ' + event.observed_at; return li;}));
  }
  async function frame() {
    const response = await request('frame');
    frameHash = response.headers.get('X-Frame-SHA256');
    if (frameURL) URL.revokeObjectURL(frameURL);
    frameURL = URL.createObjectURL(await response.blob()); $('screen').src = frameURL;
    $('frame-hash').textContent = 'Frame SHA-256: ' + frameHash;
  }
  async function transcript() {
    const report = await (await request('continuity')).json();
    if (!report) return;
    $('analysis-status').textContent = report.messages + ' exported messages · ' + report.findings.length + ' observations. ' +
      (report.visual_comparison === 'operator_annotated' ? 'Compared with operator frame annotations.' : 'No frame annotations to compare.');
    if (transcriptURL) URL.revokeObjectURL(transcriptURL);
    transcriptURL = URL.createObjectURL(await (await request('transcript')).blob());
    $('transcript').src = transcriptURL; $('transcript').hidden = false;
  }
  async function download(path, filename, body) {
    const response = await request(path, body), url = URL.createObjectURL(await response.blob());
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = filename; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }
  $('login-form').addEventListener('submit', event => {event.preventDefault(); token = $('token').value.trim(); $('token').value = ''; void run(refresh);});
  $('client').addEventListener('change', () => {
    const web = $('client').value === 'web';
    for (const option of $('method').options) option.disabled = web && option.value !== 'visual';
    if (web) $('method').value = 'visual';
  });
  $('begin-form').addEventListener('submit', event => {event.preventDefault(); void run(async () => {
    await request('begin', {case: $('case').value, client: $('client').value, method: $('method').value, connector: $('connector').value});
  });});
  for (const action of ['start', 'pause', 'finish']) $(action).addEventListener('click', () => void run(() => request(action, {})));
  // The kill switch is never suppressed by an in-flight UI request.
  $('stop').addEventListener('click', () => {void request('stop', {}).then(refresh).catch(error => {$('error').textContent = error.message;});});
  $('frame').addEventListener('click', () => void run(frame));
  for (const direction of ['up', 'down']) $(direction).addEventListener('click', () => void run(async () => {await request('scroll', {direction}); await frame();}));
  $('screen').addEventListener('click', event => {
    if (!['setup', 'paused'].includes(status?.phase)) return;
    const rect = event.currentTarget.getBoundingClientRect();
    const x = Math.min(1279, Math.max(0, Math.floor((event.clientX - rect.left) * 1280 / rect.width)));
    const y = Math.min(719, Math.max(0, Math.floor((event.clientY - rect.top) * 720 / rect.height)));
    void run(async () => {await request('input', {action: 'click', x, y}); await frame();});
  });
  $('input-form').addEventListener('submit', event => {event.preventDefault(); const text = $('client-text').value; $('client-text').value = ''; void run(async () => {await request('input', {action: 'text', text}); await frame();});});
  for (const button of $('keys').querySelectorAll('button')) button.addEventListener('click', () => void run(async () => {await request('input', {action: 'key', key: button.dataset.key}); await frame();}));
  $('find-exports').addEventListener('click', () => void run(async () => {
    const files = await (await request('exports')).json(); $('exports').replaceChildren(...files.map(name => new Option(name, name)));
    if (!files.length) $('analysis-status').textContent = 'No result.json found in /exports.';
  }));
  $('import').addEventListener('click', () => void run(async () => {await request('import', {name: $('exports').value}); await transcript();}));
  $('annotation-form').addEventListener('submit', event => {event.preventDefault(); void run(async () => {
    const chat = Number($('chat-id').value), message = Number($('message-id').value);
    if (!Number.isSafeInteger(chat) || !Number.isSafeInteger(message)) throw new Error('IDs must be safe integers.');
    await request('annotate', {chat_id: chat, message_id: message, text: $('message-text').value, frame_sha256: frameHash}); await transcript();
  });});
  $('checkpoint').addEventListener('click', () => void run(() => download('checkpoint', 'trusted-checkpoint.json')));
  $('download').addEventListener('click', () => void run(() => download('export', 'trusted-live.zip', {})));
  // No background input or auto-scrolling. Status polling contains no client interaction.
  setInterval(() => {if (token && !busy) void run(async () => {});}, 10000);
  setInterval(() => {if (token && !busy && ['setup', 'paused', 'collecting'].includes(status?.phase)) void run(frame);}, 4000);
})();
