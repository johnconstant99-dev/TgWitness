(() => {
  'use strict';
  const assetBase = new URL(document.querySelector('.export-clinic').dataset.assets, document.baseURI);
  const asset = path => new URL(path, assetBase).href;
  const downloadBase = new URL(document.querySelector('.export-clinic').dataset.downloads, document.baseURI);
  const download = path => new URL(path, downloadBase).href;
  const data = JSON.parse(document.getElementById('comparison-data').textContent);
  const video = document.getElementById('demo-video');
  const source = document.getElementById('video-source');
  const chapters = [...document.querySelectorAll('[data-chapter]')];
  const clock = seconds => `${Math.floor(seconds / 60)}:${String(Math.floor(seconds % 60)).padStart(2, '0')}`;
  let mode = 'short';
  function seek(time, play = true) {
    const apply = () => { video.currentTime = time; if (play) video.play().catch(() => {}); };
    if (video.readyState >= 1) apply();
    else { video.addEventListener('loadedmetadata', apply, {once:true}); video.preload = 'metadata'; video.load(); }
  }
  document.querySelectorAll('[data-version]').forEach(button => button.addEventListener('click', () => {
    const next = button.dataset.version;
    if (next === mode) return;
    video.pause(); mode = next;
    source.src = download(mode === 'short' ? 'export-clinic-2min.mp4' : 'export-clinic-full.mp4');
    video.preload = 'metadata';
    video.load();
    document.querySelectorAll('[data-version]').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
    document.getElementById('film-version-caption').textContent = mode === 'short'
      ? '1:59.7 · Setup and repeated steps are accelerated ×2–×15 and labeled. Sign-in, the first export and selected comparisons run at their original speed. No audio.'
      : '6:08.8 source duration · Complete recording with no time edits. This MP4 is a container conversion without video re-encoding. Original MKV available below.';
    chapters.forEach(chapter => chapter.querySelector('.chapter-time').textContent = clock(Number(chapter.dataset[mode])));
  }));
  chapters.forEach(button => button.addEventListener('click', () => seek(Number(button.dataset[mode]))));
  document.querySelectorAll('[data-play-film]').forEach(button => button.addEventListener('click', () => {
    document.getElementById('film').scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth'});
    video.play().catch(() => {});
  }));

  const byId = id => document.getElementById(id);
  let active = data.cases.find(item => item.id === 'bot');
  let sample = 0;
  function message(container, text) {
    container.replaceChildren();
    const lines = text.split('\n');
    lines.forEach((line, index) => {
      if (/^RESULT: (FAIL|PASS)$/.test(line)) { const mark = document.createElement('mark'); mark.textContent = line; container.append(mark); }
      else container.append(document.createTextNode(line));
      if (index < lines.length - 1) container.append(document.createTextNode('\n'));
    });
  }
  function renderCase() {
    const item = active.differences[sample];
    byId('case-name').textContent = active.chat_name;
    byId('case-count').textContent = `${active.message_count} messages · ${active.changed_messages} changed`;
    message(byId('before-message'), item.before_text);
    message(byId('modified-message'), item.modified_text);
    byId('message-reference').textContent = `result.json · message ${item.message_id} · ${item.date.replace('T', ' ')}`;
    byId('before-hash').textContent = active.json_before_sha256.slice(0, 16) + '…';
    byId('modified-hash').textContent = active.json_modified_sha256.slice(0, 16) + '…';
    byId('before-copy').dataset.hash = active.json_before_sha256;
    byId('modified-copy').dataset.hash = active.json_modified_sha256;
    byId('sample-position').textContent = `Changed message ${sample + 1} of ${active.differences.length}`;
    byId('sample-previous').disabled = sample === 0;
    byId('sample-next').disabled = sample === active.differences.length - 1;
    document.querySelectorAll('[data-case]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.case === active.id)));
    byId('image-comparison').hidden = !active.image_pair;
    byId('no-media').hidden = Boolean(active.image_pair);
    if (active.image_pair) {
      byId('before-image').src = asset(active.image_pair.before);
      byId('modified-image').src = asset(active.image_pair.modified);
      byId('before-image').alt = `Retained image before local modification, ${active.label}`;
      byId('modified-image').alt = `Deliberately substituted image, ${active.label}`;
      byId('image-filename').textContent = active.image_pair.file;
    }
  }
  document.querySelectorAll('[data-case]').forEach(button => button.addEventListener('click', () => {
    active = data.cases.find(item => item.id === button.dataset.case); sample = 0; renderCase();
  }));
  byId('sample-previous').addEventListener('click', () => { if (sample > 0) { sample--; renderCase(); } });
  byId('sample-next').addEventListener('click', () => { if (sample < active.differences.length - 1) { sample++; renderCase(); } });
  document.querySelectorAll('[data-hash]').forEach(button => button.addEventListener('click', async () => {
    try {
      if (!navigator.clipboard) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(button.dataset.hash);
      const toast = byId('copy-notice'); toast.hidden = false; setTimeout(() => { toast.hidden = true; }, 1800);
    } catch { button.textContent = button.dataset.hash; button.style.overflowWrap = 'anywhere'; }
  }));
  renderCase();
})();
