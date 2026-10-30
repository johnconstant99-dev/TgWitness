'use strict';

// Translations for this page's language, embedded by the site build; English is the key and the fallback.
const DICT = (() => { try { return JSON.parse(document.getElementById('site-dict')?.textContent || '{}'); } catch { return {}; } })();
const T = (text, values = {}) => (DICT[text] || text).replace(/\{(\w+)\}/g, (match, key) => key in values ? values[key] : match);

// Search reads one static file of this site (this language's search.json): no queries leave the browser.
const searchBox = document.querySelector('.search');
const searchInput = document.querySelector('#guide-search');
const searchResults = document.querySelector('#search-results');
const searchStatus = document.querySelector('.search-status');
const clearSearch = document.querySelector('.search-clear');
const normalize = value => value.normalize('NFKC').toLocaleLowerCase(document.documentElement.lang || 'en');
const indexUrl = new URL(searchBox.dataset.index, location.href);
let catalog = {labels:{prompt:searchStatus.textContent, results:'', empty:''}, pages:[]};
let entries = [];
const loading = fetch(indexUrl).then(response => response.ok ? response.json() : Promise.reject(response.status)).then(index => {
  catalog = index;
  entries = index.pages.map(page => ({...page, url:new URL(page.url, indexUrl).href,
    normalized:normalize([page.title, page.description, page.keywords, page.text].join(' '))}));
  if (searchInput.value) search();
});

function search() {
  const terms = normalize(searchInput.value.slice(0, 160)).trim().split(/\s+/).filter(Boolean);
  searchResults.replaceChildren();
  clearSearch.hidden = !searchInput.value;
  searchResults.hidden = !terms.length;
  if (!terms.length) { searchStatus.textContent = catalog.labels.prompt; return; }
  const matches = entries.filter(page => terms.every(term => page.normalized.includes(term)));
  matches.sort((a,b) => terms.filter(term => normalize(b.title + ' ' + b.keywords).includes(term)).length - terms.filter(term => normalize(a.title + ' ' + a.keywords).includes(term)).length);
  searchStatus.textContent = matches.length ? catalog.labels.results + ' ' + matches.length : catalog.labels.empty;
  searchResults.hidden = !matches.length;
  matches.forEach(page => {
    const link = document.createElement('a');
    link.className = 'search-result';
    link.href = page.url;
    const title = document.createElement('strong');
    const description = document.createElement('span');
    title.textContent = page.title;
    description.textContent = page.description;
    link.append(title, description);
    searchResults.append(link);
  });
}
loading.then(() => { searchBox.hidden = false; }).catch(() => { searchBox.hidden = true; });
searchInput.maxLength = 160;
searchInput.addEventListener('input', search);
clearSearch.addEventListener('click', () => { searchInput.value = ''; search(); searchInput.focus(); });
searchInput.addEventListener('keydown', event => {
  if (event.key === 'Escape') { searchInput.value = ''; search(); }
  if (event.key === 'ArrowDown' && searchResults.firstElementChild) { event.preventDefault(); searchResults.firstElementChild.focus(); }
});
// "/" or Ctrl/Cmd+K jumps to search from anywhere outside a text field.
document.addEventListener('keydown', event => {
  const typing = event.target.closest('input, textarea, [contenteditable]');
  if ((event.key === '/' && !typing && !event.ctrlKey && !event.metaKey && !event.altKey)
      || (event.key.toLowerCase() === 'k' && (event.ctrlKey || event.metaKey))) {
    event.preventDefault();
    searchInput.focus();
    searchInput.select();
  }
});

// On a phone the reference groups start folded so the page itself comes first.
if (matchMedia('(max-width: 800px)').matches) document.querySelectorAll('.wiki-group[open]').forEach(group => { group.open = false; });

const motion = matchMedia('(prefers-reduced-motion: reduce)');
const observe = 'IntersectionObserver' in window;

// Reading progress along the top edge.
const progress = document.querySelector('.read-progress span');
if (progress) {
  let queued = false;
  const update = () => {
    queued = false;
    const room = document.documentElement.scrollHeight - innerHeight;
    progress.style.transform = `scaleX(${room > 0 ? Math.min(1, scrollY / room) : 0})`;
  };
  addEventListener('scroll', () => { if (!queued) { queued = true; requestAnimationFrame(update); } }, {passive:true});
  addEventListener('resize', update);
  update();
}

// The section being read is marked in "On this page".
const tocLinks = [...document.querySelectorAll('.toc a[href^="#"]')];
if (observe && tocLinks.length) {
  const sections = tocLinks.map(link => document.getElementById(decodeURIComponent(link.hash.slice(1)))).filter(Boolean);
  const mark = id => tocLinks.forEach(link => link.classList.toggle('is-active', link.hash.slice(1) === id));
  const spy = new IntersectionObserver(() => {
    const passed = sections.filter(section => section.getBoundingClientRect().top < innerHeight * .3);
    mark((passed[passed.length - 1] || sections[0]).id);
  }, {rootMargin:'0px 0px -60% 0px', threshold:[0, 1]});
  sections.forEach(section => spy.observe(section));
}

// Content below the first screen eases in as it is reached; nothing is hidden without this script.
if (observe && !motion.matches) {
  const blocks = document.querySelectorAll('.guide-content > :is(h2, .guide-grid, .lab, figure, .table-wrap, .threat-grid, .checklist, .fact-strip, .wiki-index), .wiki-body > :is(h2, .flow-figure, .table-wrap, pre)');
  const reveal = new IntersectionObserver(entries => entries.forEach(entry => {
    if (!entry.isIntersecting) return;
    entry.target.classList.add('is-revealed');
    reveal.unobserve(entry.target);
  }), {rootMargin:'0px 0px -8% 0px'});
  blocks.forEach(block => {
    if (block.getBoundingClientRect().top > innerHeight) {
      block.classList.add('will-reveal');
      reveal.observe(block);
    }
  });
}

// Diagrams draw themselves when they come into view; a dot then runs along each connection.
document.querySelectorAll('[data-diagram]').forEach(figure => {
  const svg = figure.querySelector('svg');
  const pulses = [...figure.querySelectorAll('animateMotion')];
  if (!observe || motion.matches) return;
  figure.classList.add('will-draw');
  let started = false;
  new IntersectionObserver(entries => {
    const visible = entries[0].isIntersecting;
    if (visible && !started) {
      started = true;
      figure.classList.add('is-drawn');
      setTimeout(() => {
        figure.classList.add('is-live');
        pulses.forEach(pulse => { try { pulse.beginElement(); } catch { /* SMIL unavailable */ } });
      }, 1300);
    } else if (started && svg.pauseAnimations) {
      if (visible) svg.unpauseAnimations(); else svg.pauseAnimations();
    }
  }, {threshold:.25}).observe(figure);
});

const copyLabel = T('Copy');
const copyStatus = document.createElement('p');
copyStatus.className = 'search-status';
copyStatus.setAttribute('role', 'status');
document.querySelector('.guide-footer').prepend(copyStatus);
document.querySelectorAll('pre').forEach(pre => {
  const code = pre.querySelector('code');
  if (!code) return;
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'copy-control';
  button.textContent = copyLabel;
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(code.textContent);
      button.textContent = T('Copied');
      copyStatus.textContent = T('Command copied.');
    } catch {
      const range = document.createRange();
      range.selectNodeContents(code);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      button.textContent = T('Selected — Ctrl/Cmd+C');
      copyStatus.textContent = T('Command selected. Copy it manually.');
    }
    setTimeout(() => { button.textContent = copyLabel; }, 2500);
  });
  pre.append(button);
});

// Light or dark: the system's choice until the reader picks one; kept in this browser only.
const themeToggle = document.querySelector('[data-theme-toggle]');
if (themeToggle) {
  const sync = () => themeToggle.setAttribute('aria-pressed', String(document.documentElement.dataset.theme === 'dark'));
  themeToggle.hidden = false;
  sync();
  themeToggle.addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.classList.add('theme-changing');
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('tgw-theme', next); } catch { /* private mode */ }
    sync();
    setTimeout(() => document.documentElement.classList.remove('theme-changing'), 400);
  });
}
// The language list closes on Escape or a click elsewhere.
const languageMenu = document.querySelector('.lang-menu');
if (languageMenu) {
  document.addEventListener('click', event => { if (!languageMenu.contains(event.target)) languageMenu.open = false; });
  languageMenu.addEventListener('keydown', event => {
    if (event.key === 'Escape') { languageMenu.open = false; languageMenu.querySelector('summary').focus(); }
  });
}
