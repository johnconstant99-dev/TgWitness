(() => {
  const root = document.querySelector('.validation');
  if (!root) return;
  const controls = root.querySelector('.v-switch');
  const rates = [...root.querySelectorAll('[data-rate]')];
  const maximum = Math.max(1, ...rates.flatMap(el => [Number(el.dataset.acquisition), Number(el.dataset.endToEnd)]));
  for (const button of controls.querySelectorAll('button')) {
    button.addEventListener('click', () => {
      const metric = button.dataset.metric;
      for (const option of controls.querySelectorAll('button')) option.setAttribute('aria-pressed', String(option === button));
      for (const element of rates) {
        const rate = Number(element.getAttribute('data-' + metric));
        element.textContent = rate.toFixed(3);
        root.querySelector('[data-bar="' + element.dataset.rate + '"]').style.width = (rate / maximum * 100) + '%';
      }
      for (const note of root.querySelectorAll('[data-metric-note]')) note.hidden = note.dataset.metricNote !== metric;
    });
  }
  controls.hidden = false;
})();
