'use strict';

(() => {
  const dictionary = (() => {
    try { return JSON.parse(document.getElementById('site-dict')?.textContent || '{}'); }
    catch { return {}; }
  })();
  const T = (source, values) => (dictionary[source] || source).replace(/\{(\w+)\}/g,
    (match, key) => key in values ? values[key] : match);
  const motion = matchMedia('(prefers-reduced-motion: reduce)');

  function enhance(lab) {
    const steps = [...lab.querySelectorAll('[data-workflow-step]')];
    const nodes = [...lab.querySelectorAll('[data-workflow-node]')];
    const controls = lab.querySelector('[data-workflow-controls]');
    const play = lab.querySelector('[data-workflow-play]');
    const next = lab.querySelector('[data-workflow-next]');
    const reset = lab.querySelector('[data-workflow-reset]');
    const status = lab.querySelector('[data-workflow-status]');
    const progress = lab.querySelector('[data-workflow-progress]');
    if (!steps.length || !controls || !play || !next || !reset || !status || !progress) return;

    let step = 0, playing = false, timer;
    const groups = [...lab.querySelectorAll('[data-workflow-choices]')];
    const select = (group, value) => {
      const choices = [...group.querySelectorAll('[data-workflow-choice]')];
      if (!choices.some(button => button.dataset.workflowChoice === value)) return;
      for (const button of choices) button.setAttribute('aria-pressed', String(button.dataset.workflowChoice === value));
      const kind = group.dataset.workflowChoices;
      lab.dataset['workflow' + kind[0].toUpperCase() + kind.slice(1)] = value;
      if (kind === 'design') {
        lab.querySelectorAll('[data-workflow-design]').forEach(node => { node.dataset.workflowDesign = value; });
      } else {
        const attribute = kind === 'identity' ? 'data-workflow-identity-value' : 'data-workflow-content';
        lab.querySelectorAll(`[${attribute}]`).forEach(node => { node.hidden = node.getAttribute(attribute) !== value; });
      }
    };
    const render = () => {
      lab.dataset.step = String(step);
      lab.dataset.playing = String(playing);
      for (const [index, item] of steps.entries()) {
        if (index === step) item.setAttribute('aria-current', 'step');
        else item.removeAttribute('aria-current');
        item.classList.toggle('is-complete', index < step);
      }
      for (const node of nodes) {
        const index = Number(node.dataset.workflowNode);
        node.classList.toggle('is-current', index === step);
        node.classList.toggle('is-complete', index < step);
      }
      const explanation = steps[step].textContent.replace(/\s+/g, ' ').trim();
      if (status.textContent !== explanation) status.textContent = explanation;
      progress.textContent = T('Step {n} of {total}', {n: step + 1, total: steps.length});
      play.querySelector('[data-workflow-play-label]').hidden = playing;
      play.querySelector('[data-workflow-pause-label]').hidden = !playing;
      next.disabled = step === steps.length - 1;
    };
    const stop = () => {
      clearTimeout(timer);
      playing = false;
      render();
    };
    const advance = () => {
      step = Math.min(step + 1, steps.length - 1);
      if (step === steps.length - 1) playing = false;
      render();
      if (playing) timer = setTimeout(advance, 2400);
    };
    play.addEventListener('click', () => {
      if (playing) { stop(); return; }
      lab.dataset.workflowInteracted = 'true';
      if (step === steps.length - 1) step = 0;
      playing = true;
      render();
      timer = setTimeout(advance, 2400);
    });
    next.addEventListener('click', () => {
      lab.dataset.workflowInteracted = 'true';
      stop();
      advance();
    });
    reset.addEventListener('click', () => {
      stop();
      step = 0;
      for (const group of groups) select(group, group.querySelector('[data-workflow-choice]').dataset.workflowChoice);
      render();
    });
    for (const group of groups) {
      const choices = [...group.querySelectorAll('[data-workflow-choice]')];
      if (!choices.length) continue;
      choices.forEach(button => button.addEventListener('click', () => {
        stop();
        step = 1;
        lab.dataset.workflowInteracted = 'true';
        select(group, button.dataset.workflowChoice);
        render();
      }));
      select(group, choices[0].dataset.workflowChoice);
      group.hidden = false;
    }
    document.addEventListener('visibilitychange', () => { if (document.hidden) stop(); });
    window.addEventListener('pagehide', stop);
    motion.addEventListener('change', stop);
    if ('IntersectionObserver' in window) {
      new IntersectionObserver(entries => {
        if (!entries[0].isIntersecting && playing) stop();
      }).observe(lab);
    }
    lab.classList.add('is-enhanced');
    render();
    controls.hidden = false;
  }
  document.querySelectorAll('[data-workflow]').forEach(enhance);
})();
