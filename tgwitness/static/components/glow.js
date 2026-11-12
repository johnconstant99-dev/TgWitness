const TARGETS = ".pulse-kpi, .workflow-card, .home-account, .hub-summary, .export-task-choices button, .report-design, .report-template, .answer-card, .accounts-total, .login-card";

export function createGlow({root = document} = {}) {
  const still = () => window.tgwReducedMotion?.() ?? matchMedia("(prefers-reduced-motion: reduce)").matches;
  let last = null, frame = 0, point = null;

  function apply() {
    frame = 0;
    if (!point) return;
    const target = point.target.closest?.(TARGETS);
    if (last && last !== target) { last.classList.remove("glow-on"); last = null; }
    if (!target) return;
    const box = target.getBoundingClientRect();
    target.style.setProperty("--glow-x", point.x - box.left + "px");
    target.style.setProperty("--glow-y", point.y - box.top + "px");
    target.classList.add("glow-on");
    last = target;
  }

  root.addEventListener("pointermove", event => {
    if (event.pointerType === "touch" || still()) return;
    point = {target: event.target, x: event.clientX, y: event.clientY};
    if (!frame) frame = requestAnimationFrame(apply);
  }, {passive: true});
  root.addEventListener("pointerleave", () => { if (last) { last.classList.remove("glow-on"); last = null; } point = null; });
}
