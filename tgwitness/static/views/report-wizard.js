const STEPS = [["data", "Data", "sources"], ["design", "Report design", "sparkle"], ["contents", "Contents", "layers"],
  ["details", "Case details", "edit"], ["check", "Check", "shield"]];

export function createReportWizard({form, node, tr, icon}) {
  const pick = selector => form.querySelector(selector);
  const fields = pick("#report-fields"), stage = pick(".studio-stage"), controls = pick(".studio-controls"), layout = pick(".studio-layout");
  if (!fields || !stage || !controls || !layout || pick(".studio-shell")) return null;
  const panes = new Map(STEPS.map(([id]) => {
    const pane = node("section", "studio-pane");
    pane.dataset.pane = id; pane.hidden = true;
    return [id, pane];
  }));
  const shell = node("div", "studio-shell"), main = node("div", "studio-main"), rail = node("ol", "studio-rail");
  const buttons = new Map();
  let current = "";

  STEPS.forEach(([id, label, glyph], index) => {
    const item = node("li"), button = node("button", "studio-step"), dot = node("span", "studio-step-dot");
    button.type = "button"; button.dataset.step = id;
    dot.append(icon(glyph), icon("check"));
    button.append(dot, node("span", "studio-step-name", tr(label)));
    button.setAttribute("aria-label", tr("Step {n}", {n: index + 1}) + ": " + tr(label));
    button.addEventListener("click", () => go(id));
    item.append(button); rail.append(item); buttons.set(id, button);
  });

  const always = node("div", "studio-always"), chips = node("ul", "studio-always-list");
  for (const [label, glyph] of [["In brief", "report"], ["Basis of trust", "shield"], ["Coverage", "activity"], ["Anomaly indicators", "alert"],
    ["Timestamps", "clock"], ["Chain of custody", "link"], ["Standards and methodology", "layers"], ["Reading this record", "help"],
    ["Verification", "check"], ["Digital signature", "fingerprint"]]) {
    const chip = node("li");
    chip.append(icon(glyph), node("span", "", tr(label)), icon("lock"));
    chips.append(chip);
  }
  always.append(node("strong", "", tr("Always included")), chips);

  panes.get("data").append(pick("#report-data"));
  panes.get("design").append(pick(".report-designs"));
  panes.get("contents").append(always, pick(".report-templates"), pick(".report-outline"));
  const sections = [...controls.querySelectorAll(":scope > .studio-section")];
  for (const child of [...controls.children]) {
    const contents = child === sections[0] || child.matches(".report-parts, .studio-fixed");
    panes.get(contents ? "contents" : "details").append(child);
  }
  const charts = sections[0]?.querySelector(":scope > legend"), details = sections[1]?.querySelector(":scope > legend");
  if (charts) charts.textContent = tr("Charts");
  if (details) details.classList.add("visually-hidden");
  const fixed = panes.get("contents").querySelector(".studio-fixed");
  if (fixed) always.append(fixed);
  const profiles = pick("#report-profiles");
  if (profiles) panes.get("details").append(profiles);
  panes.get("check").append(pick("#report-preview"));

  const actions = node("div", "studio-nav"), back = node("button", "secondary"), next = node("button", "secondary studio-next"), finish = node("button", "primary");
  back.type = next.type = finish.type = "button";
  back.append(icon("chevron"), node("span", "", tr("Back")));
  next.append(node("span", "", tr("Next")), icon("chevron"));
  finish.append(icon("download"), node("span", "", tr("Go to downloads")));
  back.addEventListener("click", () => step(-1));
  next.addEventListener("click", () => step(1));
  finish.addEventListener("click", () => form.querySelector("#report-open-downloads")?.click());
  actions.append(back, next, finish);
  const save = pick(".studio-save");
  for (const old of [pick(".report-steps"), pick("#report-content"), layout]) if (old) old.hidden = true;
  fields.before(shell);
  fields.prepend(...panes.values());
  main.append(rail, fields, actions);
  if (save) main.append(save);
  shell.append(main, stage);

  function step(offset) {
    const index = STEPS.findIndex(([id]) => id === current) + offset;
    if (index >= 0 && index < STEPS.length) go(STEPS[index][0], {focus: true});
  }

  function go(id, {focus = false} = {}) {
    if (!panes.has(id) || id === current) return;
    const from = STEPS.findIndex(([name]) => name === current), to = STEPS.findIndex(([name]) => name === id);
    current = id;
    buttons.get(id).classList.add("seen");
    for (const [name, pane] of panes) {
      pane.hidden = name !== id;
      if (name === id) pane.dataset.direction = from < 0 ? "none" : to > from ? "forward" : "back";
    }
    STEPS.forEach(([name], index) => {
      const button = buttons.get(name);
      button.classList.toggle("done", index < to);
      if (index === to) button.setAttribute("aria-current", "step"); else button.removeAttribute("aria-current");
    });
    rail.dataset.progress = to;
    back.hidden = to === 0; next.hidden = finish.hidden = to === STEPS.length - 1; finish.hidden = !next.hidden;
    shell.dataset.step = id;
    if (focus) {
      if (shell.getBoundingClientRect().top < 0) shell.scrollIntoView({block: "start"});
      (panes.get(id).querySelector("input:not([type=hidden]):not(:disabled), select:not(:disabled), textarea:not(:disabled), button:not(:disabled)")
        || buttons.get(id)).focus({preventScroll: true});
    }
  }

  form.addEventListener("keydown", event => {
    if (event.key !== "Enter" || event.isComposing || !event.target.matches("input:not([type=file]), select")) return;
    event.preventDefault();
    if (event.target.id === "report-profile-name") form.querySelector("#report-profile-save")?.click();
  });

  function reveal(element) {
    const pane = element?.closest?.(".studio-pane");
    if (pane) go(pane.dataset.pane);
  }

  function revealInvalid() {
    reveal([...form.querySelectorAll(":invalid")].find(control => control.closest(".studio-pane") && !control.matches("fieldset")));
  }

  let submitting = false;
  const attempt = () => { submitting = true; setTimeout(() => { submitting = false; }, 0); };
  form.addEventListener("click", event => { if (event.target.closest?.("button[type=submit]")) attempt(); }, true);
  document.addEventListener("keydown", event => { if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") attempt(); }, true);
  form.addEventListener("invalid", event => { if (submitting) { submitting = false; reveal(event.target); } }, true);
  go("data");
  return {go, reveal, revealInvalid};
}
