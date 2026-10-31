import {createHealthActions} from "./health-actions.js";
export function createHealthBar({node, icon, tr, stateNames, partNames, lines, diagnose, canDiagnose, workspace, actionContext}) {
  const names = ["connection", "intake", "sources", "media"];
  const labels = {connection: tr("Telegram"), intake: tr("Intake"), sources: tr("Sources"), media: tr("Attachments")};
  const bar = node("div", "health-toolbar"); bar.setAttribute("aria-label", tr("Collector health"));
  const dialog = node("dialog", "health-dialog"); dialog.id = "health-dialog"; dialog.setAttribute("aria-labelledby", "health-title");
  const head = node("div", "health-dialog-head"), title = node("h2", "", tr("Collector health")); title.id = "health-title";
  const close = node("button", "quiet"); close.type = "button"; close.title = tr("Close"); close.setAttribute("aria-label", tr("Close"));
  close.append(icon("x")); head.append(title, close);
  const tabs = node("div", "health-part-tabs"); tabs.setAttribute("role", "tablist"); tabs.setAttribute("aria-label", tr("Collector health"));
  const content = node("div", "health-part-body"); content.id = "health-strip";
  dialog.append(head, tabs, content); document.body.append(dialog);
  workspace.querySelector(".health-details")?.remove(); workspace.querySelector(".topbar").after(bar);
  const chips = new Map(), panels = new Map(), buttons = new Map();
  let selected = null, latest = null, identity = null;
  function state(part) { return Object.hasOwn(stateNames, part?.state) ? part.state : "unknown"; }
  function setSelected(name) {
    if (!panels.has(name)) return;
    selected = name;
    for (const id of names) {
      panels.get(id).root.hidden = id !== name;
      buttons.get(id).setAttribute("aria-selected", String(id === name));
      buttons.get(id).tabIndex = id === name ? 0 : -1;
    }
  }
  function open(name) {
    if (!latest || workspace.hidden || workspace.inert) return;
    setSelected(name);
    if (!dialog.open) dialog.showModal();
    buttons.get(name).focus();
  }
  for (const name of names) {
    const chip = node("button", "health-chip"); chip.type = "button";
    chip.dataset.healthPart = name; chip.setAttribute("aria-haspopup", "dialog"); chip.setAttribute("aria-controls", dialog.id);
    const mark = node("span", "health-chip-mark"), label = node("span", "health-chip-label", labels[name]);
    const value = node("span", "health-chip-value"); chip.append(mark, label, value); chip.addEventListener("click", () => open(name));
    bar.append(chip); chips.set(name, {root: chip, mark, value});
    const tab = node("button", "quiet", labels[name]); tab.type = "button"; tab.id = "health-tab-" + name;
    tab.setAttribute("role", "tab"); tab.setAttribute("aria-controls", "health-part-" + name);
    tab.addEventListener("click", () => setSelected(name)); tabs.append(tab); buttons.set(name, tab);
    const panel = node("section", "health-part"), panelTitle = node("h3", "", partNames[name]);
    panel.id = "health-part-" + name; panel.setAttribute("role", "tabpanel"); panel.setAttribute("aria-labelledby", tab.id);
    const badge = node("span", "health-part-status"), facts = node("div", "health-facts"), actions = node("div", "health-actions");
    const diagnostic = node("button", "secondary", tr("Diagnostics")); diagnostic.type = "button";
    diagnostic.addEventListener("click", () => { dialog.close(); diagnose(name); }); actions.append(diagnostic);
    panel.append(panelTitle, badge, facts, actions); content.append(panel);
    panels.set(name, {root: panel, badge, facts, actions, diagnostic});
  }
  tabs.addEventListener("keydown", event => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const offset = event.key === "ArrowRight" ? 1 : -1;
    const index = event.key === "Home" ? 0 : event.key === "End" ? names.length - 1
      : (names.indexOf(selected) + offset + names.length) % names.length;
    setSelected(names[index]); buttons.get(names[index]).focus();
  });
  close.addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", event => {
    if (event.target !== dialog) return;
    const rect = dialog.getBoundingClientRect();
    if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) dialog.close();
  });
  function hide() { if (dialog.open) dialog.close(); selected = null; }
  window.addEventListener("tgwitness:route", hide);
  window.addEventListener("tgwitness:lock", hide);
  new MutationObserver(() => { if (workspace.hidden || workspace.inert) hide(); }).observe(workspace, {attributes: true, attributeFilter: ["hidden", "inert"]});
  const controller = {update, open, close: hide, actions: name => panels.get(name)?.actions};
  const actions = actionContext ? createHealthActions({node,tr,health:controller,close:hide,context:actionContext}) : null;
  function update(health, {profile, demo = false} = {}) {
    if (profile !== identity) { hide(); identity = profile; }
    latest = health; bar.hidden = demo || !health;
    if (!health) { hide(); return; }
    for (const name of names) {
      const part = health[name] || {}, key = state(part), caption = stateNames[key][0];
      const chip = chips.get(name), panel = panels.get(name), facts = lines(name, part).filter(Boolean);
      if (chip.root.dataset.state !== key) {
        chip.root.dataset.state = key; chip.mark.replaceChildren(icon(stateNames[key][1]));
      }
      const count = name === "sources" ? part.counts?.unconfirmed : name === "media" ? part.counts?.pending : 0;
      const value = count > 0 ? String(count) : caption;
      if (chip.value.textContent !== value) chip.value.textContent = value;
      chip.root.title = partNames[name] + " · " + caption + (facts[0] ? "\n" + facts[0] : "");
      chip.root.setAttribute("aria-label", chip.root.title);
      panel.badge.dataset.state = key; panel.badge.textContent = caption;
      while (panel.facts.childElementCount > facts.length) panel.facts.lastElementChild.remove();
      facts.forEach((text, index) => {
        let paragraph = panel.facts.children[index];
        if (!paragraph) { paragraph = node("p"); panel.facts.append(paragraph); }
        if (paragraph.textContent !== text) paragraph.textContent = text;
      });
      panel.diagnostic.hidden = !canDiagnose(name);
    }
    actions?.update();
  }
  return controller;
}
