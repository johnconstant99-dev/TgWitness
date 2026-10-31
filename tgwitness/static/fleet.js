(() => {
  "use strict";
  // Account groups with shared settings, and importing many accounts into their own workspaces.
  let groups = [], sections = [], picked = [], importing = false;
  const editable = () => !!state.me?.admin && !state.status?.demo;
  const SECTIONS = {parameters: "Parameters", reports: "Report settings", capture: "Capture and monitoring",
                    recheck: "Recheck schedule", route: "IP protection mode"};
  const labelOf = id => (state.profiles || []).find(p => p.id === id)?.label || id;

  async function load() {
    if (!state.status) return;
    const revision = state.workspaceRevision;
    try {
      const result = await json("profile-groups", undefined, {root: true});
      groups = result.groups; sections = result.sections;
    } catch { if (revision !== state.workspaceRevision) return; groups = []; }
    fillSelects(); decorate();
  }

  function fillSelects() {
    const add = $("account-add-group"), target = $("fleet-group");
    const previous = [add.value, target.value];
    add.replaceChildren(new Option(tr("No group"), ""));
    target.replaceChildren(new Option(tr("A new group"), "__new"), new Option(tr("No group"), ""));
    for (const group of groups) { add.append(new Option(group.label, group.id)); target.append(new Option(group.label, group.id)); }
    add.value = [...add.options].some(o => o.value === previous[0]) ? previous[0] : "";
    target.value = [...target.options].some(o => o.value === previous[1]) ? previous[1] : (groups.length ? groups[0].id : "__new");
    $("fleet-group-name").closest("div").hidden = target.value !== "__new";
  }

  function groupSelect(profileId, current) {
    const select = node("select", "fleet-card-group");
    select.setAttribute("aria-label", tr("Group"));
    select.append(new Option(tr("No group"), ""));
    for (const group of groups) select.append(new Option(group.label, group.id));
    select.value = current || "";
    select.disabled = !editable();
    select.addEventListener("change", () => busy(null, async () => {
      const result = await json("profiles/" + encodeURIComponent(profileId) + "/group", {group: select.value || null},
                               {root: true, method: "PUT"});
      groups = result.groups; decorate();
      toast(tr("Workspace moved."));
    }));
    return select;
  }

  function settingsPanel(group) {
    const panel = node("details", "fleet-group-settings"), summary = node("summary", "", tr("Shared settings"));
    const body = node("div", "fleet-settings-body");
    const templateLabel = node("label", "", tr("Copy from")), template = node("select");
    template.id = "fleet-template-" + group.id; templateLabel.htmlFor = template.id;
    template.append(new Option(tr("Choose a workspace"), ""));
    for (const profile of state.profiles || []) template.append(new Option(profile.label, profile.id));
    template.value = group.template || "";
    const checks = node("div", "fleet-sections");
    for (const key of sections) {
      const row = node("label", "check-label"), box = node("input");
      box.type = "checkbox"; box.value = key; box.checked = (group.sections || []).includes(key);
      row.append(box, " " + tr(SECTIONS[key] || key)); checks.append(row);
    }
    const save = node("button", "secondary", tr("Save group settings")); save.type = "button";
    save.addEventListener("click", () => busy(save, async () => {
      const chosen = [...checks.querySelectorAll("input:checked")].map(i => i.value);
      const result = await json("profile-groups/" + group.id, {label: group.label, template: template.value || null, sections: chosen},
                               {root: true, method: "PATCH"});
      groups = result.groups; decorate();
      toast(tr("Group settings saved. Use Apply to copy them to the members."));
    }));
    body.append(templateLabel, template, node("p", "hint", tr("These settings are copied from the chosen workspace to every other member when you press Apply. Each member records what it received in its signed journal; an observing workspace keeps its IP mode until it is paused.")), checks, save);
    for (const field of body.querySelectorAll("input, select, button")) field.disabled = !editable();
    panel.append(summary, body);
    return panel;
  }

  function groupSection(group, cards) {
    const section = node("section", "fleet-group card"), head = node("div", "fleet-group-head");
    const who = node("div"), title = node("h2", "", group.label);
    title.append(node("span", "fleet-count", String(group.members.length)));
    const shares = (group.sections || []).map(key => tr(SECTIONS[key] || key));
    who.append(title, node("p", "hint", group.template && shares.length ?
      tr("Shares {list} from {name}", {list: shares.join(", "), name: labelOf(group.template)}) :
      tr("Choose what the group shares under Shared settings.")));
    const actions = node("div", "fleet-group-actions");
    const apply = node("button", "primary small", tr("Apply to members")); apply.type = "button";
    apply.disabled = !group.template || !shares.length || !group.members.some(id => id !== group.template) || !editable();
    apply.addEventListener("click", () => busy(apply, async () => {
      const result = await json("profile-groups/" + group.id + "/apply", {}, {root: true});
      groups = result.groups; decorate();
      const done = result.results.filter(r => r.status === "applied").length;
      const skipped = result.results.filter(r => (r.skipped || []).length).length;
      toast(tr("Settings copied to {n} workspaces.", {n: done}) + (skipped ? " " + tr("{n} kept their IP mode while observing.", {n: skipped}) : ""));
    }));
    const rename = node("button", "quiet small", tr("Rename")); rename.type = "button";
    rename.addEventListener("click", () => busy(rename, async () => {
      const label = (window.prompt(tr("New name for this group:"), group.label) || "").trim();
      if (!label || label === group.label) return;
      const result = await json("profile-groups/" + group.id, {label, template: group.template, sections: group.sections},
                               {root: true, method: "PATCH"});
      groups = result.groups; fillSelects(); decorate();
    }));
    const remove = node("button", "quiet small danger-text", tr("Delete group")); remove.type = "button";
    remove.addEventListener("click", () => busy(remove, async () => {
      if (!window.confirm(tr("Delete the group \"{name}\"? Its workspaces stay and lose only the grouping.", {name: group.label}))) return;
      const result = await json("profile-groups/" + group.id, undefined, {root: true, method: "DELETE"});
      groups = result.groups; fillSelects(); decorate();
    }));
    actions.append(apply, rename, remove);
    for (const button of [rename, remove]) button.disabled = !editable();
    head.append(who, actions);
    const grid = node("div", "accounts-grid");
    for (const id of group.members) if (cards.has(id)) grid.append(cards.get(id));
    if (!group.members.length) grid.append(node("p", "hint fleet-empty", tr("No workspaces in this group yet. Move one here or import accounts into it.")));
    section.append(head, settingsPanel(group), grid);
    return section;
  }

  function decorate() {
    const list = $("accounts-list"), box = $("fleet-groups");
    if (!list || !box) return;
    const cards = new Map([...document.querySelectorAll(".account-card[data-profile]")].map(card => [card.dataset.profile, card]));
    const membership = new Map(groups.flatMap(group => group.members.map(id => [id, group.id])));
    for (const [id, card] of cards) {
      card.querySelector(".fleet-card-row")?.remove();
      const row = node("div", "fleet-card-row"), label = node("span", "", tr("Group"));
      row.append(label, groupSelect(id, membership.get(id)));
      card.querySelector(".account-actions")?.before(row);
    }
    box.replaceChildren(...groups.map(group => groupSection(group, cards)));
    for (const [id, card] of cards) if (!membership.has(id)) list.append(card);
    for (const id of ["fleet-import-open", "fleet-group-new"]) $(id).disabled = !editable();
    let title = $("fleet-ungrouped");
    if (!title) { title = node("h2", "fleet-ungrouped", ""); title.id = "fleet-ungrouped"; list.before(title); }
    title.textContent = tr("Without group");
    title.hidden = !groups.length || !list.children.length;
  }

  // Bulk import ---------------------------------------------------------------------------
  function bundles(files) {
    const byName = new Map();
    for (const file of files) {
      const key = file.name.replace(/\.(session|json|zip|txt)$/i, "").toLowerCase();
      if (!byName.has(key)) byName.set(key, {name: file.name.replace(/\.(session|json|zip|txt)$/i, ""), files: []});
      byName.get(key).files.push(file);
    }
    return [...byName.values()];
  }

  function base64(buffer) {
    const bytes = new Uint8Array(buffer); let text = "";
    for (let i = 0; i < bytes.length; i += 0x8000) text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(text);
  }

  function renderPicked() {
    const list = $("fleet-results"); list.replaceChildren();
    for (const bundle of picked) {
      const item = node("li", "fleet-result waiting");
      item.append(node("strong", "", bundle.name), node("span", "hint", bundle.files.map(f => f.name).join(" + ")),
                  node("span", "fleet-state", tr("Waiting")));
      bundle.row = item; list.append(item);
    }
    $("fleet-import-start").disabled = !picked.length || !editable();
    $("fleet-import-summary").textContent = picked.length ? trn("{n} account ready to import", "{n} accounts ready to import", picked.length) : "";
  }

  function pick(files) {
    if (importing || !editable()) return;
    picked = bundles(files.filter(f => f.size <= 8 * 1024 * 1024));
    if (files.some(f => f.size > 8 * 1024 * 1024)) toast(tr("Files above 8 MiB were left out."), true);
    renderPicked();
  }

  function mark(bundle, kind, text) {
    bundle.row.className = "fleet-result " + kind;
    bundle.row.querySelector(".fleet-state").textContent = text;
  }

  async function run() {
    if (importing || !editable()) return;
    const revision = state.workspaceRevision, queue = [...picked];
    const current = () => revision === state.workspaceRevision && !!state.token;
    const pairText = $("fleet-api").value.trim();
    const pair = pairText.match(/^(\d{1,10})\s*[:\s]\s*([0-9a-fA-F]{32})$/);
    if (pairText && !pair) throw new Error(tr("Enter the API pair as ID:Hash, or leave it empty."));
    let passcode = $("fleet-passcode").value, group = $("fleet-group").value || null;
    importing = true;
    const fields = [...$("fleet-import").querySelectorAll("input, select, button")];
    fields.forEach(field => { field.disabled = true; });
    try {
      if (group === "__new") {
        const label = $("fleet-group-name").value.trim() || tr("Imported accounts");
        const result = await json("profile-groups", {label}, {root: true});
        group = result.groups[result.groups.length - 1].id; groups = result.groups;
        fillSelects(); $("fleet-group").value = group;
        $("fleet-group-name").closest("div").hidden = true;
      }
      for (const bundle of queue) {
        if (!current()) return;
        if (bundle.done) continue;
        mark(bundle, "busy", tr("Importing…"));
        try {
          if (bundle.files.length > 4 || bundle.files.reduce((n, f) => n + f.size, 0) > 8 * 1024 * 1024)
            throw new Error(tr("One account · up to 4 files · 8 MiB total"));
          const files = await Promise.all(bundle.files.map(async f => ({name: f.name, content: base64(await f.arrayBuffer())})));
          if (!current()) return;
          const body = {files, label: bundle.name.slice(0, 80), group, passcode,
                        ...(pair ? {api_id: Number(pair[1]), api_hash: pair[2].toLowerCase()} : {})};
          const result = await json("profiles/import", body, {root: true});
          const a = result.account;
          mark(bundle, "ok", (a.username ? "@" + a.username + " · " : "") + "ID " + a.id);
          bundle.done = true;
        } catch (error) {
          if (!current() || error instanceof StaleView) return;
          mark(bundle, "bad", error.message);
        }
        $("fleet-import-summary").textContent = tr("{done} of {total} imported", {
          done: queue.filter(b => b.done).length, total: queue.length});
      }
      await loadProfiles(); await load();
      if (current()) toast(tr("{n} accounts imported.", {n: queue.filter(b => b.done).length}));
    } finally {
      passcode = "";
      importing = false;
      fields.forEach(field => { field.disabled = !editable(); });
      if (current()) {
        $("fleet-passcode").value = "";
        $("fleet-import-start").disabled = !editable() || !picked.some(b => !b.done);
      }
    }
  }

  $("fleet-import-open").addEventListener("click", () => {
    show("fleet-import", true); fillSelects(); $("fleet-import").scrollIntoView({block: "start", behavior: "smooth"});
  });
  $("fleet-import-close").addEventListener("click", () => { show("fleet-import", false); picked = []; renderPicked(); });
  $("fleet-files").addEventListener("change", () => { pick([...$("fleet-files").files]); $("fleet-files").value = ""; });
  const drop = $("fleet-drop");
  drop.addEventListener("dragover", e => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", e => { e.preventDefault(); drop.classList.remove("over"); pick([...e.dataTransfer.files]); });
  $("fleet-group").addEventListener("change", () => { $("fleet-group-name").closest("div").hidden = $("fleet-group").value !== "__new"; });
  $("fleet-import-start").addEventListener("click", e => busy(e.currentTarget, () => run(e.currentTarget)));
  $("fleet-group-new").addEventListener("click", e => busy(e.currentTarget, async () => {
    const label = (window.prompt(tr("Name of the new group:"), "") || "").trim(); if (!label) return;
    groups = (await json("profile-groups", {label}, {root: true})).groups; fillSelects(); decorate();
    toast(tr("Group created. Move workspaces into it or import accounts."));
  }));
  window.addEventListener("tgwitness:lock", () => {
    picked = []; groups = []; sections = [];
    for (const id of ["fleet-passcode", "fleet-api", "fleet-files"]) $(id).value = "";
    $("fleet-groups").replaceChildren(); renderPicked(); show("fleet-import", false);
  });
  window.TgWitnessFleet = {load, decorate};
})();
