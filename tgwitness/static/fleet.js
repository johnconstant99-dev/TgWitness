(() => {
  "use strict";
  // Account groups with shared settings, and importing many accounts into their own workspaces.
  let groups = [], sections = [], picked = [], importing = false;
  let loadSerial = 0, formRevision = -1, restorePoint = null, loadError = "", creating = null;
  const settings = new Map(), moving = new Map(), writing = new Map();
  const editable = () => !!state.me?.admin && !state.status?.demo;
  const SECTIONS = {parameters: "Parameters", reports: "Report settings", capture: "Capture and monitoring",
                    recheck: "Recheck schedule", route: "IP protection mode"};
  const labelOf = id => (state.profiles || []).find(p => p.id === id)?.label || id;

  function clearForms() {
    settings.clear(); moving.clear(); writing.clear(); restorePoint = null; creating = null;
    formRevision = state.workspaceRevision; loadSerial++;
  }

  function beforeRender() {
    if (formRevision !== state.workspaceRevision) clearForms();
    const element = document.activeElement;
    if (!element?.closest("#fleet-groups, #accounts-list")) { restorePoint = null; return; }
    restorePoint = {element, profile: element.matches(".fleet-card-group") ? element.closest(".account-card").dataset.profile : null,
                    x: window.scrollX, y: window.scrollY};
  }

  function accept(result) {
    loadSerial++;
    groups = result.groups;
    if (result.sections) sections = result.sections;
  }

  async function acceptWrite(result, serial) {
    if (serial === loadSerial) accept(result);
    else await load();
  }

  function groupControls(id) {
    const entry = settings.get(id), disabled = !editable() || writing.has(id);
    if (entry) entry.panel.querySelectorAll("input, select, button").forEach(field => { field.disabled = disabled; });
    const section = [...$("fleet-groups").children].find(n => n.dataset.group === id);
    section?.querySelectorAll(".fleet-group-actions button").forEach(button => {
      button.disabled = disabled || button.dataset.unavailable === "true";
    });
  }

  async function writeGroup(id, work) {
    if (writing.has(id) || !editable()) return;
    const marker = {}, revision = state.workspaceRevision;
    writing.set(id, marker); const serial = ++loadSerial; groupControls(id);
    try { return await work(serial); }
    finally {
      if (writing.get(id) === marker) writing.delete(id);
      if (revision === state.workspaceRevision) groupControls(id);
    }
  }

  async function load() {
    if (!state.status || state.view !== "accounts") return;
    if (formRevision !== state.workspaceRevision) clearForms();
    const revision = state.workspaceRevision, serial = ++loadSerial;
    try {
      const result = await json("profile-groups", undefined, {root: true});
      if (revision !== state.workspaceRevision || serial !== loadSerial || state.view !== "accounts") return;
      groups = result.groups; sections = result.sections;
      loadError = "";
    } catch (error) {
      if (revision !== state.workspaceRevision || serial !== loadSerial || error instanceof StaleView) return;
      if (loadError !== error.message) toast(error.message, true);
      loadError = error.message;
      return;
    }
    fillSelects(); decorate();
  }

  function fillSelects() {
    const add = $("account-add-group"), target = $("fleet-group");
    const choices=groups.map(group=>[group.id,group.label]);
    syncOptions(add,[["",tr("No group")],...choices]);
    syncOptions(target,[["__new",tr("A new group")],["",tr("No group")],...choices],groups[0]?.id||"__new");
    $("fleet-group-name").closest("div").hidden = target.value !== "__new";
  }

  function groupSelect(profileId, current) {
    const select = node("select", "fleet-card-group");
    select.setAttribute("aria-label", tr("Group"));
    select.append(new Option(tr("No group"), ""));
    for (const group of groups) select.append(new Option(group.label, group.id));
    select.value = moving.get(profileId)?.group ?? current ?? "";
    select.disabled = !editable() || moving.has(profileId);
    select.addEventListener("change", () => busy(null, async () => {
      if (!editable() || moving.has(profileId)) return;
      const marker = {group: select.value}, revision = state.workspaceRevision;
      moving.set(profileId, marker); select.disabled = true; const serial = ++loadSerial;
      try {
        const result = await json("profiles/" + encodeURIComponent(profileId) + "/group", {group: marker.group || null},
                                 {root: true, method: "PUT"});
        await acceptWrite(result, serial); toast(tr("Workspace moved."));
      } finally {
        if (moving.get(profileId) === marker) moving.delete(profileId);
        if (revision === state.workspaceRevision) decorate();
      }
    }));
    return select;
  }

  function updateGroupSelect(select,profileId,current){
    syncOptions(select,[["",tr("No group")],...groups.map(group=>[group.id,group.label])]);
    select.value=moving.get(profileId)?.group??current??"";
    select.disabled=!editable()||moving.has(profileId);
  }

  function settingsPanel(group) {
    let entry = settings.get(group.id);
    if (entry) {
      entry.group = group;
      updateSettings(entry);
      return entry.panel;
    }
    const panel = node("details", "fleet-group-settings"), summary = node("summary", "", tr("Shared settings"));
    const body = node("div", "fleet-settings-body");
    const templateLabel = node("label", "", tr("Copy from")), template = node("select");
    template.id = "fleet-template-" + group.id; templateLabel.htmlFor = template.id;
    const checks = node("div", "fleet-sections");
    for (const key of sections) {
      const row = node("label", "check-label"), box = node("input");
      box.type = "checkbox"; box.value = key; box.checked = (group.sections || []).includes(key);
      row.append(box, " " + tr(SECTIONS[key] || key)); checks.append(row);
    }
    const save = node("button", "secondary", tr("Save group settings")); save.type = "button";
    entry = {panel, template, checks, save, group, dirty: false, options: ""};
    settings.set(group.id, entry);
    panel.addEventListener("change", () => { entry.dirty = true; });
    save.addEventListener("click", () => busy(save, () => writeGroup(group.id, async serial => {
      const chosen = [...checks.querySelectorAll("input:checked")].map(i => i.value);
      const result = await json("profile-groups/" + group.id, {label: entry.group.label, template: template.value || null, sections: chosen},
                               {root: true, method: "PATCH"});
      await acceptWrite(result, serial); entry.dirty = false; decorate();
      toast(tr("Group settings saved. Use Apply to copy them to the members."));
    })));
    body.append(templateLabel, template, node("p", "hint", tr("These settings are copied from the chosen workspace to every other member when you press Apply. Each member records what it received in its signed journal; an observing workspace keeps its IP mode until it is paused.")), checks, save);
    for (const field of body.querySelectorAll("input, select, button")) field.disabled = !editable();
    panel.append(summary, body);
    updateSettings(entry);
    return panel;
  }

  function updateSettings(entry) {
    const {template, checks, group} = entry;
    const options = JSON.stringify((state.profiles || []).map(p => [p.id, p.label]));
    if (entry.options !== options) {
      const previous = template.value;
      syncOptions(template,[["",tr("Choose a workspace")],...(state.profiles||[]).map(profile=>[profile.id,profile.label])]);
      template.value = previous; entry.options = options;
    }
    if (!entry.dirty) {
      template.value = group.template || "";
      checks.querySelectorAll("input").forEach(input => { input.checked = (group.sections || []).includes(input.value); });
    }
    groupControls(group.id);
  }

  function groupSection(group, cards, headerOnly=false) {
    const section = node("section", "fleet-group card"), head = node("div", "fleet-group-head");
    section.dataset.group = group.id;section.groupData=group;
    const who = node("div"), title = node("h2", "", group.label);
    title.append(node("span", "fleet-count", String(group.members.length)));
    const shares = (group.sections || []).map(key => tr(SECTIONS[key] || key));
    who.append(title, node("p", "hint", group.template && shares.length ?
      tr("Shares {list} from {name}", {list: shares.join(", "), name: labelOf(group.template)}) :
      tr("Choose what the group shares under Shared settings.")));
    const actions = node("div", "fleet-group-actions");
    const apply = node("button", "primary small", tr("Apply to members")); apply.type = "button";
    apply.dataset.unavailable = String(!group.template || !shares.length || !group.members.some(id => id !== group.template));
    apply.disabled = apply.dataset.unavailable === "true" || !editable() || writing.has(group.id);
    apply.addEventListener("click", () => busy(apply, () => writeGroup(group.id, async serial => {
      const result = await json("profile-groups/" + group.id + "/apply", {}, {root: true});
      await acceptWrite(result, serial); decorate();
      const done = result.results.filter(r => r.status === "applied").length;
      const skipped = result.results.filter(r => (r.skipped || []).length).length;
      toast(tr("Settings copied to {n} workspaces.", {n: done}) + (skipped ? " " + tr("{n} kept their IP mode while observing.", {n: skipped}) : ""));
    })));
    const rename = node("button", "quiet small", tr("Rename")); rename.type = "button";
    rename.addEventListener("click", () => busy(rename, () => writeGroup(group.id, async serial => {
      const label = (window.prompt(tr("New name for this group:"), group.label) || "").trim();
      if (!label || label === group.label) return;
      const result = await json("profile-groups/" + group.id, {label, template: group.template, sections: group.sections},
                               {root: true, method: "PATCH"});
      await acceptWrite(result, serial); fillSelects(); decorate();
    })));
    const remove = node("button", "quiet small danger-text", tr("Delete group")); remove.type = "button";
    remove.addEventListener("click", () => busy(remove, () => writeGroup(group.id, async serial => {
      if (!window.confirm(tr("Delete the group \"{name}\"? Its workspaces stay and lose only the grouping.", {name: group.label}))) return;
      const result = await json("profile-groups/" + group.id, undefined, {root: true, method: "DELETE"});
      await acceptWrite(result, serial); fillSelects(); decorate();
    })));
    actions.append(apply, rename, remove);
    for (const button of [rename, remove]) button.disabled = !editable() || writing.has(group.id);
    head.append(who, actions);
    section.append(head);if(headerOnly)return section;
    const grid = node("div", "accounts-grid");
    section.append(settingsPanel(group), grid);
    return section;
  }

  function decorate() {
    const list = $("accounts-list"), box = $("fleet-groups");
    if (!list || !box) return;
    if (formRevision !== state.workspaceRevision) clearForms();
    if (!restorePoint) beforeRender();
    for (const id of settings.keys()) if (!groups.some(group => group.id === id)) settings.delete(id);
    const cards = new Map([...$("view-accounts").querySelectorAll(".account-card[data-profile]")].map(card => [card.dataset.profile, card]));
    const membership = new Map(groups.flatMap(group => group.members.map(id => [id, group.id])));
    for (const [id, card] of cards) {
      let select=card.querySelector('.fleet-card-group');
      if(!select){const row=node('div','fleet-card-row');select=groupSelect(id,membership.get(id));
        row.append(node('span','',tr('Group')),select);card.querySelector('.account-actions')?.before(row);}
      else updateGroupSelect(select,id,membership.get(id));
    }
    const previous=new Map([...box.children].map(section=>[section.dataset.group,section]));
    const sections=groups.map(value=>{
      let section=previous.get(value.id),group=section?Object.assign(section.groupData,value):value;
      if(!section)section=groupSection(group,cards);
      else{
        const fresh=groupSection(group,cards,true),oldHead=section.querySelector('.fleet-group-head'),newHead=fresh.querySelector('.fleet-group-head');
        if(oldHead.firstElementChild.outerHTML!==newHead.firstElementChild.outerHTML)oldHead.firstElementChild.replaceWith(newHead.firstElementChild);
        [...oldHead.querySelectorAll('button')].forEach((button,index)=>{const candidate=newHead.querySelectorAll('button')[index];
          button.dataset.unavailable=candidate.dataset.unavailable||'false';if(!button.hasAttribute('aria-busy'))button.disabled=candidate.disabled;});
        settingsPanel(group);
      }
      const grid=section.querySelector('.accounts-grid'),members=window.TgWitnessAccounts?.ownsRows?[]:group.members.map(id=>cards.get(id)).filter(Boolean);
      grid.hidden=!!window.TgWitnessAccounts?.ownsRows;
      if(!members.length)members.push(grid.querySelector('.fleet-empty')||node('p','hint fleet-empty',tr('No workspaces in this group yet. Move one here or import accounts into it.')));
      placeChildren(grid,members);return section;
    });
    // Move cards before retiring an old group, so removal never drops an account.
    placeChildren(list,[...cards].filter(([id])=>window.TgWitnessAccounts?.ownsRows||!membership.has(id)).map(([,card])=>card));
    placeChildren(box,sections);
    $("fleet-import-open").disabled = !editable();
    $("fleet-group-new").disabled = !editable() || !!creating;
    let title = $("fleet-ungrouped");
    if (!title) { title = node("h2", "fleet-ungrouped", ""); title.id = "fleet-ungrouped"; list.before(title); }
    title.textContent = tr("Without group");
    title.hidden = !!window.TgWitnessAccounts?.ownsRows || !groups.length || !list.children.length;
    window.TgWitnessAccounts?.updateStatus();
    if (restorePoint) {
      const focus = restorePoint.profile ? [...$("view-accounts").querySelectorAll(".account-card[data-profile]")]
        .find(card => card.dataset.profile === restorePoint.profile)?.querySelector(".fleet-card-group") : restorePoint.element;
      if (focus?.isConnected && !focus.disabled) {
        focus.focus({preventScroll: true}); window.scrollTo({left: restorePoint.x, top: restorePoint.y, behavior: "instant"});
      }
      restorePoint = null;
    }
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
        const serial = ++loadSerial;
        const result = await json("profile-groups", {label}, {root: true});
        group = result.groups[result.groups.length - 1].id; await acceptWrite(result, serial);
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
      $("fleet-import-start").disabled = !editable() || !picked.some(b => !b.done);
      if (current()) {
        $("fleet-passcode").value = "";
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
  $("fleet-import-start").addEventListener("click", () => busy(null, run));
  $("fleet-group-new").addEventListener("click", () => busy(null, async () => {
    if (!editable() || creating) return;
    const label = (window.prompt(tr("Name of the new group:"), "") || "").trim(); if (!label) return;
    const marker = {}, serial = ++loadSerial;
    creating = marker; $("fleet-group-new").disabled = true;
    try {
      await acceptWrite(await json("profile-groups", {label}, {root: true}), serial); fillSelects(); decorate();
      toast(tr("Group created. Move workspaces into it or import accounts."));
    } finally {
      if (creating === marker) creating = null;
      $("fleet-group-new").disabled = !editable() || !!creating;
    }
  }));
  window.addEventListener("tgwitness:lock", () => {
    clearForms(); loadError = "";
    picked = []; groups = []; sections = [];
    for (const id of ["fleet-passcode", "fleet-api", "fleet-files"]) $(id).value = "";
    $("fleet-groups").replaceChildren(); renderPicked(); show("fleet-import", false);
  });
  window.TgWitnessFleet = {load, decorate, beforeRender};
})();
