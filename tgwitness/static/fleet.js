(() => {
  "use strict";
  let groups = [], sections = [], picked = [], importing = false, stopping = false, pickSerial = 0;
  let loadSerial = 0, formRevision = -1, restorePoint = null, loadError = "", creating = null;
  const LIMIT = 8 * 1024 * 1024, SUFFIX = /\.(session|json|zip|txt)$/i, IGNORED = /(^|\/)(\.|__MACOSX\/)|-journal$/i;
  const LABELS = {waiting: "Waiting", ready: "Session found", checking: "Checking…", alive: "Active", revoked: "Revoked",
                  banned: "Banned or deleted", duplicate: "Duplicate", password: "Two-step password required",
                  frozen: "Frozen", invalid: "File cannot be used", unchecked: "Not checked", importing: "Importing…",
                  imported: "Imported", failed: "Not imported", cancelled: "Cancelled"};
  const KINDS = {alive: "live", imported: "ok", checking: "busy", importing: "busy", revoked: "bad", banned: "bad",
                 duplicate: "bad", password: "bad", frozen: "bad", invalid: "bad", failed: "bad"};
  const settings = new Map(), moving = new Map(), writing = new Map(), groupActions = new Map();
  const editable = () => !!state.me?.admin && !state.status?.demo;
  const SECTIONS = {parameters: "Parameters", reports: "Report settings", capture: "Capture and monitoring",
                    recheck: "Recheck schedule", route: "IP protection mode"};
  const labelOf = id => (state.profiles || []).find(p => p.id === id)?.label || id;

  function clearForms() {
    settings.clear(); moving.clear(); writing.clear(); groupActions.clear(); restorePoint = null; creating = null;
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
    const entry = settings.get(id), disabled = !editable() || writing.has(id) || groupActions.has(id);
    if (entry) entry.panel.querySelectorAll("input, select, button").forEach(field => { field.disabled = disabled; });
    const section = [...$("fleet-groups").children].find(n => n.dataset.group === id);
    section?.querySelectorAll(".fleet-group-actions button").forEach(button => {
      button.disabled = disabled || button.dataset.unavailable === "true";
    });
  }

  async function writeGroup(id, work) {
    if (writing.has(id) || groupActions.has(id) || !editable()) return;
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
    select.disabled = !editable() || moving.has(profileId) || groupActions.size;
    select.addEventListener("change", () => busy(null, async () => {
      if (!editable() || moving.has(profileId) || groupActions.size) return;
      const marker = {group: select.value}, revision = state.workspaceRevision;
      moving.set(profileId, marker); select.disabled = true; const serial = ++loadSerial;
      try {
        const result = await json("profiles/" + encodeURIComponent(profileId) + "/group", {group: marker.group || null},
                                 {root: true, method: "PUT"});
        await acceptWrite(result, serial); toast(tr("Workspace moved."));
        if (marker.group) await offerShared(marker.group, profileId);
      } finally {
        if (moving.get(profileId) === marker) moving.delete(profileId);
        if (revision === state.workspaceRevision) decorate();
      }
    }));
    return select;
  }

  async function offerShared(groupId, profileId) {
    const revision = state.workspaceRevision;
    const shared = await json("profile-groups/" + encodeURIComponent(groupId) + "/settings", undefined, {root: true});
    const member = shared.members.find(m => m.id === profileId);
    if (!member?.available || !member.own.length) return;
    const keys = member.own.filter(key => key !== "route");
    if (!keys.length) return;
    const names = keys.map(key => tr(shared.keys.find(k => k.key === key)?.label || key));
    const list = names.length > 6 ? [...names.slice(0, 6), tr("and {n} more", {n: names.length - 6})] : names;
    if (!(await window.TgWitnessDialogs.confirm(trn("{n} setting of this account differs from the group {name}:", "{n} settings of this account differ from the group {name}:",
        keys.length, {name: shared.group.label}) + "\n\n" + list.join("\n") + "\n\n" +
        tr("Take the group's values? Otherwise the account keeps its own and Settings marks them ✏️."),
        {title: tr("Take the shared settings?"), confirmText: tr("Take the group's values")}))) return;
    if (revision !== state.workspaceRevision) return;
    const result = await json("profile-groups/" + encodeURIComponent(groupId) + "/settings/adopt", {profiles: [profileId], keys}, {root: true});
    const remaining = result.members.find(m => m.id === profileId)?.own || [];
    if (result.failed.length) toast(result.failed.map(f => f.label + ": " + tr(f.error)).join(" · "), true);
    else if (remaining.includes("route") || result.kept_own?.length) toast(tr("Settings saved.") + " " + tr("Own route preserved"));
    else if (remaining.length) toast(tr("Settings saved."));
    else toast(tr("The account now follows the group."));
  }

  function openShared(group) {
    return busy(null, async () => {
      await navigate("settings");
      if (state.view === "settings") await settingsHub?.openGroup(group.id);
    });
  }

  function updateGroupSelect(select,profileId,current){
    syncOptions(select,[["",tr("No group")],...groups.map(group=>[group.id,group.label])]);
    select.value=moving.get(profileId)?.group??current??"";
    select.disabled=!editable()||moving.has(profileId)||!!groupActions.size;
  }

  function settingsPanel(group) {
    let entry = settings.get(group.id);
    if (entry) {
      entry.group = group;
      updateSettings(entry);
      return entry.panel;
    }
    const panel = node("details", "fleet-group-settings"), summary = node("summary", "", tr("Copy settings from one account"));
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
    body.append(templateLabel, template, node("p", "hint", tr("Apply copies these settings from the chosen account to every other member, and the group then shares them: accounts added later start with them. Each member records what it received in its signed journal; an observing account keeps its IP mode until it is paused.")), checks, save);
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

  function groupRun(group) {
    const members = () => (state.profiles || []).filter(p => group.members.includes(p.id) && p.collector);
    const due = {start: p => !p.collector.running && p.collector.has_session, stop: p => p.collector.running};
    return [["start", tr("Start all")], ["stop", tr("Pause all")]].map(([action, label]) => {
      const button = node("button", "secondary small", label); button.type = "button";
      button.dataset.unavailable = String(!may("collect") || !!state.status?.demo || !members().some(due[action]));
      button.disabled = button.dataset.unavailable === "true" || groupActions.has(group.id);
      button.addEventListener("click", () => busy(null, async () => {
        if (button.disabled || groupActions.has(group.id) || writing.has(group.id) || moving.size || !may("collect")) return;
        const marker = {}, revision = state.workspaceRevision, done = [], failed = [];
        const current = () => revision === state.workspaceRevision && !!state.token && state.view === "accounts"
          && groupActions.get(group.id) === marker && may("collect");
        groupActions.set(group.id, marker); decorate();
        try {
          for (const profile of members().filter(due[action])) {
            if (!current()) return;
            if (!groups.find(item => item.id === group.id)?.members.includes(profile.id)) continue;
            try {
              await json("collector/" + action, {}, {profile: profile.id});
              if (!current()) return;
              done.push(profile.label);
            } catch (error) {
              if (!current() || error instanceof StaleView) return;
              failed.push(profile.label + ": " + error.message);
            }
          }
          if (!current()) return;
          await loadProfiles();
          if (!current()) return;
          toast([action === "start" ? trn("{n} workspace started.", "{n} workspaces started.", done.length)
                                    : trn("{n} workspace paused.", "{n} workspaces paused.", done.length),
                 ...failed].join(" · "), !!failed.length);
        } finally {
          if (groupActions.get(group.id) === marker) groupActions.delete(group.id);
          if (revision === state.workspaceRevision && state.view === "accounts") decorate();
        }
      }));
      return button;
    });
  }

  function groupSection(group, cards, headerOnly=false) {
    const section = node("section", "fleet-group card"), head = node("div", "fleet-group-head");
    section.dataset.group = group.id;section.groupData=group;
    const who = node("div"), title = node("h2", "", group.label);
    title.append(node("span", "fleet-count", String(group.members.length)));
    const shares = (group.sections || []).map(key => tr(SECTIONS[key] || key));
    who.append(title, node("p", "hint", group.template && shares.length ?
      tr("Copies {list} from {name}", {list: shares.join(", "), name: labelOf(group.template)}) :
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
      toast(trn("Settings copied to {n} workspace.", "Settings copied to {n} workspaces.", done) + (skipped ? " " +
        trn("{n} workspace kept its IP mode while observing.", "{n} workspaces kept their IP mode while observing.", skipped) : ""));
    })));
    const rename = node("button", "quiet small", tr("Rename")); rename.type = "button";
    rename.addEventListener("click", () => busy(rename, () => writeGroup(group.id, async serial => {
      const label = ((await window.TgWitnessDialogs.prompt(tr("New name for this group:"), {title: tr("Rename"), value: group.label, maxLength: 80})) || "").trim();
      if (!label || label === group.label) return;
      const result = await json("profile-groups/" + group.id, {label, template: group.template, sections: group.sections},
                               {root: true, method: "PATCH"});
      await acceptWrite(result, serial); fillSelects(); decorate();
    })));
    const remove = node("button", "quiet small danger-text", tr("Delete group")); remove.type = "button";
    remove.addEventListener("click", () => busy(remove, () => writeGroup(group.id, async serial => {
      if (!(await window.TgWitnessDialogs.confirm(tr("Delete the group \"{name}\"? Its workspaces stay and lose only the grouping.", {name: group.label}), {danger: true, confirmText: tr("Delete")}))) return;
      const result = await json("profile-groups/" + group.id, undefined, {root: true, method: "DELETE"});
      await acceptWrite(result, serial); fillSelects(); decorate();
    })));
    const shared = node("button", "secondary small", tr("Shared settings")); shared.type = "button";
    shared.dataset.action = "shared-settings"; shared.disabled = !editable();
    shared.addEventListener("click", () => openShared(group));
    const page = node("button", "secondary small", tr("Open group")); page.type = "button";
    page.dataset.action = "open-group";
    page.addEventListener("click", () => busy(null, () => window.TgWitnessOpenGroup?.(group.id)));
    actions.append(page, shared, apply, ...groupRun(group), rename, remove);
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
    placeChildren(list,[...cards].filter(([id])=>window.TgWitnessAccounts?.ownsRows||!membership.has(id)).map(([,card])=>card));
    placeChildren(box,sections);
    if (!groups.length) {
      const empty = node("div", "fleet-groups-empty");
      const create = node("button", "secondary small", tr("New group")); create.type = "button";
      create.disabled = !editable() || !!creating;
      create.addEventListener("click", () => $("fleet-group-new").click());
      empty.append(node("p", "", tr("No groups yet. A group keeps shared settings for several accounts: connection, recording and notifications.")), create);
      box.replaceChildren(empty);
    }
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

  const local = (file, path) => ({name: file.name, path: path || file.webkitRelativePath || file.name, size: file.size,
                                  read: async () => file});

  async function unzip(entry) {
    const bytes = new Uint8Array(await (await entry.read()).arrayBuffer()), view = new DataView(bytes.buffer), found = [];
    let end = bytes.length - 22;
    while (end >= Math.max(0, bytes.length - 65557) && view.getUint32(end, true) !== 0x06054b50) end--;
    if (end < Math.max(0, bytes.length - 65557)) return null;
    for (let at = view.getUint32(end + 16, true), count = view.getUint16(end + 10, true); count > 0; count--) {
      if (at + 46 > bytes.length || view.getUint32(at, true) !== 0x02014b50) return null;
      const flags = view.getUint16(at + 8, true), method = view.getUint16(at + 10, true), packed = view.getUint32(at + 20, true);
      const size = view.getUint32(at + 24, true), length = view.getUint16(at + 28, true), offset = view.getUint32(at + 42, true);
      const path = new TextDecoder().decode(bytes.subarray(at + 46, at + 46 + length)), name = path.split("/").pop();
      at += 46 + length + view.getUint16(at + 30, true) + view.getUint16(at + 32, true);
      if (path.endsWith("/")) continue;
      if (flags & 1 || ![0, 8].includes(method) || packed === 0xffffffff || offset + 30 > bytes.length) return null;
      const start = offset + 30 + view.getUint16(offset + 26, true) + view.getUint16(offset + 28, true);
      const data = new Blob([bytes.subarray(start, start + packed)]);
      found.push({name, path: entry.path + "/" + path, size, read: async () => new File([method ?
        await new Response(data.stream().pipeThrough(new DecompressionStream("deflate-raw"))).blob() : data], name)});
    }
    return found.some(item => /(^|\/)key_datas?$/i.test(item.path)) ? null : found;
  }

  async function walk(roots) {
    const found = [];
    const visit = async entry => {
      if (entry.isFile) {
        found.push(local(await new Promise((resolve, reject) => entry.file(resolve, reject)), entry.fullPath.replace(/^\//, "")));
        return;
      }
      const reader = entry.createReader();
      for (let batch; (batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject))).length;)
        for (const child of batch) await visit(child);
    };
    for (const entry of roots) await visit(entry);
    return found;
  }

  function bundles(entries) {
    const byName = new Map();
    for (const entry of entries) {
      const key = entry.path.replace(SUFFIX, "").toLowerCase();
      if (!byName.has(key)) byName.set(key, {name: entry.name.replace(SUFFIX, ""), files: [], state: "waiting"});
      byName.get(key).files.push(entry);
    }
    return [...byName].sort(([a], [b]) => a.localeCompare(b)).map(([, bundle]) => bundle);
  }

  function base64(buffer) {
    const bytes = new Uint8Array(buffer); let text = "";
    for (let i = 0; i < bytes.length; i += 0x8000) text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(text);
  }

  async function each(items, work) {
    const queue = [...items];
    await Promise.all(Array.from({length: Math.min(4, queue.length)}, async () => {
      while (queue.length) await work(queue.shift());
    }));
  }

  const who = account => (account.username ? "@" + account.username + " · " : "") + "ID " + account.id;

  function controls() {
    const count = test => picked.filter(bundle => test(bundle.state)).length;
    const live = count(s => s === "alive"), open = count(s => ["ready", "unchecked"].includes(s));
    $("fleet-import-check").disabled = importing || !editable() || !open;
    $("fleet-import-start").disabled = importing || !editable() || !live;
    if (!importing) $("fleet-import-summary").textContent = picked.length ? tr("Active: {live} · imported: {done} · not usable: {bad} · not checked: {open}",
      {live, open, done: count(s => s === "imported"), bad: count(s => KINDS[s] === "bad")}) : "";
  }

  function renderPicked(unsupported = []) {
    const list = $("fleet-results"); list.replaceChildren();
    for (const bundle of picked) {
      const item = node("li", "fleet-result waiting");
      item.append(node("strong", "", bundle.name), node("span", "hint", ""), node("span", "fleet-state", ""));
      bundle.row = item; list.append(item); mark(bundle, bundle.state);
    }
    for (const entry of unsupported) {
      const item = node("li", "fleet-result bad");
      item.append(node("strong", "", entry.name), node("span", "hint", ""), node("span", "fleet-state",
        tr("Unsupported account file. Expected SQLite, TData ZIP, account JSON, or StringSession text.")));
      list.append(item);
    }
    controls();
  }

  async function pick(entries) {
    if (importing || !editable()) return;
    const serial = ++pickSerial, revision = state.workspaceRevision, expanded = [];
    for (const entry of entries.filter(entry => !IGNORED.test(entry.path))) {
      const inner = /\.zip$/i.test(entry.name) ? await unzip(entry).catch(() => null) : null;
      expanded.push(...(inner?.length ? inner.filter(item => !IGNORED.test(item.path)) : [entry]));
    }
    if (serial !== pickSerial || revision !== state.workspaceRevision || importing) return;
    const supported = expanded.filter(entry => SUFFIX.test(entry.name));
    if (supported.some(entry => entry.size > LIMIT)) toast(tr("Files above 8 MiB were left out."), true);
    picked = bundles(supported.filter(entry => entry.size <= LIMIT));
    renderPicked(expanded.filter(entry => !SUFFIX.test(entry.name)));
    await inspect();
  }

  async function inspect() {
    const serial = pickSerial, revision = state.workspaceRevision, passcode = $("fleet-passcode").value;
    const current = () => serial === pickSerial && revision === state.workspaceRevision && !!state.token;
    const queue = picked.filter(bundle => bundle.state !== "imported");
    for (const bundle of queue) mark(bundle, "waiting");
    await each(queue, async bundle => {
      try {
        if (bundle.files.length > 4 || bundle.files.reduce((n, f) => n + f.size, 0) > LIMIT)
          throw new Error(tr("One account · up to 4 files · 8 MiB total"));
        bundle.body = bundle.body || await Promise.all(bundle.files.map(async f => ({name: f.name,
          content: base64(await (await f.read()).arrayBuffer())})));
        const result = await json("auth/import/preview", {files: bundle.body, passcode}, {root: true});
        if (!current()) return;
        if (!result.can_connect) return mark(bundle, "invalid", tr(result.message));
        Object.assign(bundle, {keyId: result.key_id, userId: result.expected_user_id});
        mark(bundle, "ready", result.formats.map(format => tr(format)).join(" + "));
      } catch (error) {
        if (current() && !(error instanceof StaleView)) mark(bundle, "invalid", error.message);
      }
    });
    if (!current()) return;
    const seen = new Map();
    for (const bundle of picked.filter(bundle => bundle.state === "ready")) {
      const twin = seen.get("key:" + bundle.keyId) || seen.get("user:" + bundle.userId);
      if (twin) mark(bundle, "duplicate", tr("Same session or account as {name}.", {name: twin.name}));
      else for (const key of ["key:" + bundle.keyId, ...(bundle.userId ? ["user:" + bundle.userId] : [])]) seen.set(key, bundle);
    }
    controls();
  }

  function apiPair() {
    const text = $("fleet-api").value.trim(), pair = text.match(/^(\d{1,10})\s*[:\s]\s*([0-9a-fA-F]{32})$/);
    if (text && !pair) throw new Error(tr("Enter the API pair as ID:Hash, or leave it empty."));
    return pair ? {api_id: Number(pair[1]), api_hash: pair[2].toLowerCase()} : {};
  }

  function working(on) {
    importing = on;
    if (on) stopping = false;
    for (const field of $("fleet-import").querySelectorAll("input, select, button"))
      if (field.id !== "fleet-import-close" && field.id !== "fleet-import-stop") field.disabled = on || !editable();
    show("fleet-import-stop", on); $("fleet-import-stop").disabled = !on;
    if (!on) controls();
  }

  async function check() {
    if (importing || !editable()) return;
    const pair = apiPair(), passcode = $("fleet-passcode").value, revision = state.workspaceRevision, serial = pickSerial;
    const current = () => serial === pickSerial && revision === state.workspaceRevision && !!state.token;
    const queue = picked.filter(bundle => ["ready", "unchecked"].includes(bundle.state));
    working(true);
    try {
      await each(queue, async bundle => {
        if (!current() || stopping) return;
        mark(bundle, "checking");
        try {
          const result = await json("profiles/check", {files: bundle.body, passcode, ...pair}, {root: true});
          if (!current()) return;
          bundle.account = result.account;
          mark(bundle, result.state, result.account ? who(result.account) : importError(result.message));
        } catch (error) {
          if (current() && !(error instanceof StaleView)) mark(bundle, "unchecked", error.message);
        }
      });
      if (!current()) return;
      const seen = new Map();
      for (const bundle of picked.filter(bundle => bundle.state === "alive")) {
        const twin = seen.get(bundle.account.id);
        if (twin) mark(bundle, "duplicate", tr("Same session or account as {name}.", {name: twin.name}));
        else seen.set(bundle.account.id, bundle);
      }
    } finally {
      working(false);
    }
  }

  function importError(message) {
    const reason = /^Not imported: (.+)$/s.exec(message)?.[1] ?? message;
    const owner = /^This Telegram account already has a workspace: (.+)\.$/s.exec(reason)?.[1];
    return owner === undefined ? tr(reason) : tr("This Telegram account already has a workspace: {label}.", {label: owner});
  }

  function mark(bundle, status, message = "") {
    bundle.state = status;
    if (!bundle.row) return;
    bundle.row.className = "fleet-result " + (KINDS[status] || "waiting");
    bundle.row.dataset.state = status;
    const hint = bundle.row.querySelector(".hint");
    hint.replaceChildren(bundle.files.map(f => f.name).join(" + "));
    if (message) hint.append(node("span", "fleet-detail", message));
    bundle.row.querySelector(".fleet-state").textContent = tr(LABELS[status]);
  }

  async function run() {
    if (importing || !editable()) return;
    const revision = state.workspaceRevision, queue = picked.filter(bundle => bundle.state === "alive");
    const current = () => revision === state.workspaceRevision && !!state.token;
    const pair = apiPair();
    let passcode = $("fleet-passcode").value, group = $("fleet-group").value || null;
    working(true);
    try {
      if (group === "__new") {
        const label = $("fleet-group-name").value.trim() || tr("Imported accounts");
        const serial = ++loadSerial;
        const result = await json("profile-groups", {label}, {root: true});
        group = result.groups[result.groups.length - 1].id; await acceptWrite(result, serial);
        fillSelects(); $("fleet-group").value = group;
        $("fleet-group-name").closest("div").hidden = true;
      }
      const done = () => queue.filter(bundle => bundle.state === "imported").length;
      for (const bundle of queue) {
        if (!current()) return;
        if (stopping) { mark(bundle, "cancelled", who(bundle.account)); continue; }
        mark(bundle, "importing", who(bundle.account));
        try {
          const result = await json("profiles/import", {files: bundle.body, label: bundle.name.slice(0, 80), group, passcode, ...pair},
                                    {root: true});
          mark(bundle, "imported", who(result.account));
        } catch (error) {
          if (!current() || error instanceof StaleView) return;
          mark(bundle, "failed", importError(error.message));
        }
        $("fleet-import-summary").textContent = tr("{done} of {total} imported", {done: done(), total: queue.length});
      }
      await loadProfiles(); await load();
      if (current()) toast(trn("{n} account imported.", "{n} accounts imported.", done()));
    } finally {
      passcode = "";
      working(false);
      if (current()) $("fleet-passcode").value = "";
    }
  }

  $("fleet-import-open").addEventListener("click", () => {
    show("fleet-import", true); fillSelects(); $("fleet-import").scrollIntoView({block: "start", behavior: "smooth"});
  });
  $("fleet-import-close").addEventListener("click", () => {
    stopping = importing; pickSerial++; show("fleet-import", false); picked = []; renderPicked();
  });
  $("fleet-import-stop").addEventListener("click", () => { stopping = true; $("fleet-import-stop").disabled = true; });
  for (const id of ["fleet-files", "fleet-folder"]) $(id).addEventListener("change", () => {
    const entries = [...$(id).files].map(file => local(file)); $(id).value = "";
    busy(null, () => pick(entries));
  });
  $("fleet-folder-open").addEventListener("click", () => $("fleet-folder").click());
  const drop = $("fleet-drop");
  drop.addEventListener("dragover", e => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", e => {
    e.preventDefault(); drop.classList.remove("over");
    const roots = [...e.dataTransfer.items].map(item => item.webkitGetAsEntry?.()).filter(Boolean);
    const files = [...e.dataTransfer.files].map(file => local(file));
    busy(null, async () => pick(roots.length ? await walk(roots) : files));
  });
  $("fleet-passcode").addEventListener("change", () => { if (picked.length && !importing) busy(null, inspect); });
  $("fleet-group").addEventListener("change", () => { $("fleet-group-name").closest("div").hidden = $("fleet-group").value !== "__new"; });
  $("fleet-import-check").addEventListener("click", () => busy(null, check));
  $("fleet-import-start").addEventListener("click", () => busy(null, run));
  $("fleet-group-new").addEventListener("click", () => busy(null, async () => {
    if (!editable() || creating) return;
    const label = ((await window.TgWitnessDialogs.prompt(tr("Name of the new group:"), {title: tr("New group"), maxLength: 80})) || "").trim(); if (!label) return;
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
    picked = []; groups = []; sections = []; pickSerial++;
    for (const id of ["fleet-passcode", "fleet-api", "fleet-files", "fleet-folder"]) $(id).value = "";
    $("fleet-groups").replaceChildren(); renderPicked(); show("fleet-import", false);
  });
  window.TgWitnessFleet = {load, decorate, beforeRender};
})();
