const monitoring = ["messages", "edits", "deletions", "reactions", "membership"];
const media = [
  ["photo", "Photos"], ["video", "Videos"], ["animation", "GIFs & animations"],
  ["video_note", "Round video messages"], ["voice", "Voice messages"],
  ["audio", "Music & audio"], ["sticker", "Stickers"], ["document", "Files & documents"],
];
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const copy = value => JSON.parse(JSON.stringify(value));

function changes(before, after) {
  if (before && after && typeof before === "object" && typeof after === "object")
    return [...new Set([...Object.keys(before), ...Object.keys(after)])]
      .reduce((total, key) => total + changes(before[key], after[key]), 0);
  return before === after ? 0 : 1;
}

/** Sources keeps drafts, selection and chat-list requests within one workspace. */
export function createSources(context) {
  const {root, tr, getState, getSession, may, json, refreshStatus, toast} = context;
  const find = id => root.querySelector("#" + id);
  const form = find("recording-form"), listeners = new AbortController();
  const tabs = [...root.querySelectorAll("[data-source-tab]")];
  let tab = "scope", baseline = null, session = getSession(), saving = false, generation = 0;
  let dirty = {monitoring: false, capture: false, recheck: false};
  const selection = new Set(), pageSize = 10;
  const kindType = {channel: "channels", supergroup: "groups", group: "groups", private: "private", bot: "bots"};
  let sourcePage = 0, sourceBusy = false, sourceAttempt = 0, rowsVersion = "";
  const selectedDialogs = new Set();
  let dialogPage = 0, dialogVersion = "", dialogOpen = false, dialogAttempt = 0;
  let dialogLoading = false, dialogError = "", dialogResult = null, dialogRefreshedAt = null, autoRequested = false;
  const on = (element, event, handler) => element.addEventListener(event, handler, {signal: listeners.signal});
  const allowed = group => !getState().status?.demo && may(group === "recheck" ? "sources" : "settings");
  const permission = group => may(group === "recheck" ? "sources" : "settings");

  function showTab(name, focus = false) {
    if (!tabs.some(button => button.dataset.sourceTab === name)) name = "scope";
    tab = name;
    for (const button of tabs) {
      const selected = button.dataset.sourceTab === tab;
      button.setAttribute("aria-selected", String(selected));
      button.tabIndex = selected ? 0 : -1;
      find("sources-panel-" + button.dataset.sourceTab).hidden = !selected;
      if (selected && focus) button.focus();
    }
    if (name === "recording") updateStatus(getState().status);
    if (name === "chats") {renderTargets(); renderDialogs();}
  }
  for (const button of tabs) {
    on(button, "click", () => showTab(button.dataset.sourceTab));
    on(button, "keydown", event => {
      const index = tabs.indexOf(button);
      const next = {ArrowRight: (index + 1) % tabs.length, ArrowLeft: (index + tabs.length - 1) % tabs.length,
        Home: 0, End: tabs.length - 1}[event.key];
      if (next === undefined) return;
      event.preventDefault();
      showTab(tabs[next].dataset.sourceTab, true);
    });
  }

  function buildMedia() {
    const box = find("media-rules");
    for (const [key, label] of media) {
      const row = root.ownerDocument.createElement("div");
      row.className = "media-rule";
      const checkbox = root.ownerDocument.createElement("input");
      checkbox.type = "checkbox"; checkbox.id = "media-on-" + key;
      const title = root.ownerDocument.createElement("label");
      title.htmlFor = checkbox.id; title.textContent = tr(label);
      const size = root.ownerDocument.createElement("input");
      Object.assign(size, {id: "media-max-" + key, type: "number", min: "1", max: "2000", step: "1", required: true});
      size.setAttribute("aria-label", tr("Maximum size for {type}", {type: tr(label)}));
      const field = root.ownerDocument.createElement("span");
      field.className = "field-unit";
      const unit = root.ownerDocument.createElement("span");
      unit.className = "unit"; unit.textContent = tr("MiB");
      field.append(size, unit); row.append(checkbox, title, field); box.append(row);
    }
  }
  buildMedia();

  function read() {
    return {
      monitoring: Object.fromEntries(monitoring.map(key => [key, find("monitor-" + key).checked])),
      capture: {
        ...baseline?.capture,
        download_media: find("download-media").checked, max_media_mb: Number(find("max-media").value),
        types: Object.fromEntries(media.map(([key]) => [key, {
          enabled: find("media-on-" + key).checked, max_mb: Number(find("media-max-" + key).value),
        }])),
      },
      recheck: {recheck_minutes: Number(find("recheck-priority").value),
        recheck_other_minutes: Number(find("recheck-other").value)},
    };
  }

  function write(group, value) {
    if (group === "monitoring") {
      for (const key of monitoring) find("monitor-" + key).checked = value[key] ?? true;
    } else if (group === "capture") {
      find("download-media").checked = value.download_media;
      find("max-media").value = String(value.max_media_mb);
      for (const [key] of media) {
        const rule = value.types[key] || {enabled: true, max_mb: value.max_media_mb};
        find("media-on-" + key).checked = rule.enabled;
        find("media-max-" + key).value = String(rule.max_mb);
      }
    } else {
      find("recheck-priority").value = String(value.recheck_minutes);
      find("recheck-other").value = String(value.recheck_other_minutes);
    }
  }

  function clearValidation() {
    for (const input of form.querySelectorAll("[aria-invalid]")) {
      const error = input.id + "-field-error";
      find(error)?.remove();
      input.removeAttribute("aria-invalid");
      const ids = (input.getAttribute("aria-describedby") || "").split(/\s+/).filter(id => id && id !== error);
      if (ids.length) input.setAttribute("aria-describedby", ids.join(" "));
      else input.removeAttribute("aria-describedby");
    }
  }

  function renderDraft() {
    if (!baseline) return;
    const draft = read();
    let count = 0;
    for (const group of Object.keys(dirty)) {
      dirty[group] = allowed(group) && !same(draft[group], baseline[group]);
      if (dirty[group]) count += changes(baseline[group], draft[group]);
    }
    context.setDirty({...dirty});
    find("recording-change-count").textContent = count
      ? tr(count === 1 ? "1 unsaved change" : "{n} unsaved changes", {n: count}) : tr("No unsaved changes");
    const badge = find("recording-tab-dirty");
    badge.hidden = !count; badge.textContent = String(count);
    find("recording-save").disabled = saving || !count;
    find("recording-discard").disabled = saving || !count;
    find("recording-save").textContent = tr(saving ? "Saving…" : "Save recording settings");
    find("recording-savebar").classList.toggle("is-dirty", !!count);
    find("monitoring-unsaved").textContent = dirty.monitoring ? tr("Unsaved changes") : "";
    find("capture-unsaved").textContent = dirty.capture ? tr("Unsaved changes") : "";
    const enabled = monitoring.filter(key => draft.monitoring[key]);
    find("monitoring-note").textContent = tr(!enabled.length
      ? "No live event types selected. Only operational and other group service records will continue."
      : !draft.monitoring.messages
        ? "New message capture is off. Edits and deletion notices may have no earlier content to compare."
        : "Original messages provide context for later edits and deletion notices. Already saved records remain available.");
  }

  function element(tag, className = "", text = "") {
    const node = root.ownerDocument.createElement(tag);
    node.className = className; node.textContent = text;
    return node;
  }

  function sourceState(target, status) {
    const seen = status.collector.source_status?.[String(target.chat_id)];
    if (status.scope?.exclude.includes(target.chat_id)) return "excluded";
    if (seen?.state === "access_unconfirmed") return seen.ignored ? "ignored" : "unconfirmed";
    return target.enabled ? "enabled" : "paused";
  }

  function matchingTargets() {
    const status = getState().status;
    if (!status) return [];
    const term = find("target-search").value.trim().toLocaleLowerCase();
    const filter = find("target-filter").value, kind = find("target-kind").value;
    const sort = find("target-sort").value;
    return status.targets.filter(target =>
      (target.title + " " + target.chat_id).toLocaleLowerCase().includes(term)
      && (!kind || kindType[target.kind] === kind)
      && (!filter || (filter === "priority" ? target.priority
        : filter === "enabled" ? target.enabled && sourceState(target, status) !== "excluded"
          : filter === "paused" ? !target.enabled : sourceState(target, status) === filter)))
      .sort((a, b) => {
        if (sort === "priority" && !!a.priority !== !!b.priority) return Number(b.priority) - Number(a.priority);
        if (sort === "status" && !!a.enabled !== !!b.enabled) return Number(b.enabled) - Number(a.enabled);
        return (sort === "name-desc" ? -1 : 1) * a.title.localeCompare(b.title) || a.chat_id - b.chat_id;
      });
  }

  function sourceButton(action, target, label, className = "quiet small") {
    const button = element("button", className, label);
    button.type = "button"; button.dataset.sourceAction = action;
    button.dataset.chatId = String(target.chat_id);
    button.dataset.sourceFocus = target.chat_id + ":" + action;
    return button;
  }

  function renderTargets() {
    const status = getState().status;
    if (!status || getState().view !== "sources") return;
    const known = new Set(status.targets.map(target => target.chat_id));
    for (const id of selection) if (!known.has(id)) selection.delete(id);
    const matches = matchingTargets();
    sourcePage = Math.min(sourcePage, Math.max(0, Math.ceil(matches.length / pageSize) - 1));
    const visible = matches.slice(sourcePage * pageSize, (sourcePage + 1) * pageSize);
    const snapshot = visible.map(target => ({...target, state: sourceState(target, status),
      visibility: status.collector.source_status?.[String(target.chat_id)]?.visibility,
      role: status.collector.source_status?.[String(target.chat_id)]?.role}));
    const version = JSON.stringify(snapshot);
    const body = find("target-list");
    if (version !== rowsVersion) {
      const active = body.contains(root.ownerDocument.activeElement)
        ? root.ownerDocument.activeElement.dataset.sourceFocus : null;
      const fragment = root.ownerDocument.createDocumentFragment();
      for (const target of visible) {
        const row = element("tr", "target-row"), pick = element("td", "source-select-cell");
        const checkbox = element("input", "source-select");
        checkbox.type = "checkbox"; checkbox.dataset.sourceAction = "select";
        checkbox.dataset.chatId = String(target.chat_id); checkbox.dataset.sourceFocus = target.chat_id + ":select";
        checkbox.setAttribute("aria-label", tr("Select {name}", {name: target.title}));
        pick.append(checkbox);
        const name = element("td", "source-name-cell");
        name.append(element("strong", "", target.title), element("span", "source-id", String(target.chat_id)));
        if (target.origin === "scope") name.append(element("span", "source-origin", tr("auto")));
        const type = element("td", "source-type-cell", context.termText(target.kind));
        const state = sourceState(target, status), stateCell = element("td", "source-status-cell");
        const label = {enabled: tr("Enabled"), paused: tr("Paused"), excluded: tr("Excluded"),
          unconfirmed: tr("Unconfirmed"), ignored: tr("Ignored")}[state];
        const toggle = sourceButton("toggle", target, label, "source-state " + state);
        toggle.setAttribute("aria-label", tr(target.enabled && state !== "excluded"
          ? "Pause recording for {name}" : "Enable recording for {name}", {name: target.title}));
        stateCell.append(toggle);
        const starCell = element("td", "source-star-cell");
        const star = sourceButton("star", target, "", "icon-button star" + (target.priority ? " on" : ""));
        star.append(context.icon("star")); star.setAttribute("aria-pressed", String(!!target.priority));
        star.setAttribute("aria-label", tr("Priority recheck for {name}", {name: target.title}));
        star.title = tr(target.priority ? "Priority" : "Regular");
        starCell.append(star);
        const menuCell = element("td", "source-menu-cell"), menu = element("details", "source-row-menu");
        const summary = element("summary", "", "⋯");
        summary.setAttribute("aria-label", tr("Actions for {name}", {name: target.title}));
        summary.dataset.sourceFocus = target.chat_id + ":menu";
        const actions = element("div", "source-row-actions");
        if ((status.scope?.mode || "selected") !== "selected" && state !== "excluded")
          actions.append(sourceButton("exclude", target, tr("Exclude from scope")));
        actions.append(sourceButton("remove", target, tr("Remove source")));
        menu.append(summary, actions); menuCell.append(menu);
        row.append(pick, name, type, stateCell, starCell, menuCell); fragment.append(row);
      }
      body.replaceChildren(fragment); rowsVersion = version;
      if (active) [...body.querySelectorAll("[data-source-focus]")].find(node => node.dataset.sourceFocus === active)
        ?.focus({preventScroll: true});
    }
    const blocked = sourceBusy || dialogLoading || status.demo || !may("sources");
    find("target-card").setAttribute("aria-busy", String(sourceBusy));
    body.querySelectorAll("input,button").forEach(node => node.disabled = blocked);
    body.querySelectorAll("input.source-select").forEach(node => node.checked = selection.has(Number(node.dataset.chatId)));
    const master = find("target-select-page");
    master.checked = !!visible.length && visible.every(target => selection.has(target.chat_id));
    master.indeterminate = !master.checked && visible.some(target => selection.has(target.chat_id));
    master.disabled = blocked || !visible.length;
    find("target-match-count").textContent = tr("{shown} of {total}", {shown: matches.length, total: status.targets.length});
    find("target-bulk-actions").hidden = !selection.size;
    find("target-selection-count").textContent = tr("{n} selected", {n: selection.size});
    find("target-bulk-apply").disabled = blocked || !selection.size;
    find("target-bulk-apply").textContent = tr(sourceBusy ? "Applying…" : "Apply");
    find("target-selection-clear").disabled = sourceBusy;
    find("target-bulk-action").disabled = blocked;
    const exclude = find("target-bulk-action").querySelector('[value="exclude"]');
    exclude.hidden = exclude.disabled = (status.scope?.mode || "selected") === "selected";
    if (exclude.disabled && find("target-bulk-action").value === "exclude") find("target-bulk-action").value = "pause";
    find("target-empty").hidden = !!matches.length;
    find("target-empty-message").textContent = tr(status.targets.length
      ? "No sources match these filters." : status.collector.has_session
        ? "No sources selected yet. Load chats to choose what to record." : "Connect an account to choose sources.");
    find("target-clear-filters").hidden = !status.targets.length;
    find("target-page-count").textContent = matches.length
      ? tr("{from}–{to} of {total}", {from: sourcePage * pageSize + 1,
        to: Math.min((sourcePage + 1) * pageSize, matches.length), total: matches.length}) : "";
    find("target-prev").disabled = sourceBusy || sourcePage === 0;
    find("target-next").disabled = sourceBusy || (sourcePage + 1) * pageSize >= matches.length;
    find("target-select-matching").disabled = blocked || !matches.length;
    find("target-select-matching").textContent = tr(matches.length > 500 ? "Select first 500 matching" : "Select all matching");
  }

  async function runSourceAction(ids, action) {
    const state = getState(), status = state.status;
    if (sourceBusy || dialogLoading || !status || status.demo || !may("sources") || !ids.length) return;
    if (ids.length > 500) {toast(tr("Choose up to 500 sources at a time."), true); return;}
    const wide = (status.scope?.mode || "selected") !== "selected";
    if (action === "remove" && !context.confirm(tr(ids.length === 1
      ? "Remove this source? Saved messages and files stay. Cached people profiles are removed."
      : "Remove {n} sources? Saved messages and files stay. Cached people profiles are removed.", {n: ids.length})
      + (wide ? " " + tr("These chats are also excluded so the scope does not add them again.") : ""))) return;
    const current = getSession(), attempt = ++sourceAttempt, profile = state.profile;
    sourceBusy = true; renderTargets(); renderDialogs(); renderDialogRefresh();
    try {
      let result;
      if (action === "exclude") {
        if (!wide) return;
        result = await json("scope", {...status.scope,
          exclude: [...new Set([...status.scope.exclude, ...ids])], acknowledged: false}, {profile});
      } else {
        const change = {enable: {enabled: true}, pause: {enabled: false}, priority: {priority: true},
          regular: {priority: false}, remove: {remove: true}}[action];
        if (!change) return;
        result = await json("targets/batch", {chat_ids: ids, ...change}, {profile});
      }
      if (current !== getSession() || attempt !== sourceAttempt) return;
      for (const id of ids) {selection.delete(id); selectedDialogs.delete(id);}
      if (action === "enable") context.scopeExclusions(ids, false);
      if (action === "exclude" || action === "remove" && wide) context.scopeExclusions(ids, true);
      await refreshStatus();
      if (current !== getSession() || attempt !== sourceAttempt) return;
      if (["enable", "exclude", "remove"].includes(action)) await context.loadScope();
      if (current !== getSession() || attempt !== sourceAttempt) return;
      const message = result.cache_cleanup_pending?.length
        ? tr("Sources removed. A cached people profile could not be cleared; saved evidence is unchanged.")
        : tr(action === "remove" ? (ids.length === 1 ? "Source removed. Saved evidence stays." : "{n} sources removed. Saved evidence stays.")
          : action === "exclude" ? (ids.length === 1 ? "Source excluded." : "{n} sources excluded.")
            : ids.length === 1 ? "Source updated." : "{n} sources updated.", {n: ids.length});
      find("source-action-result").textContent = message; toast(message);
    } catch (error) {
      if (current !== getSession() || attempt !== sourceAttempt) return;
      find("source-action-result").textContent = error.message; toast(error.message, true);
    } finally {
      if (current === getSession() && attempt === sourceAttempt) {
        sourceBusy = false; renderTargets(); renderDialogs(); renderDialogRefresh();
      }
    }
  }
  for (const id of ["target-search", "target-filter", "target-kind", "target-sort"])
    on(find(id), id === "target-search" ? "input" : "change", () => {sourcePage = 0; renderTargets();});
  on(find("target-clear-filters"), "click", () => {
    for (const id of ["target-search", "target-filter", "target-kind"]) find(id).value = "";
    sourcePage = 0; renderTargets(); find("target-search").focus();
  });
  on(find("target-select-page"), "change", event => {
    for (const target of matchingTargets().slice(sourcePage * pageSize, (sourcePage + 1) * pageSize)) {
      if (!event.target.checked) selection.delete(target.chat_id);
      else if (selection.size < 500) selection.add(target.chat_id);
    }
    renderTargets();
  });
  on(find("target-select-matching"), "click", () => {
    selection.clear();
    for (const target of matchingTargets().slice(0, 500)) selection.add(target.chat_id);
    renderTargets();
  });
  on(find("target-selection-clear"), "click", () => {selection.clear(); renderTargets();});
  on(find("target-prev"), "click", () => {sourcePage--; renderTargets();});
  on(find("target-next"), "click", () => {sourcePage++; renderTargets();});
  on(find("target-bulk-apply"), "click", () => runSourceAction([...selection], find("target-bulk-action").value));
  on(find("target-list"), "change", event => {
    const checkbox = event.target.closest('[data-source-action="select"]');
    if (!checkbox) return;
    const id = Number(checkbox.dataset.chatId);
    if (!checkbox.checked) selection.delete(id);
    else if (selection.size < 500) selection.add(id);
    else toast(tr("Choose up to 500 sources at a time."), true);
    renderTargets();
  });
  on(find("target-list"), "click", event => {
    const button = event.target.closest("button[data-source-action]");
    if (!button) return;
    const target = getState().status?.targets.find(item => item.chat_id === Number(button.dataset.chatId));
    if (!target) return;
    button.closest("details")?.removeAttribute("open");
    let action = button.dataset.sourceAction;
    if (action === "toggle") action = target.enabled && sourceState(target, getState().status) !== "excluded" ? "pause" : "enable";
    if (action === "star") action = target.priority ? "regular" : "priority";
    runSourceAction([target.chat_id], action);
  });

  function matchingDialogs() {
    const term = find("dialog-search").value.trim().toLocaleLowerCase(), kind = find("dialog-kind").value;
    return getState().dialogs.filter(item => (item.title + " " + item.chat_id).toLocaleLowerCase().includes(term)
      && (!kind || kindType[item.kind] === kind));
  }

  function renderDialogRefresh() {
    const status = getState().status;
    if (!status || getState().view !== "sources") return;
    const button = find("load-dialogs"), disabled = status.demo || !may("sources") || !status.collector.has_session;
    button.disabled = disabled || dialogLoading || sourceBusy;
    button.textContent = tr(dialogLoading ? "Refreshing…" : "Refresh chat list");
    button.setAttribute("aria-busy", String(dialogLoading));
    button.title = !status.collector.has_session && !status.demo ? tr("Connect your Telegram account first") : "";
    const note = find("dialog-refresh-status");
    note.textContent = dialogLoading ? tr("Refreshing chat list… Saved sources remain available.")
      : dialogError ? tr("Chat list could not be refreshed: {error}", {error: dialogError})
        : dialogRefreshedAt ? tr("Last refreshed in this session: {time}", {time: context.formatTime(dialogRefreshedAt)})
          : tr("Not refreshed in this session.");
    note.classList.toggle("source-refresh-error", !!dialogError && !dialogLoading);
    find("dialog-refresh-progress").hidden = !dialogLoading;
    find("dialog-refresh-retry").hidden = !dialogError || dialogLoading;
    find("dialog-refresh-retry").disabled = disabled || sourceBusy;
  }

  function renderDialogs() {
    const state = getState(), status = state.status;
    if (!status || state.view !== "sources") return;
    find("available-card").hidden = !dialogOpen;
    find("target-card").hidden = dialogOpen;
    if (!dialogOpen) return;
    const enabled = new Set(status.targets.filter(target => target.enabled
      && !status.scope?.exclude.includes(target.chat_id)).map(target => target.chat_id));
    const available = new Set(state.dialogs.map(item => item.chat_id));
    for (const id of selectedDialogs) if (!available.has(id) || enabled.has(id)) selectedDialogs.delete(id);
    const matches = matchingDialogs();
    dialogPage = Math.min(dialogPage, Math.max(0, Math.ceil(matches.length / pageSize) - 1));
    const visible = matches.slice(dialogPage * pageSize, (dialogPage + 1) * pageSize);
    const version = JSON.stringify(visible.map(item => ({...item, selected: enabled.has(item.chat_id)})));
    const list = find("dialog-list");
    if (version !== dialogVersion) {
      const focused = list.contains(root.ownerDocument.activeElement)
        ? root.ownerDocument.activeElement.dataset.dialogFocus : null;
      const fragment = root.ownerDocument.createDocumentFragment();
      for (const item of visible) {
        const row = element("div", "target-row"), chosen = enabled.has(item.chat_id);
        const checkbox = element("input", "source-select");
        checkbox.type = "checkbox"; checkbox.dataset.chatId = String(item.chat_id);
        checkbox.dataset.dialogFocus = item.chat_id + ":select";
        checkbox.setAttribute("aria-label", tr("Select {name}", {name: item.title}));
        checkbox.hidden = chosen;
        const info = element("div", "available-source-name");
        info.append(element("strong", "", item.title), element("p", "hint",
          context.termText(item.kind) + " · " + item.chat_id));
        const add = element("button", "secondary small", tr(chosen ? "Selected" : "Add source"));
        add.type = "button"; add.dataset.dialogAdd = String(item.chat_id);
        add.dataset.dialogFocus = item.chat_id + ":add"; add.dataset.chosen = String(chosen);
        row.append(checkbox, info, add); fragment.append(row);
      }
      if (!visible.length) fragment.append(element("p", "hint", tr("No available chats match this search.")));
      list.replaceChildren(fragment); dialogVersion = version;
      if (focused) [...list.querySelectorAll("[data-dialog-focus]")].find(node => node.dataset.dialogFocus === focused)
        ?.focus({preventScroll: true});
    }
    const blocked = status.demo || !may("sources") || sourceBusy || dialogLoading;
    list.querySelectorAll("input").forEach(node => {
      node.checked = selectedDialogs.has(Number(node.dataset.chatId)); node.disabled = blocked;
    });
    list.querySelectorAll("button").forEach(node => node.disabled = blocked || node.dataset.chosen === "true");
    const addable = matches.filter(item => !enabled.has(item.chat_id));
    find("dialog-add-selected").disabled = blocked || !selectedDialogs.size;
    find("dialog-add-selected").textContent = tr("Add selected") + " · " + selectedDialogs.size;
    find("dialog-add-matching").disabled = blocked || !addable.length || addable.length > 500;
    find("dialog-add-matching").textContent = tr("Add all matching") + " · " + addable.length;
    find("dialog-limit").textContent = (dialogResult?.may_be_truncated
      ? tr("First {n} chats inspected; more may exist.", {n: dialogResult.limit})
      : tr("Showing the chats already available to this account."))
      + (addable.length > 500 ? " " + tr("Narrow the filters to add up to 500 sources at a time.") : "");
    find("dialog-page-count").textContent = matches.length ? tr("{from}–{to} of {total}", {
      from: dialogPage * pageSize + 1, to: Math.min((dialogPage + 1) * pageSize, matches.length), total: matches.length}) : "";
    find("dialog-prev").disabled = blocked || dialogPage === 0;
    find("dialog-next").disabled = blocked || (dialogPage + 1) * pageSize >= matches.length;
  }

  async function loadDialogs() {
    const status = getState().status;
    if (!status || status.demo || !may("sources") || !status.collector.has_session || dialogLoading || sourceBusy) return;
    const current = getSession(), attempt = ++dialogAttempt, profile = getState().profile;
    dialogLoading = true; dialogError = ""; autoRequested = true;
    showTab("chats"); renderDialogRefresh(); renderDialogs(); renderTargets();
    try {
      const result = await json("dialogs", undefined, {profile});
      if (current !== getSession() || attempt !== dialogAttempt) return;
      context.setDialogs(result); dialogResult = result; dialogRefreshedAt = new Date().toISOString(); dialogOpen = true;
      if (getState().view === "sources") {renderDialogs(); context.renderScope();}
      await refreshStatus();
    } catch (error) {
      if (current !== getSession() || attempt !== dialogAttempt || error.name === "StaleView") return;
      dialogError = error.message;
    } finally {
      if (current === getSession() && attempt === dialogAttempt) {
        dialogLoading = false; renderDialogRefresh(); renderDialogs(); renderTargets();
      }
    }
  }
  on(find("load-dialogs"), "click", loadDialogs);
  on(find("dialog-refresh-retry"), "click", loadDialogs);
  for (const id of ["dialog-search", "dialog-kind"])
    on(find(id), id === "dialog-search" ? "input" : "change", () => {dialogPage = 0; renderDialogs();});
  on(find("dialog-prev"), "click", () => {dialogPage--; renderDialogs();});
  on(find("dialog-next"), "click", () => {dialogPage++; renderDialogs();});
  on(find("dialog-add-selected"), "click", () => runSourceAction([...selectedDialogs], "enable"));
  on(find("dialog-add-matching"), "click", () => {
    const status = getState().status;
    const enabled = new Set(status.targets.filter(item => item.enabled && !status.scope?.exclude.includes(item.chat_id))
      .map(item => item.chat_id));
    runSourceAction(matchingDialogs().filter(item => !enabled.has(item.chat_id)).map(item => item.chat_id), "enable");
  });
  on(find("dialog-list"), "change", event => {
    const checkbox = event.target.closest("input.source-select");
    if (!checkbox) return;
    const id = Number(checkbox.dataset.chatId);
    if (!checkbox.checked) selectedDialogs.delete(id);
    else if (selectedDialogs.size < 500) selectedDialogs.add(id);
    else toast(tr("Choose up to 500 sources at a time."), true);
    renderDialogs();
  });
  on(find("dialog-list"), "click", event => {
    const button = event.target.closest("button[data-dialog-add]");
    if (button) runSourceAction([Number(button.dataset.dialogAdd)], "enable");
  });
  on(find("finish-source-selection"), "click", () => {
    dialogOpen = false; renderDialogs(); context.focusObservation();
  });

  function updateStatus(status) {
    if (!status) return;
    if (session !== getSession()) resetSession();
    const latest = {
      monitoring: Object.fromEntries(monitoring.map(key => [key, status.monitoring?.[key] ?? true])),
      capture: copy(status.capture),
      recheck: copy(status.recheck),
    };
    for (const group of Object.keys(dirty)) {
      if (!baseline || !dirty[group] || !allowed(group)) write(group, latest[group]);
      find(group === "monitoring" ? "monitoring-form" : group === "capture" ? "capture-form" : "recheck-form")
        .querySelectorAll("input,select,button").forEach(element => element.disabled = !allowed(group));
    }
    baseline = latest;
    const enabled = monitoring.filter(key => latest.monitoring[key]);
    find("monitoring-current").textContent = tr("Saved for this account: {list}.", {
      list: enabled.length ? enabled.map(key => context.termText(key)).join(", ") : tr("no live event categories"),
    });
    find("sources-scope-summary").textContent = context.scopeName(status.scope?.mode || "selected");
    find("sources-count-summary").textContent = tr("{n} enabled sources", {n: status.targets.filter(item => item.enabled).length});
    find("sources-recording-summary").textContent = tr(status.collector.running ? "Observation enabled" : "Observation paused");
    find("sources-tab-count").textContent = String(status.targets.length);
    const note = find("recording-result");
    if (status.demo) note.textContent = tr("This demo is read-only. Recording settings can be changed in your own workspace.");
    else if (!permission("monitoring") && !permission("recheck")) note.textContent = tr("This access cannot change recording settings.");
    renderDraft();
    if (getState().view === "sources") {
      renderTargets(); renderDialogRefresh(); renderDialogs();
      if (!autoRequested && !status.demo && status.collector.has_session && !status.targets.length) loadDialogs();
    }
  }

  on(form, "input", event => {
    if (event.target.id === "max-media")
      for (const [key] of media) find("media-max-" + key).value = event.target.value;
    find("recording-result").textContent = "";
    renderDraft();
  });
  on(form, "change", renderDraft);
  for (const button of root.querySelectorAll("[data-monitor-preset]")) {
    on(button, "click", () => {
      if (!allowed("monitoring")) return;
      for (const key of monitoring)
        find("monitor-" + key).checked = button.dataset.monitorPreset === "all" || ["messages", "edits", "deletions"].includes(key);
      renderDraft();
    });
  }
  on(find("recording-discard"), "click", () => {
    if (saving || !baseline) return;
    for (const group of Object.keys(dirty)) write(group, baseline[group]);
    clearValidation();
    find("recording-result").textContent = tr("Changes discarded.");
    renderDraft();
  });

  on(form, "submit", async event => {
    event.preventDefault();
    if (saving || !baseline || !form.reportValidity()) return;
    renderDraft();
    const draft = read(), payload = Object.fromEntries(Object.keys(dirty).filter(group => dirty[group])
      .map(group => [group, draft[group]]));
    if (!Object.keys(payload).length) return;
    const current = getSession(), attempt = ++generation, profile = getState().profile;
    saving = true; renderDraft();
    try {
      const result = await json("recording", payload, {profile});
      if (current !== getSession() || attempt !== generation) return;
      baseline = {monitoring: result.monitoring, capture: result.capture, recheck: result.recheck};
      context.saved(result);
      renderDraft();
      await refreshStatus();
      if (current !== getSession() || attempt !== generation) return;
      const message = Object.values(dirty).some(Boolean)
        ? tr("Settings saved. Newer edits are still unsaved.")
        : tr("Recording settings saved.");
      find("recording-result").textContent = message;
      toast(message);
    } catch (error) {
      if (current !== getSession() || attempt !== generation || error.name === "StaleView") return;
      find("recording-result").textContent = error.message;
      toast(error.message, true);
    } finally {
      if (current === getSession() && attempt === generation) {saving = false; renderDraft();}
    }
  });

  function resetSession() {
    generation++; session = getSession(); baseline = null; saving = false;
    dirty = {monitoring: false, capture: false, recheck: false};
    selection.clear(); sourcePage = 0; sourceBusy = false; sourceAttempt++; rowsVersion = "";
    selectedDialogs.clear(); dialogPage = 0; dialogVersion = ""; dialogOpen = false; dialogAttempt++;
    dialogLoading = false; dialogError = ""; dialogResult = null; dialogRefreshedAt = null; autoRequested = false;
    for (const id of ["target-search", "target-filter", "target-kind"]) find(id).value = "";
    find("target-sort").value = "name"; find("target-bulk-actions").hidden = true;
    find("dialog-search").value = ""; find("dialog-kind").value = ""; find("available-card").hidden = true;
    find("target-card").hidden = false;
    find("dialog-refresh-status").textContent = tr("Not refreshed in this session.");
    find("dialog-refresh-retry").hidden = find("dialog-refresh-progress").hidden = true;
    find("target-card").setAttribute("aria-busy", "false");
    for (const id of ["target-match-count", "target-selection-count", "target-page-count", "dialog-page-count", "dialog-limit"])
      find(id).textContent = "";
    find("source-action-result").textContent = "";
    context.setDirty({...dirty}); form.reset(); clearValidation(); find("recording-result").textContent = "";
    find("recording-save").disabled = find("recording-discard").disabled = true;
    find("recording-tab-dirty").hidden = true;
    for (const id of ["target-list", "dialog-list", "scope-exclude"])
      find(id)?.replaceChildren();
    for (const id of ["sources-scope-summary", "sources-count-summary", "sources-recording-summary"])
      find(id).textContent = "";
    find("sources-tab-count").textContent = "0";
    showTab("scope");
  }
  return {
    enter({params} = {}) {showTab(params?.tab || tab); updateStatus(getState().status);},
    updateStatus, showTab, renderTargets, loadDialogs, runSourceAction,
    filterTargets(value) {
      showTab("chats"); find("target-search").value=""; find("target-kind").value="";
      find("target-filter").value=value; sourcePage=0; renderTargets();
    },
    leave() {},
    resetSession,
    destroy() {generation++; listeners.abort();},
  };
}
