const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const groupNames = {collection: "Collection", recheck: "Recheck", attachments: "Media", people: "People",
  notifications: "Notifications", exports: "Exports", connection: "Telegram", proxies: "MTProxy"};

export function createParameters(context) {
  const {root, tr, getState, getSession, json, may, toast, refreshStatus} = context;
  const find = id => root.querySelector("#" + id), form = find("parameters-form");
  const listeners = new AbortController(), fields = new Map(), groups = new Map();
  let session = getSession(), catalog = null, request = 0, saving = false, schema = "", selected = "collection";
  let pending = null, resetPlan = null;
  const unavailableDrafts = new Map();
  const on = (node, event, fn) => node.addEventListener(event, fn, {signal: listeners.signal});
  const active = () => getState().view === "parameters";
  const allowed = () => may("settings") && !getState().status?.demo;
  const make = (tag, className = "", text = "") => {
    const node = root.ownerDocument.createElement(tag); node.className = className; node.textContent = text; return node;
  };
  const raw = entry => entry.item.kind === "bool" ? entry.field.checked : entry.field.value;
  const value = entry => entry.item.kind === "bool" ? entry.field.checked : entry.item.kind === "lines"
    ? entry.field.value.split("\n").map(line => line.trim()).filter(Boolean)
    : entry.field.value.trim() ? Number(entry.field.value) : NaN;
  const write = (entry, next) => {
    if (entry.item.kind === "bool") entry.field.checked = next;
    else entry.field.value = entry.item.kind === "lines" ? next.join("\n") : String(next);
  };
  const formatted = value => Array.isArray(value) ? tr(value.length === 1 ? "1 line" : "{n} lines", {n: value.length})
    : typeof value === "boolean" ? tr(value ? "On" : "Off") : Number(value).toLocaleString();
  const draft = () => Object.fromEntries([...fields].filter(([, entry]) => !equal(value(entry), entry.item.value))
    .map(([key, entry]) => [key, value(entry)]));

  function problem(entry) {
    if (entry.serverError) return entry.serverError;
    if (entry.item.kind !== "int") return "";
    const number = Number(entry.field.value);
    return !entry.field.value.trim() || !Number.isInteger(number) || number < entry.item.low || number > entry.item.high
      ? tr("Enter a whole number from {low} to {high}.", {
        low: entry.item.low.toLocaleString(), high: entry.item.high.toLocaleString()}) : "";
  }

  function impact(entry) {
    if (problem(entry)) return "";
    const number = value(entry);
    if (entry.item.key === "dialog_limit" && number > entry.item.default)
      return tr("A larger chat list takes more Telegram requests and longer to refresh. This does not download message history.");
    if (entry.item.key === "scope_refresh_minutes" && number < entry.item.default)
      return tr("More frequent list refreshes mean more Telegram requests. Repeated manual refreshes add to that work.");
    if (entry.item.key === "startup_buffer")
      return tr("This is a memory buffer for updates arriving during startup, not a history-import limit. A larger buffer needs more RAM.");
    if (entry.item.key === "proxy_rotate_hours" && number > 0)
      return tr("Automatic MTProxy mode only. A planned switch reconnects the account even while its current proxy works. It does not remove Telegram rate limits.");
    return "";
  }

  function offset() {
    root.style.setProperty("--parameters-top", Math.max(0, context.headerOffset?.() || 0) + "px");
    root.style.setProperty("--parameters-group-top", ((context.headerOffset?.() || 0)
      + find("parameters-toolbar").getBoundingClientRect().height + 16) + "px");
  }

  function filter() {
    const query = find("parameters-search").value.trim().toLocaleLowerCase(), changed = find("parameters-changed").checked;
    let total = 0;
    for (const [id, group] of groups) {
      let count = 0;
      for (const entry of group.entries) {
        entry.row.hidden = !!(query && !entry.search.includes(query) || changed && !entry.row.classList.contains("changed"));
        if (!entry.row.hidden) count++;
      }
      total += count; group.card.hidden = group.link.hidden = !count;
      group.link.setAttribute("aria-current", id === selected ? "location" : "false");
    }
    find("parameters-count").textContent = tr("{shown} of {total} parameters", {shown: total, total: fields.size});
    find("parameters-empty").hidden = !!total || !catalog;
    offset();
  }

  function selectSection(id, {record = true, scroll = true} = {}) {
    if (!groups.has(id)) return false;
    selected = id; if (record) context.sectionChanged?.(id); filter();
    if (scroll) groups.get(id).card.scrollIntoView({block: "start", behavior: "instant"});
    return true;
  }

  function renderDraft() {
    if (!catalog || !active()) return;
    let count = 0, invalid = 0;
    for (const entry of fields.values()) {
      const changed = !equal(value(entry), entry.item.default);
      entry.row.classList.toggle("changed", changed);
      entry.resetWrap.hidden = entry.marker.hidden = !changed; entry.reset.disabled = !allowed() || saving;
      entry.field.disabled = !allowed();
      const error = problem(entry); invalid += Number(!!error);
      entry.error.textContent = error; entry.error.hidden = !error;
      const effect = impact(entry); entry.impact.textContent = effect; entry.impact.hidden = !effect;
      entry.row.classList.toggle("invalid", !!error);
      if (error) entry.field.setAttribute("aria-invalid", "true"); else entry.field.removeAttribute("aria-invalid");
      if (!equal(value(entry), entry.item.value)) count++;
    }
    const total = count + unavailableDrafts.size;
    context.setDirty(!!total);
    find("parameters-change-count").textContent = total
      ? tr(total === 1 ? "1 unsaved change" : "{n} unsaved changes", {n: total}) : tr("No unsaved changes");
    find("parameters-unsaved").textContent = invalid
      ? tr(invalid === 1 ? "Fix 1 invalid value to save." : "Fix {n} invalid values to save.", {n: invalid})
      : saving ? tr("Saving parameters…") : "";
    find("parameters-save").disabled = !allowed() || saving || !count || !!invalid;
    find("parameters-review-invalid").hidden = !invalid;
    find("parameters-save").textContent = tr(saving ? "Saving…" : "Save parameters");
    find("parameters-discard").disabled = !allowed() || saving || !total;
    find("parameters-savebar").classList.toggle("is-dirty", !!total);
    const changedDefaults = [...fields.values()].some(entry => !equal(value(entry), entry.item.default));
    find("parameters-reset").disabled = !allowed() || saving || !changedDefaults;
    if (!allowed()) {find("parameters-reset-dialog").close(); resetPlan = null;}
    for (const group of groups.values()) {
      const changed = group.entries.filter(entry => !equal(value(entry), entry.item.default)).length;
      group.count.hidden = !changed; group.count.textContent = String(changed);
    }
    filter();
  }

  function build(data) {
    fields.clear(); groups.clear(); find("parameters-groups").replaceChildren(); find("parameters-nav").replaceChildren();
    for (const group of data.groups) {
      const card = make("section", "card padded parameters-group"), grid = make("div", "parameters-grid");
      card.id = "parameters-group-" + group.id;
      card.append(make("h2", "", tr(groupNames[group.id] || group.title)), make("p", "muted", tr(group.description)), grid);
      if (group.id === "recheck") {
        const note = make("details", "parameters-rate-note"); note.id = "parameters-floodwait";
        note.append(make("summary", "", tr("What is FloodWait?")), make("p", "hint",
          tr("FloodWait is Telegram asking the account to wait before another request. Larger batches and shorter pauses can cause more of these waits. Changing proxies does not remove the limit.")));
        grid.before(note);
      }
      const link = make("a", "", tr(groupNames[group.id] || group.title)), count = make("span", "parameters-nav-count");
      link.href = context.sectionHref?.(group.id) || "#" + card.id; link.dataset.parameterGroup = group.id;
      count.hidden = true; link.append(count); find("parameters-nav").append(link);
      const entryGroup = {card, link, count, entries: []}; groups.set(group.id, entryGroup);
      for (const item of group.items) {
        const row = make("div", "parameter-row"), id = "parameter-" + item.key;
        const label = make("label", item.kind === "bool" ? "check-label" : "", tr(item.label)); label.htmlFor = id;
        const field = make(item.kind === "lines" ? "textarea" : "input");
        field.id = id; field.dataset.parameter = item.key;
        if (item.kind === "bool") {field.type = "checkbox"; label.prepend(field); row.append(label);}
        else {
          const line = make("div", "parameter-field");
          if (item.kind === "lines") {field.rows = 3; field.spellcheck = false;}
          else Object.assign(field, {type: "number", min: item.low, max: item.high, step: 1, required: true});
          line.append(field); if (item.unit) line.append(make("span", "unit", tr(item.unit))); row.append(label, line);
        }
        const marker = make("span", "parameter-changed", tr("Changed")); label.append(marker);
        if (item.help) {const help = make("p", "hint", tr(item.help)); help.id = id + "-help"; row.append(help);}
        const meta = make("p", "hint parameter-meta", [item.kind === "int"
          ? tr("Range: {low}–{high} {unit}", {low: item.low.toLocaleString(), high: item.high.toLocaleString(), unit: tr(item.unit)}) : "",
          tr("Default: {value}", {value: formatted(item.default) + (item.kind === "int" && item.unit ? " " + tr(item.unit) : "")})].filter(Boolean).join(" · "));
        meta.id = id + "-meta";
        const reset = make("button", "text-link", tr("Restore default")); reset.type = "button"; reset.dataset.parameterReset = item.key;
        reset.setAttribute("aria-label", tr("Restore default for {name}", {name: tr(item.label)}));
        const resetWrap = make("span", "parameter-reset"); resetWrap.append(" · ", reset); meta.append(resetWrap);
        const error = make("p", "parameter-error"); error.id = id + "-parameter-error"; error.hidden = true; error.setAttribute("aria-live", "polite");
        const effect = make("p", "parameter-impact"); effect.id = id + "-impact"; effect.hidden = true;
        field.setAttribute("aria-describedby", [meta.id, item.help ? id + "-help" : "", error.id, effect.id].filter(Boolean).join(" "));
        row.append(meta, error, effect); grid.append(row);
        const entry = {item, field, row, reset, resetWrap, marker, error, impact: effect, serverError: "", search: [item.key, item.label, item.help, tr(item.label), tr(item.help || ""),
          group.id, tr(groupNames[group.id] || group.title)].join(" ").toLocaleLowerCase()};
        fields.set(item.key, entry); entryGroup.entries.push(entry); write(entry, item.value);
      }
      find("parameters-groups").append(card);
    }
  }

  function accept(data, submitted = null) {
    if (!active()) {pending = {data, submitted}; context.saved(data); return;}
    const nextSchema = JSON.stringify(data.groups.map(group => ({id: group.id, items: group.items.map(({value, ...item}) => item)})));
    if (nextSchema !== schema) {
      const edits = [...fields].filter(([key, entry]) => submitted
        ? !equal(raw(entry), submitted[key]) : !equal(value(entry), entry.item.value))
        .map(([key, entry]) => ({key, kind: entry.item.kind, label: entry.item.label, raw: raw(entry)}));
      const focused = root.contains(root.ownerDocument.activeElement) ? root.ownerDocument.activeElement.dataset.parameter : null;
      build(data); schema = nextSchema;
      for (const [key, edit] of unavailableDrafts) if (fields.get(key)?.item.kind === edit.kind) {
        if (edit.kind === "bool") fields.get(key).field.checked = edit.raw; else fields.get(key).field.value = edit.raw;
        unavailableDrafts.delete(key);
      }
      for (const edit of edits) {
        const entry = fields.get(edit.key);
        if (entry && entry.item.kind === edit.kind) {
          if (edit.kind === "bool") entry.field.checked = edit.raw; else entry.field.value = edit.raw;
        } else unavailableDrafts.set(edit.key, edit);
      }
      const warning = find("parameters-catalog-warning"); warning.hidden = !unavailableDrafts.size;
      warning.textContent = unavailableDrafts.size ? tr("These edited parameters changed or disappeared from this version. They were not saved:")
        + "\n" + [...unavailableDrafts.values()].map(edit => tr(edit.label) + ": " + String(edit.raw)).join("\n") : "";
      if (focused && fields.has(focused)) fields.get(focused).field.focus({preventScroll: true});
      if (!groups.has(selected)) selected = groups.keys().next().value;
    }
    else for (const group of data.groups) for (const item of group.items) {
      const entry = fields.get(item.key);
      if (submitted ? equal(raw(entry), submitted[item.key]) : equal(value(entry), entry.item.value)) write(entry, item.value);
      entry.item = item;
    }
    catalog = data; context.saved(data); renderDraft();
  }

  async function load({signal, current = active} = {}) {
    if (!active()) return;
    if (session !== getSession()) resetSession();
    if (pending) {const next = pending; pending = null; accept(next.data, next.submitted);}
    if (saving) {renderDraft(); return;}
    const mine = ++request, now = getSession(), profile = getState().profile;
    find("parameters-result").textContent = catalog ? "" : tr("Loading parameters…");
    try {
      const result = await json("parameters", undefined, {profile, signal});
      if (mine !== request || now !== getSession() || !current()) return;
      accept(result); find("parameters-result").textContent = "";
      if (getState().parameterSection) selectSection(getState().parameterSection, {record: false, scroll: false});
    } catch (error) {
      if (mine !== request || now !== getSession() || !current() || error.name === "AbortError" || error.name === "StaleView") return;
      find("parameters-result").textContent = error.message; throw error;
    }
  }

  on(find("parameters-search"), "input", filter); on(find("parameters-changed"), "change", filter);
  on(find("parameters-clear-search"), "click", () => {
    find("parameters-search").value = ""; find("parameters-changed").checked = false; filter(); find("parameters-search").focus();
  });
  on(find("parameters-nav"), "click", event => {
    const link = event.target.closest("a[data-parameter-group]"); if (!link) return;
    event.preventDefault(); selectSection(link.dataset.parameterGroup);
  });
  on(form, "input", event => {
    const entry = fields.get(event.target.dataset.parameter); if (entry) entry.serverError = "";
    // The shared native-validation listener runs first; this view owns its inline result.
    queueMicrotask(renderDraft);
  });
  on(form, "click", event => {
    const button = event.target.closest("button[data-parameter-reset]"); if (!button || !allowed() || saving) return;
    const entry = fields.get(button.dataset.parameterReset); entry.serverError = ""; write(entry, entry.item.default); renderDraft();
    (entry.row.hidden ? find("parameters-search") : entry.field).focus();
  });
  on(form, "submit", async event => {
    event.preventDefault(); if (!catalog || !allowed() || saving) return;
    const invalid = [...fields.values()].find(entry => problem(entry));
    if (invalid) {renderDraft(); invalid.field.focus(); return;}
    const values = draft(); if (!Object.keys(values).length) return;
    const submitted = Object.fromEntries([...fields].map(([key, entry]) => [key, raw(entry)]));
    const now = getSession(), profile = getState().profile; request++; saving = true; renderDraft();
    try {
      const result = await json("parameters", {values}, {profile});
      if (now !== getSession()) return;
      accept(result, submitted); await refreshStatus();
      if (now !== getSession()) return;
      const message = active() && Object.keys(draft()).length
        ? tr("Parameters saved. Newer edits are still unsaved.") : tr("Parameters saved and recorded in the signed journal.");
      if (active()) find("parameters-result").textContent = message;
      toast(message);
    } catch (error) {
      if (now !== getSession() || error.name === "StaleView") return;
      const entry = fields.get(error.parameter);
      if (entry && equal(raw(entry), submitted[error.parameter])) {
        entry.serverError = error.message;
        if (active()) {find("parameters-search").value = ""; find("parameters-changed").checked = false; filter(); entry.field.focus();}
      }
      if (active()) find("parameters-result").textContent = error.message;
      toast(error.message, true);
    } finally {if (now === getSession()) {saving = false; renderDraft();}}
  });
  on(find("parameters-discard"), "click", () => {
    if (!allowed() || saving || !catalog) return;
    for (const entry of fields.values()) {write(entry, entry.item.value); entry.serverError = "";}
    unavailableDrafts.clear(); find("parameters-catalog-warning").hidden = true; find("parameters-catalog-warning").textContent = "";
    find("parameters-result").textContent = tr("Changes discarded."); renderDraft();
  });
  on(find("parameters-review-invalid"), "click", () => {
    const entry = [...fields.values()].find(item => problem(item)); if (!entry) return;
    find("parameters-search").value = ""; find("parameters-changed").checked = false; filter(); entry.field.focus();
  });
  const plannedDefaults = () => [...fields].filter(([, entry]) => !equal(value(entry), entry.item.default))
    .map(([key, entry]) => ({key, before: raw(entry), after: entry.item.default}));
  function showResetPlan() {
    resetPlan = {session: getSession(), changes: plannedDefaults()};
    const list = find("parameters-reset-list"); list.replaceChildren();
    for (const change of resetPlan.changes) {
      const entry = fields.get(change.key), item = make("li"), values = make("div", "parameters-reset-values");
      const before = entry.item.kind === "bool" ? formatted(change.before) : String(change.before).trim() || tr("Empty");
      const after = entry.item.kind === "lines" ? change.after.join("\n") || tr("Empty") : formatted(change.after);
      const unit = entry.item.kind === "int" && entry.item.unit ? " " + tr(entry.item.unit) : "";
      values.append(make("code", "", before + unit), make("span", "", "→"), make("code", "", after + unit));
      item.append(make("strong", "", tr(entry.item.label)), values); list.append(item);
    }
  }
  on(find("parameters-reset"), "click", () => {
    if (!allowed() || saving || !catalog) return;
    find("parameters-menu").open = false; find("parameters-reset-note").textContent = "";
    showResetPlan(); if (resetPlan.changes.length) find("parameters-reset-dialog").showModal();
  });
  on(find("parameters-reset-cancel"), "click", () => {resetPlan = null; find("parameters-reset-dialog").close();});
  on(find("parameters-reset-apply"), "click", () => {
    if (!resetPlan || resetPlan.session !== getSession() || !allowed() || saving) return;
    if (!equal(resetPlan.changes, plannedDefaults())) {
      showResetPlan(); find("parameters-reset-note").textContent = tr("Values changed while this dialog was open. Review the updated list."); return;
    }
    for (const change of resetPlan.changes) {
      const entry = fields.get(change.key); write(entry, entry.item.default); entry.serverError = "";
    }
    resetPlan = null; find("parameters-reset-dialog").close(); renderDraft();
    find("parameters-result").textContent = tr("Defaults prepared. Save parameters to apply them.");
    find("parameters-save").focus();
  });
  on(root.ownerDocument.defaultView, "resize", () => {if (active()) offset();});

  function resetSession() {
    request++; session = getSession(); saving = false; catalog = null; schema = ""; selected = "collection";
    pending = resetPlan = null; find("parameters-reset-dialog").close(); find("parameters-menu").open = false;
    unavailableDrafts.clear(); find("parameters-catalog-warning").hidden = true; find("parameters-catalog-warning").textContent = "";
    find("parameters-reset-list").replaceChildren(); find("parameters-reset-note").textContent = "";
    fields.clear(); groups.clear(); find("parameters-groups").replaceChildren(); find("parameters-nav").replaceChildren();
    find("parameters-search").value = ""; find("parameters-changed").checked = false;
    for (const id of ["parameters-count", "parameters-result", "parameters-unsaved"]) find(id).textContent = "";
    find("parameters-change-count").textContent = tr("No unsaved changes");
    find("parameters-save").disabled = find("parameters-discard").disabled = true;
    find("parameters-review-invalid").hidden = true;
    context.setDirty(false); context.saved(null);
  }
  return {load, enter: load, selectSection, updateStatus() {if (active()) renderDraft();},
    leave() {request++; find("parameters-reset-dialog").close(); resetPlan = null;}, resetSession,
    destroy() {request++; listeners.abort();}};
}
