(() => {
  "use strict";
  // Proxy servers of the automatic MTProxy route: checks, countries, lists and the GitHub search.
  let view = null, timer = null, limit = 150, request = 0, generation = 0, pending = 0;
  let mutations = Promise.resolve(), sourceKey = "";
  const draft = new Map();
  const fields = ["pool-github-search", "pool-github-query", "pool-github-max", "pool-countries"];
  const filter = {q: "", country: "", source: "", status: ""};
  const automatic = () => $("network-kind").value === "mtproxy_auto";
  const active = () => !!state.token && !!state.status && state.view === "connection" &&
    state.connectionSettings && automatic() && $("proxy-pool").open && !$("workspace").hidden && !$("workspace").inert;
  function sourceFields() {
    $("pool-sources").querySelector(".pool-search-fields").hidden =
      !view?.settings.github_token || !$("pool-github-search").checked;
    $("pool-github-status").hidden = !$("pool-github-search").checked;
  }
  function sync() {
    $("proxy-pool").hidden = !automatic();
    if (!automatic()) { stop(); return; }
    if (view) render();
    if (active()) load();
  }
  function stop() { clearTimeout(timer); timer = null; request++; }
  function clear() {
    stop(); generation++; view = null; pending = 0; mutations = Promise.resolve(); sourceKey = ""; draft.clear();
    $("pool-token").value = ""; $("pool-paste").value = ""; $("pool-url").value = "";
    $("pool-save-state").textContent = "";
    $("pool-stats").replaceChildren(); $("pool-rows").replaceChildren(); $("pool-count").textContent = "";
    for (const id of fields) if ($(id).type !== "checkbox") $(id).value = "";
    sourceFields();
  }
  function poll() {
    clearTimeout(timer);
    if (active() && !pending && view?.summary.checking) timer = setTimeout(load, 4000);
  }
  function controls() {
    const readOnly = !state.me?.admin || !!state.status?.demo;
    for (const field of $("pool-sources").querySelectorAll("input, select, button")) {
      const waiting = pending > 0 && (field.tagName === "BUTTON" || field.dataset.source);
      field.disabled = readOnly || !!waiting;
    }
    $("pool-github-search").disabled ||= !view?.settings.github_token;
    $("pool-token-remove").disabled ||= !view?.settings.github_token;
    $("pool-check").disabled = !!state.status?.demo || pending > 0 || !!view?.summary.checking;
    $("pool-update").disabled = readOnly || pending > 0;
    for (const button of $("pool-rows").querySelectorAll("button"))
      button.disabled = !!state.status?.demo || pending > 0 || !!state.status?.collector.running;
  }
  async function mutate(work) {
    const owner = generation, revision = state.workspaceRevision;
    const current = () => owner === generation && revision === state.workspaceRevision && !!state.token;
    pending++; stop(); controls();
    const operation = mutations.then(async () => {
      if (!current()) throw new StaleView();
      return work();
    });
    mutations = operation.catch(() => {});
    try { return await operation; }
    finally { if (current()) { pending--; if (view) render(); else controls(); poll(); } }
  }
  function runAction(button, work) {
    return busy(button, () => mutate(work)).finally(controls);
  }
  const flag = code => /^[A-Z]{2}$/.test(code || "") ? String.fromCodePoint(...[...code].map(c => 127397 + c.charCodeAt(0))) : "";
  function countryName(code) {
    try { return new Intl.DisplayNames([document.documentElement.lang || "en"], {type: "region"}).of(code) || code; }
    catch { return code; }
  }
  const speed = ms => ms == null ? "" : ms < 350 ? "fast" : ms < 900 ? "medium" : "slow";
  const STATUS = {ok: "Answering", resting: "Resting", untested: "Not checked"};

  async function load() {
    clearTimeout(timer);
    $("proxy-pool").hidden = !automatic();
    if (!active() || pending) return;
    if (state.status.demo) { demo(); return; }
    const profile = state.profile, revision = state.workspaceRevision, serial = ++request;
    try {
      const result = await json("network/proxies");
      if (profile !== state.profile || serial !== request || !active()) return;
      view = result; render();
      poll();
    } catch (error) {
      if (serial !== request || revision !== state.workspaceRevision || error instanceof StaleView || !active()) return;
      $("pool-count").textContent = error.message;
      poll();
    }
  }

  function demo() {
    $("pool-stats").replaceChildren();
    $("pool-rows").replaceChildren();
    $("pool-count").textContent = tr("Available in your own workspace");
    for (const id of ["pool-check", "pool-update", "pool-save", "pool-token-save", "pool-token-remove"]) $(id).disabled = true;
    sourceFields();
  }

  function tile(label, value, tone) {
    const box = node("div", "pool-stat" + (tone ? " " + tone : ""));
    box.append(node("strong", "", value), node("span", "", label));
    return box;
  }

  function renderStats() {
    const s = view.summary, box = $("pool-stats");
    box.replaceChildren(
      tile(tr("Listed"), s.listed.toLocaleString()),
      tile(tr("Answering"), s.ok.toLocaleString(), s.ok ? "good" : "warn"),
      tile(tr("Resting"), s.resting.toLocaleString(), s.resting ? "warn" : ""),
      tile(tr("Median ping"), s.median_ms ? s.median_ms + " " + tr("ms") : "—", speed(s.median_ms)),
      tile(tr("Countries"), s.countries.toLocaleString()),
      tile(tr("Last check"), s.checking ? tr("Checking now…") : s.checked_at ?
        new Date(s.checked_at * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"}) : tr("Not yet")));
    $("pool-check").disabled = s.checking;
    let note = $("pool-note");
    if (!note) { note = node("p", "hint pool-note"); note.id = "pool-note"; box.after(note); }
    note.textContent = view.download_problem ? tr(view.download_problem) + " " +
      tr("List updates and country lookups wait for it; checks of the servers themselves still run.") :
      !view.settings.countries ? tr("Country lookups are switched off under Lists and sources.") : "";
    note.hidden = !note.textContent;
  }

  function options(select, items, all) {
    const expected = [["", all], ...items];
    if (select.options.length === expected.length && expected.every(([value, label], i) =>
      select.options[i].value === value && select.options[i].text === label)) return;
    const previous = select.value;
    select.replaceChildren(new Option(all, ""));
    for (const [value, label] of items) select.append(new Option(label, value));
    select.value = items.some(([value]) => value === previous) ? previous : "";
  }

  function matches(row) {
    const q = filter.q.trim().toLowerCase();
    if (filter.country && row.country !== filter.country) return false;
    if (filter.source && row.source !== filter.source) return false;
    if (filter.status && row.status !== filter.status) return false;
    if (!q) return true;
    return [row.host, String(row.port), row.label || "", row.country || "", row.country ? countryName(row.country) : "",
            ...(row.used_by || [])].some(text => text.toLowerCase().includes(q));
  }

  function order(a, b) {
    const rank = r => r.status === "ok" ? 0 : r.status === "untested" ? 1 : 2;
    return rank(a) - rank(b) || (a.latency_ms ?? 1e9) - (b.latency_ms ?? 1e9) || a.host.localeCompare(b.host);
  }

  function renderTable() {
    const body = $("pool-rows"), rows = view.rows.filter(matches).sort(order), shown = rows.slice(0, limit);
    body.replaceChildren();
    for (const row of shown) {
      const tr_ = node("tr", "pool-row " + row.status);
      const country = node("td", "pool-country");
      if (row.country) {
        country.title = countryName(row.country);
        country.append(node("span", "pool-flag", flag(row.country)), node("span", "pool-code", row.country));
      } else country.append(node("span", "muted", "—"));
      const server = node("td", "pool-server"); server.append(node("code", "", row.host + ":" + row.port));
      const ping = node("td", "pool-ping");
      if (row.latency_ms) {
        const bar = node("span", "pool-bar " + speed(row.latency_ms)), fill = node("i");
        fill.style.width = Math.max(6, Math.min(100, 100 - row.latency_ms / 15)) + "%";
        bar.append(fill); ping.append(bar, node("span", "pool-ms", row.latency_ms + " " + tr("ms")));
      } else ping.append(node("span", "muted", "—"));
      const status = node("td"), pill = node("span", "pool-pill " + row.status, tr(STATUS[row.status]));
      if (row.status === "resting" && row.error_type) pill.title = row.error_type + " · " + trn("{n} failure", "{n} failures", row.failures);
      status.append(pill);
      const source = node("td", "pool-source-cell", row.label || row.source || "—");
      const users = node("td", "pool-users", (row.used_by || []).join(", ") || "—");
      const action = node("td"), use = node("button", "text-link", tr("Use"));
      use.type = "button"; use.disabled = state.status.collector.running;
      use.title = tr("Save this server as this workspace's route");
      use.addEventListener("click", () => runAction(use, async () => {
        await json("network/catalog/" + encodeURIComponent(row.id), {});
        await routeSaved();
      }));
      action.append(use);
      tr_.append(country, server, ping, status, source, users, action);
      body.append(tr_);
    }
    if (!rows.length) {
      const empty = node("tr"), cell = node("td", "pool-empty", view.rows.length ? tr("No server matches these filters.") :
        tr("No servers yet. Update the lists or add your own below."));
      cell.colSpan = 7; empty.append(cell); body.append(empty);
    }
    $("pool-count").textContent = tr("{shown} of {total} servers", {shown: shown.length.toLocaleString(), total: rows.length.toLocaleString()});
    show("pool-more", rows.length > shown.length);
  }

  function sourceRow(source, own) {
    const row = node("div", "pool-source-item" + (source.enabled ? "" : " off"));
    const toggle = node("input"); toggle.type = "checkbox"; toggle.checked = source.enabled;
    toggle.dataset.source = source.id; toggle.dataset.own = own ? "1" : "";
    toggle.setAttribute("aria-label", tr("Use this list"));
    const text = node("div", "pool-source-text"), title = source.homepage ? node("a", "", source.label) : node("strong", "", source.label);
    if (source.homepage) { title.href = source.homepage; title.target = "_blank"; title.rel = "noopener noreferrer"; }
    const detail = source.fetched_at ? tr("Saved {date} · {n} compatible", {date: formatTime(source.fetched_at), n: source.compatible}) :
      source.kind === "github" ? tr("Runs with the next list update") : tr("No saved list yet");
    text.append(title, node("span", "hint", (source.kind === "list" ? tr("Uploaded list") + " · " : "") + detail));
    row.append(toggle, text);
    if (own) {
      const remove = node("button", "quiet small", tr("Remove")); remove.type = "button"; remove.dataset.remove = source.id;
      row.append(remove);
    }
    return row;
  }

  function renderSources() {
    const settings = view.settings, own = new Set(settings.custom.map(item => item.id));
    const bundled = $("pool-bundled"), mine = $("pool-own");
    const nextKey = JSON.stringify([view.sources, [...own]]);
    if (nextKey !== sourceKey) {
      bundled.replaceChildren(...view.sources.filter(s => s.kind === "builtin").map(s => sourceRow(s, false)));
      const ownRows = view.sources.filter(s => own.has(s.id)).map(s => sourceRow(s, true));
      mine.replaceChildren(...(ownRows.length ? ownRows : [node("p", "hint", tr("No lists of your own yet."))]));
      sourceKey = nextKey;
    }
    for (const toggle of $("pool-sources").querySelectorAll("[data-source]"))
      toggle.checked = !!view.sources.find(source => source.id === toggle.dataset.source)?.enabled;
    $("pool-token-state").textContent = tr(settings.github_token ? "Token stored" : "No token");
    $("pool-token-state").className = "pool-pill " + (settings.github_token ? "ok" : "untested");
    $("pool-token-remove").disabled = !settings.github_token;
    const values = [settings.github.enabled, settings.github.query, String(settings.github.max_files), settings.countries];
    fields.forEach((id, index) => {
      const field = $(id), key = field.type === "checkbox" ? "checked" : "value";
      const value = draft.has(id) ? draft.get(id) : values[index];
      if (field[key] !== value) field[key] = value;
    });
    const g = settings.github_status;
    $("pool-github-status").textContent = !settings.github_token ? tr("Save a token to search GitHub.") :
      g.error ? tr("Last search failed: {error}", {error: g.error}) :
      g.last_run ? tr("Last search {date}: {files} files, {n} compatible servers", {date: formatTime(g.last_run), files: g.files, n: g.proxies}) :
      tr("The search runs with the next list update.");
    sourceFields();
  }

  function render() {
    renderStats();
    options($("pool-country"), [...new Set(view.rows.map(r => r.country).filter(Boolean))].sort()
      .map(code => [code, flag(code) + " " + countryName(code)]), tr("All countries"));
    options($("pool-source"), view.sources.filter(s => s.enabled).map(s => [s.id, s.label]), tr("All lists"));
    filter.country = $("pool-country").value; filter.source = $("pool-source").value;
    renderTable(); renderSources();
    controls();
  }

  function settingsBody(change) {
    const s = view.settings, body = {disabled: [...s.disabled], custom: s.custom.map(item => ({...item})),
      github: {...s.github}, countries: s.countries};
    change(body);
    return body;
  }

  async function saveSettings(change) {
    view = await json("network/sources", settingsBody(change));
    render();
  }

  for (const id of fields) $(id).addEventListener("input", () => {
    const field = $(id); draft.set(id, field.type === "checkbox" ? field.checked : field.value);
    $("pool-save-state").textContent = "";
    if (id === "pool-github-search") sourceFields();
  });

  $("pool-search").addEventListener("input", () => { filter.q = $("pool-search").value; limit = 150; if (view) renderTable(); });
  $("pool-country").addEventListener("change", () => { filter.country = $("pool-country").value; if (view) renderTable(); });
  $("pool-source").addEventListener("change", () => { filter.source = $("pool-source").value; if (view) renderTable(); });
  $("pool-status").addEventListener("click", event => {
    const button = event.target.closest("[data-status]"); if (!button) return;
    filter.status = button.dataset.status;
    for (const b of $("pool-status").querySelectorAll("[data-status]")) b.setAttribute("aria-pressed", String(b === button));
    if (view) renderTable();
  });
  $("pool-more").addEventListener("click", () => { limit += 300; renderTable(); });
  $("pool-check").addEventListener("click", e => runAction(e.currentTarget, async () => {
    view = await json("network/proxies/check", {}); render();
    toast(tr("Checking every server. Results appear as they come in."));
  }));
  $("pool-update").addEventListener("click", e => runAction(e.currentTarget, async () => {
    const result = await json("network/catalog/refresh", {}, {root: true});
    toast(result.throttled ? tr("The list was refreshed recently. Wait one minute before another download.") :
      tr("Lists updated: {n} sources.", {n: (result.refresh?.updated || []).length}));
    view = await json("network/proxies"); render();
  }));
  $("pool-sources").addEventListener("change", event => {
    const toggle = event.target.closest("[data-source]"); if (!toggle) return;
    const enabled = toggle.checked, source = toggle.dataset.source, own = toggle.dataset.own;
    runAction(null, () => saveSettings(body => {
      if (own) body.custom.find(item => item.id === source).enabled = enabled;
      else body.disabled = enabled ? body.disabled.filter(id => id !== source) : [...body.disabled, source];
    }));
  });
  $("pool-sources").addEventListener("click", event => {
    const remove = event.target.closest("[data-remove]"); if (!remove) return;
    runAction(remove, async () => {
      await saveSettings(body => { body.custom = body.custom.filter(item => item.id !== remove.dataset.remove); });
      toast(tr("List removed."));
    });
  });
  $("pool-add-url").addEventListener("submit", e => { e.preventDefault(); runAction(e.submitter, async () => {
    const url = $("pool-url").value.trim();
    await saveSettings(body => body.custom.push({kind: "url", url, format: $("pool-url-format").value, label: "", enabled: true}));
    if ($("pool-url").value.trim() === url) $("pool-url").value = "";
    toast(tr("List added. It is downloaded with the next list update."));
  }); });
  async function importLists(files) {
    if (!state.me?.admin || state.status?.demo) return;
    const revision = state.workspaceRevision;
    let added = 0;
    for (const file of files) {
      if (revision !== state.workspaceRevision || !state.token) return;
      if (file.size > 1024 * 1024) { toast(tr("{name}: a list may have at most 1 MiB.", {name: file.name}), true); continue; }
      try {
        const text = await file.text();
        if (revision !== state.workspaceRevision || !state.token) return;
        view = await json("network/sources/list", {label: file.name, text});
        added += view.added.compatible;
      } catch (error) {
        if (revision !== state.workspaceRevision || error instanceof StaleView) return;
        toast(file.name + ": " + error.message, true);
      }
    }
    if (view) render();
    if (added) toast(tr("{n} servers added from your files.", {n: added}));
  }
  function addLists(files) { return runAction(null, () => importLists(files)); }
  $("pool-files").addEventListener("change", () => { const files = [...$("pool-files").files]; $("pool-files").value = ""; addLists(files); });
  const drop = $("pool-drop");
  drop.addEventListener("dragover", e => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", e => { e.preventDefault(); drop.classList.remove("over"); addLists([...e.dataTransfer.files]); });
  $("pool-paste-add").addEventListener("click", e => runAction(e.currentTarget, async () => {
    const text = $("pool-paste").value.trim(); if (!text) throw new Error(tr("Paste at least one proxy link."));
    view = await json("network/sources/list", {label: tr("Pasted links"), text});
    if ($("pool-paste").value.trim() === text) $("pool-paste").value = "";
    render();
    toast(tr("{n} servers added.", {n: view.added.compatible}));
  }));
  $("pool-token-save").addEventListener("click", e => runAction(e.currentTarget, async () => {
    const token = $("pool-token").value.trim(); if (!token) throw new Error(tr("Paste a GitHub token first."));
    view = await json("network/github-token", {token});
    if ($("pool-token").value.trim() === token) $("pool-token").value = "";
    render();
    toast(tr("GitHub token saved in the encrypted vault."));
  }));
  $("pool-token-remove").addEventListener("click", e => runAction(e.currentTarget, async () => {
    view = await json("network/github-token", {token: ""}); render();
    toast(tr("GitHub token removed."));
  }));
  $("pool-save").addEventListener("click", e => {
    const submitted = new Map(fields.map(id => [id, $(id).type === "checkbox" ? $(id).checked : $(id).value]));
    runAction(e.currentTarget, async () => {
    await saveSettings(body => {
      body.github = {enabled: submitted.get("pool-github-search"), query: submitted.get("pool-github-query").trim(),
                     max_files: Number(submitted.get("pool-github-max")) || 20};
      body.countries = submitted.get("pool-countries");
    });
    for (const [id, value] of submitted) if (draft.get(id) === value) draft.delete(id);
    $("pool-save-state").textContent = draft.size ? "" : tr("Saved. Applies from the next list update.");
  }); });
  window.addEventListener("tgwitness:lock", clear);
  $("proxy-pool").addEventListener("toggle", () => { if ($("proxy-pool").open) load(); else stop(); });
  window.TgWitnessProxies = {load, stop, clear, sync};
})();
