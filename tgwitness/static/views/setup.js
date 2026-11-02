// Setup by goal (levels.py): four answers, the settings suggested for them and the two scales.
// Nothing is saved until Apply; the scales come from what is set now, plus what Apply would add.
const APPLIED = ["timestamps", "drand", "devices"];
const STEP_ITEMS = {alerts: "alerts", replica: "replica", server: "server", gateway: "gateway_log", code: "code",
  witness: "witness"};

function goalName(tr, goal) {
  return {personal: () => tr("A personal record"), investigation: () => tr("An investigation"),
    evidence: () => tr("Evidence for a case")}[goal]?.() || tr("No goal chosen");
}

function goalNote(tr, goal) {
  return {
    personal: () => tr("For yourself the signed journal is usually enough. Timestamps are free and help if someone else ever needs the record."),
    investigation: () => tr("Timestamps date what you collected and the device list shows whether anyone else used the account. Notifications and an off-site copy keep collection going and the record safe."),
    evidence: () => tr("Everything an outsider can check is on. For the strongest record, collect on a sealed server around the clock and keep a locked off-site copy."),
  }[goal]?.() || "";
}

function itemName(tr, id) {
  return {journal: () => tr("Signed journal"), timestamps: () => tr("Independent timestamps"),
    drand: () => tr("Proof of live recording"), devices: () => tr("Telegram's device list"),
    code: () => tr("Code check"), witness: () => tr("Witness bot"), server: () => tr("Sealed server"),
    always_on: () => tr("Runs around the clock"), replica: () => tr("Off-site copy"),
    replica_lock: () => tr("Copy under Object Lock"), alerts: () => tr("Problem notifications"),
    gateway_log: () => tr("Cloudflare's log of the server's DNS")}[id]?.() || id;
}

function levelName(tr, level) {
  return {basic: () => tr("Basic"), moderate: () => tr("Moderate"), high: () => tr("High"),
    maximum: () => tr("Maximum")}[level]?.() || level;
}

export function levelOf(levels, percent) {
  return levels.find(([floor]) => percent >= floor)?.[1] || "basic";
}

function score(scale, levels) {
  const total = scale.items.reduce((sum, item) => sum + item.weight, 0);
  const got = scale.items.reduce((sum, item) => sum + (item.on ? item.weight : 0), 0);
  const percent = total ? Math.round(100 * got / total) : 0;
  return {percent, level: levelOf(levels, percent)};
}

// Both scales; with `after`, the part Apply would add is shown on top of the current state.
export function renderScales(box, data, {tr, node, after = null, compact = false}) {
  box.replaceChildren();
  const describe = {
    credibility: [tr("Credibility"), tr("What someone else can check: when the record existed, that it was written live and which program wrote it.")],
    reliability: [tr("Reliability"), tr("How likely collection keeps running and the record survives a lost or seized machine.")],
  };
  for (const key of ["credibility", "reliability"]) {
    const now = score(data.assessment[key], data.levels), next = after ? score(after[key], data.levels) : now;
    const wrap = node("div", "level-scale level-" + next.level);
    const head = node("div", "level-head");
    head.append(node("strong", "", describe[key][0]), node("span", "level-name", levelName(tr, next.level)));
    if (after && next.percent !== now.percent)
      head.append(node("span", "level-was", tr("now: {level}", {level: levelName(tr, now.level)})));
    const bar = node("div", "level-bar");
    bar.setAttribute("role", "meter"); bar.setAttribute("aria-valuemin", "0"); bar.setAttribute("aria-valuemax", "100");
    bar.setAttribute("aria-valuenow", String(next.percent)); bar.setAttribute("aria-label", describe[key][0]);
    bar.setAttribute("aria-valuetext", levelName(tr, next.level) + " · " + next.percent + "%");
    const solid = node("span", "level-now"), gain = node("span", "level-gain");
    solid.style.width = Math.min(now.percent, next.percent) + "%";
    gain.style.width = Math.max(0, next.percent - now.percent) + "%";
    bar.append(solid, gain);
    wrap.append(head, bar);
    if (!compact) {
      wrap.append(node("p", "hint", describe[key][1]));
      const list = node("ul", "level-items"), items = (after || data.assessment)[key].items;
      for (const item of items) {
        const row = node("li", item.on ? "on" : "off");
        row.append(node("span", "level-mark", item.on ? "✓" : "○"), node("span", "", itemName(tr, item.id)),
          node("span", "level-weight", "+" + item.weight));
        list.append(row);
      }
      wrap.append(list);
    }
    box.append(wrap);
  }
}

export function createSetup(context) {
  const {root, tr, json, node, toast, may, getState, answered, openExtra} = context;
  const form = root.querySelector("#setup-form"), find = id => root.querySelector("#" + id);
  let data = null, wanted = null, edited = false;
  const pick = name => form.querySelector(`input[name="setup-${name}"]:checked`)?.value || null;
  const choose = (name, value) => {
    const input = form.querySelector(`input[name="setup-${name}"][value="${value}"]`);
    if (input) input.checked = true;
  };
  const allowed = () => may("settings") && !getState().status?.demo;
  const itemOn = (scale, id) => data.assessment[scale].items.find(item => item.id === id)?.on;

  function answers() {
    return {goal: pick("goal"), size: pick("size"), files: pick("files"), place: pick("place"),
      timestamps: find("setup-timestamps").checked, drand: find("setup-drand").checked,
      devices: find("setup-devices").checked};
  }

  // The scales as they would be after Apply: the applied switches and the answer to "where".
  function predicted(a) {
    const copy = JSON.parse(JSON.stringify(data.assessment));
    for (const item of copy.credibility.items) {
      if (item.id === "timestamps") item.on = a.timestamps;
      if (item.id === "drand") item.on = a.timestamps && a.drand;
      if (item.id === "devices") item.on = a.timestamps && a.devices;
    }
    for (const item of copy.reliability.items) if (item.id === "always_on") item.on = data.sealed || a.place === "server";
    return copy;
  }

  function preset(goal) {
    const recommended = data.recommended[goal];
    for (const id of APPLIED) find("setup-" + id).checked = itemOn("credibility", id) || recommended.apply.includes(id);
  }

  function facts(a) {
    const list = find("setup-facts"); list.replaceChildren();
    const add = text => list.append(node("li", "", text));
    add({text: () => tr("Photos and files: not downloaded, a note says a file was sent."),
      media: () => tr("Photos and files: standard limits."),
      all: () => tr("Photos and files: everything up to 1 GB each.")}[a.files]());
    add(tr("Chats read from the account's list: {n}.", {n: data.limits.dialog_limit[a.size].toLocaleString()}));
    if (a.files === "all" && a.size === "large")
      add(tr("Downloads pause when free disk space falls below {n} MiB.", {n: data.limits.reserve_mb.toLocaleString()}));
    if (a.timestamps && !itemOn("credibility", "timestamps"))
      add(tr("Timestamps every {n} minutes.", {n: String(data.recommended[a.goal].interval_minutes)}));
  }

  function update() {
    if (!data) return;
    const a = answers();
    find("setup-drand").disabled = find("setup-devices").disabled = !a.timestamps || !allowed();
    if (!a.timestamps) find("setup-drand").checked = find("setup-devices").checked = false;
    const ready = !!a.goal;
    find("setup-proposal").hidden = !ready;
    if (!ready) return;
    find("setup-goal-note").textContent = goalNote(tr, a.goal);
    facts(answers());
    const recommended = data.recommended[a.goal].steps;
    for (const row of find("setup-steps").querySelectorAll("li[data-step]")) {
      const step = row.dataset.step, scale = step === "alerts" || step === "replica" ? "reliability" : "credibility";
      const done = itemOn(scale, STEP_ITEMS[step]), tag = row.querySelector(".setup-tag");
      tag.textContent = done ? tr("Done") : recommended.includes(step) ? tr("Recommended") : "";
      tag.className = "setup-tag" + (done ? " done" : recommended.includes(step) ? " recommended" : "");
      row.classList.toggle("setup-step-done", !!done);
    }
    renderScales(find("setup-scales"), data, {tr, node, after: predicted(answers())});
  }

  function render() {
    if (!data) return;
    const saved = data.saved && !data.saved.skipped ? data.saved : null, current = data.current;
    const goal = wanted || saved?.goal || null;
    form.querySelectorAll('input[name="setup-goal"]').forEach(input => input.checked = input.value === goal);
    choose("size", current.size); choose("files", current.files); choose("place", current.place);
    if (goal) preset(goal);
    find("setup-skip").hidden = !!data.saved;
    form.querySelectorAll("input,button[type=submit],#setup-skip").forEach(control => control.disabled = !allowed());
    find("setup-status").textContent = saved ? tr("Applied {time} for: {goal}.", {time: context.fmtFull(saved.at), goal: goalName(tr, saved.goal)}) : "";
    update();
  }

  // A reload that lands after the person changed an answer keeps the answers and refreshes the rest.
  async function load() {
    const first = !data;
    data = await json("setup");
    if (edited && !first) update(); else render();
    return data;
  }

  form.addEventListener("change", event => {
    edited = true;
    if (event.target.name === "setup-goal") { wanted = event.target.value; preset(wanted); }
    update();
  });
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const button = event.submitter; if (button) button.disabled = true;
    try {
      const result = await json("setup", answers());
      data = result; wanted = null; edited = false; answered();
      render();
      toast(result.changed.length ? tr("Settings applied for: {goal}.", {goal: goalName(tr, result.saved.goal)})
        : tr("Saved. The current settings already match."));
    } catch (error) { toast(error.message, true); }
    finally { if (button) button.disabled = !allowed(); }
  });
  find("setup-skip").addEventListener("click", async () => {
    try { data = await json("setup/skip", {}); edited = false; answered(); render(); openExtra(null); }
    catch (error) { toast(error.message, true); }
  });

  return {
    load, render, goalName: goal => goalName(tr, goal),
    start(goal) { wanted = goal; edited = false; if (data) render(); },
    get data() { return data; },
  };
}
