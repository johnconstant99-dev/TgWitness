const KINDS = "coverage.gap,connection.restored,process.started,process.stopped,observation.started,observation.stopped";
const INTERRUPTIONS = {transport_disconnected: "Connection to Telegram lost", authorization_required: "Telegram signed this account out", resume_failed: ""};
const STOPS = {shutdown: "TgWitness was shut down", operator: "Observation paused"};
const LISTED = 3;

export function intervals(events, chat) {
  const found = [];
  let open = null;
  const start = (at, reason, unexpected) => {
    if (!open) open = {from: at, reasons: new Set(), unexpected};
    if (reason) open.reasons.add(reason);
  };
  for (const event of [...events].sort((a, b) => a.seq - b.seq)) {
    const account = event.chat_id === null || event.chat_id === undefined;
    if (!account && event.chat_id !== chat) continue;
    const at = Date.parse(event.observed_at), payload = event.payload || {};
    if (!Number.isFinite(at)) continue;
    if (event.kind === "coverage.gap") {
      if (account && Object.hasOwn(INTERRUPTIONS, payload.reason)) start(at, INTERRUPTIONS[payload.reason], true);
      else found.push({from: at, to: at, reasons: []});
    } else if (event.kind === "observation.stopped") start(at, STOPS[payload.reason] || STOPS.operator, !Object.hasOwn(STOPS, payload.reason));
    else if (event.kind === "process.stopped") start(at, STOPS.shutdown, false);
    else if (event.kind === "process.started") {
      const before = Date.parse(payload.previous_observation?.observed_at);
      start(Number.isFinite(before) ? Math.min(before, at) : at, STOPS.shutdown, false);
    } else if (open) {
      found.push({from: open.from, to: at, reasons: [...open.reasons]});
      open = null;
    }
  }
  if (open?.unexpected) found.push({from: open.from, to: null, reasons: [...open.reasons]});
  const merged = [];
  for (const item of found.sort((a, b) => a.from - b.from)) {
    const last = merged.at(-1);
    if (last && (last.to === null || item.from <= last.to + 1000)) {
      last.to = last.to === null || item.to === null ? null : Math.max(last.to, item.to);
      last.reasons = [...new Set([...last.reasons, ...item.reasons])];
    } else merged.push({...item});
  }
  return merged;
}

export function createChatGaps({node, tr, icon, json, fmtTime, openJournal, allowJournal}) {
  let numbers = new Map(), periods = [], loadedKey = "", pendingKey = "";
  const cache = new Map();

  function marker(kind, key, build) {
    const id = kind + ":" + key;
    let box = cache.get(id);
    if (!box) {
      box = node("div", "chat-gap");
      box.dataset.kind = kind; box.setAttribute("role", "note");
      build(box);
      if (cache.size > 400) cache.clear();
      cache.set(id, box);
    }
    return box;
  }

  function numberMarker(list) {
    const total = list.reduce((sum, gap) => sum + gap.missing, 0);
    return marker("numbers", list.map(gap => gap.low + "-" + gap.high).join(","), box => {
      const ranges = list.slice(0, LISTED).map(gap => gap.low === gap.high ? "#" + gap.low : "#" + gap.low + "–#" + gap.high);
      if (list.length > LISTED) ranges.push("…");
      box.append(icon("question"), node("b", "", total.toLocaleString()),
        node("span", "", tr("Message numbers not observed") + ": " + ranges.join(", ")));
    });
  }

  function periodMarker(list) {
    return marker("coverage", list.map(item => item.from + "-" + item.to).join(","), box => {
      const lines = node("span", "chat-gap-lines");
      for (const item of list.slice(0, LISTED)) {
        const reasons = item.reasons.map(reason => tr(reason)).join(" · ");
        const from = fmtTime(new Date(item.from).toISOString()), to = item.to === null ? "…" : fmtTime(new Date(item.to).toISOString());
        lines.append(node("span", "", (from === to ? from : from + " – " + to) + (reasons ? " · " + reasons : "")));
      }
      if (list.length > LISTED) lines.append(node("span", "", "+" + (list.length - LISTED)));
      box.append(icon("alert"), node("strong", "", tr("Coverage gap")), lines);
      if (allowJournal()) {
        const open = node("button", "text-link", tr("Show in the journal"));
        open.type = "button";
        open.addEventListener("click", () => openJournal("coverage.gap"));
        box.append(open);
      }
    });
  }

  function between(previous, message, when) {
    if (!previous) return [];
    const marks = [], holes = [];
    for (const gap of numbers.values()) if (gap.low > previous.id && gap.high < message.message_id) holes.push(gap);
    if (holes.length) marks.push(numberMarker(holes.sort((a, b) => a.low - b.low)));
    const from = Date.parse(previous.when), to = Date.parse(when);
    if (Number.isFinite(from) && Number.isFinite(to) && to > from) {
      const hit = periods.filter(item => item.from >= from && item.from < to);
      if (hit.length) marks.push(periodMarker(hit));
    }
    return marks;
  }

  function after(previous) {
    const from = Date.parse(previous?.when);
    if (!Number.isFinite(from)) return [];
    const hit = periods.filter(item => item.from >= from);
    return hit.length ? [periodMarker(hit)] : [];
  }

  function load(chatKey, dataKey, chat, done) {
    const key = chatKey + "|" + dataKey;
    if (key === loadedKey || key === pendingKey) return;
    if (!loadedKey.startsWith(chatKey + "|")) periods = [];
    pendingKey = key;
    json("events?kind=" + KINDS + "&limit=500").then(result => {
      if (pendingKey !== key) return;
      const next = intervals(result.events || [], chat), changed = JSON.stringify(next) !== JSON.stringify(periods);
      periods = next; loadedKey = key; pendingKey = "";
      if (changed) done();
    }).catch(() => {if (pendingKey === key) {loadedKey = key; pendingKey = "";}});
  }

  return {reset: () => {numbers = new Map();}, add: list => {for (const gap of list || []) numbers.set(gap.low, gap);}, between, after, load};
}
