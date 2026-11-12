const SERIES = [
  ["messages", "Messages", "message", ["message.new", "message.snapshot", "message.recovered"]],
  ["edits", "Edits", "edit", ["message.edited"]],
  ["reactions", "Reactions", "heart", ["reaction.snapshot"]],
  ["deletions", "Deletions", "trash", ["message.deleted", "message.missing_on_recheck"]],
];
const KNOWN = new Map(SERIES.flatMap(([id, , , kinds]) => kinds.map(kind => [kind, id])));
const SVG = "http://www.w3.org/2000/svg";

export function createPulse({anchor, chartsAnchor, node, tr, icon, json, session, can, openJournal, openChat}) {
  const kpis = node("div", "pulse pulse-kpis"), charts = node("div", "pulse pulse-charts"), root = kpis;
  kpis.setAttribute("role", "group"); kpis.setAttribute("aria-label", tr("Overview"));
  charts.hidden = true;
  anchor.after(kpis);
  chartsAnchor.after(charts);
  const still = () => window.tgwReducedMotion?.() ?? matchMedia("(prefers-reduced-motion: reduce)").matches;
  const tiles = new Map();
  let loadedKey = "", requestKey = "", chats = null, shownMix = "";

  function count(el, value) {
    const from = Number(el.dataset.value || 0);
    el.dataset.value = value;
    cancelAnimationFrame(el.frame);
    if (from === value || still() || !el.dataset.ready) { el.dataset.ready = "1"; el.textContent = value.toLocaleString(); return; }
    const start = performance.now();
    const step = now => {
      const t = Math.min(1, (now - start) / 700), eased = 1 - Math.pow(1 - t, 3);
      el.textContent = Math.round(from + (value - from) * eased).toLocaleString();
      if (t < 1) el.frame = requestAnimationFrame(step);
    };
    el.frame = requestAnimationFrame(step);
  }

  function tile(id, label, glyph, tone, value, action) {
    let item = tiles.get(id);
    if (!item) {
      const box = node(action ? "button" : "div", "pulse-kpi card");
      if (action) { box.type = "button"; box.addEventListener("click", () => tiles.get(id).action()); }
      const mark = node("span", "tile"); mark.dataset.tone = tone; mark.append(icon(glyph));
      const number = node("strong", "pulse-num", "0"), text = node("span", "pulse-label", tr(label));
      box.append(mark, number, text);
      kpis.append(box);
      item = {box, number};
      tiles.set(id, item);
    }
    item.action = action;
    item.box.dataset.empty = String(!value);
    count(item.number, value);
  }

  function totals(counts) {
    const sums = Object.fromEntries(SERIES.map(([id]) => [id, 0]));
    let other = 0;
    for (const [kind, value] of Object.entries(counts || {})) {
      const id = KNOWN.get(kind);
      if (id) sums[id] += value; else other += value;
    }
    return {...sums, other};
  }

  function legend(values) {
    const list = node("ul", "pulse-legend");
    for (const [id, label] of [...SERIES, ["other", "Other"]]) {
      if (values && !values[id]) continue;
      const item = node("li"), dot = node("i", "pulse-dot");
      dot.dataset.series = id;
      item.append(dot, node("span", "", tr(label)));
      if (values) item.append(node("b", "", values[id].toLocaleString()));
      list.append(item);
    }
    return list;
  }

  function card(cls, title, extra) {
    const box = node("article", "card pulse-card " + cls), head = node("header");
    head.append(node("h2", "", tr(title)));
    if (extra) head.append(extra);
    box.append(head);
    return box;
  }

  function mixCard(sums, total) {
    const box = card("pulse-mix", "Record composition"), body = node("div", "pulse-mix-body");
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("viewBox", "0 0 120 120"); svg.setAttribute("class", "pulse-donut"); svg.setAttribute("role", "img");
    const parts = [...SERIES.map(([id, label]) => [id, label]), ["other", "Other"]].filter(([id]) => sums[id]);
    svg.setAttribute("aria-label", parts.map(([id, label]) => tr(label) + ": " + sums[id].toLocaleString()).join(", "));
    const track = document.createElementNS(SVG, "circle");
    for (const [key, value] of [["cx", 60], ["cy", 60], ["r", 46], ["class", "pulse-track"]]) track.setAttribute(key, value);
    svg.append(track);
    let offset = 0;
    const gap = parts.length > 1 ? 1.2 : 0;
    parts.forEach(([id], index) => {
      const share = sums[id] / total * 100, arc = document.createElementNS(SVG, "circle");
      for (const [key, value] of [["cx", 60], ["cy", 60], ["r", 46], ["pathLength", 100], ["class", "pulse-arc"],
        ["stroke-dasharray", Math.max(.6, share - gap) + " 100"], ["stroke-dashoffset", -offset]]) arc.setAttribute(key, value);
      arc.dataset.series = id;
      arc.style.animationDelay = index * 90 + "ms";
      const hint = document.createElementNS(SVG, "title");
      hint.textContent = tr(SERIES.find(row => row[0] === id)?.[1] || "Other") + ": " + sums[id].toLocaleString() + " · " + Math.round(share) + "%";
      arc.append(hint);
      svg.append(arc);
      offset += share;
    });
    const center = node("div", "pulse-donut-center");
    center.append(node("strong", "", total.toLocaleString()), node("span", "", tr("Records")));
    const ring = node("div", "pulse-donut-wrap");
    ring.append(svg, center);
    body.append(ring, legend(sums));
    box.append(body);
    return box;
  }

  const topChats = list => list.filter(chat => chat.messages || chat.edited || chat.deleted).sort((a, b) => b.messages - a.messages).slice(0, 5);

  function chatsCard(top) {
    if (!top.length) return null;
    const peak = Math.max(1, ...top.map(chat => chat.messages));
    const box = card("pulse-chats", "Activity by chat"), rows = node("div", "pulse-rows");
    top.forEach((chat, index) => {
      const row = node(can("chats") ? "button" : "div", "pulse-row");
      if (row.tagName === "BUTTON") { row.type = "button"; row.addEventListener("click", () => openChat(chat.chat_id)); }
      const name = node("span", "pulse-row-name", chat.title || String(chat.chat_id)), meter = node("span", "pulse-meter"), fill = node("i");
      fill.style.width = Math.max(3, chat.messages / peak * 100) + "%";
      fill.style.animationDelay = index * 70 + "ms";
      meter.append(fill);
      const facts = node("span", "pulse-row-facts");
      facts.append(node("b", "", chat.messages.toLocaleString()));
      for (const [glyph, value, tone, label] of [["edit", chat.edited, "edits", "Edits"], ["trash", chat.deleted, "deletions", "Deletions"]]) {
        if (!value) continue;
        const fact = node("span", "pulse-fact"); fact.dataset.series = tone; fact.title = tr(label);
        fact.setAttribute("aria-label", tr(label) + ": " + value);
        fact.append(icon(glyph), document.createTextNode(value.toLocaleString()));
        facts.append(fact);
      }
      row.append(name, meter, facts);
      rows.append(row);
    });
    box.append(rows);
    return box;
  }

  function renderCharts(status) {
    const sums = totals(status.stats.counts), total = Object.values(sums).reduce((a, b) => a + b, 0);
    const top = chats ? topChats(chats) : null;
    const key = JSON.stringify([sums, top && top.map(chat => [chat.chat_id, chat.title, chat.messages, chat.edited, chat.deleted])]);
    if (key === shownMix) return;
    shownMix = key;
    const cards = [], content = total - sums.other;
    if (content) cards.push(mixCard(sums, total));
    if (top) cards.push(chatsCard(top));
    charts.replaceChildren(...cards.filter(Boolean));
    charts.dataset.count = charts.childElementCount;
    charts.hidden = !charts.childElementCount;
  }

  function load(status) {
    const key = session() + ":" + JSON.stringify(totals(status.stats.counts));
    if (key === requestKey) return;
    requestKey = key;
    if (!can("chats")) return;
    json("chats").catch(() => null).then(list => {
      if (requestKey !== key) return;
      chats = list ? list.chats || [] : null;
      loadedKey = key;
      renderCharts(status);
    });
  }

  function update(status) {
    const counts = status.stats.counts || {}, sums = totals(counts), journal = can("observations");
    const go = kind => journal ? () => openJournal(kind) : null;
    if (session() !== root.dataset.session) { root.dataset.session = session(); chats = null; shownMix = ""; for (const item of tiles.values()) delete item.number.dataset.ready; }
    tile("records", "Records", "journal", "blue", status.stats.total, go(""));
    tile("messages", "Messages", "message", "indigo", sums.messages, go("messages"));
    tile("edits", "Edits", "edit", "orange", sums.edits, go("message.edited"));
    tile("deletions", "Deletions", "trash", "red", sums.deletions, go("message.deleted,message.missing_on_recheck"));
    tile("gaps", "Gaps", "alert", counts["coverage.gap"] ? "pink" : "green", counts["coverage.gap"] || 0, go("coverage.gap"));
    tile("chats", "Chats", "sources", "teal", status.targets.filter(target => target.enabled).length, can("chats") ? () => openChat(null) : null);
    renderCharts(status);
    load(status);
  }

  return {update};
}
