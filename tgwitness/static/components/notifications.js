const number = value => Number.isSafeInteger(Number(value)) && Number(value) > 0 ? Number(value) : 0;
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  node.className = className || "";
  if (text !== undefined) node.textContent = text;
  return node;
};

export function createNotifications(adapter) {
  const {panel, toggle, badge, list, readAll, rules, closeButton, filters, summary, status, tr, trn, formatTime} = adapter;
  const memories = new Map();
  let scope = "", category = "all", signature = "", generation = 0, busy = false, mode = "";
  document.body.append(panel);
  const context = () => adapter.context();
  const scopeKey = c => `${c.fingerprint || "unknown"}:${c.profile}`;
  const active = () => context().active;
  const rows = () => (adapter.items() || []).filter(item => item && number(item.seq));
  const readKey = item => item.read_key || item.group_id || `event:${item.seq}`;

  function memory() {
    const c = context(), key = scopeKey(c);
    if (!memories.has(key)) {
      let saved = {};
      try {
        const raw = localStorage.getItem("tgwitness-notifications-v1:" + key);
        const ownerKey = "tgwitness-notification-legacy-owner:" + c.profile;
        const owner = localStorage.getItem(ownerKey);
        saved = raw ? JSON.parse(raw) : {all: !owner || owner === c.fingerprint
          ? number(localStorage.getItem("tgwitness-read-" + c.profile)) : 0};
        if (!owner && c.fingerprint) localStorage.setItem(ownerKey, c.fingerprint);
      } catch { /* Read state remains usable when browser storage is unavailable. */ }
      const groups = Object.create(null);
      for (const [id, seq] of Object.entries(saved?.groups || {}).slice(-256)) if (number(seq)) groups[id] = number(seq);
      memories.set(key, {all: number(saved?.all), groups});
    }
    return memories.get(key);
  }

  function persist() {
    const saved = memory();
    saved.groups = Object.fromEntries(Object.entries(saved.groups).filter(([,seq]) => seq > saved.all)
      .sort((a,b) => b[1] - a[1]).slice(0,256));
    try { localStorage.setItem("tgwitness-notifications-v1:" + scopeKey(context()), JSON.stringify(saved)); }
    catch { /* Keep the in-memory acknowledgement. */ }
  }

  function unread(item) {
    const saved = memory();
    return item.seq > Math.max(saved.all, number(saved.groups[readKey(item)]));
  }

  function acknowledge(item) {
    const saved = memory(), key = readKey(item);
    saved.groups[key] = Math.max(number(saved.groups[key]), item.seq);
    persist(); render();
  }

  function close({restore = false} = {}) {
    generation++;
    if (panel.open) panel.close();
    panel.hidden = true;
    mode = "";
    toggle.setAttribute("aria-expanded", "false");
    if (restore && active()) toggle.focus({preventScroll:true});
  }

  function place() {
    if (!panel.open) return;
    const vv = window.visualViewport, width = vv?.width || innerWidth, height = vv?.height || innerHeight;
    const x = vv?.offsetLeft || 0, y = vv?.offsetTop || 0, mobile = width <= 600;
    const nextMode = mobile ? "sheet" : "popover";
    if (mode && mode !== nextMode) {
      panel.close();
      mobile ? panel.showModal() : panel.show();
    }
    mode = nextMode; panel.dataset.mode = mode;
    panel.setAttribute("aria-modal", String(mobile));
    const margin = mobile ? 8 : 12, rect = toggle.getBoundingClientRect();
    panel.style.width = Math.min(mobile ? 520 : 440, width - 2 * margin) + "px";
    panel.style.maxHeight = Math.max(0, height - 2 * margin) + "px";
    let left = x + (width - panel.offsetWidth) / 2, top;
    if (mobile) {
      panel.style.maxHeight = Math.min(680, height - 24) + "px";
      top = y + height - panel.offsetHeight - margin;
    } else {
      const below = y + height - rect.bottom - 8 - margin, above = rect.top - y - 8 - margin;
      const flip = below < Math.min(380, panel.scrollHeight) && above > below;
      panel.style.maxHeight = Math.max(0, Math.min(620, flip ? above : below, height - 2 * margin)) + "px";
      left = document.documentElement.dir === "rtl" ? rect.left : rect.right - panel.offsetWidth;
      left = Math.max(x + margin, Math.min(left, x + width - panel.offsetWidth - margin));
      top = flip ? rect.top - panel.offsetHeight - 8 : rect.bottom + 8;
      top = Math.max(y + margin, Math.min(top, y + height - panel.offsetHeight - margin));
    }
    panel.style.left = left + "px"; panel.style.top = top + "px";
  }

  async function activate(item, kind) {
    if (busy || !active()) return;
    const current = scopeKey(context()), revision = context().revision;
    busy = true;
    close();
    try {
      await adapter.action(item, kind);
      if (current === scopeKey(context()) && revision === context().revision && active()) acknowledge(item);
    } catch (error) { if (active() && current === scopeKey(context())) adapter.error(error); }
    finally { busy = false; }
  }

  function card(item) {
    const isUnread = unread(item), severity = ["error","warning","success","info"].includes(item.severity)
      ? item.severity : item.level === "problem" ? "warning" : item.level === "ok" ? "success" : "info";
    const card = el("article", `notice-card severity-${severity}${isUnread ? " unread" : ""}`);
    card.dataset.group = item.group_id || readKey(item); card.dataset.seq = item.seq;
    const head = el("div", "notice-card-head"), label = el("span", "notice-kind");
    const labels = {error:tr("Error"), warning:tr("Warning"), success:tr("Resolved"), info:tr("Chat change")};
    const categories = {connection:tr("Connection"),collection:tr("Collection"),sources:tr("Sources"),media:tr("Attachments"),
      timestamps:tr("Timestamps"),replica:tr("Off-site copy"),server:tr("Server"),exports:tr("Exports"),accounts:tr("Accounts")};
    label.append(el("span", "notice-dot"), document.createTextNode([categories[item.category], labels[severity]].filter(Boolean).join(" · ")));
    const count = Math.max(1,number(item.count || item.occurrences || item.records)), sampled = item.count_exact === false;
    head.append(label);
    if (count > 1 || sampled) {
      const times = el("span", "notice-repeat", sampled ? tr("{n}+ records", {n:count}) : trn("{n} record", "{n} records", count));
      if (sampled) times.title = tr("Count from the latest {n} matching records.", {n:item.scan_limit || count});
      head.append(times);
    }
    card.append(head, el("p", "notice-text", item.text));
    const meta = el("div", "notice-meta"), at = el("time", "", formatTime(item.last_at || item.at));
    at.dateTime = item.last_at || item.at;
    if (count > 1 && item.first_at) at.title = tr("First recorded: {time}", {time:formatTime(item.first_at)});
    meta.append(at);
    const read = el("button", "notice-ack", isUnread ? tr("Mark as read") : tr("Read"));
    read.type = "button"; read.disabled = !isUnread; read.dataset.noticeControl = "read";
    read.addEventListener("click", () => acknowledge(item)); card.append(meta);
    const actions = el("div", "notice-actions"), action = item.action?.type || (item.level === "change" ? "chat" : "record");
    const primary = el("button", "notice-action", tr(action === "chat" ? "Open chat" : action === "diagnostics" ? "Diagnostics" : "View record"));
    primary.type = "button"; primary.dataset.noticeControl = "primary";
    primary.addEventListener("click", () => activate(item, "primary")); actions.append(primary);
    if (action !== "record") {
      const record = el("button", "notice-action secondary-action", tr("View record"));
      record.type = "button"; record.dataset.noticeControl = "record";
      record.addEventListener("click", () => activate(item, "record")); actions.append(record);
    }
    actions.append(read); card.append(actions); return card;
  }

  function render() {
    if (!active()) {
      close(); list.replaceChildren(); badge.hidden = true; signature = "";
      toggle.setAttribute("aria-label", tr("Notifications")); return;
    }
    const c = context(), nextScope = scopeKey(c);
    if (scope !== nextScope) { close(); scope = nextScope; category = "all"; signature = ""; }
    const items = active() ? rows() : [], unreadCount = items.filter(unread).length;
    badge.textContent = unreadCount > 99 ? "99+" : String(unreadCount); badge.hidden = !unreadCount;
    toggle.setAttribute("aria-label", unreadCount ? trn("{n} unread notification", "{n} unread notifications", unreadCount) : tr("Notifications"));
    summary.textContent = unreadCount ? trn("{n} unread notification", "{n} unread notifications", unreadCount) : tr("All caught up");
    readAll.disabled = !unreadCount;
    rules.hidden = !adapter.canRules();
    for (const button of filters) {
      const selected = button.dataset.noticeFilter === category;
      button.setAttribute("aria-selected", String(selected)); button.tabIndex = selected ? 0 : -1;
      if (selected) list.setAttribute("aria-labelledby", button.id);
    }
    const visible = items.filter(item => category === "all" || (category === "changes") === (item.level === "change"));
    const next = JSON.stringify([nextScope, category, visible, memory()]);
    if (next !== signature) {
      const focused = document.activeElement, group = focused?.closest(".notice-card")?.dataset.group;
      const control = focused?.dataset.noticeControl, scroll = list.scrollTop;
      const fragment = document.createDocumentFragment();
      for (const item of visible) fragment.append(card(item));
      if (!visible.length) fragment.append(el("p", "notice-empty", tr(category === "all"
        ? "Nothing yet. Problems and changes in observed chats appear here." : category === "changes" ? "No chat changes yet." : "No problems recorded.")));
      list.replaceChildren(fragment); list.scrollTop = scroll; signature = next;
      if (group && control) {
        const target = [...list.querySelectorAll(".notice-card")].find(row => row.dataset.group === group)
          ?.querySelector(`[data-notice-control="${control}"]`);
        (target && !target.disabled ? target : closeButton).focus({preventScroll:true});
      }
    }
    if (!active()) close(); else place();
  }

  async function open() {
    if (!active()) return;
    render();
    panel.hidden = false;
    mode = "";
    (window.visualViewport?.width || innerWidth) <= 600 ? panel.showModal() : panel.show();
    toggle.setAttribute("aria-expanded", "true"); place();
    filters.find(button => button.dataset.noticeFilter === category)?.focus({preventScroll:true});
    const ticket = ++generation, revision = context().revision;
    status.textContent = tr("Updating…");
    try { await adapter.refresh(); }
    catch (error) {
      if (ticket === generation && active()) status.textContent = tr("Could not refresh notifications. Open again to retry.");
      return;
    }
    if (ticket === generation && revision === context().revision && active()) { status.textContent = ""; render(); }
  }

  toggle.disabled = false;
  toggle.addEventListener("click", () => panel.open ? close({restore:true}) : open());
  closeButton.addEventListener("click", () => close({restore:true}));
  panel.addEventListener("cancel", event => {event.preventDefault(); close({restore:true});});
  document.addEventListener("keydown", event => {
    if (event.key === "Escape" && panel.open) {event.preventDefault(); event.stopImmediatePropagation(); close({restore:true});}
  }, true);
  document.addEventListener("pointerdown", event => {
    if (!panel.open || toggle.contains(event.target)) return;
    const rect = panel.getBoundingClientRect(), inside = event.clientX >= rect.left && event.clientX <= rect.right
      && event.clientY >= rect.top && event.clientY <= rect.bottom;
    if (!panel.contains(event.target) || !inside) close();
  });
  for (const button of filters) {
    button.addEventListener("click", () => {category = button.dataset.noticeFilter; list.scrollTop = 0; render();});
    button.addEventListener("keydown", event => {
      if (!["ArrowLeft","ArrowRight","Home","End"].includes(event.key)) return;
      event.preventDefault();
      const direction = document.documentElement.dir === "rtl" ? -1 : 1;
      const index = event.key === "Home" ? 0 : event.key === "End" ? filters.length - 1
        : (filters.indexOf(button) + (event.key === "ArrowRight" ? direction : -direction) + filters.length) % filters.length;
      category = filters[index].dataset.noticeFilter; render(); filters[index].focus();
    });
  }
  readAll.addEventListener("click", () => {
    memory().all = Math.max(memory().all, ...rows().map(item => item.seq)); persist(); render();
  });
  rules.addEventListener("click", async () => {
    if (!active() || !adapter.canRules()) return;
    close();
    try {await adapter.openRules();} catch (error) {adapter.error(error);}
  });
  window.addEventListener("resize", place);
  window.addEventListener("scroll", place, true);
  window.visualViewport?.addEventListener("resize", place);
  window.visualViewport?.addEventListener("scroll", place);
  window.addEventListener("tgwitness:lock", () => {close(); list.replaceChildren(); badge.hidden = true; signature = "";});
  new MutationObserver(render).observe(adapter.workspace, {attributes:true, attributeFilter:["hidden","inert"]});
  render();
  return {render, close};
}
