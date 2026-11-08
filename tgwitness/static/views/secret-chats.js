export function createSecretChats(context) {
  const {root, tr, trn, json, toast, busy, node, formatTime, download, confirm, getSession, may, humanSize, actionText} = context;
  const find = id => root.querySelector("#" + id);
  let view = null, selected = null, timer = null, active = false, session = getSession(), request = 0;
  let renderedChat = null, threadStamp = null, activation = 0;
  let olderRequest = 0, loadingOlder = false;
  const drafts = new Map(), sending = new Set();

  function actionOwner() {
    const owner = getSession(), started = activation;
    return (requireActive = true) => (!requireActive || (active && started === activation)) && owner === session && owner === getSession();
  }

  function threads() {
    const map = new Map();
    const chat = id => {
      if (!map.has(id)) map.set(id, {id, snapshot: null, peer: null, items: [], files: new Map(), deleted: new Set(), last: ""});
      return map.get(id);
    };
    for (const snapshot of view.chats) Object.assign(chat(snapshot.id), {snapshot, peer: snapshot.peer_user_id});
    for (const record of view.records) {
      const p = record.payload || {}, id = p.secret_chat_id;
      if (id === undefined || id === null) continue;
      const item = chat(id);
      item.peer = item.peer || p.peer_user_id || null;
      item.last = record.observed_at || item.last;
      if (record.kind === "secret_chat.file") item.files.set(p.random_id, p);
      else if (record.kind === "secret_chat.action" && p.action === "DeleteMessages")
        for (const randomId of p.details?.random_ids || []) item.deleted.add(randomId);
      if (["secret_chat.message", "secret_chat.action", "secret_chat.ready", "secret_chat.closed", "secret_chat.requested",
           "secret_chat.accepted", "secret_chat.decrypt_failed", "secret_chat.send_failed", "secret_chat.file_failed"].includes(record.kind))
        item.items.push(record);
    }
    return [...map.values()].sort((a, b) => String(b.last).localeCompare(String(a.last)));
  }

  function stateText(item) {
    const state = item.snapshot?.state || (item.items.some(r => r.kind === "secret_chat.closed") ? "closed" : "unknown");
    return {requested: tr("Waiting for the other side"), pending: tr("Request received"), ready: tr("Active"),
      rekeying: tr("Active"), closed: tr("Ended"), unknown: tr("Not loaded")}[state] || state;
  }

  function renderSettings() {
    const settings = view.settings, editable = may("settings");
    find("secret-unavailable").hidden = view.available;
    find("secret-unavailable").textContent = view.available ? "" : tr(view.unavailable_reason);
    find("secret-enabled").checked = settings.enabled;
    find("secret-accept").checked = settings.accept_incoming;
    find("secret-enabled").disabled = !view.available || !editable;
    find("secret-accept").disabled = !view.available || !editable || !settings.enabled;
    find("secret-status").textContent = !settings.enabled ? tr("Pseudo-secret is off for this account.") :
      view.connected ? tr("Connected: new messages are recorded as they arrive.") :
      tr("Not connected yet: Telegram keeps new messages until this account connects.") + (view.error ? " " + tr("Last error: {error}", {error: view.error}) : "");
    const start = find("secret-start");
    for (const field of start.querySelectorAll("input, button")) field.disabled = !settings.enabled || !view.connected || !may("interact");
  }

  function renderList(items) {
    const list = find("secret-list");
    list.replaceChildren();
    if (!items.length) list.append(node("p", "hint", tr("No pseudo-secret chats yet.")));
    for (const item of items) {
      const button = node("button", "secret-chat-row" + (item.id === selected ? " selected" : ""));
      button.type = "button";
      button.append(node("b", "", tr("User ID {id}", {id: item.peer ?? "?"})), node("small", "", stateText(item) + " · " +
        trn("{n} record", "{n} records", item.items.length)));
      button.addEventListener("click", () => {selected = item.id; render();});
      list.append(button);
    }
    if (view.pending_files) list.append(node("p", "hint", tr("Attachments waiting to be saved: {n}", {n: view.pending_files})));
    if (view.next_before) {
      list.append(node("p", "hint", tr("Earlier records are available. Load older records to see more history.")));
      const older = node("button", "quiet", tr("Load older records"));
      older.type = "button"; older.disabled = loadingOlder;
      older.addEventListener("click", () => busy(older, loadOlder));
      list.append(older);
    }
  }

  function message(record, item) {
    const p = record.payload, out = p.direction === "out";
    const row = node("div", "secret-message " + (out ? "out" : "in") + (item.deleted.has(p.random_id) ? " deleted" : ""));
    const head = node("small", "", (out ? tr("Sent") : tr("Received")) + " · " + formatTime(record.observed_at));
    row.append(head);
    if (p.text) row.append(node("p", "", p.text));
    if (p.media) row.append(node("p", "hint", tr("Attachment") + " · " + String(p.media._ || "").replace("DecryptedMessageMedia", "")));
    const file = item.files.get(p.random_id);
    if (file) {
      const save = node("button", "text-link", tr("Save file") + " · " + humanSize(file.size));
      save.type = "button";
      save.addEventListener("click", () => busy(save, () => download("media/" + file.media_sha256, file.media_sha256)));
      row.append(save);
    }
    const notes = [];
    if (p.ttl) notes.push(tr("timer {n} s", {n: p.ttl}));
    if (item.deleted.has(p.random_id)) notes.push(tr("deleted by the other side; kept here"));
    if (notes.length) row.append(node("small", "secret-note", notes.join(" · ")));
    return row;
  }

  function renderThread(items) {
    const box = find("secret-thread");
    const item = items.find(entry => entry.id === selected);
    const stamp = JSON.stringify([item, may("interact"), sending.has(selected)],
      (_, value) => value instanceof Map || value instanceof Set ? [...value] : value);
    if (stamp === threadStamp) return;
    const previous = box.querySelector("textarea"), oldFeed = box.querySelector(".secret-feed");
    const sameChat = renderedChat === selected;
    const focus = sameChat && previous === document.activeElement;
    const selection = focus ? [previous.selectionStart, previous.selectionEnd] : null;
    const scroll = sameChat && oldFeed && oldFeed.scrollHeight - oldFeed.scrollTop - oldFeed.clientHeight > 24
      ? oldFeed.scrollTop : null;
    threadStamp = stamp; renderedChat = selected;
    box.replaceChildren();
    if (!item) {box.append(node("p", "hint", tr("Choose a chat to read it."))); return;}
    const head = node("div", "secret-thread-head");
    head.append(node("b", "", tr("User ID {id}", {id: item.peer ?? "?"})), node("span", "hint", stateText(item)));
    const key = item.snapshot?.key_visualization || item.items.find(r => r.kind === "secret_chat.ready")?.payload.key_visualization;
    if (key) head.append(node("code", "secret-key", key.match(/.{1,8}/g).join(" ")),
      node("small", "hint", tr("Compare with the key picture under Encryption key on the other device.")));
    const actions = node("div", "route-actions");
    const state = item.snapshot?.state;
    if (state === "pending" && may("interact")) {
      const accept = node("button", "primary", tr("Accept here"));
      accept.type = "button";
      accept.addEventListener("click", () => busy(accept, async () => {
        const current = actionOwner();
        if (!(await confirm(tr("Accept this chat in TgWitness? This account's other devices will not get it."))) || !current()) return;
        await json("secret-chats/" + item.id + "/accept", {}); if (current()) await load();
      }));
      actions.append(accept);
    }
    if (state && state !== "closed" && may("interact")) {
      const close = node("button", "quiet", tr("End chat"));
      close.type = "button";
      close.addEventListener("click", () => busy(close, async () => {
        const current = actionOwner();
        if (!(await confirm(tr("End this chat? The journal keeps every record."))) || !current()) return;
        await json("secret-chats/" + item.id + "/close", {}); if (current()) await load();
      }));
      actions.append(close);
    }
    head.append(actions);
    box.append(head);
    const feed = node("div", "secret-feed");
    for (const record of item.items) {
      if (record.kind === "secret_chat.message") feed.append(message(record, item));
      else feed.append(node("p", "secret-event", formatTime(record.observed_at) + " · " + eventText(record)));
    }
    box.append(feed);
    if (["ready", "rekeying"].includes(state) && may("interact")) {
      const form = node("form", "secret-send"), input = node("textarea"), send = node("button", "primary", tr("Send"));
      input.maxLength = 4096; input.rows = 2; input.setAttribute("aria-label", tr("Message"));
      input.value = drafts.get(item.id) || "";
      input.addEventListener("input", () => drafts.set(item.id, input.value));
      send.type = "submit"; send.disabled = sending.has(item.id);
      form.append(input, send);
      form.addEventListener("submit", event => {event.preventDefault(); busy(send, async () => {
        const current = actionOwner(), draft = input.value, text = draft.trim();
        if (!text || !current() || sending.has(item.id)) return;
        drafts.set(item.id, draft); sending.add(item.id);
        try {
          await json("secret-chats/" + item.id + "/messages", {text});
          if (!current(false)) return;
          if (drafts.get(item.id) === draft) drafts.delete(item.id);
          await load();
        } finally {
          if (current(false)) {sending.delete(item.id); threadStamp = null; if (active) render();}
        }
      });});
      box.append(form, node("p", "hint", tr("Sent messages are recorded. TgWitness does not mark received messages as read.")));
      if (focus) {input.focus({preventScroll: true}); input.setSelectionRange(...selection);}
    }
    feed.scrollTop = scroll ?? feed.scrollHeight;
  }

  function eventText(record) {
    const p = record.payload;
    switch (record.kind) {
      case "secret_chat.requested": return p.direction === "out" ? tr("Requested by this account") : tr("Request from the other side");
      case "secret_chat.accepted": return p.automatic ? tr("Accepted automatically") : tr("Accepted here");
      case "secret_chat.ready": return tr("Established");
      case "secret_chat.closed": return p.history_deleted_by_peer ? tr("The other side deleted the chat; the journal keeps every record.") : tr("Ended") + (p.reason ? " · " + p.reason : "");
      case "secret_chat.action": return actionText(p);
      case "secret_chat.decrypt_failed": return tr("A message could not be decrypted and was refused.");
      case "secret_chat.send_failed": return tr("Telegram rejected a sent message.");
      case "secret_chat.file_failed": return tr("A file could not be saved.");
      default: return record.kind;
    }
  }

  function render() {
    if (!view) return;
    renderSettings();
    const items = threads();
    if (selected === null && items.length) selected = items[0].id;
    renderList(items);
    renderThread(items);
  }

  async function load() {
    const current = ++request, owner = getSession();
    if (owner !== session) {
      session = owner; view = null; selected = null; renderedChat = null; threadStamp = null;
      olderRequest++; loadingOlder = false;
      drafts.clear(); sending.clear(); find("secret-user").value = "";
      find("secret-list").replaceChildren(); find("secret-thread").replaceChildren();
    }
    const cursor = view ? view.records.at(-1)?.seq || 0 : null;
    const result = await json("secret-chats" + (cursor === null ? "" : "?after=" + encodeURIComponent(cursor)));
    if (current !== request || owner !== getSession()) return;
    mergeView(result, cursor !== null); render();
  }

  function mergeView(result, keepCursor = true) {
    const records = new Map((view?.records || []).map(record => [record.seq, record]));
    for (const record of result.records) records.set(record.seq, record);
    const nextBefore = keepCursor && view ? view.next_before : result.next_before;
    view = {...result, records: [...records.values()].sort((a, b) => a.seq - b.seq), next_before: nextBefore};
  }

  async function loadOlder() {
    if (!view?.next_before || loadingOlder) return;
    const current = actionOwner(), serial = ++olderRequest, before = view.next_before;
    loadingOlder = true;
    try {
      const result = await json("secret-chats?before=" + encodeURIComponent(before));
      if (!current() || serial !== olderRequest) return;
      const records = new Map(view.records.map(record => [record.seq, record]));
      for (const record of result.records) records.set(record.seq, record);
      view = {...view, records: [...records.values()].sort((a, b) => a.seq - b.seq), next_before: result.next_before};
    } finally {
      if (current(false) && serial === olderRequest) {loadingOlder = false; if (active) render();}
    }
  }

  function schedule() {
    clearTimeout(timer);
    if (active) timer = setTimeout(() => load().catch(() => {}).finally(schedule), 4000);
  }

  async function saveSettings() {
    if (!view) return;
    const current = actionOwner();
    const body = {enabled: find("secret-enabled").checked, accept_incoming: find("secret-accept").checked};
    if (body.accept_incoming && !view.settings.accept_incoming &&
        !(await confirm(tr("Accept every incoming request in TgWitness? Accepted chats do not reach this account's other devices.")))) {
      if (current()) find("secret-accept").checked = false; return;
    }
    if (!current()) return;
    let result;
    try {result = await json("secret-chats/settings", body);}
    catch (error) {if (current()) renderSettings(); throw error;}
    if (!current(false)) return;
    view = {...result, records: view.records, next_before: view.next_before};
    if (active) render();
    await load();
    toast(tr("Pseudo-secret settings saved."));
  }

  find("secret-enabled").addEventListener("change", event => busy(event.currentTarget, saveSettings));
  find("secret-accept").addEventListener("change", event => busy(event.currentTarget, saveSettings));
  find("secret-start").addEventListener("submit", event => {event.preventDefault(); busy(event.submitter, async () => {
    const current = actionOwner();
    const user = find("secret-user").value.trim();
    if (!user) throw new Error(tr("Enter a @username or a user ID."));
    const chat = await json("secret-chats", {user});
    if (!current()) return;
    find("secret-user").value = ""; selected = chat.id; await load();
    toast(tr("Request sent. The chat opens when the other side accepts."));
  });});

  return {
    async enter() {
      active = true; activation++;
      try {await load();} finally {schedule();}
    },
    leave() {active = false; activation++; clearTimeout(timer);},
    reset() {active = false; activation++; clearTimeout(timer); view = null; selected = null; request++;
      olderRequest++; loadingOlder = false;
      renderedChat = null; threadStamp = null; drafts.clear(); sending.clear(); find("secret-user").value = "";
      find("secret-list").replaceChildren(); find("secret-thread").replaceChildren();},
  };
}
