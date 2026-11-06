(() => {
  "use strict";
  const dialog = document.getElementById("secret-demo");
  if (!dialog || !window.TGW_ONLINE_DEMO) return;
  const find = id => dialog.querySelector("#secret-demo-" + id);
  const buttons = action => dialog.querySelectorAll('[data-secret-action="' + action + '"]');
  const MAX_CHATS = 20, MAX_ENTRIES = 100;
  const FILE_TEXT = "SYNTHETIC DEMONSTRATION\nThis is a fictional attachment from the Secret Chat preview.\nNo Telegram connection was made.\n";
  let chats = [], selected = 1, nextId = 1, minute = 0, opener = null;
  const current = () => chats.find(chat => chat.id === selected);
  const element = (tag, text, className = "") => {
    const item = document.createElement(tag);
    item.textContent = text;
    item.className = className;
    return item;
  };

  function entry(chat, kind, text, extra = {}) {
    const at = new Date(Date.UTC(2026, 10, 6, 16, minute++)).toISOString();
    chat.entries.push({id: chat.entries.length + 1, kind, text, at, ...extra});
  }

  function newChat(peer, state) {
    const chat = {id: nextId++, peer, state, entries: []};
    chats.push(chat);
    selected = chat.id;
    entry(chat, "notice", state === "pending" ? "Incoming sample request. Choose whether to accept it." :
      state === "requested" ? "Sample request sent. Waiting for the fictional peer to accept." : "Sample chat established.");
    return chat;
  }

  function reset() {
    chats = []; nextId = 1; minute = 0;
    const chat = newChat("@morgan_sample", "ready");
    entry(chat, "in", "Here is the message we will preserve in this fictional example.");
    entry(chat, "in", "This sample carries a 15-second timer. A deletion notice will leave this copy visible.", {ttl: 15});
    newChat("@alex_sample", "pending");
    selected = chat.id;
    find("message").value = "";
    find("user").value = "@sample_peer";
    render("Scenario reset. Select a conversation or start a sample chat.");
  }

  function render(update = "") {
    const chat = current();
    const labels = {ready: "Active · simulated", pending: "Incoming request · simulated",
      requested: "Waiting for peer · simulated", closed: "Ended · simulated"};
    const list = find("chats");
    list.replaceChildren();
    for (const item of chats) {
      const button = element("button", "", "secret-demo-chat");
      button.type = "button";
      button.dataset.secretChat = String(item.id);
      button.setAttribute("aria-pressed", String(item.id === selected));
      button.append(element("strong", item.peer), element("small", labels[item.state]));
      list.append(button);
    }
    find("peer").textContent = chat.peer;
    find("state").textContent = labels[chat.state];
    const ready = chat.state === "ready", room = chat.entries.length < MAX_ENTRIES - 1;
    find("step").textContent = !room ? "Sample limit reached. Reset the scenario to try again." :
      chat.state === "pending" ? "Accept this fictional request to open its conversation." :
      chat.state === "requested" ? "Use Simulate peer acceptance to continue the example." :
      ready ? "Send a sample message to receive a scripted reply. Peer actions below are simulations." :
      "This sample chat has ended. Its earlier messages remain visible until reset.";
    for (const button of buttons("accept")) button.hidden = chat.state !== "pending";
    for (const button of buttons("peer-accept")) button.hidden = chat.state !== "requested";
    for (const field of find("send").querySelectorAll("textarea, button")) field.disabled = !ready || !room;
    for (const action of ["file", "delete", "end"])
      for (const button of buttons(action)) button.disabled = !ready || !room ||
        action === "delete" && !chat.entries.some(item => item.kind === "in" && !item.deleted);
    for (const field of find("start").querySelectorAll("input, button")) field.disabled = chats.length >= MAX_CHATS;
    for (const button of buttons("incoming")) button.disabled = chats.length >= MAX_CHATS;
    const feed = find("feed");
    feed.replaceChildren();
    for (const item of chat.entries) {
      const row = element("li", "", "secret-demo-entry secret-demo-" + item.kind);
      row.dataset.entryId = String(item.id);
      if (item.deleted) row.classList.add("secret-demo-retained");
      const time = element("time", item.at.slice(11, 16) + " UTC · sample");
      time.dateTime = item.at;
      const label = item.kind === "out" ? "You · simulated" : item.kind === "in" ? chat.peer + " · simulated" : "Sample notice";
      const head = element("div", "", "secret-demo-entry-heading");
      head.append(element("strong", label), time);
      row.append(head, element("p", item.text));
      if (item.ttl) row.append(element("small", "Timer: " + item.ttl + " s · illustration, no countdown"));
      if (item.file) {
        const save = element("button", "Save fictional sample-note.txt · " + new TextEncoder().encode(FILE_TEXT).length + " bytes", "text-link");
        save.type = "button"; save.dataset.secretAction = "download";
        row.append(save);
      }
      if (item.deleted) row.append(element("small", "Peer deletion simulated · copy retained", "secret-demo-kept"));
      feed.append(row);
    }
    feed.scrollTop = feed.scrollHeight;
    find("update").textContent = update || chat.entries.length + " simulated entries in this conversation.";
  }

  document.addEventListener("click", event => {
    const trigger = event.target.closest("[data-secret-demo-open]");
    if (trigger) {
      opener = trigger;
      if (!dialog.open) dialog.showModal();
      find("message").disabled ? find("user").focus() : find("message").focus();
      return;
    }
    if (!dialog.contains(event.target)) return;
    const selectedButton = event.target.closest("[data-secret-chat]");
    if (selectedButton) {
      selected = Number(selectedButton.dataset.secretChat);
      find("message").value = "";
      render(); return;
    }
    const button = event.target.closest("[data-secret-action]");
    if (!button || button.disabled) return;
    const action = button.dataset.secretAction, chat = current();
    if (action === "dismiss") {dialog.close(); return;}
    if (action === "reset") {reset(); return;}
    if (action === "incoming") {
      if (chats.length >= MAX_CHATS) return;
      newChat("@visitor_sample_" + nextId, "pending");
      render("Incoming sample request. No Telegram request was received."); return;
    }
    if (action === "download") {
      const href = URL.createObjectURL(new Blob([FILE_TEXT], {type: "text/plain;charset=utf-8"}));
      const link = element("a", ""); link.href = href; link.download = "fictional-secret-chat-note.txt";
      dialog.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(href), 1000); return;
    }
    if (action === "accept" && chat.state === "pending" || action === "peer-accept" && chat.state === "requested") {
      chat.state = "ready";
      entry(chat, "notice", action === "accept" ? "Incoming sample request accepted here." : "Fictional peer acceptance simulated.");
      entry(chat, "in", "Hello. This reply is scripted for the demonstration.");
    } else if (chat.state === "ready" && chat.entries.length < MAX_ENTRIES - 1) {
      if (action === "file") entry(chat, "in", "A fictional attachment is ready to save.", {file: true});
      if (action === "delete") {
        const target = chat.entries.findLast(item => item.kind === "in" && !item.deleted);
        if (target) {
          target.deleted = true;
          entry(chat, "notice", "Peer deletion simulated for entry " + target.id + ". Its earlier copy is retained.");
        }
      }
      if (action === "end") {chat.state = "closed"; entry(chat, "notice", "Sample chat ended. Earlier entries remain visible.");}
    }
    render();
  });

  find("start").addEventListener("submit", event => {
    event.preventDefault();
    const peer = find("user").value.trim();
    if (!peer || chats.length >= MAX_CHATS) return;
    newChat(peer.slice(0, 64), "requested");
    find("message").value = "";
    render("Sample request created locally. Simulate acceptance to continue.");
  });
  find("send").addEventListener("submit", event => {
    event.preventDefault();
    const chat = current(), text = find("message").value.trim();
    if (!text || chat.state !== "ready" || chat.entries.length >= MAX_ENTRIES - 1) return;
    entry(chat, "out", text.slice(0, 4096));
    entry(chat, "in", "Scripted reply: your sample message is visible in this fictional conversation.");
    find("message").value = "";
    render("Sample message and scripted reply added. Nothing was sent to Telegram.");
    find("message").focus();
  });
  dialog.addEventListener("close", () => {if (opener?.isConnected) opener.focus();});
  reset();
})();
