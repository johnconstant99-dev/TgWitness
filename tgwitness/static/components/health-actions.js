export function createHealthActions({node, tr, health, close, context}) {
  const {getState, getSession, may, json, refreshStatus, toast, getSources, navigate} = context;
  let pending = null;
  const buttons = new Map();
  function add(part, key, label, action) {
    const button = node("button", "secondary", tr(label)); button.type = "button";
    button.dataset.healthAction = key; buttons.set(key, button); health.actions(part).append(button);
    button.addEventListener("click", async () => {
      if (pending !== null) return;
      const session = getSession(), state = getState(), snapshot = state.status;
      pending = session; update();
      try {
        await action(snapshot, state.profile, session);
        if (session === getSession()) await refreshStatus();
      } catch (error) {
        if (session === getSession() && !["StaleView", "AbortError"].includes(error.name)) toast(error.message, true);
      } finally { if (pending === session) {pending = null; update();} }
    });
    return button;
  }
  function unconfirmed(status) {
    return status.targets.filter(target => target.enabled &&
      status.collector.source_status?.[String(target.chat_id)]?.state === "access_unconfirmed" &&
      !status.collector.source_status[String(target.chat_id)].ignored).map(target => target.chat_id);
  }
  async function sourceView(session) {
    close(); await navigate("sources");
    const view = await getSources();
    return getSession() === session ? view : null;
  }
  add("sources", "show-sources", "Show affected sources", async (_, __, session) => {
    (await sourceView(session))?.filterTargets("unconfirmed");
  });
  add("sources", "exclude-sources", "Exclude from scope", async (status, _, session) => {
    const ids = unconfirmed(status), wide = (status.scope?.mode || "selected") !== "selected";
    if (!ids.length || !window.confirm(tr(wide
      ? "Exclude {n} unconfirmed sources? Collection for these chats will stop; saved evidence stays."
      : "Pause {n} unconfirmed sources? Collection for these chats will stop; saved evidence stays.", {n: ids.length}))) return;
    const view = await sourceView(session);
    if (view) {view.filterTargets("unconfirmed"); await view.runSourceAction(ids, wide ? "exclude" : "pause");}
  });
  add("sources", "ignore-sources", "Ignore until visible", async (status, profile, session) => {
    const ids = unconfirmed(status); if (!ids.length) return;
    await json("targets/ignore-unconfirmed", {chat_ids: ids, ignored: true}, {profile});
    if (session === getSession()) toast(tr("Warnings are ignored until these sources appear in Telegram. Collection settings stay the same."));
  });
  add("media", "enable-media", "Enable downloads", async (status, profile, session) => {
    await json("capture", {...status.capture, download_media: true}, {profile});
    if (session === getSession()) toast(tr("Attachment downloads enabled."));
  });
  add("media", "clear-queue", "Clear waiting queue", async (status, profile, session) => {
    if (!window.confirm(tr("Cancel the waiting attachment jobs shown now? Running downloads and saved files stay. Cancelled jobs will not be retried automatically."))) return;
    const result = await json("media/queue/clear", {through_seq: status.stats.head?.seq || 0}, {profile});
    if (session === getSession()) toast(tr("Cancelled {n} waiting attachment jobs.", {n: result.cancelled}));
  });
  add("media", "disabled-receipts", "Skip download-disabled notices", async (status, profile, session) => {
    const record = status.capture.record_disabled_media === false;
    await json("capture", {...status.capture, record_disabled_media: record}, {profile});
    if (session === getSession()) toast(tr(record
      ? "New download-disabled notices will be recorded."
      : "New download-disabled notices are suppressed. Existing records stay in the journal."));
  });
  function update() {
    const status = getState().status;
    if (!status) return;
    if (pending !== null && pending !== getSession()) pending = null;
    const ids = unconfirmed(status), canSources = may("sources") && !status.demo;
    const canMedia = may("settings") && !status.demo && !status.chats_limited;
    for (const button of buttons.values()) button.disabled = pending !== null;
    buttons.get("show-sources").hidden = !ids.length;
    buttons.get("show-sources").textContent = tr("Show these {n} sources", {n: ids.length});
    buttons.get("exclude-sources").hidden = !ids.length || !canSources || ids.length > 500 || status.chats_limited && (status.scope?.mode || "selected") !== "selected";
    buttons.get("exclude-sources").textContent = tr((status.scope?.mode || "selected") === "selected" ? "Pause these sources" : "Exclude from scope");
    buttons.get("ignore-sources").hidden = !ids.length || !canSources || ids.length > 500;
    buttons.get("enable-media").hidden = !canMedia || status.capture.download_media;
    const counts = status.health?.media?.counts || {};
    buttons.get("clear-queue").hidden = !canMedia || !(counts.pending || counts.retry);
    buttons.get("disabled-receipts").hidden = !canMedia || status.capture.download_media;
    buttons.get("disabled-receipts").textContent = tr(status.capture.record_disabled_media === false
      ? "Record download-disabled notices" : "Skip download-disabled notices");
  }
  return {update};
}
