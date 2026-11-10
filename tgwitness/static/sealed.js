"use strict";
const $ = id => document.getElementById(id);
let lang = "en", qrId = null, ended = false;
let lastState = null, connectionFailed = false, statusError = "", actionError = "";
const english = new WeakMap();
const tr = (text, values = {}) => {
  const translated = lang === "en" ? text : window.TGW_SEALED_LOCALES?.[lang]?.[text];
  return (typeof translated === "string" ? translated : text).replace(/\{(\w+)\}/g,
    (match, name) => Object.hasOwn(values, name) ? String(values[name]) : match);
};
const fragment = new URLSearchParams(location.hash.slice(1));
if (fragment.has("access")) {
  sessionStorage.setItem("sealed-access", fragment.get("access"));
  history.replaceState(null, "", location.pathname);
}
const token = sessionStorage.getItem("sealed-access") || "";
function translate() {
  document.documentElement.lang = lang;
  $("language").value = lang;
  document.querySelectorAll("[data-i18n]").forEach(el => {
    if (!english.has(el)) english.set(el, el.textContent);
    el.textContent = tr(english.get(el));
  });
}
$("language").onchange = () => {
  lang = $("language").value; translate(); describeMode();
  if (assessmentResult) renderAssessment(assessmentResult);
  if (lastState) renderState(lastState);
  else renderError();
};
translate();
async function api(path, body) {
  const response = await fetch("/api/" + path, {method: body === undefined ? "GET" : "POST",
    headers: {"Authorization": "Bearer " + token, "Content-Type": "application/json", "X-TgWitness-Language": lang,
      "X-TgWitness-System-Language": navigator.language},
    body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store", redirect: "error"});
  const data = await response.json();
  if (!response.ok) throw Object.assign(new Error(data.detail || "Request failed"), {status: response.status});
  return data;
}
function bind(id, action) {
  $(id).onclick = async () => {
    $(id).disabled = true; actionError = ""; renderError();
    try {await action(); await poll().catch(() => {});}
    catch (error) {actionError = error.message; renderError();}
    finally {$(id).disabled = false;}
  };
}
function credentials() {
  const id = $("api-id").value.trim(), hash = $("api-hash").value.trim();
  if (!id && !hash) return {};
  if (!/^[0-9]+$/.test(id) || Number(id) < 1 || Number(id) > 2147483647 || !/^[a-fA-F0-9]{32}$/.test(hash)) {
    $("custom-api").open = true;
    throw new Error($("api-error").textContent);
  }
  return {api_id: Number(id), api_hash: hash};
}
bind("send-code", async () => {
  await api("phone", {...credentials(), phone: $("phone").value.trim()});
  qrId = null; $("qr-image").hidden = true;
});
bind("confirm-code", async () => {await api("code", {code: $("code").value}); $("code").value = "";});
bind("confirm-password", async () => {await api("password", {password: $("password").value}); $("password").value = "";});
bind("qr", async () => {
  const result = await api("qr", credentials()); qrId = result.id;
  $("qr-image").src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(result.svg);
  $("qr-image").hidden = false;
});
bind("refresh", async () => {
  const result = await api("dialogs"); $("chats").replaceChildren();
  result.dialogs.forEach(chat => {const option = document.createElement("option");
    option.value = String(chat.chat_id); option.textContent = `${chat.title} (${chat.chat_id})`;
    $("chats").append(option);
  });
  $("collect").disabled = !result.dialogs.length;
  $("preflight").disabled = !result.dialogs.length;
  clearAssessment();
  $("dialog-note").textContent = result.may_be_truncated ? tr("The dialog list reached its limit; some chats may be missing.") : "";
});
const mediaTypes = {photo: 20, video: 100, animation: 20, video_note: 50, voice: 20, audio: 50, sticker: 5, document: 50};
const mediaNames = {photo: "Photos", video: "Videos", animation: "Animations", video_note: "Video messages",
  voice: "Voice messages", audio: "Audio", sticker: "Stickers", document: "Documents"};
function translatedText(text, tag = "span") {
  const element = document.createElement(tag); element.dataset.i18n = ""; element.textContent = text; return element;
}
for (const [kind, limit] of Object.entries(mediaTypes)) {
  const row = document.createElement("div"), label = document.createElement("label"), check = document.createElement("input");
  check.type = "checkbox"; check.id = "type-" + kind; check.checked = true;
  label.append(check, " ", translatedText(mediaNames[kind])); row.append(label);
  const sizeLabel = document.createElement("label"), size = document.createElement("input");
  size.type = "number"; size.id = "limit-" + kind; size.min = "1"; size.max = "2000"; size.value = String(limit);
  sizeLabel.append(translatedText("Download limit (MiB)"), " ", size); row.append(sizeLabel);
  const action = document.createElement("select"); action.id = "action-" + kind; action.setAttribute("aria-label", kind + " action");
  for (const [value, text] of [["", "Use selected attachment action"], ["download", "Download"], ["hashes_only", "Hashes only"], ["exclude", "Skip"]]) {
    const option = translatedText(text, "option"); option.value = value; action.append(option);
  }
  row.append(action); $("media-rules").append(row);
}
function selection() {
  const journal = $("export-mode").value === "journal";
  const selected = Array.from($("chats").selectedOptions, option => Number(option.value));
  if ((journal || $("export-scope").value === "chat") && !selected.length) {
    throw new Error(tr("Load chats and select at least one."));
  }
  const types = {};
  for (const kind of Object.keys(mediaTypes)) {
    const field = $("limit-" + kind);
    if (!field.checkValidity() || !Number.isInteger(Number(field.value))) throw new Error(tr("Download limits must be whole numbers from 1 to 2000 MiB."));
    types[kind] = {enabled: $("type-" + kind).checked, max_mb: Number(field.value), action: $("action-" + kind).value || null};
  }
  const options = {transport: $("export-mode").value, export_format: $("export-format").value,
    chat_ids: $("export-scope").value === "account" ? [] : selected,
    chat_kinds: ["private", "bot", "group", "supergroup", "channel"].filter(kind => $("kind-" + kind).checked),
    include_archived: $("account-archived").checked, own_messages_only: $("account-own").checked,
    messages_first: true, media_action: $("media-action").value, oversized_media: $("oversized-media").value,
    max_media_file_mib: 2000, max_total_gib: Number($("total-budget").value), budget_exhausted: "hashes_only",
    media_types: Object.keys(types).filter(k => types[k].enabled).map(k => k === "video_note" ? "video_message" : k),
    media_rules: Object.fromEntries(Object.entries(types).map(([k, rule]) => [k === "video_note" ? "video_message" : k, rule])),
    from_utc: $("from-date").value ? $("from-date").value + "T00:00:00Z" : null,
    to_utc: $("through-date").value ? new Date(Date.parse($("through-date").value + "T00:00:00Z") + 86400000).toISOString() : null,
    include_profile: $("account-profile").checked, include_contacts: $("account-contacts").checked,
    include_profile_photos: $("account-photos").checked, include_stories: $("account-stories").checked,
    include_session_metadata: $("account-sessions").checked, include_other_data: $("account-other").checked};
  const accountMode = !journal;
  if (accountMode) {
    if (!$("total-budget").checkValidity() || !Number.isInteger(options.max_total_gib)) throw new Error(tr("Enter a whole media budget from 1 to 1024 GiB."));
    if (options.to_utc && options.from_utc && options.to_utc <= options.from_utc) throw new Error(tr("The end date must be on or after the start date."));
    if ($("include-avatars").checked) throw new Error("Participant avatar capture is available in single-chat regular capture. For account export use Account profile photos.");
    return {mode: "account", account_scope: $("export-scope").value === "account" ? "all" : "selected", account_options: options};
  }
  return {chat_id: Number($("chats").value), capture: {download_media: true, media_action: $("media-action").value,
    oversized_media: $("oversized-media").value, include_avatars: $("include-avatars").checked,
    messages_first: $("messages-first").checked, preserve_ephemeral_media: $("preserve-ephemeral-media").checked, types}};
}
let assessedSelection = null, assessmentResult = null;
function describeMode() {
  const mode = $("export-mode").value;
  $("mode-description").textContent = mode === "takeout" ? tr(
    "Official export requests, with Telegram approval when required. Settings stay configurable below.") : mode === "regular" ? tr(
    "Regular API cannot enumerate groups and channels you left, and contacts include Telegram users rather than the full saved phone contact list. Rate limits still apply.") : tr(
    "One chat, its history and changes observed while this runner is active.");
  $("chat-help").textContent = mode === "journal" ? tr("Choose one chat.") : tr(
    "Select one or more chats, use Ctrl or Cmd with a click to add another, or Shift with arrow keys. An empty selection cannot start an account export.");
}
function clearAssessment() {
  assessedSelection = null; assessmentResult = null; $("save-selection").disabled = true;
  $("preflight-result").textContent = ""; $("preflight-details").hidden = true;
  $("preflight-budget").textContent = ""; $("budget-actions").hidden = true;
  const journal = $("export-mode").value === "journal";
  $("account-options").hidden = journal;
  $("export-scope").disabled = journal;
  $("export-format").disabled = journal;
  for (const id of ["export-scope", "export-format"]) {
    $(id).hidden = journal; document.querySelector(`label[for="${id}"]`).hidden = journal;
  }
  $("account-other").disabled = $("export-mode").value !== "takeout";
  if ($("account-other").disabled) $("account-other").checked = false;
  $("takeout-notice").hidden = $("export-mode").value !== "takeout";
  $("include-avatars").disabled = !journal;
  $("include-avatars").parentElement.hidden = !journal;
  if (!journal) $("include-avatars").checked = false;
  $("messages-first").disabled = !journal;
  $("preserve-ephemeral-media").disabled = !journal;
  $("preserve-ephemeral-media").parentElement.hidden = !journal;
  if (!journal) $("messages-first").checked = true;
  $("chat-picker").hidden = !journal && $("export-scope").value === "account";
  $("chats").multiple = !journal; $("chats").size = journal ? 1 : 6;
  $("collect").disabled = !$("chat-picker").hidden && !$("chats").selectedOptions.length;
  $("preflight").disabled = $("collect").disabled;
  describeMode();
}
$("capture-settings").addEventListener("input", clearAssessment);
$("capture-settings").addEventListener("change", clearAssessment);
clearAssessment();
translate();
bind("preflight", async () => {
  const options = selection(), stamp = JSON.stringify(options);
  $("preflight-result").textContent = tr("Checking disk and up to 25 recent messages per sampled chat…");
  const result = await api("preflight", options);
  if (JSON.stringify(selection()) !== stamp || $("selection").hidden) return;
  assessmentResult = result; renderAssessment(result);
  $("preflight-json").textContent = JSON.stringify(result, null, 2); $("preflight-details").hidden = false;
  assessedSelection = result.selection; $("save-selection").disabled = !assessedSelection;
  $("collect").disabled = !result.can_start;
});
function renderAssessment(result) {
  const sample = result.sample || {}, format = bytes => bytes >= 1048576 ? (bytes / 1048576).toFixed(2) + " MiB" :
    bytes >= 1024 ? (bytes / 1024).toFixed(1) + " KiB" : (bytes || 0) + " B";
  $("preflight-result").textContent = (result.can_start ? tr("Settings accepted.") : tr("Cannot start with these resources.")) + " " + tr(
    "Sample: {messages} messages, file downloads {downloads}, estimated unique hash data {hashes}. {minutes} session minutes remain.",
    {messages: sample.messages_examined || 0, downloads: format(sample.known_download_bytes),
      hashes: format(sample.hash_manifest_estimate_bytes), minutes: Math.ceil(result.remaining_seconds / 60)}) + " " +
    (result.issues || []).map(issue => tr(issue.message)).join(" ");
  const plan = result.time_plan;
  if (!plan) return;
  const minutes = seconds => Math.ceil(seconds / 60), states = {
    estimated_fit: tr("Fits the time estimate."),
    over_budget: tr("The selected volume exceeds the available time."),
    no_collection_time: tr("Only archive preparation time remains."),
    unknown: tr("Not all selected data could be measured.")};
  $("preflight-budget").textContent = (states[plan.fit] || "") + " " + tr(
    "{messages} history messages counted. Estimated work: {work} min, archive preparation: {sealing} min, available: {available} min. Download assumption: 1 MiB/s with a 2× time margin.",
    {messages: plan.messages_to_read, work: minutes(plan.acquisition_seconds), sealing: minutes(plan.sealing_reserve_seconds),
      available: minutes(plan.remaining_seconds)}) +
    (plan.approval === "not_requested" ? " " + tr("Takeout approval time will be added when Telegram reports it.") : "") +
    (plan.files_exceed_budget ? " " + tr("Estimated files also exceed the selected download budget.") : "");
  $("budget-actions").hidden = !plan.suggestions.length;
  $("budget-messages").hidden = !plan.suggestions.includes("messages_only");
  $("budget-chats").hidden = !plan.suggestions.includes("fewer_chats") || $("export-mode").value === "journal";
}
$("budget-messages").onclick = () => {
  $("media-action").value = "exclude";
  for (const kind of Object.keys(mediaTypes)) $("action-" + kind).value = "";
  for (const id of ["include-avatars", "preserve-ephemeral-media", "account-photos", "account-stories", "account-other"]) $(id).checked = false;
  clearAssessment(); $("preflight").click();
};
$("budget-chats").onclick = () => {$("export-scope").value = "chat"; clearAssessment(); $("chats").focus();};
$("save-selection").onclick = () => {
  if (!assessedSelection) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(assessedSelection, null, 2) + "\n"], {type: "application/json"}));
  const link = document.createElement("a"); link.href = url; link.download = "sealed-export-settings.json";
  document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
};
bind("collect", () => api("collect", selection()));
bind("resume", () => api("resume", {}));
bind("finish", () => api("finish", {}));
bind("cancel", () => api("cancel", {}));
let polling = false;
function renderError() {
  $("error").textContent = lastState?.revocation === "not_confirmed" ? tr(
    "Session revocation was not confirmed. End this session in Telegram Settings > Devices.") : connectionFailed ? statusError || tr(
    "Connection unavailable. The runner may be finishing, check GitHub Artifacts.") : !token ? tr(
    "Open the connection file with your private key in the setup helper first.") :
    actionError || (lastState?.phase === "collecting" ? lastState.account_export?.error || "" : "");
}
function chatSummary(state) {
  const history = state.history, media = state.media || {};
  const pending = ["queued", "retry", "running", "cancelled"].reduce((sum, key) => sum + (media[key] || 0), 0);
  const complete = history.phase === "complete" && !history.unavailable && !media.failed && !pending;
  return (complete ? tr("History reading completed within the selected scope.") : tr(
    "Partial capture, check the gaps recorded in the archive.")) + " " + tr(
    "Messages preserved: {captured}, unavailable: {unavailable}. Attachments saved: {done}, hashes only: {hashed}, skipped: {skipped}, failed: {failed}, unfinished: {pending}.",
    {captured: history.captured || 0, unavailable: history.unavailable || 0, done: media.done || 0, hashed: media.hashed || 0,
      skipped: media.skipped || 0, failed: media.failed || 0, pending});
}
function renderState(state) {
    const terminal = ["sealed", "cancelled", "failed"].includes(state.phase);
    $("login").hidden = state.authorized || state.phase !== "login";
    $("selection").hidden = !state.authorized || state.phase !== "login";
    $("code-box").hidden = state.login !== "login_required";
    $("password-box").hidden = state.login !== "password_required";
    $("progress").hidden = state.phase !== "collecting";
    $("complete").hidden = state.phase !== "sealed";
    const account = state.account_export;
    $("complete-summary").textContent = account ?
      (account.phase === "done" ? tr("Export completed within the selected scope.") : tr("Partial export: some selected data could not be acquired.")) + " " + tr(
        "{messages} messages preserved, {failures} recorded failures. See coverage details in the archive.",
        {messages: account.counts?.messages || 0, failures: account.coverage?.failures || 0}) : chatSummary(state);
    if (state.revocation === "revoked") $("complete-summary").textContent += " " + tr(
      "Telegram session revocation confirmed.");
    $("capture-messages").textContent = String(account ? Math.max(account.counts?.messages || 0, account.acquisition?.messages_preserved || 0) : state.history.captured || 0);
    $("capture-unavailable").textContent = String(account ? account.coverage?.failures || 0 : state.history.unavailable || 0);
    $("capture-remaining").textContent = String(Math.ceil(state.remaining_seconds / 60));
    const budget = state.time_budget;
    $("capture-budget").textContent = budget ? tr(
      "Collection time left: {collection} min, reserved for the archive: {sealing} min.",
      {collection: Math.ceil(budget.collection_seconds / 60), sealing: Math.ceil(budget.sealing_reserve_seconds / 60)}) +
      (budget.estimated_remaining_seconds == null ? "" : " " + tr("Current completion estimate: {minutes} min.",
        {minutes: Math.ceil(budget.estimated_remaining_seconds / 60)})) +
      (budget.fit === "wait_exceeds_window" ? " " + tr("Telegram's reported wait exceeds this session. Approve Takeout from an established session, or finish with the data already saved.") :
       budget.fit === "over_budget" ? " " + tr("At the current rate, the full selection will not fit; collection stops before packaging time.") : "") : "";
    const transfer = account?.active && account.transfer;
    $("capture-transfer").hidden = !transfer;
    const mib = bytes => (bytes / 1024**2).toFixed(2);
    $("capture-transfer").textContent = !transfer ? "" : transfer.total_bytes == null ? tr(
      "Current file: {received} MiB received. The file is preserved after the download completes.", {received: mib(transfer.received_bytes)}) : tr(
      "Current file: {received} MiB received of {total} MiB. The file is preserved after the download completes.",
      {received: mib(transfer.received_bytes), total: mib(transfer.total_bytes)});
    $("resume").hidden = account ? !["paused", "waiting", "failed"].includes(account.phase) || account.active : state.history.phase !== "paused";
    $("resume").textContent = account?.wait_reason === "takeout_approval" ? tr("Check export approval") : tr("Resume paused capture");
    $("cancel").hidden = terminal || state.phase === "sealing";
    $("counts").textContent = JSON.stringify({history: state.history.phase, messages: state.history.captured || 0,
      unavailable: state.history.unavailable || 0, media: state.media, account_export: account, remaining_seconds: state.remaining_seconds}, null, 2);
    $("context").textContent = JSON.stringify({recipient_sha256: state.recipient_sha256, ...state.context,
      selection: state.selection, selection_sha256: state.selection_sha256}, null, 2);
    $("status").textContent = state.phase === "sealed" ? tr("Capture finished. Wait for the encrypted result in GitHub Artifacts.") :
      state.phase === "cancelled" ? tr("Cancelled. No archive will be published.") :
      state.phase === "failed" ? tr("Capture failed. Check this run in GitHub.") :
      state.phase === "sealing" ? tr("Preparing the archive…") :
      state.phase === "collecting" ? tr("Capturing available messages and files…") :
      state.authorized ? tr("Connected. Choose what to export.") :
      tr("Sign in to Telegram to continue.");
    if (account?.wait_reason === "takeout_approval" && state.phase === "collecting") $("status").textContent =
      tr("Telegram requires export approval from another device that was already signed in before this request. The requesting session and a fresh login cannot approve it. After allowing the export there, click Check export approval. Telegram reported {delay} seconds of waiting, this runner has {remaining} seconds left. A new runner may require approval again.",
        {delay: account.delay_seconds, remaining: state.remaining_seconds});
    if (state.authorized) {$("api-hash").value = ""; $("phone").value = ""; qrId = null;}
    renderError();
    if (terminal) {ended = true; sessionStorage.removeItem("sealed-access");}
}
async function poll() {
  if (polling || ended) return;
  polling = true;
  try {
    const state = await api("status");
    lastState = state; connectionFailed = false; statusError = ""; renderState(state);
    if (qrId) {const qr = await api("qr/" + encodeURIComponent(qrId));
      if (["expired", "failed", "cancelled"].includes(qr.step)) {qrId = null; $("qr-image").hidden = true;
        actionError = tr("QR expired or failed. Generate another code."); renderError();}}
  } catch (error) {connectionFailed = true; statusError = error.status ? error.message : ""; renderError(); throw error;
  } finally {polling = false;}
}
if (!token) renderError();
else {poll().catch(() => {});
  setInterval(() => {if (!ended) poll().catch(() => {});}, 1500);}
