"use strict";
const $ = id => document.getElementById(id);
let lang = "en", qrId = null, ended = false;
const tr = (en, ru) => lang === "ru" ? ru : en;
const fragment = new URLSearchParams(location.hash.slice(1));
if (fragment.has("access")) {
  sessionStorage.setItem("sealed-access", fragment.get("access"));
  history.replaceState(null, "", location.pathname);
}
const token = sessionStorage.getItem("sealed-access") || "";
function translate() {
  document.documentElement.lang = lang;
  $("language").value = lang;
  document.querySelectorAll("[data-en]").forEach(el => {el.textContent = el.dataset[lang];});
}
$("language").onchange = () => {lang = $("language").value; translate(); poll();};
translate();
async function api(path, body) {
  const response = await fetch("/api/" + path, {method: body === undefined ? "GET" : "POST",
    headers: {"Authorization": "Bearer " + token, "Content-Type": "application/json", "X-TgWitness-Language": lang,
      "X-TgWitness-System-Language": navigator.language},
    body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store", redirect: "error"});
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || "Request failed");
  return data;
}
function bind(id, action) {
  $(id).onclick = async () => {
    $(id).disabled = true; $("error").textContent = "";
    try {await action(); await poll();}
    catch (error) {$("error").textContent = error.message;}
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
  $("dialog-note").textContent = result.may_be_truncated ? tr("The dialog list reached its limit; some chats may be missing.", "Достигнут предел списка: некоторые чаты могут отсутствовать.") : "";
});
const mediaTypes = {photo: 20, video: 100, animation: 20, video_note: 50, voice: 20, audio: 50, sticker: 5, document: 50};
for (const [kind, limit] of Object.entries(mediaTypes)) {
  const row = document.createElement("div"), label = document.createElement("label"), check = document.createElement("input");
  check.type = "checkbox"; check.id = "type-" + kind; check.checked = !["animation", "sticker"].includes(kind);
  label.append(check, " " + kind.replaceAll("_", " ")); row.append(label);
  const sizeLabel = document.createElement("label"), size = document.createElement("input");
  size.type = "number"; size.id = "limit-" + kind; size.min = "1"; size.max = "2000"; size.value = String(limit);
  sizeLabel.append("Download limit (MiB) ", size); row.append(sizeLabel);
  const action = document.createElement("select"); action.id = "action-" + kind; action.setAttribute("aria-label", kind + " action");
  for (const [value, text] of [["", "Use selected attachment action"], ["download", "Download"], ["hashes_only", "Hashes only"], ["exclude", "Skip"]]) {
    const option = document.createElement("option"); option.value = value; option.textContent = text; action.append(option);
  }
  row.append(action); $("media-rules").append(row);
}
function selection() {
  const types = {};
  for (const kind of Object.keys(mediaTypes)) {
    const field = $("limit-" + kind);
    if (!field.checkValidity() || !Number.isInteger(Number(field.value))) throw new Error("Download limits must be whole numbers from 1 to 2000 MiB.");
    types[kind] = {enabled: $("type-" + kind).checked, max_mb: Number(field.value), action: $("action-" + kind).value || null};
  }
  const options = {transport: $("export-transport").value, export_format: $("export-format").value,
    chat_ids: $("export-scope").value === "account" ? [] : [Number($("chats").value)],
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
  const accountMode = $("export-scope").value !== "journal";
  if (accountMode) {
    if (!$("total-budget").checkValidity() || !Number.isInteger(options.max_total_gib)) throw new Error("Enter a whole media budget from 1 to 1024 GiB.");
    if (options.to_utc && options.from_utc && options.to_utc <= options.from_utc) throw new Error("The end date must be on or after the start date.");
    if ($("include-avatars").checked) throw new Error("Participant avatar capture is available in single-chat regular capture. For account export use Account profile photos.");
    return {mode: "account", account_options: options};
  }
  return {chat_id: Number($("chats").value), capture: {download_media: true, media_action: $("media-action").value,
    oversized_media: $("oversized-media").value, include_avatars: $("include-avatars").checked,
    messages_first: $("messages-first").checked, types}};
}
function clearAssessment() {
  $("preflight-result").textContent = ""; $("preflight-details").hidden = true;
  const journal = $("export-scope").value === "journal";
  $("account-options").hidden = journal;
  $("export-transport").disabled = journal;
  $("export-format").disabled = journal;
  $("include-avatars").disabled = !journal;
  if (!journal) $("include-avatars").checked = false;
  $("messages-first").disabled = !journal;
  if (!journal) $("messages-first").checked = true;
  $("chats").disabled = $("export-scope").value === "account";
  $("collect").disabled = $("export-scope").value !== "account" && !$("chats").options.length;
  $("preflight").disabled = $("collect").disabled;
}
$("capture-settings").addEventListener("change", clearAssessment);
$("chats").addEventListener("change", clearAssessment);
clearAssessment();
bind("preflight", async () => {
  const options = selection(), stamp = JSON.stringify(options);
  $("preflight-result").textContent = "Checking current disk and a sample of up to 25 recent messages…";
  const result = await api("preflight", options);
  if (JSON.stringify(selection()) !== stamp || $("selection").hidden) return;
  const sample = result.sample || {}, format = bytes => bytes >= 1048576 ? (bytes / 1048576).toFixed(2) + " MiB" :
    bytes >= 1024 ? (bytes / 1024).toFixed(1) + " KiB" : (bytes || 0) + " B";
  $("preflight-result").textContent = `${result.can_start ? "Settings accepted." : "Cannot start with these resources."} ` +
    `Sample: ${sample.messages_examined || 0} messages; file downloads ${format(sample.known_download_bytes)}; ` +
    `estimated unique hash data ${format(sample.hash_manifest_estimate_bytes)}. ` +
    `Total archive size and duration remain unknown. ${Math.ceil(result.remaining_seconds / 60)} capture minutes remain. ` +
    (result.issues || []).map(issue => issue.message).join(" ");
  $("preflight-json").textContent = JSON.stringify(result, null, 2); $("preflight-details").hidden = false;
  $("collect").disabled = !result.can_start;
});
bind("collect", () => api("collect", selection()));
bind("resume", () => api("resume", {}));
bind("finish", () => api("finish", {}));
bind("cancel", () => api("cancel", {}));
let polling = false;
async function poll() {
  if (polling || ended) return;
  polling = true;
  try {
    const state = await api("status");
    const terminal = ["sealed", "cancelled", "failed"].includes(state.phase);
    $("login").hidden = state.authorized || state.phase !== "login";
    $("selection").hidden = !state.authorized || state.phase !== "login";
    $("code-box").hidden = state.login !== "login_required";
    $("password-box").hidden = state.login !== "password_required";
    $("progress").hidden = state.phase !== "collecting";
    $("complete").hidden = state.phase !== "sealed";
    const account = state.account_export;
    $("complete-summary").textContent = account ?
      `${account.phase === "done" ? "Export completed within the selected scope." : "Partial export: some selected data could not be acquired."} ` +
      `${account.counts?.messages || 0} messages preserved; ${account.coverage?.failures || 0} recorded failures. ` +
      (account.phase === "done" ? "" : "See the archive's coverage details for missing history and attachments.") : "";
    $("capture-messages").textContent = String(account ? Math.max(account.counts?.messages || 0, account.acquisition?.messages_preserved || 0) : state.history.captured || 0);
    $("capture-unavailable").textContent = String(account ? account.coverage?.failures || 0 : state.history.unavailable || 0);
    $("capture-remaining").textContent = String(Math.ceil(state.remaining_seconds / 60));
    $("resume").hidden = account ? !["paused", "waiting", "failed"].includes(account.phase) || account.active : state.history.phase !== "paused";
    $("resume").textContent = account?.wait_reason === "takeout_approval" ? "Check export approval" : tr("Resume paused capture", "Продолжить сбор");
    $("cancel").hidden = terminal || state.phase === "sealing";
    $("counts").textContent = JSON.stringify({history: state.history.phase, messages: state.history.captured || 0,
      unavailable: state.history.unavailable || 0, media: state.media, account_export: account, remaining_seconds: state.remaining_seconds}, null, 2);
    $("context").textContent = JSON.stringify({recipient_sha256: state.recipient_sha256, ...state.context}, null, 2);
    $("status").textContent = state.phase === "sealed" ? tr("Capture finished. Wait for the encrypted result in GitHub Artifacts.", "Сбор завершён. Дождитесь зашифрованного результата в GitHub Artifacts.") :
      state.phase === "cancelled" ? tr("Cancelled. No archive will be published.", "Отменено. Архив не будет опубликован.") :
      state.phase === "failed" ? tr("Capture failed. Check this run in GitHub.", "Ошибка сбора. Проверьте запуск в GitHub.") :
      state.phase === "sealing" ? tr("Preparing the archive…", "Готовим архив…") :
      state.phase === "collecting" ? tr("Capturing available messages and files…", "Собираем доступные сообщения и файлы…") :
      state.authorized ? tr("Connected. Choose what to export.", "Вход выполнен. Выберите данные для выгрузки.") :
      tr("Sign in to Telegram to continue.", "Для продолжения войдите в Telegram.");
    if (account?.wait_reason === "takeout_approval" && state.phase === "collecting") $("status").textContent =
      `Telegram requires export approval. Review the request in an established Telegram session, then click Check export approval. Telegram reported ${account.delay_seconds} seconds of waiting. This runner has ${state.remaining_seconds} seconds left. A new runner may require approval again; use a persistent local export if the wait cannot fit.`;
    else if (account?.error && state.phase === "collecting") $("error").textContent = account.error;
    if (state.authorized) {$("api-hash").value = ""; $("phone").value = ""; qrId = null;}
    if (state.revocation === "not_confirmed") $("error").textContent = tr("Session revocation was not confirmed. End this session in Telegram Settings > Devices.", "Отзыв сессии не подтверждён. Завершите её в Telegram: Настройки → Устройства.");
    if (terminal) {ended = true; sessionStorage.removeItem("sealed-access");}
    if (qrId) {const qr = await api("qr/" + encodeURIComponent(qrId));
      if (["expired", "failed", "cancelled"].includes(qr.step)) {qrId = null; $("qr-image").hidden = true;
        $("error").textContent = tr("QR expired or failed. Generate another code.", "QR истёк или вход не удался. Создайте новый код.");}}
  } finally {polling = false;}
}
if (!token) {$("error").textContent = tr("Open the connection file with your private key in the setup helper first.", "Сначала откройте файл подключения своим закрытым ключом в помощнике запуска.");}
else {poll().catch(error => {$("error").textContent = error.message;});
  setInterval(() => {if (!ended) poll().catch(() => {$("error").textContent = tr("Connection unavailable. The runner may be finishing; check GitHub Artifacts.", "Нет соединения. Возможно, запуск завершается: проверьте GitHub Artifacts.");});}, 1500);}
