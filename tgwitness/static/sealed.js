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
$("language").onchange = () => {lang = $("language").value; translate(); describeMode(); if (assessmentResult) renderAssessment(assessmentResult); poll();};
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
const mediaNames = {photo: ["Photos", "Фото"], video: ["Videos", "Видео"], animation: ["Animations", "Анимации"],
  video_note: ["Video messages", "Видеосообщения"], voice: ["Voice messages", "Голосовые сообщения"],
  audio: ["Audio", "Аудио"], sticker: ["Stickers", "Стикеры"], document: ["Documents", "Документы"]};
function translatedText(en, ru) {
  const span = document.createElement("span"); span.dataset.en = en; span.dataset.ru = ru; return span;
}
for (const [kind, limit] of Object.entries(mediaTypes)) {
  const row = document.createElement("div"), label = document.createElement("label"), check = document.createElement("input");
  check.type = "checkbox"; check.id = "type-" + kind; check.checked = true;
  label.append(check, " ", translatedText(...mediaNames[kind])); row.append(label);
  const sizeLabel = document.createElement("label"), size = document.createElement("input");
  size.type = "number"; size.id = "limit-" + kind; size.min = "1"; size.max = "2000"; size.value = String(limit);
  sizeLabel.append(translatedText("Download limit（MiB）", "Предел скачивания（МиБ）"), " ", size); row.append(sizeLabel);
  const action = document.createElement("select"); action.id = "action-" + kind; action.setAttribute("aria-label", kind + " action");
  for (const [value, en, ru] of [["", "Use selected attachment action", "Общее правило вложений"], ["download", "Download", "Скачать"],
    ["hashes_only", "Hashes only", "Только хеши"], ["exclude", "Skip", "Пропустить"]]) {
    const option = document.createElement("option"); option.value = value; option.dataset.en = en; option.dataset.ru = ru; action.append(option);
  }
  row.append(action); $("media-rules").append(row);
}
function selection() {
  const journal = $("export-mode").value === "journal";
  const selected = Array.from($("chats").selectedOptions, option => Number(option.value));
  if ((journal || $("export-scope").value === "chat") && !selected.length) {
    throw new Error(tr("Load chats and select at least one．", "Загрузите список и выберите хотя бы один чат．"));
  }
  const types = {};
  for (const kind of Object.keys(mediaTypes)) {
    const field = $("limit-" + kind);
    if (!field.checkValidity() || !Number.isInteger(Number(field.value))) throw new Error(tr("Download limits must be whole numbers from 1 to 2000 MiB．", "Предел скачивания должен быть целым числом от 1 до 2000 МиБ．"));
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
    if (!$("total-budget").checkValidity() || !Number.isInteger(options.max_total_gib)) throw new Error(tr("Enter a whole media budget from 1 to 1024 GiB．", "Укажите целый бюджет вложений от 1 до 1024 ГиБ．"));
    if (options.to_utc && options.from_utc && options.to_utc <= options.from_utc) throw new Error(tr("The end date must be on or after the start date．", "Конец периода не может предшествовать его началу．"));
    if ($("include-avatars").checked) throw new Error("Participant avatar capture is available in single-chat regular capture. For account export use Account profile photos.");
    return {mode: "account", account_scope: $("export-scope").value === "account" ? "all" : "selected", account_options: options};
  }
  return {chat_id: Number($("chats").value), capture: {download_media: true, media_action: $("media-action").value,
    oversized_media: $("oversized-media").value, include_avatars: $("include-avatars").checked,
    messages_first: $("messages-first").checked, types}};
}
let assessedSelection = null, assessmentResult = null;
function describeMode() {
  const mode = $("export-mode").value;
  $("mode-description").textContent = mode === "takeout" ? tr(
    "Official export requests，with Telegram approval when required．Settings stay configurable below．",
    "Официальные запросы экспорта，с подтверждением Telegram，если оно потребуется．Настройки выгрузки доступны ниже．") : mode === "regular" ? tr(
    "Regular API cannot enumerate groups and channels you left，and contacts include Telegram users rather than the full saved phone contact list．Rate limits still apply．",
    "Обычный API не перечисляет группы и каналы，из которых вы вышли，а контакты включают пользователей Telegram，но не весь сохранённый телефонный список．Лимиты запросов сохраняются．") : tr(
    "One chat，its history and changes observed while this runner is active．",
    "Один чат，его история и изменения，наблюдаемые во время работы этого запуска．");
  $("chat-help").textContent = mode === "journal" ? tr("Choose one chat．", "Выберите один чат．") : tr(
    "Select one or more chats，use Ctrl or Cmd with a click to add another，or Shift with arrow keys．An empty selection cannot start an account export．",
    "Выберите один или несколько чатов，для добавления используйте Ctrl или Cmd с нажатием，либо Shift со стрелками．С пустым выбором выгрузка не запустится．");
}
function clearAssessment() {
  assessedSelection = null; assessmentResult = null; $("save-selection").disabled = true;
  $("preflight-result").textContent = ""; $("preflight-details").hidden = true;
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
  $("preflight-result").textContent = tr("Checking disk and up to 25 recent messages per sampled chat…", "Проверяем диск и до 25 последних сообщений в каждом проверяемом чате…");
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
  $("preflight-result").textContent = (result.can_start ? tr("Settings accepted．", "Настройки приняты．") : tr("Cannot start with these resources．", "Недостаточно ресурсов для запуска．")) + " " + tr(
    `Sample：${sample.messages_examined || 0} messages，file downloads ${format(sample.known_download_bytes)}，estimated unique hash data ${format(sample.hash_manifest_estimate_bytes)}．Total archive size and duration remain unknown．${Math.ceil(result.remaining_seconds / 60)} capture minutes remain．`,
    `В выборке ${sample.messages_examined || 0} сообщений，файлы для скачивания ${format(sample.known_download_bytes)}，оценка объёма уникальных хешей ${format(sample.hash_manifest_estimate_bytes)}．Общий размер и длительность пока неизвестны，осталось ${Math.ceil(result.remaining_seconds / 60)} минут．`) + " " +
    (result.issues || []).map(issue => lang === "ru" ? ({
      approval_not_checked: "Telegram может потребовать подтверждения экспорта，эта проверка не запускает Takeout и не определяет срок ожидания．",
      left_chats_unavailable: "Обычный API не перечисляет покинутые каналы и супергруппы．",
      insufficient_free_disk: "Для рабочих файлов и упаковки свободно менее 256 МиБ．",
      empty_selection: "Не выбраны чаты или данные аккаунта．",
      account_busy: "Аккаунт занят другой выгрузкой，выборка не прочитана．",
      sample_incomplete: "Выборку не удалось прочитать полностью，общий размер и время остаются неизвестными．",
      sample_exceeds_media_budget: "Даже файлы из выборки превышают бюджет，часть файлов не будет скачана．",
      sample_exceeds_free_disk: "Даже файлам из выборки требуется больше свободного места．",
      browser_delivery_size_risk: "Файлы из выборки превышают предел расшифровки в браузере，используйте локальную команду．"
    }[issue.code] || issue.message) : issue.message).join(" ");
}
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
      (account.phase === "done" ? tr("Export completed within the selected scope．", "Выгрузка выбранных данных завершена．") : tr("Partial export：some selected data could not be acquired．", "Неполная выгрузка，часть выбранных данных не получена．")) + " " + tr(
        `${account.counts?.messages || 0} messages preserved，${account.coverage?.failures || 0} recorded failures．See coverage details in the archive．`,
        `Сохранено сообщений：${account.counts?.messages || 0}，ошибок：${account.coverage?.failures || 0}．Подробности о полноте есть в архиве．`) : "";
    $("capture-messages").textContent = String(account ? Math.max(account.counts?.messages || 0, account.acquisition?.messages_preserved || 0) : state.history.captured || 0);
    $("capture-unavailable").textContent = String(account ? account.coverage?.failures || 0 : state.history.unavailable || 0);
    $("capture-remaining").textContent = String(Math.ceil(state.remaining_seconds / 60));
    $("resume").hidden = account ? !["paused", "waiting", "failed"].includes(account.phase) || account.active : state.history.phase !== "paused";
    $("resume").textContent = account?.wait_reason === "takeout_approval" ? tr("Check export approval", "Проверить подтверждение экспорта") : tr("Resume paused capture", "Продолжить сбор");
    $("cancel").hidden = terminal || state.phase === "sealing";
    $("counts").textContent = JSON.stringify({history: state.history.phase, messages: state.history.captured || 0,
      unavailable: state.history.unavailable || 0, media: state.media, account_export: account, remaining_seconds: state.remaining_seconds}, null, 2);
    $("context").textContent = JSON.stringify({recipient_sha256: state.recipient_sha256, ...state.context,
      selection: state.selection, selection_sha256: state.selection_sha256}, null, 2);
    $("status").textContent = state.phase === "sealed" ? tr("Capture finished. Wait for the encrypted result in GitHub Artifacts.", "Сбор завершён. Дождитесь зашифрованного результата в GitHub Artifacts.") :
      state.phase === "cancelled" ? tr("Cancelled. No archive will be published.", "Отменено. Архив не будет опубликован.") :
      state.phase === "failed" ? tr("Capture failed. Check this run in GitHub.", "Ошибка сбора. Проверьте запуск в GitHub.") :
      state.phase === "sealing" ? tr("Preparing the archive…", "Готовим архив…") :
      state.phase === "collecting" ? tr("Capturing available messages and files…", "Собираем доступные сообщения и файлы…") :
      state.authorized ? tr("Connected. Choose what to export.", "Вход выполнен. Выберите данные для выгрузки.") :
      tr("Sign in to Telegram to continue.", "Для продолжения войдите в Telegram.");
    if (account?.wait_reason === "takeout_approval" && state.phase === "collecting") $("status").textContent =
      tr(`Telegram requires export approval．Review the request in an established Telegram session，then click Check export approval．Telegram reported ${account.delay_seconds} seconds of waiting，this runner has ${state.remaining_seconds} seconds left．A new runner may require approval again．`,
        `Telegram требует подтверждения экспорта，проверьте запрос в уже действующей сессии и нажмите «Проверить подтверждение экспорта»．Telegram сообщил об ожидании ${account.delay_seconds} секунд，у этого запуска осталось ${state.remaining_seconds} секунд．Новый запуск может снова потребовать подтверждения．`);
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
