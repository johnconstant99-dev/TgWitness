"use strict";
const $ = id => document.getElementById(id);
let lang = navigator.language.startsWith("ru") ? "ru" : "en", qrId = null, ended = false;
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
    headers: {"Authorization": "Bearer " + token, "Content-Type": "application/json"},
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
  $("dialog-note").textContent = result.may_be_truncated ? tr("The dialog list reached its limit; some chats may be missing.", "Достигнут предел списка: некоторые чаты могут отсутствовать.") : "";
});
bind("collect", () => api("collect", {chat_id: Number($("chats").value)}));
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
    $("capture-messages").textContent = String(state.history.captured || 0);
    $("capture-unavailable").textContent = String(state.history.unavailable || 0);
    $("capture-remaining").textContent = String(Math.ceil(state.remaining_seconds / 60));
    $("resume").hidden = state.history.phase !== "paused";
    $("cancel").hidden = terminal || state.phase === "sealing";
    $("counts").textContent = JSON.stringify({history: state.history.phase, messages: state.history.captured || 0,
      unavailable: state.history.unavailable || 0, media: state.media, remaining_seconds: state.remaining_seconds}, null, 2);
    $("context").textContent = JSON.stringify({recipient_sha256: state.recipient_sha256, ...state.context}, null, 2);
    $("status").textContent = state.phase === "sealed" ? tr("Capture finished. Wait for the encrypted result in GitHub Artifacts.", "Сбор завершён. Дождитесь зашифрованного результата в GitHub Artifacts.") :
      state.phase === "cancelled" ? tr("Cancelled. No archive will be published.", "Отменено. Архив не будет опубликован.") :
      state.phase === "failed" ? tr("Capture failed. Check this run in GitHub.", "Ошибка сбора. Проверьте запуск в GitHub.") :
      state.phase === "sealing" ? tr("Preparing the archive…", "Готовим архив…") :
      state.phase === "collecting" ? tr("Capturing available messages and files…", "Собираем доступные сообщения и файлы…") :
      state.authorized ? tr("Connected. Choose a chat to capture.", "Вход выполнен. Выберите чат для выгрузки.") :
      tr("Sign in to Telegram to continue.", "Для продолжения войдите в Telegram.");
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
