(() => {
  "use strict";
  const root = document.querySelector("[data-capture-wizard]");
  if (!root) return;
  const encoder = new TextEncoder(), decoder = new TextDecoder();
  const requested = root.dataset.siteLanguage || new URLSearchParams(location.search).get("lang") || window.TGW_LANG || navigator.language;
  const languages = window.TGW_CAPTURE_LANGUAGES || {en:"English",ru:"Русский"};
  const tag = requested.toLowerCase().replaceAll("_", "-");
  let lang = /^zh-(?:hant|tw|hk|mo)(?:-|$)/.test(tag) ? "zh-Hant" : Object.keys(languages).find(code => code.toLowerCase() === tag) || (Object.hasOwn(languages, tag.split("-")[0]) ? tag.split("-")[0] : "en"), epoch = 0;
  const initial = () => ({step: 1, key: null, privateKey: null, saved: false, connection: null,
    repository: "", busy: false, error: "", note: "", delivered: false});
  let state = initial();
  const t = (en, ru) => window.TGW_CAPTURE_LOCALES?.[lang]?.[en] ?? (lang === "ru" ? ru : en);
  const esc = value => String(value).replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
  const icon = name => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${{
    lock:'<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7.5a4 4 0 0 1 8 0V11"/>',
    check:'<path d="m5 12 4 4L19 6"/>',
    arrow:'<path d="M5 12h14m-5-5 5 5-5 5"/>',
    file:'<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z M14 3v5h5 M9 13h6 M9 17h4"/>',
    external:'<path d="M14 4h6v6M20 4l-8 8M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h4"/>'
  }[name]}</svg>`;
  const button = (action, text, cls = "primary", disabled = false) => `<button type="button" class="${cls}" data-capture-action="${action}" ${disabled || state.busy ? "disabled" : ""}>${text}</button>`;
  const link = (url, text, cls = "secondary", id = "") => `<a ${id ? `id="${id}"` : ""} class="${cls}" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${text}${icon("external")}</a>`;
  const ready = () => !!state.key && state.saved;
  const repository = () => /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(state.repository) ? state.repository : "";
  const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
  const unb64 = text => Uint8Array.from(atob(text), ch => ch.charCodeAt(0));
  function save(bytes, name, type) {
    const url = URL.createObjectURL(new Blob([bytes], {type})), a = document.createElement("a");
    a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 10000);
  }
  function render(focus = false) {
    const titles = [t("Save your key", "Сохраните ключ"), t("Start the collector", "Запустите сборщик"),
      t("Capture the chat", "Выгрузите чат"), t("Get your archive", "Получите архив")];
    const subtitles = [t("On this device", "На этом устройстве"), t("In your own fork", "В своём форке"),
      t("In a temporary panel", "Во временной панели"), t("Back here", "Снова здесь")];
    root.lang = lang; root.dir = ["ar","fa","ur","he"].includes(lang) ? "rtl" : "ltr";
    if (root.closest(".capture-page")) {
      document.documentElement.lang=lang;
      const home=document.querySelector(".capture-header .brand");
      if (home) {const url=new URL(home.href);url.searchParams.set("lang",lang);home.href=url.href;}
    }
    root.innerHTML = `<div class="page-heading capture-heading"><div><span class="eyebrow">GITHUB ACTIONS <span class="capture-preview">${t("PREVIEW", "ПРЕДВАРИТЕЛЬНАЯ ВЕРСИЯ")}</span></span>
      <h1>${t("Capture a chat through GitHub", "Выгрузка чата через GitHub")}</h1>
      <p class="page-description">${t("Collect a Telegram chat on a temporary runner. Receive an encrypted archive and GitHub provenance.", "Выгрузите чат Telegram на временной машине. Получите зашифрованный архив и аттестацию GitHub.")}</p></div>
      <label class="capture-language"><span>${t("Language", "Язык")}</span><select id="capture-language">${Object.entries(languages).map(([code,name])=>`<option value="${code}" ${lang === code ? "selected" : ""}>${esc(name)}</option>`).join("")}</select></label></div>
      <div data-capture-story></div><div class="capture-setup-heading" id="capture-setup" tabindex="-1"><h2>${t("Capture your chat", "Выгрузка чата")}</h2><p>${t("Follow these four steps. Keep this tab open.", "Четыре шага. Оставьте эту вкладку открытой.")}</p></div>
      <div class="capture-layout"><aside class="capture-rail"><ol class="capture-steps" aria-label="${t("Capture steps", "Шаги выгрузки")}">${titles.map((title, i) => `<li><button type="button" data-capture-step="${i+1}" ${state.busy || (i > 0 && !ready()) ? "disabled" : ""} ${state.step === i+1 ? 'aria-current="step"' : ""}><span class="capture-number">${i+1}</span><span><strong>${title}</strong><small>${subtitles[i]}</small></span></button></li>`).join("")}</ol>
      <div class="capture-private">${icon("lock")}<p>${t("Your private key stays here. Save it before continuing.", "Закрытый ключ остаётся здесь. Сохраните его перед продолжением.")}</p></div>
      <a id="instructions" class="text-link" href="https://phishdestroy.github.io/TgWitness/${lang === "en" ? "" : lang + "/"}docs/capture/" target="_blank" rel="noopener noreferrer">${t("Full instructions", "Подробная инструкция")}</a></aside>
      <div class="capture-work"><section class="card capture-card" aria-labelledby="capture-step-title" aria-busy="${state.busy}"><div class="capture-step-heading"><span class="eyebrow">${t("STEP", "ШАГ")} ${state.step} / 4</span><h2 id="capture-step-title" tabindex="-1">${titles[state.step-1]}</h2></div>
      <p id="capture-error" class="notice error" role="alert" ${state.error ? "" : "hidden"}>${esc(state.error)}</p>
      <p class="capture-feedback" role="status" ${state.busy || state.note ? "" : "hidden"}>${esc(state.busy ? t("Processing locally…", "Обработка в браузере…") : state.note)}</p>
      ${state.step === 1 ? keyStep() : state.step === 2 ? githubStep() : state.step === 3 ? connectionStep() : resultStep()}
      </section><details class="capture-boundary"><summary>${t("What does GitHub verify?", "Что подтверждает GitHub?")}</summary><p>${t("The attestation binds the archive to an approved collector workflow and detects later changes. It does not prove that every message is true or that the history is complete. GitHub and the HTTPS tunnel remain trusted infrastructure.", "Аттестация связывает архив с разрешённой версией сборщика и позволяет обнаружить последующие изменения. Она не доказывает истинность каждого сообщения или полноту истории. GitHub и HTTPS-туннель остаются доверенной инфраструктурой.")}</p></details>
      ${state.key ? button("reset", t("Start a new capture", "Начать новую выгрузку"), "quiet capture-reset") : ""}</div></div>`;
    root.querySelector("#recipient")?.setAttribute("aria-label", t("Public encryption key", "Открытый ключ шифрования"));
    const recipient = root.querySelector("#recipient"); if (recipient) recipient.value = state.key?.recipient || "";
    window.TgWitnessCaptureStory?.mount(root.querySelector("[data-capture-story]"), lang);
    if (focus) root.querySelector("#capture-step-title").focus({preventScroll:true});
  }
  function keyStep() {
    return `<p class="capture-lead">${t("Save this key to open the connection and archive.", "Сохраните ключ: он нужен для подключения и расшифровки архива.")}</p>
      ${state.key ? `<div class="capture-success">${icon("check")}<div><strong>${t("Your key is ready", "Ключ готов")}</strong><p>sealed-key.json</p></div>${button("save-key", t("Save again", "Скачать ещё раз"), "secondary")}</div>
      <label class="check-label capture-confirm"><input id="capture-key-saved" type="checkbox" ${state.saved ? "checked" : ""}>${t("I saved sealed-key.json. A lost key cannot be recovered.", "Я сохранил sealed-key.json. Потерянный ключ не восстановить.")}</label>` :
      `<div class="capture-key-hero">${icon("lock")}<div><strong>${t("A key just for this capture", "Ключ только для этой выгрузки")}</strong><p>${t("Created on your device. Never sent to GitHub.", "Создаётся на вашем устройстве. Не отправляется в GitHub.")}</p></div></div>
      ${button("generate", icon("lock") + t("Create and save key", "Создать и сохранить ключ"))}`}
      <div class="capture-import"><p>${t("Already have a key? Open the saved file.", "Ключ уже есть? Откройте сохранённый файл.")}</p><label class="capture-file-button secondary" for="key-file">${icon("file")}${t("Choose key file", "Выбрать файл ключа")}<input class="capture-file-input" id="key-file" type="file" accept=".json" ${state.busy ? "disabled" : ""}></label></div>
      <div class="capture-actions">${button("next", t("Continue to GitHub", "Перейти к запуску") + icon("arrow"), "primary", !ready())}
      ${state.key ? button("result", t("I already have an archive", "У меня уже есть архив"), "quiet", !ready()) : ""}</div>`;
  }
  function githubStep() {
    return `<p class="capture-lead">${t("Start the collector on GitHub, then return here.", "Запустите сборщик в GitHub и вернитесь сюда.")}</p>
      <ol class="capture-checklist"><li><strong>${t("Create your own fork", "Создайте свой форк")}</strong><p>${t("Copy the code to your GitHub account. The repository contains no chats.", "Форк — копия кода в вашем GitHub. Переписка туда не попадает.")}</p>${link("https://github.com/phishdestroy/TgWitness/fork", t("Create a fork", "Создать форк"))}</li>
      <li><strong>${t("Copy the public key", "Скопируйте открытый ключ")}</strong><p>${t("Paste this value into recipient in the GitHub form. Keep sealed-key.json on your device.", "Вставьте это значение в поле recipient в GitHub. Файл sealed-key.json оставьте у себя.")}</p><div class="capture-copy"><textarea id="recipient" rows="3" readonly></textarea>${button("copy", t("Copy", "Копировать"), "secondary")}</div></li>
      <li><strong>${t("Run Sealed chat capture", "Запустите Sealed chat capture")}</strong><p>${t("Enable Actions in your fork. Open the workflow, press Run workflow, paste recipient and choose 30, 60 or 120 minutes.", "Включите Actions в своём форке. Откройте workflow, нажмите Run workflow, вставьте recipient и выберите 30, 60 или 120 минут.")}</p>
      <label for="capture-repository">${t("Your fork (optional shortcut)", "Ваш форк (для быстрого перехода)")}</label><input id="capture-repository" placeholder="username/TgWitness" value="${esc(state.repository)}" autocomplete="off" spellcheck="false" maxlength="160">
      <a id="capture-workflow-link" class="secondary" ${repository() ? `href="https://github.com/${esc(repository())}/actions/workflows/sealed-witness.yml"` : "hidden"} target="_blank" rel="noopener noreferrer">${t("Open Actions in my fork", "Открыть Actions в моём форке")}${icon("external")}</a></li></ol>
      <p class="hint">${t("No GitHub token is needed here. GitHub account limits and usage rules apply.", "Токен GitHub здесь не нужен. Действуют лимиты аккаунта и правила использования GitHub.")}</p>
      <div class="capture-actions">${button("next", t("Run started — continue", "Запуск начат — продолжить") + icon("arrow"))}${button("back", t("Back", "Назад"), "quiet")}</div>`;
  }
  function connectionStep() {
    return `<p class="capture-lead">${t("Keep the GitHub run active. Download sealed-connection from its Artifacts, unzip it, and select the file below.", "Оставьте задачу GitHub работающей. Скачайте sealed-connection из её Artifacts, распакуйте ZIP и выберите файл ниже.")}</p>
      <div class="capture-file-path"><span>sealed-connection.zip</span>${icon("arrow")}<strong>connection.tgwsealed</strong></div>
      <label class="capture-file-picker" for="connection-file">${icon("file")}<strong>${t("Open connection.tgwsealed", "Открыть connection.tgwsealed")}</strong><span>${t("The connection is decrypted on this device.", "Подключение расшифровывается на этом устройстве.")}</span><input class="capture-file-input" id="connection-file" type="file" accept=".tgwsealed" ${state.busy ? "disabled" : ""}></label>
      ${state.connection ? `<div class="capture-success">${icon("check")}<div><strong>${t("Your temporary panel is ready", "Временная панель готова")}</strong><p>${t("Open it, sign in to Telegram, select one chat and start capture.", "Откройте её, войдите в Telegram, выберите один чат и начните сбор.")}</p></div></div>
      ${link(state.connection.url, t("Sign in to Telegram and choose a chat", "Войти в Telegram и выбрать чат"), "primary", "open-connection")}
      <p class="hint">${t("After capture, return to step 4. Keep the panel link private.", "После сбора вернитесь на шаг 4. Ссылку на панель держите в секрете.")}</p>` : ""}
      <div class="capture-actions">${button("next", t("Go to the result", "Перейти к получению архива") + icon("arrow"))}${button("back", t("Back", "Назад"), "quiet")}</div>`;
  }
  function resultStep() {
    return `<p class="capture-lead">${t("Once the GitHub run finishes, download sealed-result from Artifacts and unzip it. Open the encrypted file here with the same key.", "После завершения задачи GitHub скачайте sealed-result из Artifacts и распакуйте ZIP. Откройте зашифрованный файл здесь с тем же ключом.")}</p>
      <div class="capture-file-path"><span>sealed-result.zip</span>${icon("arrow")}<strong>delivery.tgwsealed</strong></div>
      <label class="capture-file-picker" for="result-file">${icon("file")}<strong>${t("Decrypt and save archive", "Расшифровать и сохранить архив")}</strong><span>delivery.tgwsealed · ${t("up to 256 MiB", "до 256 МиБ")}</span><input class="capture-file-input" id="result-file" type="file" accept=".tgwsealed" ${state.busy ? "disabled" : ""}></label>
      ${state.delivered ? `<div class="capture-success">${icon("check")}<div><strong>${t("Decrypted — save delivery.zip", "Расшифровано — сохраните delivery.zip")}</strong><p>${t("It contains evidence.zip and attestation.jsonl. Decryption does not yet verify the signature.", "Внутри evidence.zip и attestation.jsonl. Расшифровка ещё не означает, что подпись проверена.")}</p></div></div>` : ""}
      <details class="capture-command" ${state.delivered ? "open" : ""}><summary>${t("Verify the archive after downloading", "Проверить архив после скачивания")}</summary><p>${t("Unzip delivery.zip. Run this command using a trusted TgWitness installation and GitHub CLI; replace OWNER/TgWitness with the fork that ran the capture.", "Распакуйте delivery.zip. Выполните команду в доверенной установке TgWitness с GitHub CLI; вместо OWNER/TgWitness укажите форк, из которого запускался сбор.")}</p><pre>python -m tgwitness.sealed_verify evidence.zip --bundle attestation.jsonl --repo ${esc(repository() || "OWNER/TgWitness")}</pre></details>
      <details class="capture-command"><summary>${t("Archive larger than 256 MiB?", "Архив больше 256 МиБ?")}</summary><p>${t("Decrypt it with the local command instead of loading the entire file into browser memory.", "Расшифруйте его локальной командой, чтобы не загружать весь файл в память браузера.")}</p><pre>python -m tgwitness.sealed_crypto decrypt delivery.tgwsealed --key sealed-key.json --out delivery.zip</pre></details>
      <p class="hint">${t("Artifacts expire after one day. End the temporary Telegram session in Settings → Devices if logout was not confirmed.", "Артефакты хранятся один день. Если выход не подтверждён, завершите временную сессию в Telegram → Настройки → Устройства.")}</p>
      <div class="capture-actions">${button("back", t("Back", "Назад"), "secondary")}</div>`;
  }
  async function perform(work) {
    if (state.busy) return;
    const version = epoch;
    state.busy = true; state.error = ""; state.note = ""; render();
    try {const apply = await work(); if (version === epoch) apply();}
    catch (error) {if (version === epoch) state.error = error.message;}
    finally {if (version === epoch) {state.busy = false; render();}}
  }
  async function readKey(value) {
    if (value.format !== "tgwitness-recipient-key-v1") throw new Error(t("Choose a TgWitness sealed-key.json file.", "Выберите файл sealed-key.json, созданный TgWitness."));
    const key = await crypto.subtle.importKey("pkcs8", unb64(value.private_key), {name:"RSA-OAEP",hash:"SHA-256"}, false, ["decrypt"]);
    const pub = await crypto.subtle.importKey("spki", unb64(value.recipient), {name:"RSA-OAEP",hash:"SHA-256"}, false, ["encrypt"]);
    if (![3072,4096].includes(key.algorithm.modulusLength)) throw new Error("Unsupported key size");
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const opened = await crypto.subtle.decrypt("RSA-OAEP", key, await crypto.subtle.encrypt("RSA-OAEP", pub, challenge));
    if (b64(opened) !== b64(challenge)) throw new Error("Key pair mismatch");
    return key;
  }
  async function decrypt(file, maximum) {
    if (!state.privateKey || !file) throw new Error(t("Load your saved key on step 1 first.", "Сначала загрузите сохранённый ключ на шаге 1."));
    if (file.size > maximum) throw new Error(t("This file is too large. Use the local decryption command below.", "Этот файл слишком большой. Используйте локальную команду расшифровки ниже."));
    try {
      const key = state.privateKey, bytes = new Uint8Array(await file.arrayBuffer()), magic = encoder.encode("TGWSEAL1\n");
      if (bytes.length < 29 || decoder.decode(bytes.slice(0,magic.length)) !== "TGWSEAL1\n") throw new Error("format");
      const length = new DataView(bytes.buffer).getUint32(magic.length), end = magic.length+4+length;
      if (!length || length > 8192 || end+16 > bytes.length) throw new Error("header");
      const info = JSON.parse(decoder.decode(bytes.slice(magic.length+4,end)));
      if (info.algorithm !== "RSA-OAEP-256+A256GCM" || Object.keys(info).sort().join(",") !== "algorithm,key,nonce") throw new Error("algorithm");
      const raw = await crypto.subtle.decrypt("RSA-OAEP",key,unb64(info.key)), iv = unb64(info.nonce);
      if (raw.byteLength !== 32 || iv.length !== 12) throw new Error("parameters");
      const aes = await crypto.subtle.importKey("raw",raw,"AES-GCM",false,["decrypt"]);
      return await crypto.subtle.decrypt({name:"AES-GCM",iv,additionalData:bytes.slice(0,end),tagLength:128},aes,bytes.slice(end));
    } catch {throw new Error(t("Could not decrypt. Use the key from this run and the unpacked .tgwsealed file, not the GitHub ZIP.", "Не удалось расшифровать. Нужны ключ этого запуска и распакованный файл .tgwsealed, а не ZIP из GitHub."));}
  }
  root.addEventListener("click", event => {
    const step = event.target.closest("[data-capture-step]");
    if (step && !state.busy && (Number(step.dataset.captureStep) === 1 || ready())) {state.step=Number(step.dataset.captureStep);state.error="";state.note="";render(true);return;}
    const action = event.target.closest("[data-capture-action]")?.dataset.captureAction;
    if (!action || state.busy) return;
    if (action === "reset") {epoch++;state=initial();render(true);return;}
    if (action === "back" || action === "next" || action === "result") {
      if (action !== "back" && !ready()) return;
      state.step=action === "back" ? Math.max(1,state.step-1) : action === "result" ? 4 : Math.min(4,state.step+1);
      state.error="";state.note="";render(true);return;
    }
    if (action === "save-key") {save(JSON.stringify(state.key),"sealed-key.json","application/json");return;}
    if (action === "copy") {
      const text=state.key.recipient, version=epoch, field=root.querySelector("#recipient");
      const manual=()=>{if(field.isConnected){field.select();const feedback=root.querySelector(".capture-feedback");feedback.hidden=false;feedback.textContent=t("The key is selected. Copy it manually with Ctrl+C or your browser's Copy action.","Ключ выделен. Скопируйте его вручную через Ctrl+C или команду «Копировать» браузера.");}};
      navigator.clipboard?.writeText(text).then(()=>{if(version===epoch && state.step===2){state.note=t("Public key copied. Paste it into recipient in GitHub.","Открытый ключ скопирован. Вставьте его в recipient в GitHub.");render();}},manual) ?? manual();
      return;
    }
    if (action === "generate") perform(async()=>{
      if (!globalThis.isSecureContext || !crypto.subtle) throw new Error(t("Open this page over HTTPS or localhost to create a key.", "Откройте страницу по HTTPS или через localhost для создания ключа."));
      const pair=await crypto.subtle.generateKey({name:"RSA-OAEP",modulusLength:3072,publicExponent:new Uint8Array([1,0,1]),hash:"SHA-256"},true,["encrypt","decrypt"]);
      const record={format:"tgwitness-recipient-key-v1",recipient:b64(await crypto.subtle.exportKey("spki",pair.publicKey)),private_key:b64(await crypto.subtle.exportKey("pkcs8",pair.privateKey))};
      const key=await readKey(record);
      return ()=>{state.key=record;state.privateKey=key;save(JSON.stringify(record),"sealed-key.json","application/json");};
    });
  });
  root.addEventListener("input", event => {
    if (event.target.id !== "capture-repository") return;
    state.repository=event.target.value.trim();
    const target=root.querySelector("#capture-workflow-link");target.hidden=!repository();
    if (repository()) target.href="https://github.com/"+repository()+"/actions/workflows/sealed-witness.yml";
  });
  root.addEventListener("change", event => {
    const input=event.target;
    if (input.id === "capture-language") {lang=input.value;render();return;}
    if (input.id === "capture-key-saved") {state.saved=input.checked;render();return;}
    const file=input.files?.[0];if (!file) return;
    if (input.id === "key-file") perform(async()=>{
      if (file.size > 16384) throw new Error(t("This is not a key file. Choose sealed-key.json.", "Это не файл ключа. Выберите sealed-key.json."));
      let value,key;
      try {value=JSON.parse(await file.text());key=await readKey(value);} catch {throw new Error(t("Cannot read this key. Choose the saved sealed-key.json file.", "Не удалось прочитать ключ. Выберите сохранённый sealed-key.json."));}
      return ()=>{state.key=value;state.privateKey=key;state.saved=true;state.connection=null;state.delivered=false;};
    });
    if (input.id === "connection-file") perform(async()=>{
      state.connection=null;
      const value=JSON.parse(decoder.decode(await decrypt(file,65536))), url=new URL(value.url);
      if (value.format !== "tgwitness-sealed-connection-v1" || url.protocol !== "https:" || !/^[a-z0-9-]+\.trycloudflare\.com$/.test(url.hostname) ||
          url.username || url.password || url.port || url.pathname !== "/" || url.search || !/^#access=[A-Za-z0-9_-]{43}$/.test(url.hash))
        throw new Error(t("This is not a valid capture connection file.", "Это не корректный файл подключения к сборщику."));
      return ()=>{state.connection={url:url.href};};
    });
    if (input.id === "result-file") perform(async()=>{
      const value=await decrypt(file,256*1024*1024), header=new Uint8Array(value,0,Math.min(4,value.byteLength));
      if (header[0]!==80 || header[1]!==75 || header[2]!==3 || header[3]!==4) throw new Error(t("The decrypted file is not an archive.", "Расшифрованный файл не является архивом."));
      return ()=>{save(value,"delivery.zip","application/zip");state.delivered=true;};
    });
  });
  addEventListener("tgwitness:lock",()=>{epoch++;state=initial();window.TgWitnessCaptureStory?.reset();render();});
  render();
})();
