(() => {
  "use strict";
  const root = document.querySelector("[data-capture-wizard]");
  if (!root) return;
  const encoder = new TextEncoder(), decoder = new TextDecoder();
  const requested = root.dataset.siteLanguage || new URLSearchParams(location.search).get("lang") || window.TGW_LANG || navigator.language;
  const languages = window.TGW_CAPTURE_LANGUAGES || {en:"English",ru:"Русский"};
  const languageTag = value => {
    const tag = String(value || "").toLowerCase().replaceAll("_", "-");
    return /^zh-(?:hant|tw|hk|mo)(?:-|$)/.test(tag) ? "zh-Hant" :
      Object.keys(languages).find(code => code.toLowerCase() === tag) ||
      Object.keys(languages).find(code => code === tag.split("-")[0]) || "en";
  };
  let lang = languageTag(requested), epoch = 0;
  const initial = () => ({step: 1, key: null, privateKey: null, saved: false, connection: null,
    repository: "", busy: false, error: "", note: "", delivered: false});
  let state = initial();
  const t = en => {
    const translated = lang === "en" ? en : window.TGW_CAPTURE_LOCALES?.[lang]?.[en];
    return typeof translated === "string" ? translated : en;
  };
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
    const titles = [t("Save your key"), t("Start the collector"),
      t("Capture the chat"), t("Get your archive")];
    const subtitles = [t("On this device"), t("In your own fork"),
      t("In a temporary panel"), t("Back here")];
    root.lang = lang; root.dir = ["ar","fa","ur","he"].includes(lang) ? "rtl" : "ltr";
    if (root.closest(".capture-page")) {
      document.documentElement.lang=lang;
      const home=document.querySelector(".capture-header .brand");
      if (home) {const url=new URL(home.href);url.searchParams.set("lang",lang);home.href=url.href;}
    }
    root.innerHTML = `<div class="page-heading capture-heading"><div><span class="eyebrow">GITHUB ACTIONS <span class="capture-preview">${t("PREVIEW")}</span></span>
      <h1>${t("Capture a chat through GitHub")}</h1>
      <p class="page-description">${t("Collect a Telegram chat on a temporary runner. Receive an encrypted archive and GitHub provenance.")}</p></div>
      <label class="capture-language"><span>${t("Language")}</span><select id="capture-language">${Object.entries(languages).map(([code,name])=>`<option value="${esc(code)}" ${lang === code ? "selected" : ""}>${esc(name)}</option>`).join("")}</select></label></div>
      <div data-capture-story></div><div class="capture-setup-heading" id="capture-setup" tabindex="-1"><h2>${t("Capture your chat")}</h2><p>${t("Follow these four steps. Keep this tab open.")}</p></div>
      <div class="capture-layout"><aside class="capture-rail"><ol class="capture-steps" aria-label="${t("Capture steps")}">${titles.map((title, i) => `<li><button type="button" data-capture-step="${i+1}" ${state.busy || (i > 0 && !ready()) ? "disabled" : ""} ${state.step === i+1 ? 'aria-current="step"' : ""}><span class="capture-number">${i+1}</span><span><strong>${title}</strong><small>${subtitles[i]}</small></span></button></li>`).join("")}</ol>
      <div class="capture-private">${icon("lock")}<p>${t("Your private key stays here. Save it before continuing.")}</p></div>
      <a id="instructions" class="text-link" href="https://phishdestroy.github.io/TgWitness/${lang === "en" ? "" : encodeURIComponent(lang) + "/"}docs/capture/" target="_blank" rel="noopener noreferrer">${t("Full instructions")}</a></aside>
      <div class="capture-work"><section class="card capture-card" aria-labelledby="capture-step-title" aria-busy="${state.busy}"><div class="capture-step-heading"><span class="eyebrow">${t("STEP")} ${state.step} / 4</span><h2 id="capture-step-title" tabindex="-1">${titles[state.step-1]}</h2></div>
      <p id="capture-error" class="notice error" role="alert" ${state.error ? "" : "hidden"}>${esc(state.error)}</p>
      <p class="capture-feedback" role="status" ${state.busy || state.note ? "" : "hidden"}>${esc(state.busy ? t("Processing locally…") : state.note)}</p>
      ${state.step === 1 ? keyStep() : state.step === 2 ? githubStep() : state.step === 3 ? connectionStep() : resultStep()}
      </section><details class="capture-boundary"><summary>${t("What does GitHub verify?")}</summary><p>${t("The attestation binds the archive to an approved collector workflow and detects later changes. GitHub and the HTTPS tunnel are part of the trusted infrastructure.")}</p></details>
      ${state.key ? button("reset", t("Start a new capture"), "quiet capture-reset") : ""}</div></div>`;
    root.querySelector("#recipient")?.setAttribute("aria-label", t("Public encryption key"));
    const recipient = root.querySelector("#recipient"); if (recipient) recipient.value = state.key?.recipient || "";
    window.TgWitnessCaptureStory?.mount(root.querySelector("[data-capture-story]"), lang);
    if (focus) root.querySelector("#capture-step-title").focus({preventScroll:true});
  }
  function keyStep() {
    return `<p class="capture-lead">${t("Save this key to open the connection and archive.")}</p>
      ${state.key ? `<div class="capture-success">${icon("check")}<div><strong>${t("Your key is ready")}</strong><p>sealed-key.json</p></div>${button("save-key", t("Save again"), "secondary")}</div>
      <label class="check-label capture-confirm"><input id="capture-key-saved" type="checkbox" ${state.saved ? "checked" : ""}>${t("I saved sealed-key.json. A lost key cannot be recovered.")}</label>` :
      `<div class="capture-key-hero">${icon("lock")}<div><strong>${t("A key just for this capture")}</strong><p>${t("Created on your device. Never sent to GitHub.")}</p></div></div>
      ${button("generate", icon("lock") + t("Create and save key"))}`}
      <div class="capture-import"><p>${t("Already have a key? Open the saved file.")}</p><label class="capture-file-button secondary" for="key-file">${icon("file")}${t("Choose key file")}<input class="capture-file-input" id="key-file" type="file" accept=".json" ${state.busy ? "disabled" : ""}></label></div>
      <div class="capture-actions">${button("next", t("Continue to GitHub") + icon("arrow"), "primary", !ready())}
      ${state.key ? button("result", t("I already have an archive"), "quiet", !ready()) : ""}</div>`;
  }
  function githubStep() {
    return `<p class="capture-lead">${t("Start the collector on GitHub, then return here.")}</p>
      <ol class="capture-checklist"><li><strong>${t("Create your own fork")}</strong><p>${t("Copy the code to your GitHub account. The repository contains no chats.")}</p>${link("https://github.com/phishdestroy/TgWitness/fork", t("Create a fork"))}</li>
      <li><strong>${t("Copy the public key")}</strong><p>${t("Paste this value into recipient in the GitHub form. Keep sealed-key.json on your device.")}</p><div class="capture-copy"><textarea id="recipient" rows="3" readonly></textarea>${button("copy", t("Copy"), "secondary")}</div></li>
      <li><strong>${t("Run Sealed chat capture")}</strong><p>${t("Enable Actions in your fork. Open the workflow, press Run workflow, paste recipient and choose 30, 60 or 120 minutes.")}</p>
      <label for="capture-repository">${t("Your fork (optional shortcut)")}</label><input id="capture-repository" placeholder="username/TgWitness" value="${esc(state.repository)}" autocomplete="off" spellcheck="false" maxlength="160">
      <a id="capture-workflow-link" class="secondary" ${repository() ? `href="https://github.com/${esc(repository())}/actions/workflows/sealed-witness.yml"` : "hidden"} target="_blank" rel="noopener noreferrer">${t("Open Actions in my fork")}${icon("external")}</a></li></ol>
      <details class="capture-command"><summary>${t("Choose API export or official client")}</summary><p>${t("Set client to api for full-account Takeout or regular API export. Set client to official_web for guarded Telegram Web observation with video. Choose official_egress=proxy and supply official_proxy, or explicitly choose direct to use the runner public IP without a proxy. This visual mode records one selected chat as rendered, without a custom Telegram API session.")}</p><p>${t("Keep proxy credentials in the repository Actions secrets OFFICIAL_PROXY_USERNAME and OFFICIAL_PROXY_PASSWORD, never in workflow input fields. An optional official_expected_ip requires that exit address; both modes stop on an observed exit change. Direct mode exposes the runner address to Telegram. A Quick Tunnel opens the temporary panel; it does not provide the account exit.")}</p></details>
      <p class="hint">${t("No GitHub token is needed here. GitHub account limits and usage rules apply.")}</p>
      <div class="capture-actions">${button("next", t("Run started — continue") + icon("arrow"))}${button("back", t("Back"), "quiet")}</div>`;
  }
  function connectionStep() {
    return `<p class="capture-lead">${t("Keep the GitHub run active. Download sealed-connection from its Artifacts, unzip it, and select the file below.")}</p>
      <div class="capture-file-path"><span>sealed-connection.zip</span>${icon("arrow")}<strong>connection.tgwsealed</strong></div>
      <label class="capture-file-picker" for="connection-file">${icon("file")}<strong>${t("Open connection.tgwsealed")}</strong><span>${t("The connection is decrypted on this device.")}</span><input class="capture-file-input" id="connection-file" type="file" accept=".tgwsealed" ${state.busy ? "disabled" : ""}></label>
      ${state.connection ? `<div class="capture-success">${icon("check")}<div><strong>${t("Your temporary panel is ready")}</strong><p>${t("Open the temporary panel, sign in to Telegram and choose the export mode, chats and attachments before starting.")}</p></div></div>
      ${link(state.connection.url, t("Sign in to Telegram and choose export settings"), "primary", "open-connection")}
      <p class="hint">${t("After capture, return to step 4. Keep the panel link private.")}</p>` : ""}
      <div class="capture-actions">${button("next", t("Go to the result") + icon("arrow"))}${button("back", t("Back"), "quiet")}</div>`;
  }
  function resultStep() {
    return `<p class="capture-lead">${t("Once the GitHub run finishes, download sealed-result from Artifacts and unzip it. Open the encrypted file here with the same key.")}</p>
      <div class="capture-file-path"><span>sealed-result.zip</span>${icon("arrow")}<strong>delivery.tgwsealed</strong></div>
      <label class="capture-file-picker" for="result-file">${icon("file")}<strong>${t("Decrypt and save archive")}</strong><span>delivery.tgwsealed · ${t("up to 256 MiB")}</span><input class="capture-file-input" id="result-file" type="file" accept=".tgwsealed" ${state.busy ? "disabled" : ""}></label>
      ${state.delivered ? `<div class="capture-success">${icon("check")}<div><strong>${t("Decrypted — save delivery.zip")}</strong><p>${t("It contains evidence.zip and attestation.jsonl. Decryption does not yet verify the signature.")}</p></div></div>` : ""}
      <details class="capture-command" ${state.delivered ? "open" : ""}><summary>${t("Verify the archive after downloading")}</summary><p>${t("Unzip delivery.zip. Run this command using a trusted TgWitness installation and GitHub CLI; replace OWNER/TgWitness with the fork that ran the capture.")}</p><pre>python -m tgwitness.sealed_verify evidence.zip --bundle attestation.jsonl --repo ${esc(repository() || "OWNER/TgWitness")}</pre></details>
      <details class="capture-command"><summary>${t("Archive larger than 256 MiB?")}</summary><p>${t("Decrypt it with the local command instead of loading the entire file into browser memory.")}</p><pre>python -m tgwitness.sealed_crypto decrypt delivery.tgwsealed --key sealed-key.json --out delivery.zip</pre></details>
      <details class="capture-command"><summary>Multipart delivery</summary><p>Open delivery.tgwsealed first and unzip delivery.zip. If it contains evidence.parts.json, keep all delivery-000001.tgwsealed files beside that manifest. Assemble the archive with your saved key, then verify it. You can also decrypt individual parts here; each keeps its numbered filename.</p><pre>python -m tgwitness.sealed_parts evidence.parts.json --key sealed-key.json --out evidence.zip
python -m tgwitness.sealed_verify evidence.parts.json --bundle attestation.jsonl --repo ${esc(repository() || "OWNER/TgWitness")} --max-gib 64</pre></details>
      <p class="hint">${t("Artifacts expire after one day. End the temporary Telegram session in Settings → Devices if logout was not confirmed.")}</p>
      <div class="capture-actions">${button("back", t("Back"), "secondary")}</div>`;
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
    if (value.format !== "tgwitness-recipient-key-v1") throw new Error(t("Choose a TgWitness sealed-key.json file."));
    const key = await crypto.subtle.importKey("pkcs8", unb64(value.private_key), {name:"RSA-OAEP",hash:"SHA-256"}, false, ["decrypt"]);
    const pub = await crypto.subtle.importKey("spki", unb64(value.recipient), {name:"RSA-OAEP",hash:"SHA-256"}, false, ["encrypt"]);
    if (![3072,4096].includes(key.algorithm.modulusLength)) throw new Error("Unsupported key size");
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const opened = await crypto.subtle.decrypt("RSA-OAEP", key, await crypto.subtle.encrypt("RSA-OAEP", pub, challenge));
    if (b64(opened) !== b64(challenge)) throw new Error("Key pair mismatch");
    return key;
  }
  async function decrypt(file, maximum) {
    if (!state.privateKey || !file) throw new Error(t("Load your saved key on step 1 first."));
    if (file.size > maximum) throw new Error(t("This file is too large. Use the local decryption command below."));
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
    } catch {throw new Error(t("Could not decrypt. Use the key from this run and the unpacked .tgwsealed file, not the GitHub ZIP."));}
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
      const manual=()=>{if(field.isConnected){field.select();const feedback=root.querySelector(".capture-feedback");feedback.hidden=false;feedback.textContent=t("The key is selected. Copy it manually with Ctrl+C or your browser's Copy action.");}};
      navigator.clipboard?.writeText(text).then(()=>{if(version===epoch && state.step===2){state.note=t("Public key copied. Paste it into recipient in GitHub.");render();}},manual) ?? manual();
      return;
    }
    if (action === "generate") perform(async()=>{
      if (!globalThis.isSecureContext || !crypto.subtle) throw new Error(t("Open this page over HTTPS or localhost to create a key."));
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
    if (input.id === "capture-language") {lang=languageTag(input.value);render();return;}
    if (input.id === "capture-key-saved") {state.saved=input.checked;render();return;}
    const file=input.files?.[0];if (!file) return;
    if (input.id === "key-file") perform(async()=>{
      if (file.size > 16384) throw new Error(t("This is not a key file. Choose sealed-key.json."));
      let value,key;
      try {value=JSON.parse(await file.text());key=await readKey(value);} catch {throw new Error(t("Cannot read this key. Choose the saved sealed-key.json file."));}
      return ()=>{state.key=value;state.privateKey=key;state.saved=true;state.connection=null;state.delivered=false;};
    });
    if (input.id === "connection-file") perform(async()=>{
      state.connection=null;
      const value=JSON.parse(decoder.decode(await decrypt(file,65536))), url=new URL(value.url);
      if (value.format !== "tgwitness-sealed-connection-v1" || url.protocol !== "https:" || !/^[a-z0-9-]+\.trycloudflare\.com$/.test(url.hostname) ||
          url.username || url.password || url.port || url.pathname !== "/" || url.search || !/^#access=[A-Za-z0-9_-]{43}$/.test(url.hash))
        throw new Error(t("This is not a valid capture connection file."));
      return ()=>{state.connection={url:url.href};};
    });
    if (input.id === "result-file") perform(async()=>{
      const value=await decrypt(file,256*1024*1024), header=new Uint8Array(value,0,Math.min(4,value.byteLength));
      const part=/^delivery-([0-9]{6})\.tgwsealed$/.exec(file.name);
      if (part) return ()=>{save(value,"evidence.zip.part"+part[1],"application/octet-stream");};
      if (header[0]!==80 || header[1]!==75 || header[2]!==3 || header[3]!==4) throw new Error(t("The decrypted file is not an archive."));
      return ()=>{save(value,"delivery.zip","application/zip");state.delivered=true;};
    });
  });
  function reset(){epoch++;state=initial();window.TgWitnessCaptureStory?.reset();render();}
  addEventListener("tgwitness:lock",reset);
  window.TgWitnessCapture={reset};
  render();
})();
