"use strict";
const $ = id => document.getElementById(id), encoder = new TextEncoder(), decoder = new TextDecoder();
const requestedLanguage = new URLSearchParams(location.search).get("lang");
let record = null, privateKey = null, lang = (requestedLanguage || navigator.language).startsWith("ru") ? "ru" : "en";
const tr = (en, ru) => lang === "ru" ? ru : en;
function translate() {document.documentElement.lang = lang; $("language").value = lang;
  document.querySelectorAll("[data-en]").forEach(el => {el.textContent = el.dataset[lang];});
  $("instructions").href = "https://github.com/phishdestroy/TgWitness/blob/main/docs/" + (lang === "ru" ? "ru/" : "") + "SEALED-ACTIONS.md";}
$("language").onchange = () => {lang = $("language").value; translate();}; translate();
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
function save(bytes, name, type) {
  const url = URL.createObjectURL(new Blob([bytes], {type})), a = document.createElement("a");
  a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 10000);
}
async function setKey(value) {
  if (value.format !== "tgwitness-recipient-key-v1") throw new Error("Invalid key file");
  const key = await crypto.subtle.importKey("pkcs8", unb64(value.private_key), {name: "RSA-OAEP", hash: "SHA-256"}, false, ["decrypt"]);
  const pub = await crypto.subtle.importKey("spki", unb64(value.recipient), {name: "RSA-OAEP", hash: "SHA-256"}, false, ["encrypt"]);
  if (![3072,4096].includes(key.algorithm.modulusLength)) throw new Error("Unsupported key size");
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const reply = await crypto.subtle.decrypt("RSA-OAEP", key, await crypto.subtle.encrypt("RSA-OAEP", pub, challenge));
  if (b64(reply) !== b64(challenge)) throw new Error("Key pair does not match");
  record = value; privateKey = key; $("recipient").value = value.recipient;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", unb64(value.recipient)));
  $("fingerprint").textContent = "SHA-256: " + Array.from(digest, n => n.toString(16).padStart(2,"0")).join("");
}
function bind(id, event, action) {$(id).addEventListener(event, async () => {
  $("error").textContent = ""; $(id).disabled = true;
  try {await action();} catch (_) {$("error").textContent = tr("Could not open or create this file. Check the selected key, file size and browser support.", "Не удалось открыть или создать файл. Проверьте выбранный ключ, размер файла и поддержку браузера.");}
  finally {$(id).disabled = false;}
});}
bind("generate", "click", async () => {
  const keys = await crypto.subtle.generateKey({name:"RSA-OAEP",modulusLength:3072,publicExponent:new Uint8Array([1,0,1]),hash:"SHA-256"},true,["encrypt","decrypt"]);
  await setKey({format:"tgwitness-recipient-key-v1", recipient:b64(await crypto.subtle.exportKey("spki",keys.publicKey)),
    private_key:b64(await crypto.subtle.exportKey("pkcs8",keys.privateKey))});
  save(JSON.stringify(record), "sealed-key.json", "application/json");
});
bind("key-file", "change", async () => {
  const file = $("key-file").files[0]; if (!file || file.size > 16384) throw new Error("Key size");
  await setKey(JSON.parse(await file.text()));
});
async function decrypt(file, maximum) {
  if (!privateKey || !file || file.size > maximum) throw new Error("Key or file size");
  const bytes = new Uint8Array(await file.arrayBuffer()), magic = encoder.encode("TGWSEAL1\n");
  if (bytes.length < 29 || decoder.decode(bytes.slice(0, magic.length)) !== "TGWSEAL1\n") throw new Error("Format");
  const length = new DataView(bytes.buffer).getUint32(magic.length), end = magic.length + 4 + length;
  if (!length || length > 8192 || end + 16 > bytes.length) throw new Error("Header");
  const info = JSON.parse(decoder.decode(bytes.slice(magic.length + 4, end)));
  if (info.algorithm !== "RSA-OAEP-256+A256GCM" || Object.keys(info).sort().join(",") !== "algorithm,key,nonce") throw new Error("Algorithm");
  const key = await crypto.subtle.decrypt("RSA-OAEP",privateKey,unb64(info.key)), iv = unb64(info.nonce);
  if (key.byteLength !== 32 || iv.length !== 12) throw new Error("Parameters");
  const aes = await crypto.subtle.importKey("raw",key,"AES-GCM",false,["decrypt"]);
  return crypto.subtle.decrypt({name:"AES-GCM",iv,additionalData:bytes.slice(0,end),tagLength:128},aes,bytes.slice(end));
}
bind("connection-file", "change", async () => {
  $("open-connection").hidden = true;
  const value = JSON.parse(decoder.decode(await decrypt($("connection-file").files[0], 65536))), url = new URL(value.url);
  if (value.format !== "tgwitness-sealed-connection-v1" || url.protocol !== "https:" ||
      !url.hostname.endsWith(".trycloudflare.com") || url.username || url.password || url.port ||
      url.pathname !== "/" || url.search || !/^#access=[A-Za-z0-9_-]{43}$/.test(url.hash)) throw new Error("Connection");
  $("connection-context").textContent = JSON.stringify(value.context,null,2);
  $("open-connection").href = url.href; $("open-connection").hidden = false;
});
bind("result-file", "change", async () => {
  const value = await decrypt($("result-file").files[0],256*1024*1024);
  const header = new Uint8Array(value,0,Math.min(4,value.byteLength));
  if (header[0] !== 80 || header[1] !== 75 || header[2] !== 3 || header[3] !== 4) throw new Error("ZIP");
  save(value,"delivery.zip","application/zip");
});
