"use strict";
const dictionary = {
  ru: {
    eyebrow:"НЕЗАВИСИМЫЙ ПРОЦЕСС НАБЛЮДЕНИЯ",heading:"Сбор виден.\nИсторию можно проверить.",lead:"Подписанные ответы коллекторов, счётчики сообщений и контрольные хеши. Без публикации переписки.",
    loading:"Получаем первый ответ…",workspaces:"Аккаунтов на стенде",collecting:"Сейчас собирают",delta:"Новых между проверками",accounts:"Коллекторы",intervalNote:"Каждый аккаунт — отдельный журнал и ключ.",
    checkTitle:"Скачайте доказательство",checkBody:"JSON содержит подписанный ответ коллектора и подпись witness. Сверьте отпечатки ключей по отдельному доверенному каналу.",compareTitle:"Сверьте с журналом",compareBody:"Независимый verifier проверит подписи, хеш и счётчики по ZIP-экспорту. Контрольное сообщение в тестовой группе позволяет отдельно проверить доставку.",boundaryTitle:"Что подтверждает эта страница",boundaryBody:"Witness проверяет подписи ответов. Счётчики и состояние сообщает коллектор; пересчёт по экспорту — отдельная проверка. Растущий хеш не доказывает полноту или происхождение сообщений. Witness на том же сервере остаётся под контролем того же оператора.",command:"Проверить скачанный JSON и соответствующий экспорт:",footer:"Только чтение · Никаких сообщений и сессий",
    connected:"Страница получает ответы монитора",offline:"Нет связи с монитором — данные могут быть устаревшими",updated:"Ответ монитора",waiting:"Первой проверки ещё нет",stale:"Проверка просрочена",monitorStopped:"Монитор остановился",ok:"Подписи проверены",no_response:"Нет ответа",invalid:"Ошибка проверки",rollback:"Журнал стал короче",fork:"Хеш изменился",key_changed:"Ключ изменился",legacy_head:"Нужен новый коллектор",new:"Новые",edits:"Правки",deletes:"Удаления",since:"Новых с предыдущей проверки",baseline:"Первая проверка — начальная точка",lastMessage:"Последнее событие сообщения",observing:"Сбор",running:"Идёт · связь есть",paused:"Приостановлен",disconnected:"Нет связи с Telegram",recovered:"Восстановлено",history:"Из истории",pending:"Очередь вложений",failures:"Ошибки вложений",backoff:"Пауза Telegram до",checked:"Witness проверил",none:"Нет",keys:"Отпечатки ключей",download:"Скачать подписанный JSON",head:"Хеш конца журнала",unknown:"Неизвестно"
  },
  en: {
    eyebrow:"AN INDEPENDENT OBSERVER PROCESS",heading:"Collection you can see.\nA record you can check.",lead:"Signed collector replies, message counters and journal hashes. Without publishing conversations.",
    loading:"Waiting for the first response…",workspaces:"Account workspaces",collecting:"Collecting now",delta:"New between checks",accounts:"Collectors",intervalNote:"Every account has its own journal and key.",checkTitle:"Download the proof",checkBody:"The JSON carries the collector's signed answer and the witness's signature. Compare key fingerprints through a separate trusted channel.",compareTitle:"Compare with the journal",compareBody:"The independent verifier checks signatures, hashes and counters against an evidence ZIP. A canary message in a test group separately checks delivery.",boundaryTitle:"What this page establishes",boundaryBody:"The witness verifies answer signatures. Counters and health are reported by the collector; recounting an export is a separate check. A growing hash does not prove completeness or Telegram origin. A witness on the same server remains under the same operator's control.",command:"Check a downloaded JSON against its evidence export:",footer:"Read only · No messages or sessions",
    connected:"The monitor is responding",offline:"Monitor unreachable — displayed data may be stale",updated:"Monitor response",waiting:"No check yet",stale:"Check overdue",monitorStopped:"Monitor stopped",ok:"Signatures checked",no_response:"No response",invalid:"Verification failed",rollback:"Journal shortened",fork:"Head changed",key_changed:"Key changed",legacy_head:"Update the collector",new:"New",edits:"Edits",deletes:"Deletions",since:"New since the previous check",baseline:"First check — baseline",lastMessage:"Last message event",observing:"Collection",running:"Running · connected",paused:"Paused",disconnected:"Telegram disconnected",recovered:"Recovered",history:"From history",pending:"Media queue",failures:"Failed media",backoff:"Telegram pause until",checked:"Witness checked",none:"None",keys:"Key fingerprints",download:"Download signed JSON",head:"Journal head hash",unknown:"Unknown"
  }
};
let language = navigator.language.startsWith("ru") ? "ru" : "en", latest = null, reachable = false, attempted = false;
Object.assign(dictionary.ru,{collecting:"Сбор включён",running:"Включён · связь есть",broadcast:"Публикация в канал",posted:"Опубликовано",failed:"Ошибка публикации",disabled:"Не настроена"});
Object.assign(dictionary.en,{collecting:"Collection enabled",running:"Enabled · connected",broadcast:"Channel broadcast",posted:"Published",failed:"Publication failed",disabled:"Not configured"});
try { language = localStorage.getItem("tgwitness-proof-lang") || language; } catch {}
if (!dictionary[language]) language = "en";
const $ = id => document.getElementById(id), t = key => dictionary[language][key] || key;
function node(tag, cls, text) { const el=document.createElement(tag); if(cls) el.className=cls; if(text!==undefined) el.textContent=text; return el; }
function date(value) { return value ? new Date(value).toLocaleString(language, {dateStyle:"short",timeStyle:"medium"}) : t("none"); }
function number(value) { return typeof value==="number" ? value.toLocaleString(language) : "—"; }
function applyLanguage() {
  document.documentElement.lang=language;
  document.querySelectorAll("[data-copy]").forEach(el=>{
    const lines=t(el.dataset.copy).split("\n"); el.replaceChildren();
    lines.forEach((line,i)=>{if(i)el.append(document.createElement("br"));el.append(document.createTextNode(line));});
  });
  $("language").textContent=language==="ru"?"EN":"RU";
  render();
}
$("language").addEventListener("click",()=>{language=language==="ru"?"en":"ru";try{localStorage.setItem("tgwitness-proof-lang",language);}catch{}applyLanguage();});
function render() {
  document.body.classList.toggle("offline",!reachable);
  $("connection").textContent=reachable?t("connected"):attempted?t("offline"):t("loading");
  if(!latest)return;
  $("title").textContent=latest.title;
  $("updated").textContent=t("updated")+": "+date(latest.generated_at);
  $("total-accounts").textContent=number(latest.workspaces.length);
  let active=0,delta=0,baselines=0;
  const openKeys=new Set([...$("accounts").querySelectorAll(".account")].filter(el=>el.querySelector("details")?.open).map(el=>el.dataset.id));
  const focused=document.activeElement, focusedCard=focused?.closest(".account");
  const focusTarget=focusedCard?{id:focusedCard.dataset.id,kind:focused.tagName}:null;
  const fragment=document.createDocumentFragment();
  for(const row of latest.workspaces) {
    const statement=row.proof?.statement, capture=statement?.capture?.statement;
    const age=statement?(Date.now()-Date.parse(statement.observed_at))/1000:Infinity;
    const stale=!reachable||row.stale||age>latest.interval_minutes*150;
    const good=statement?.status==="ok"&&!stale&&row.monitor_running;
    const status=!row.monitor_running?"monitorStopped":!statement?"waiting":stale?"stale":statement.status;
    if(good&&capture?.health.running&&capture.health.connected)active++;
    if(good&&statement.capture_delta){delta+=statement.capture_delta["message.new"];baselines++;}
    const card=node("article","account"),head=node("header");card.dataset.id=row.id;
    head.append(node("h3","",row.label),node("span","badge"+(good?" good":["invalid","rollback","fork","key_changed"].includes(status)?" bad":""),t(status)));
    card.append(head,node("p","stamp",t("checked")+": "+date(statement?.observed_at)));
    if(capture) {
      const metrics=node("dl","metrics");
      for(const [key,label] of [["message.new","new"],["message.edited","edits"],["message.deleted","deletes"]]){const item=node("div");item.append(node("dt","",t(label)),node("dd","",number(capture.counts[key])));metrics.append(item);}
      card.append(metrics,node("p","delta",statement.capture_delta?t("since")+": +"+number(statement.capture_delta["message.new"]):t("baseline")));
      const facts=node("div","facts"),health=capture.health;
      const pairs=[["lastMessage",date(capture.last_message_at)],["observing",good?t(health.running?(health.connected?"running":"disconnected"):"paused"):t("unknown")],["recovered",number(capture.counts["message.recovered"])],["history",number(capture.counts["message.snapshot"])],["pending",number(health.media_pending)],["failures",number(health.media_failed)]];
      if(health.backoff_until*1000>Date.now())pairs.push(["backoff",date(new Date(health.backoff_until*1000).toISOString())]);
      pairs.push(["broadcast",t(statement.broadcast?.status||"unknown")]);
      for(const [label,value] of pairs){const p=node("p");p.append(node("span","",t(label)),node("strong","",value));facts.append(p);}
      card.append(facts);const hash=node("code","hash",capture.head_hash);hash.title=t("head");card.append(hash);
    } else card.append(node("p","empty",t(status)));
    const keys=node("details","keys");keys.open=openKeys.has(row.id);keys.append(node("summary","",t("keys")));
    keys.append(node("p","","Collector"),node("code","",row.collector_fingerprint),node("p","","Witness"),node("code","",row.witness_fingerprint));card.append(keys);
    if(row.proof){const link=node("a","download",t("download"));link.href="api/proof/"+encodeURIComponent(row.id);link.append(node("span","","↓"));card.append(link);}
    fragment.append(card);
  }
  $("accounts").replaceChildren(fragment);
  if(focusTarget){const card=[...$("accounts").children].find(el=>el.dataset.id===focusTarget.id);card?.querySelector(focusTarget.kind==="SUMMARY"?"summary":"a")?.focus({preventScroll:true});}
  $("total-active").textContent=reachable?number(active):"—";
  $("total-delta").textContent=reachable&&baselines?"+"+number(delta):"—";
}
let refreshing=false;
async function refresh() {
  if(refreshing)return;refreshing=true;
  try {const response=await fetch("api/proof",{cache:"no-store",signal:AbortSignal.timeout(10000)});if(!response.ok)throw new Error("unavailable");latest=await response.json();reachable=true;}
  catch {reachable=false;}
  finally {attempted=true;refreshing=false;render();}
}
applyLanguage();refresh();setInterval(refresh,20000);setInterval(render,5000);
