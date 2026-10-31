"use strict";
// Interface translation. Keys are the English interface strings. Telegram content and journal
// records are never passed through here, so evidence is always shown exactly as saved.
const LANG=window.TGW_LANG||"en",DICT=window.TGW_DICT||{};
const PANEL_LANGUAGES={en:"English",ru:"Русский",uk:"Українська",es:"Español",pt:"Português (Brasil)",tr:"Türkçe",
  ar:"العربية",fa:"فارسی",ur:"اردو",hi:"हिन्दी",id:"Bahasa Indonesia",vi:"Tiếng Việt",zh:"简体中文",
  fr:"Français",de:"Deutsch",it:"Italiano",uz:"O‘zbekcha",ko:"한국어",
  "zh-Hant":"繁體中文",ms:"Bahasa Melayu",pl:"Polski",ja:"日本語",th:"ไทย",he:"עברית",bn:"বাংলা"};
const GUIDE_LANGUAGES={...PANEL_LANGUAGES,am:"አማርኛ"};
const LANGUAGES=window.TGW_SCOPE==="guide"?GUIDE_LANGUAGES:PANEL_LANGUAGES;
const RTL=new Set(["ar","fa","ur","he"]);
function fill(text,vars){return vars?text.replace(/\{(\w+)\}/g,(m,k)=>k in vars?String(vars[k]):m):text;}
function tr(text,vars){const out=DICT[text];return fill(typeof out==="string"?out:text,vars);}
// One/other English forms; translations of the "other" form may give every plural category.
function trn(one,other,n,vars){
  const all={n:Number(n).toLocaleString(),...vars},forms=DICT[other];
  if(forms&&typeof forms==="object")return fill(forms[new Intl.PluralRules(LANG).select(Number(n))]??forms.other,all);
  return tr(Number(n)===1?one:other,all);
}
const INLINE=new Set(["A","B","BR","CODE","EM","I","KBD","SMALL","SPAN","STRONG"]);
const SKIP=new Set(["SCRIPT","STYLE","TEMPLATE","PRE","TEXTAREA"]);
const normal=s=>s.replace(/\s+/g," ").trim();
const wordy=s=>/\p{L}/u.test(s);
function inlineOnly(el){return [...el.children].every(c=>INLINE.has(c.tagName)&&!c.id&&inlineOnly(c));}
// Visits the static page the same way for translating and for listing keys in tests.
function walkPage(visit,root=document.body){
  const walk=el=>{
    if(el.namespaceURI!=="http://www.w3.org/1999/xhtml"||SKIP.has(el.tagName)||el.hasAttribute("data-no-translate"))return;
    for(const name of ["placeholder","aria-label","title","alt"]){
      const value=el.getAttribute(name);
      if(value&&wordy(value))visit({key:normal(value),apply:text=>el.setAttribute(name,text)});
    }
    if(el.children.length&&inlineOnly(el)&&wordy(el.textContent)){
      if(visit({key:normal(el.innerHTML),apply:html=>{el.innerHTML=html;}},true))return;
    }
    for(const n of [...el.childNodes]){
      if(n.nodeType===1)walk(n);
      else if(n.nodeType===3&&wordy(n.nodeValue)){
        const value=n.nodeValue,lead=/^\s*/.exec(value)[0],trail=/\s*$/.exec(value)[0];
        visit({key:normal(value),apply:text=>{n.nodeValue=lead+text+trail;}});
      }
    }
  };
  walk(root);
}
function pageKeys(){
  const keys=[];
  if(wordy(document.title))keys.push(normal(document.title));
  walkPage((item,whole)=>{keys.push(item.key);return whole;});
  return keys;
}
function translatePage(){
  document.documentElement.lang=LANG;
  document.documentElement.dir=RTL.has(LANG)?"rtl":"ltr";
  if(LANG==="en")return;
  const title=DICT[normal(document.title)];if(typeof title==="string")document.title=title;
  walkPage(item=>{const text=DICT[item.key];if(typeof text!=="string")return false;item.apply(text);return true;});
}
function setLanguage(lang){
  if(!Object.hasOwn(LANGUAGES,lang))return;
  document.cookie="tgwitness-lang="+encodeURIComponent(lang)+"; path=/; max-age=31536000; SameSite=Strict";
  const url=new URL(location.href);url.searchParams.set("lang",lang);location.assign(url.href);
}
translatePage();
document.querySelectorAll("[data-sealed-helper]").forEach(link=>{
  const url=new URL(link.href);url.searchParams.set("lang",LANG==="ru"?"ru":"en");link.href=url.href;
});
if(window.TGW_SCOPE==="guide")document.querySelectorAll('a[href]:not([href^="#"])').forEach(link=>{
  const url=new URL(link.href,location.href);
  if(url.origin===location.origin&&/\/(?:guide|dedicated-account)\.html$/.test(url.pathname)){
    // Translated inline HTML keeps application-root links. Resolve both guides beside
    // the current page so the same dictionary also works under the Pages project path.
    // In-page links are left alone: with a new query string they would reload the page.
    url.pathname=new URL(url.pathname.split("/").pop(),location.href).pathname;
    url.searchParams.set("lang",LANG);link.href=url.href;
  }
});
document.querySelectorAll("select.language-select").forEach(select=>{
  for(const [code,name] of Object.entries(LANGUAGES)){const o=new Option(name,code);o.lang=code;select.append(o);}
  select.value=LANG;select.addEventListener("change",()=>setLanguage(select.value));
});
