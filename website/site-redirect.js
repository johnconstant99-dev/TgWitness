(() => {
  const languages = ["en","ru","uk","es","pt","tr","ar","fa","ur","hi","id","vi","zh","fr","de","it","uz","ko","zh-Hant","ms","pl","ja","th","he","bn"];
  const requested = new URLSearchParams(location.search).get("lang") || navigator.language;
  const lang = languages.find(x => x.toLowerCase() === requested.toLowerCase()) || (/^zh-(?:hant|tw|hk|mo)/i.test(requested) ? "zh-Hant" : languages.find(x => x === requested.split("-")[0])) || "en";
  const root = new URL(document.body.dataset.siteRoot, location.href);
  const target = new URL((lang === "en" ? "" : lang + "/") + document.body.dataset.siteTarget, root);
  target.hash = location.hash;
  location.replace(target.href);
})();
