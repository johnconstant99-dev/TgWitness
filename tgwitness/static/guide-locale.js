"use strict";
// Load the dictionary before i18n.js; explicit ?lang= links override the saved choice.
// Guides use the extended catalog; the panel opts into its catalog with data-scope="panel".
(()=>{
  const requested=new URLSearchParams(location.search).get("lang");
  const url=new URL("locale.js",document.currentScript.src);
  if(document.currentScript.dataset.scope!=="panel")url.searchParams.set("scope","guide");
  if(requested)url.searchParams.set("lang",requested);
  document.write('<script defer src="'+url.href.replace(/&/g,"&amp;").replace(/"/g,"&quot;")+'"><\/script>');
})();
