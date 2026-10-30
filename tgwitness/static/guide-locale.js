"use strict";
// Load the guide dictionary before i18n.js; explicit ?lang= links take precedence over the saved choice.
(()=>{
  const requested=new URLSearchParams(location.search).get("lang");
  const url=new URL("locale.js",document.currentScript.src);
  url.searchParams.set("scope","guide");
  if(requested)url.searchParams.set("lang",requested);
  document.write('<script defer src="'+url.href.replace(/&/g,"&amp;").replace(/"/g,"&quot;")+'"><\/script>');
})();
