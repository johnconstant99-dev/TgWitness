"use strict";



(()=>{
  const KEY="tgwitness-theme",MOTION="tgwitness-motion",root=document.documentElement;
  const systemDark=matchMedia("(prefers-color-scheme: dark)"),systemStill=matchMedia("(prefers-reduced-motion: reduce)");
  const read=(key,fallback)=>{try{return localStorage.getItem(key)||fallback;}catch{return fallback;}};
  const write=(key,value)=>{try{value?localStorage.setItem(key,value):localStorage.removeItem(key);}catch{}};
  const resolve=choice=>choice==="light"||choice==="dark"?choice:systemDark.matches?"dark":"light";
  window.tgwReducedMotion=()=>systemStill.matches&&root.dataset.motion!=="always";
  function apply(choice){
    root.dataset.theme=resolve(choice);
    document.querySelectorAll("[data-theme-choice]").forEach(b=>b.setAttribute("aria-pressed",String(b.dataset.themeChoice===choice)));
  }
  function applyMotion(){
    const always=read(MOTION,"")==="always";
    if(always)root.dataset.motion="always";else delete root.dataset.motion;
    document.querySelectorAll("[data-motion-toggle]").forEach(b=>b.setAttribute("aria-pressed",String(always)));
  }

  function choose(choice,button){
    write(KEY,choice);
    if(resolve(choice)===root.dataset.theme||!document.startViewTransition||window.tgwReducedMotion()){apply(choice);return;}
    const r=button.getBoundingClientRect(),x=r.left+r.width/2,y=r.top+r.height/2;
    const radius=Math.hypot(Math.max(x,innerWidth-x),Math.max(y,innerHeight-y));
    root.classList.add("theme-changing");
    const transition=document.startViewTransition(()=>apply(choice));
    transition.ready.then(()=>root.animate({clipPath:[`circle(0 at ${x}px ${y}px)`,`circle(${radius}px at ${x}px ${y}px)`]},
      {duration:520,easing:"cubic-bezier(.3,.7,.2,1)",pseudoElement:"::view-transition-new(root)"})).catch(()=>{});
    const done=()=>root.classList.remove("theme-changing");
    transition.finished.then(done,done);
  }
  apply(read(KEY,"system"));
  applyMotion();
  systemDark.addEventListener("change",()=>{if(read(KEY,"system")==="system")apply("system");});
  addEventListener("storage",event=>{if(event.key===KEY)apply(read(KEY,"system"));if(event.key===MOTION)applyMotion();});
  document.addEventListener("DOMContentLoaded",()=>{
    apply(read(KEY,"system"));
    applyMotion();
    document.querySelectorAll("[data-theme-choice]").forEach(b=>b.addEventListener("click",()=>choose(b.dataset.themeChoice,b)));
    document.querySelectorAll("[data-motion-toggle]").forEach(b=>b.addEventListener("click",()=>{
      write(MOTION,b.getAttribute("aria-pressed")==="true"?"":"always");applyMotion();
    }));
  });
})();
