"use strict";



(()=>{
  const root=document.documentElement,observe="IntersectionObserver" in window;
  const tr=typeof window.tr==="function"?window.tr:text=>text;
  const still=()=>typeof window.tgwReducedMotion==="function"?window.tgwReducedMotion():matchMedia("(prefers-reduced-motion: reduce)").matches;
  root.classList.add("js");


  const nav=document.querySelector("main > nav"),links=nav?[...nav.querySelectorAll('a[href^="#"]')]:[];
  const sections=[...document.querySelectorAll("main > section[id]")],owner=new Map();
  let last=null,active=null;
  for(const section of sections){
    last=links.find(link=>link.hash==="#"+section.id)||last;
    owner.set(section,last);
  }
  function mark(link){
    if(link===active)return;
    active?.removeAttribute("aria-current");
    active=link;
    if(!link)return;
    link.setAttribute("aria-current","true");
    if(nav.scrollWidth>nav.clientWidth){
      const box=link.getBoundingClientRect(),area=nav.getBoundingClientRect();
      nav.scrollBy({left:box.left+box.width/2-(area.left+area.width/2),behavior:still()?"auto":"smooth"});
    }
  }

  const bar=document.querySelector(".read-progress span"),up=document.querySelector(".to-top");
  let queued=false;
  function update(){
    queued=false;
    const room=root.scrollHeight-innerHeight;
    if(bar)bar.style.transform="scaleX("+(room>0?Math.min(1,scrollY/room):0)+")";
    up?.classList.toggle("show",scrollY>innerHeight*1.2);
    if(!links.length)return;
    let current=null;
    for(const section of sections)if(section.getBoundingClientRect().top<=innerHeight*.3)current=section;
    if(room>0&&scrollY>=room-2)current=sections[sections.length-1];
    mark(current?owner.get(current):null);
  }
  addEventListener("scroll",()=>{if(!queued){queued=true;requestAnimationFrame(update);}},{passive:true});
  addEventListener("resize",update);
  update();


  if(observe&&!still()){
    const reveal=new IntersectionObserver(entries=>entries.forEach(entry=>{
      if(!entry.isIntersecting)return;
      entry.target.classList.add("is-revealed");
      reveal.unobserve(entry.target);
    }),{rootMargin:"0px 0px -8% 0px"});
    document.querySelectorAll("main > section, main > .hero").forEach(block=>{
      if(block.getBoundingClientRect().top>innerHeight){block.classList.add("will-reveal");reveal.observe(block);}
    });
  }


  const scenes=document.querySelectorAll(".scene");
  if(observe){
    const play=new IntersectionObserver(entries=>entries.forEach(entry=>entry.target.classList.toggle("playing",entry.isIntersecting)),{threshold:.15});
    scenes.forEach(scene=>play.observe(scene));
  }else scenes.forEach(scene=>scene.classList.add("playing"));


  const status=document.createElement("p");
  status.className="sr-only";
  status.setAttribute("role","status");
  document.body.append(status);
  const icon=name=>{
    const svg=document.createElementNS("http://www.w3.org/2000/svg","svg"),use=document.createElementNS("http://www.w3.org/2000/svg","use");
    svg.setAttribute("class","i");svg.setAttribute("aria-hidden","true");use.setAttribute("href","#"+name);svg.append(use);
    return svg;
  };
  document.querySelectorAll("main pre").forEach(pre=>{
    const wrap=document.createElement("div"),button=document.createElement("button"),label=document.createElement("span");
    wrap.className="code";
    pre.before(wrap);
    wrap.append(pre);
    button.type="button";
    button.className="copy-button";
    label.textContent=tr("Copy");
    button.append(icon("i-copy"),label);
    wrap.append(button);
    const commands=pre.querySelectorAll(".t-type");
    let timer=0;
    button.addEventListener("click",async()=>{
      const text=commands.length?[...commands].map(node=>node.textContent).join("\n"):pre.textContent;
      let copied=false;
      try{await navigator.clipboard.writeText(text);copied=true;}catch{}
      if(copied){
        label.textContent=tr("Copied");
        status.textContent=tr("Copied to clipboard.");
      }else{
        const range=document.createRange(),selection=getSelection();
        range.selectNodeContents(pre.querySelector("code")||pre);
        selection.removeAllRanges();
        selection.addRange(range);
        label.textContent=tr("Selected — Ctrl/Cmd+C");
        status.textContent=tr("Text selected. Copy it manually.");
      }
      button.classList.toggle("is-done",copied);
      clearTimeout(timer);
      timer=setTimeout(()=>{label.textContent=tr("Copy");button.classList.remove("is-done");},2400);
    });
  });
})();
