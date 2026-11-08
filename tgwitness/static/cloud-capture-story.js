(() => {
  "use strict";
  const motion = matchMedia("(prefers-reduced-motion: reduce)");
  let host, lang = "en", frame = 0, playing = !motion.matches, visible = false, timer, observer;
  let scenario = "original";
  const t = en => window.TGW_CAPTURE_LOCALES?.[lang]?.[en] ?? en;
  const icon = name => `<svg viewBox="0 0 24 24" class="icon" aria-hidden="true">${{
    key: '<circle cx="8" cy="9" r="4"/><path d="m11 12 9 9m-4-4 3-3m-6 0 3-3"/>',
    chat: '<path d="M21 11a8 8 0 0 1-8 8H8l-5 3V7a4 4 0 0 1 4-4h6a8 8 0 0 1 8 8Z"/><path d="M7 8h9M7 12h6"/>',
    server: '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M12 7h5M12 18h5"/>',
    file: '<path d="M14 3H6v18h13V8ZM14 3v5h5M9 13h7M9 17h5"/>',
    lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>',
    check: '<path d="m5 12 4 4L19 6"/>',
    shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6Z"/><path d="m8 12 3 3 5-6"/>',
    arrow: '<path d="M4 12h16m-6-6 6 6-6 6"/>',
    play: '<path d="m8 4 12 8-12 8Z"/>',
    pause: '<path d="M8 4v16M16 4v16"/>',
    cross: '<path d="m6 6 12 12M18 6 6 18"/>'
  }[name]}</svg>`;
  const steps = () => [t("Your key"), t("Capture"), t("Attestation"), t("Encryption"), t("Verification")];
  const scenes = () => [
    [t("Save your key"), t("Keep the private key on your device. Copy the public key to GitHub to encrypt the archive."), "sealed-key.json"],
    [t("Choose export settings"), t("Start the collector in your fork, then sign in to Telegram in the temporary panel and configure your export."), t("Available messages and media")],
    [t("GitHub attests the archive"), t("The attestation binds the archive hash to the workflow. It does not contain the chat."), "evidence.zip + attestation.jsonl"],
    [t("Download the result"), t("Download the encrypted package and open it with your key. GitHub removes the temporary machine after the job."), "delivery.tgwsealed"],
    [t("Verify its origin"), t("Share the archive and attestation with a reviewer. They can check the hash, workflow and collector version."), t("Try the example below ↓")]
  ];
  const item = (symbol, name, detail, cls = "") => `<div class="story-object ${cls}"><span class="story-object-icon">${icon(symbol)}</span><strong>${name}</strong><small>${detail}</small></div>`;
  const wire = () => `<div class="story-wire" aria-hidden="true"><span></span>${icon("arrow")}</div>`;
  const windowCard = (title, body) => `<div class="story-window"><div class="story-window-bar"><span class="story-window-dots" aria-hidden="true">● ● ●</span><span>${title}</span></div>${body}</div>`;
  function illustration() {
    if (frame === 0) return `<div class="story-flow">${item("key", t("Your device"), "sealed-key.json", "story-origin")}${wire()}<div class="story-key-pair">${item("server", t("Public key → GitHub"), t("Encrypt the delivery"))}${item("lock", t("Private key → stays with you"), t("Open the delivery"), "story-private")}</div></div>`;
    if (frame === 1) return windowCard(t("GitHub · temporary runner"), `<div class="story-flow story-in-runner"><div class="story-chat"><span class="story-mini-label">${icon("chat")} ${t("Selected Telegram chat")}</span><div class="story-bubble">${t("Meeting at 18:00")}<small>18:02</small></div><div class="story-bubble story-bubble-reply">${t("The files are attached")}<small>18:03</small></div><div class="story-attachment">${icon("file")} document.pdf</div></div>${wire()}${item("file", "evidence.zip", t("Messages + media"))}</div>`);
    if (frame === 2) return `<div class="story-flow">${item("file", "evidence.zip", t("The original archive"))}${wire()}<div class="story-certificate"><span class="story-certificate-seal">${icon("shield")}</span><span class="story-mini-label">GITHUB ATTESTATION</span><strong>attestation.jsonl</strong><div class="story-fingerprint">SHA-256 <span>8f24 · a19c · 7d03 · …</span></div><p>${icon("check")}${t("Archive hash")}</p><p>${icon("check")}${t("Workflow identity")}</p></div></div>`;
    if (frame === 3) return `<div class="story-flow"><div class="story-file-stack">${item("file", "evidence.zip", t("Chat and media"))}${item("shield", "attestation.jsonl", t("GitHub provenance"))}</div>${wire()}<div class="story-envelope">${icon("lock")}<span class="story-cipher" aria-hidden="true">7b 4e a2 91 f0 6c<br>c8 03 5d ab 72 e9<br>1f b6 04 d8 3a 60</span><strong>delivery.tgwsealed</strong><small>${t("Opened with your private key")}</small></div></div>`;
    return `<div class="story-flow">${item("file", t("Archive + attestation"), t("Send to a reviewer"))}${wire()}<div class="story-verifier"><span class="story-mini-label">${icon("shield")}${t("Independent verification")}</span>${[t("File hash matches"), t("Workflow approved"), t("Collector version approved")].map(x => `<p>${icon("check")}${x}</p>`).join("")}<strong>${t("All three checks matter")}</strong></div></div>`;
  }
  function template() {
    return `<section class="capture-story" aria-labelledby="capture-story-title"><div class="story-title-row"><div><span class="eyebrow">${t("HOW IT WORKS")}</span><h2 id="capture-story-title">${t("Chat → archive → verification")}</h2></div><button type="button" class="secondary story-start" data-story-start>${t("Start my capture")}${icon("arrow")}</button></div>
      <div class="story-player"><div class="story-tabs" role="group" aria-label="${t("Explanation steps")}">${steps().map((name, i) => `<button type="button" data-story-frame="${i}" aria-pressed="false"><span>0${i+1}</span>${name}<i aria-hidden="true"></i></button>`).join("")}</div>
      <div class="story-scene"></div><div class="story-player-footer"><span class="story-example-label">${t("Illustration · no account connected")}</span><button type="button" class="quiet" data-story-play></button></div></div>
      <div class="story-benefits">${[["server",t("No local installation"),t("A temporary machine runs the collector for you.")],["lock",t("Private delivery"),t("The downloadable package is encrypted with your key.")],["shield",t("Checkable origin"),t("A reviewer can check the file and its collector.")]].map(([i,h,p])=>`<div>${icon(i)}<strong>${h}</strong><p>${p}</p></div>`).join("")}</div>
      <section class="story-lab" aria-labelledby="story-lab-title"><div class="story-lab-heading"><div><span class="eyebrow">${t("TRY A CHANGE")}</span><h3 id="story-lab-title">${t("Detecting changes")}</h3></div><span class="story-demo-tag">${t("DEMO")}</span></div>
      <div class="story-scenarios" role="group" aria-label="${t("Verification example")}">${[["original",t("Unchanged")],["message",t("Edit a message")],["collector",t("Replace the collector")]].map(([id,label])=>`<button type="button" data-story-scenario="${id}" aria-pressed="false">${label}</button>`).join("")}</div><div class="story-lab-result" aria-live="polite" aria-atomic="true"></div>
      <p class="story-lab-note">${t("Demo only. Verify your downloaded archive with the command in step 4.")}</p></section>
      <details class="story-details"><summary>${t("Privacy and trust")}</summary><p>${t("The key stays with you. Collection relies on GitHub, the collector and the HTTPS tunnel; the runner processes the chat in plaintext. Public metadata contains a hash and workflow details. Verification covers integrity and origin, not historical completeness or the truth of statements.")}</p></details></section>`;
  }
  function schedule() {
    clearTimeout(timer);
    const running = playing && visible && !document.hidden;
    if (host) host.dataset.running = String(running);
    if (running) timer = setTimeout(() => {
      if (frame < 4) {frame++; drawScene();} else {playing = false; drawControls(); schedule();}
    }, 7500);
  }
  function drawControls() {
    host.querySelectorAll("[data-story-frame]").forEach((b,i) => {
      b.setAttribute("aria-pressed", String(i === frame)); b.dataset.complete = String(i < frame);
    });
    host.querySelector("[data-story-play]").innerHTML = icon(playing ? "pause" : "play") + (playing ? t("Pause") : frame === 4 ? t("Replay") : t("Play explanation"));
  }
  function drawScene() {
    const [title, body, action] = scenes()[frame];
    host.querySelector(".story-scene").innerHTML = `<div class="story-narrative"><span class="story-scene-number">0${frame+1}<span> / 05</span></span><h3>${title}</h3><p>${body}</p><span class="story-your-action">${action}</span></div><div class="story-visual" data-scene="${frame}">${illustration()}</div>`;
    drawControls(); schedule();
  }
  function drawLab() {
    const changed = scenario !== "original", message = scenario === "message", collector = scenario === "collector";
    host.querySelectorAll("[data-story-scenario]").forEach(b => b.setAttribute("aria-pressed",String(b.dataset.storyScenario === scenario)));
    const row = (name, ok) => `<div class="story-check-row" data-ok="${ok}"><span>${name}</span><strong>${icon(ok ? "check" : "cross")}${ok ? t("Matches") : t("Mismatch")}</strong></div>`;
    host.querySelector(".story-lab-result").innerHTML = `<div class="story-sample"><span class="story-mini-label">${t("Example message")}</span><p>${t("Meeting at")} <strong class="${message ? "story-edited" : ""}">${message ? "21:00" : "18:00"}</strong></p><div class="story-sample-code">${icon("server")}<span>${collector ? t("Modified collector") : t("Approved collector")}</span>${collector ? icon("cross") : icon("check")}</div></div><div class="story-checks">${row(t("Archive hash"),!message)}${row(t("Workflow / collector"),!collector)}<div class="story-verdict" data-valid="${!changed}">${icon(changed ? "cross" : "shield")}<div><strong>${changed ? t("Rejected") : t("Checks pass")}</strong><p>${message ? t("The archive hash changed.") : collector ? t("This collector version is not approved.") : t("The archive and collector match.")}</p></div></div></div>`;
  }
  function mount(target, language) {
    observer?.disconnect(); clearTimeout(timer); host = target; lang = language;
    if (!host) return;
    host.innerHTML = template(); visible = false; drawScene(); drawLab();
    host.addEventListener("click", event => {
      const step = event.target.closest("[data-story-frame]");
      const sample = event.target.closest("[data-story-scenario]");
      if (step) {frame = Number(step.dataset.storyFrame); playing = false; drawScene();}
      if (sample) {scenario = sample.dataset.storyScenario; playing = false; drawControls(); schedule(); drawLab();}
      if (event.target.closest("[data-story-play]")) {if (!playing && frame === 4) frame = 0; playing = !playing; drawScene();}
      if (event.target.closest("[data-story-start]")) {
        playing = false; drawControls(); schedule();
        const setup = document.getElementById("capture-setup");
        setup?.scrollIntoView({behavior: motion.matches ? "instant" : "smooth", block: "start"});
        setup?.focus({preventScroll:true});
      }
    });
    observer = new IntersectionObserver(entries => {visible = entries[0].isIntersecting; schedule();});
    observer.observe(host.querySelector(".story-player"));
  }
  document.addEventListener("visibilitychange", schedule);
  motion.addEventListener("change", () => {if (motion.matches) {playing = false; if (host) {drawControls(); schedule();}}});
  window.TgWitnessCaptureStory = {mount, pause(){playing=false;clearTimeout(timer);}, reset() {playing = false; frame = 0; scenario = "original"; clearTimeout(timer);}};
})();
