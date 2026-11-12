const ANCHORS = /^(H1|H2|H3|H4|LEGEND|LABEL)$/;
const SKIP = "#view-connection, #view-first-run, #gate, .chat-feed, .events-table, .notify-panel, .quick-dialog, .toast";
const STATIC = ".page-heading .page-description, #workspace .view p.hint, #workspace .view p.muted, dialog p.hint, dialog p.muted, " +
  "#workspace .view .card-heading p, #view-start .workflow-intro > p, #view-start .workflow-card > p, " +
  "#view-evidence .evidence-body > small, #view-evidence .report-card > p, #dialog-refresh-description";

export function createTips({tr, icon, roots = []}) {
  let count = 0;
  function eligible(p, described) {
    if (p.dataset.tip || p.closest(SKIP) || p.hasAttribute("hidden") || p.hasAttribute("role") || p.hasAttribute("aria-live")) return false;
    if (!described && (!p.dataset.static || p.id && p.id !== "dialog-refresh-description")) return false;
    return !p.querySelector("a, button, input, select, textarea") && p.textContent.trim().length >= 40;
  }
  function anchor(p) {
    for (let item = p, depth = 0; item && depth < 4 && !item.matches(".view, dialog"); item = item.parentElement, depth++) {
      for (let node = item.previousElementSibling; node; node = node.previousElementSibling) {
        if (ANCHORS.test(node.tagName)) return node;
        const inner = (node.matches(".card-heading") || node.tagName === "DIV" && node.childElementCount <= 3) &&
          [...node.querySelectorAll("h1, h2, h3, h4, legend")].pop();
        if (inner) return inner;
      }
    }
    return null;
  }
  function attach(p) {
    p.dataset.tip = "closed";
    if (!p.id) p.id = "tip-" + (++count);
    const heading = anchor(p);
    let toggle = heading?.querySelector(":scope > .tip-toggle");
    if (!toggle) {
      toggle = document.createElement("button");
      toggle.type = "button"; toggle.className = "tip-toggle"; toggle.title = tr("Details");
      toggle.setAttribute("aria-label", tr("Details")); toggle.setAttribute("aria-expanded", "false");
      toggle.append(icon("question"));
      toggle.addEventListener("click", event => {
        event.preventDefault(); event.stopPropagation();
        const open = toggle.getAttribute("aria-expanded") !== "true";
        toggle.setAttribute("aria-expanded", String(open));
        for (const id of toggle.getAttribute("aria-controls").split(" ")) {
          const target = document.getElementById(id);
          if (target) target.dataset.tip = open ? "open" : "closed";
        }
      });
      if (heading) heading.append(toggle); else p.before(toggle);
    }
    toggle.setAttribute("aria-controls", [toggle.getAttribute("aria-controls"), p.id].filter(Boolean).join(" "));
  }
  function scan(root, selector, described) {
    const found = root.matches?.(selector) ? [root] : [];
    for (const p of [...found, ...root.querySelectorAll(selector)]) if (eligible(p, described)) attach(p);
  }
  for (const root of [document, ...roots]) {
    scan(root, STATIC, false);
    scan(root, ".page-heading .page-description", true);
  }
  new MutationObserver(records => {
    for (const record of records) for (const added of record.addedNodes)
      if (added.nodeType === 1) { scan(added, STATIC, false); scan(added, ".page-heading .page-description", true); }
  }).observe(document.getElementById("workspace"), {childList: true, subtree: true});
  return {scan};
}
