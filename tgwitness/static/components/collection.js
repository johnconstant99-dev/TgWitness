import {accountState} from "./account-state.js";

export function createCollectionControl({node, tr, status, workspace}) {
  const control = document.getElementById("collector-toggle");
  const indicator = node("span", "observation-indicator"); indicator.id = "workspace-observation";
  const dot = node("span", "observation-dot", "●"), label = node("span", "observation-label");
  dot.setAttribute("aria-hidden", "true"); indicator.append(dot, label);
  document.getElementById("profile-select").before(indicator);
  function confirmPause(name = "") {
    return window.confirm(tr("Pause observation{workspace}? New messages, edits and deletion notices will stop being collected. Missed activity can only be recovered partly.",
      {workspace: name ? " · " + name : ""}));
  }
  control.addEventListener("click", event => {
    if (status()?.collector?.running && !confirmPause()) {
      event.preventDefault(); event.stopImmediatePropagation();
    }
  }, true);
  function update() {
    const current = status(), collector = current?.collector;
    indicator.hidden = !collector || workspace.hidden;
    const account = accountState(current || {});
    const state = current?.demo ? "demo" : ({empty:"offline", collecting:"observing"}[account.kind] || account.kind);
    const text = {demo: tr("Demo"), offline: tr("Offline"), observing: tr("Observing"), reconnecting: tr("Reconnecting"),
      paused: tr("Paused"), sign_in: tr("Sign-in required"), failed: tr("Needs attention"), unavailable: tr("Unavailable")}[state];
    indicator.dataset.state = state; indicator.title = text; indicator.setAttribute("aria-label", text);
    if (label.textContent !== text) label.textContent = text;
  }
  return {update, confirmPause};
}
