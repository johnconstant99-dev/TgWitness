export function accountState(profile = {}) {
  const collector = profile.collector;
  const hasSession = Boolean(collector?.has_session);
  const needsSignIn = hasSession && (collector.authorization_required === true ||
    (collector.authorization_required === undefined && ["authorization_required", "login_required"].includes(collector.phase)) ||
    profile.health?.connection?.reason === "signed_out");
  const sourcesReady = Boolean(profile.sources_enabled > 0 || profile.targets?.some(target => target.enabled) ||
    (collector?.scope?.mode || profile.scope?.mode || "selected") !== "selected");
  const unavailable = Boolean(profile.error_type || !collector);
  const failed = ["resume_failed", "collector_error", "storage_error"].includes(collector?.phase);
  const kind = unavailable ? "unavailable" : needsSignIn ? "sign_in" : !hasSession ? "empty"
    : collector.running ? collector.connected ? "collecting" : "reconnecting" : failed ? "failed" : "paused";
  const label = {unavailable: "Unavailable", sign_in: "Sign-in required", empty: "Not connected",
    collecting: "Collecting", reconnecting: "Reconnecting", failed: "Needs attention", paused: "Paused"}[kind];
  return {kind, label, hasSession, needsSignIn, sourcesReady,
    canStart: !unavailable && hasSession && !needsSignIn && !collector.running &&
      collector.phase !== "storage_error" && sourcesReady && !["history", "export", "profile_image"].includes(collector.account_task)};
}

export function accountActivity(profile = {}) {
  const account = accountState(profile), collector = profile.collector || {};
  const task = collector.account_task || (collector.running ? "monitoring" : null);
  const kind = account.kind === "unavailable" ? "unavailable" : account.needsSignIn ? "sign_in" : !account.hasSession ? "empty"
    : task === "monitoring" ? (account.kind === "reconnecting" ? "reconnecting" : "monitoring")
    : task || (account.kind === "failed" ? "failed" : "free");
  const observing = kind === "monitoring" || kind === "reconnecting";
  return {kind, observing, busy: observing || ["history", "export", "profile_image"].includes(kind),
    canExport: kind === "free" || observing};
}
