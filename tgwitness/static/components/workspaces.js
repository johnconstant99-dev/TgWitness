const PARTS = ["connection", "intake", "sources", "media"];

export function describeWorkspace(profile, tr) {
  const collector = profile.collector;
  const problems = profile.error_type ? 1 : !collector?.has_session ? 0
    : PARTS.filter(name => ["failed", "degraded", "unknown"].includes(profile.health?.[name]?.state)).length;
  const state = profile.error_type ? tr("Unavailable") : !collector?.has_session ? tr("Account not connected")
    : collector.running ? tr(collector.connected ? "Collecting" : "Reconnecting") : tr("Paused");
  const marker = problems ? "⚠" : collector?.running ? "●" : "○";
  const count = problems ? " · " + problems : "";
  return {problems, state, label: marker + " " + profile.label + count,
    title: profile.label + " · " + state + (problems ? " · " + tr("Health checks needing attention: {n}", {n: problems}) : "")};
}

export function updateWorkspaceOptions(select, profiles, selected, tr) {
  const existing = new Map([...select.options].map(option => [option.value, option]));
  const keep = new Set(profiles.map(profile => profile.id));
  for (const option of [...select.options]) if (!keep.has(option.value)) option.remove();
  profiles.forEach((profile, index) => {
    const info = describeWorkspace(profile, tr), option = existing.get(profile.id) || new Option("", profile.id);
    if (option.textContent !== info.label) option.textContent = info.label;
    option.title = info.title; option.disabled = Boolean(profile.error_type); option.dataset.problems = String(info.problems);
    if (select.options[index] !== option) select.insertBefore(option, select.options[index] || null);
  });
  if (select.value !== selected && keep.has(selected)) select.value = selected;
  const current = profiles.find(profile => profile.id === selected);
  if (current) select.title = describeWorkspace(current, tr).title;
}
