// One name and one explanation for the priority star, in the chat list and in Sources alike.
export function priorityHint(tr, priority, collector) {
  const fast = collector?.recheck_minutes, slow = collector?.recheck_other_minutes;
  if (priority) return fast
    ? tr("Priority chat: rechecked every {n} min. Click to make it a regular chat.", {n: fast})
    : tr("Priority chat. Rechecks are off.");
  return slow
    ? tr("Regular chat: rechecked every {n} min. Click to make it a priority chat.", {n: slow})
    : tr("Regular chat: not rechecked. Click to make it a priority chat.");
}
