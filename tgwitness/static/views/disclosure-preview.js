// Display only the disclosure API's transformed sample, never source payloads.
const MAX_SAMPLES = 12;
const MAX_TEXT = 2000;
const COUNTS = [
  ['messages_before', 'Source messages'], ['messages_after', 'Included messages'],
  ['chats_before', 'Source chats'], ['chats_after', 'Included chats'],
  ['media_included', 'Media files included'], ['identities_pseudonymized', 'Identities pseudonymized'],
];
const FIELDS = {
  sender_identity: 'Sender identity', chat_identity: 'Chat identity',
  message_id: 'Message ID', text: 'Message text', attachments: 'Attachments',
};
const plain = (value, limit = MAX_TEXT) => typeof value === 'string' ? value.slice(0, limit) : '';
const count = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
const translate = (text, values = {}) => text.replace(/\{(\w+)\}/g, (match, key) => String(values[key] ?? match));

export function createDisclosurePreview({root, tr = translate, formatTime = value => String(value)}) {
  const find = id => root.querySelector('#' + id);
  const preview = find('account-disclosure-preview');
  const summary = find('account-disclosure-summary');
  const samples = find('account-disclosure-samples');
  const warnings = find('account-disclosure-warnings');
  const expiry = find('account-disclosure-expiry');
  if (![preview, summary, samples, warnings, expiry].every(Boolean)) {
    throw new Error('Disclosure preview containers are missing');
  }
  const document = root.ownerDocument;
  const element = (tag, className, text) => {
    const result = document.createElement(tag);
    if (className) result.className = className;
    if (text !== undefined) result.textContent = text;
    return result;
  };
  const dateLabel = value => {
    if (typeof value !== 'string' || !value) return '';
    try { return plain(formatTime(value), 160) || plain(value, 160); }
    catch { return plain(value, 160); }
  };

  function messageCard(after, index) {
    const legacy = typeof after === 'string';
    if (!legacy && (!after || typeof after !== 'object' || Array.isArray(after) ||
        !after.message || typeof after.message !== 'object' || Array.isArray(after.message))) return null;
    const card = element('article', 'disclosure-preview-message');
    const heading = element('h4', '', tr('Sample {number}', {number: index}));
    card.append(heading);
    if (!legacy) {
      const chat = after.chat && typeof after.chat === 'object' ? after.chat : {};
      card.append(element('p', 'disclosure-preview-chat', plain(chat.title, 240) || tr('Chat title not available')));
      const meta = element('p', 'disclosure-preview-meta');
      meta.append(element('strong', '', plain(after.message.sender, 240) || tr('Sender not available')));
      const date = dateLabel(after.message.date);
      if (date) {
        const time = element('time', '', date);
        // The display does not interpret dates or establish their accuracy.
        if (/^\d{4}-\d{2}-\d{2}T/.test(after.message.date)) time.dateTime = after.message.date;
        meta.append(time);
      }
      card.append(meta);
    }
    const text = legacy ? plain(after) : plain(after.message.text);
    card.append(element('p', 'disclosure-preview-text', text || tr('No message text in this sample.')));
    if (!legacy) {
      if (Array.isArray(after.message.attachments) && after.message.attachments.length) {
        card.append(element('p', 'disclosure-preview-note', tr('Included attachments: {count}. File contents are not shown in this preview.', {
          count: after.message.attachments.length,
        })));
      }
      const fields = Array.isArray(after.message.redacted_fields) ?
        [...new Set(after.message.redacted_fields.filter(field => typeof field === 'string' && Object.hasOwn(FIELDS, field)))] : [];
      if (fields.length) card.append(element('p', 'disclosure-preview-note', tr('Fields omitted or replaced: {fields}.', {
        fields: fields.map(field => tr(FIELDS[field])).join(', '),
      })));
    }
    return card;
  }

  function clear() {
    summary.replaceChildren();
    samples.replaceChildren();
    warnings.replaceChildren();
    expiry.textContent = '';
    preview.hidden = true;
  }

  function render(result = {}) {
    clear();
    preview.classList.add('disclosure-preview');
    const facts = result?.summary && typeof result.summary === 'object' ? result.summary : {};
    const counts = element('dl', 'disclosure-preview-counts');
    for (const [key, label] of COUNTS) {
      const value = count(facts[key]);
      if (value === null) continue;
      const pair = element('div', 'disclosure-preview-count');
      pair.append(element('dt', '', tr(label)), element('dd', '', String(value)));
      counts.append(pair);
    }
    summary.append(counts);
    if (!counts.childNodes.length) summary.append(element('p', 'hint', tr('Summary counts are not available for this preview.')));
    const cards = [];
    for (const item of Array.isArray(result?.samples) ? result.samples.slice(0, MAX_SAMPLES) : []) {
      if (cards.length === MAX_SAMPLES) break;
      const card = messageCard(item?.after, cards.length + 1);
      if (card) cards.push(card);
    }
    const included = count(facts.messages_after);
    samples.append(element('p', 'disclosure-preview-caption', included === null ?
      tr('Showing {shown} transformed message samples.', {shown: cards.length}) :
      tr('Samples shown: {shown} of {included} included messages.', {shown: cards.length, included})));
    samples.append(element('p', 'hint', tr('Sample only: up to 12 messages, with text limited to 2,000 characters per message. This is not a review of the full sharing copy.')));
    if (cards.length) samples.append(...cards);
    else samples.append(element('p', 'hint', tr('No matching transformed sample is available. Review the counts and policy before creating a file.')));
    warnings.append(element('p', 'disclosure-preview-guidance', tr('After creating the sharing copy, download it and review its index.html and any included files before sharing. The full copy can contain personal information absent from these samples.')));
    warnings.append(element('p', 'account-disclosure-warning', tr('Personal information can remain in message text, quotes, names and attachments. Review the generated file before sharing.')));
    for (const warning of (Array.isArray(result?.warnings) ? result.warnings : []).slice(0, 20)) {
      if (typeof warning === 'string' && warning) warnings.append(element('p', 'account-disclosure-warning', tr(plain(warning, 2000))));
    }
    const expires = result?.expires_at;
    if ((typeof expires === 'number' && Number.isFinite(expires)) || (typeof expires === 'string' && expires)) {
      let time;
      try { time = plain(formatTime(expires), 160); } catch { time = ''; }
      expiry.textContent = time ? tr('This preview expires {time}.', {time}) : tr('Create the derivative promptly; previews expire.');
    } else expiry.textContent = tr('Create the derivative promptly; previews expire.');
    preview.hidden = false;
  }

  return {render, clear};
}
