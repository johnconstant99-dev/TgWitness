"""Streaming, offline account/sharing reports. Signed JSONL remains authoritative.

Labels use the existing panel dictionaries, with explicit English fallbacks. Message
text is escaped, never translated. Sharing reports apply an additional display
allowlist and never serialize source records or private selection criteria.
"""
import html
import json
import re
from datetime import datetime

from . import i18n
from .report import Words

MEDIA_PATH = re.compile(r'media/[0-9a-f]{64}\Z')
COUNT_LABELS = {'messages': 'Messages', 'chats': 'Chats', 'media': 'Media files included',
                'media_saved': 'Media files included', 'media_skipped': 'Files skipped or unavailable',
                'records': 'Records', 'chats_selected': 'Selected chats'}
SCOPE_LABELS = {'from_utc': 'From date (UTC)', 'to_utc': 'Until (UTC, exclusive)',
                'report_language': 'Report language', 'identity_mode': 'Names and user IDs',
                'text_mode': 'Message text', 'include_media': 'Include media files',
                'own_messages_only': 'Only messages sent by this account',
                'sender_filter_count': 'Sender filters', 'text_filter_count': 'Text filters',
                'manual_redaction_count': 'Additional terms hidden',
                'disclosed_identity_count': 'Identities allowed to remain identifiable'}
VALUES = {'keep': 'Keep matching text', 'omit': 'Omit message text',
          'pseudonymize_all': 'Pseudonymize everyone', 'pseudonymize_third_parties': 'Pseudonymize third parties',
          'regular': 'Regular Telegram API', 'takeout': 'Telegram Takeout'}
CONTEXT_LABELS = {'archive_reference': 'Archive reference', 'created_at': 'Copy created',
                  'requested_at': 'Collection requested', 'captured_from': 'First recorded capture',
                  'captured_until': 'Last recorded capture'}
CSS = """
:root{color-scheme:light dark;--bg:#f3f5f8;--paper:#fff;--ink:#182438;--muted:#536174;--line:#dce2eb;--accent:#235dcc;--soft:#edf3ff;--warn:#fff5df}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.65 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1060px;margin:auto;padding:40px 28px 64px}header{border-top:4px solid var(--accent);padding-top:22px;margin-bottom:28px}
.brand{font-size:12px;letter-spacing:.15em;font-weight:750;color:var(--accent)}h1{font-size:clamp(26px,5vw,42px);line-height:1.2;margin:12px 0}
h2{font-size:20px;line-height:1.4;margin:28px 0 12px}h3{font-size:16px;margin:0}p{margin:8px 0 14px}.muted,small{color:var(--muted)}
.lead{font-size:17px;max-width:80ch}.badge{display:inline-block;padding:3px 9px;background:var(--soft);border:1px solid var(--line);border-radius:5px;font-size:12px;font-weight:650}
.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:24px 0}.stat{padding:15px;background:var(--paper);border:1px solid var(--line);border-radius:10px;min-width:0}
.stat dt{font-size:12px;color:var(--muted)}.stat dd{font-size:26px;line-height:1.3;font-weight:700;font-variant-numeric:tabular-nums;margin:5px 0 0;overflow-wrap:anywhere}
.panel,.message{background:var(--paper);border:1px solid var(--line);border-radius:10px;padding:20px;margin:14px 0}.panel>h2:first-child{margin-top:0}.notice{background:var(--warn);border-inline-start:3px solid #d7a33e;padding:14px 18px;margin:18px 0}
.recipient-steps{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px 30px;padding-inline-start:22px;margin-bottom:0}.recipient-steps li{padding-inline-start:3px;margin:0}.recipient-steps p{font-size:13px;margin:4px 0 0}
.facts{display:grid;grid-template-columns:minmax(120px,1fr) minmax(0,3fr);gap:8px 18px;margin:0}.facts dt{color:var(--muted)}.facts dd{margin:0;min-width:0}
.chat-list{list-style:none;padding:0}.chat-list li{display:flex;justify-content:space-between;gap:16px;padding:12px 0;border-bottom:1px solid var(--line)}
.message-head{display:flex;justify-content:space-between;align-items:baseline;gap:8px 20px;flex-wrap:wrap}.record-link{font-size:12px;white-space:nowrap}.message-meta,.record-citation{font-size:12px;color:var(--muted);margin:8px 0}.message-meta span{display:inline-block;margin-inline-end:16px}.record-citation{border-top:1px solid var(--line);padding-top:8px}.record-citation code{color:var(--ink)}.message:target{outline:2px solid var(--accent);outline-offset:3px}
.message-text{white-space:pre-wrap;overflow-wrap:anywhere;unicode-bidi:plaintext;margin:16px 0}.user{unicode-bidi:plaintext;overflow-wrap:anywhere;min-width:0}
a{color:var(--accent);text-underline-offset:3px}a,code,pre,dd{overflow-wrap:anywhere}pre{white-space:pre-wrap;font:12px/1.6 ui-monospace,monospace;margin:12px 0 0}
nav{display:flex;gap:8px 18px;flex-wrap:wrap;margin:18px 0;font-size:13px}nav a{padding:4px 0}
code{font:12px/1.6 ui-monospace,monospace}.command{display:block;padding:12px;background:var(--bg);border:1px solid var(--line);border-radius:6px;white-space:pre-wrap;direction:ltr;unicode-bidi:plaintext}
details{border-top:1px solid var(--line);padding-top:10px;margin-top:16px}summary{cursor:pointer;color:var(--muted);font-size:12px}li{margin-bottom:7px}footer{border-top:1px solid var(--line);margin-top:32px;padding-top:16px;font-size:12px;color:var(--muted)}
@media(prefers-color-scheme:dark){:root{--bg:#101722;--paper:#182231;--ink:#e8eef8;--muted:#abb8cb;--line:#354258;--accent:#9cc0ff;--soft:#233553;--warn:#332c1f}}
@media(max-width:600px){main{padding:24px 16px 40px}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.recipient-steps{grid-template-columns:1fr}.panel,.message{padding:15px}.facts{grid-template-columns:1fr;gap:2px}.facts dd{margin-bottom:10px}.chat-list li{flex-wrap:wrap}}
@page{margin:14mm}
@media print{
:root{color-scheme:light;--bg:#fff;--paper:#fff;--ink:#111;--muted:#444;--line:#bbb;--accent:#111;--soft:#fff;--warn:#fff}main{max-width:none;padding:0}body{font-size:9pt;line-height:1.4}
header{border-top-width:2px;padding-top:8px;margin-bottom:10px}h1{font-size:22pt;margin:7px 0}.lead{font-size:10pt}h2{font-size:13pt;margin:16px 0 8px;break-after:avoid}h3{font-size:10pt}p{margin:5px 0 8px}nav,details{display:none}
.panel,.message{padding:10px;margin:9px 0;border-radius:0}.recipient-guide,.stat,.message{break-inside:avoid}.recipient-steps{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px 22px}.recipient-steps p,.message-meta,.record-citation,.record-link{font-size:8pt}
.stats{grid-template-columns:repeat(3,minmax(0,1fr));margin:12px 0;gap:8px}.stat{padding:8px;border-radius:0}.stat dd{font-size:17pt}.stat dt,.badge{font-size:8pt}.facts{grid-template-columns:minmax(120px,1fr) minmax(0,3fr);gap:4px 12px}.facts dd{margin-bottom:0}.notice{margin:10px 0;padding:8px 10px}
.message-head,.message-meta{break-after:avoid}.message-text{margin:9px 0;orphans:3;widows:3}.record-citation{break-before:avoid}a{color:inherit;text-decoration:none}.chat-list li{padding:6px 0}.command{font-size:8pt;padding:8px}footer{margin-top:16px;padding-top:8px;font-size:8pt}}
"""


def validate_language(value):
    if value not in i18n.LANGUAGES:
        raise ValueError('Unsupported report language')
    return value


def e(value):
    return html.escape('' if value is None else str(value), quote=True)


def text(value):
    return value if isinstance(value, str) else ''


def encoded(value):
    return value.encode('utf-8')


def technical(value, say):
    return '<details><summary>' + e(say('Technical details')) + '</summary><pre dir="ltr">' + e(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)) + '</pre></details>'


def timestamp(value, say):
    """Keep the recorded offset; never silently assume the reader's timezone."""
    raw = text(value)
    if not raw:
        return e(say('Not recorded'))
    try:
        date = datetime.fromisoformat(raw.replace('Z', '+00:00'))
    except ValueError:
        return '<span class="user" dir="auto">' + e(raw) + '</span> · ' + e(say('Date format not recognized'))
    if date.utcoffset() is None:
        zone = say('Timezone not recorded')
        shown = raw.replace('T', ' ')
    else:
        offset = date.strftime('%z')
        zone = 'UTC' if not date.utcoffset() else 'UTC' + offset[:3] + ':' + offset[3:5] + (':' + offset[5:] if len(offset) > 5 else '')
        shown = date.replace(tzinfo=None).isoformat(sep=' ')
    return '<time dir="ltr" datetime="' + e(raw) + '">' + e(shown) + '</time> · <bdi>' + e(zone) + '</bdi>'


def recipient_guide(say, sharing=False):
    steps = [
        (say('Open'), say('Keep the ZIP unchanged. Extract all files together, then open index.html in your browser. No internet connection is needed.')),
        (say('Read'), say('Check the scope below, then read the messages. Names or text may have been changed or omitted.') if sharing else
         say('Check the selected scope and coverage, then open a chat from the list.')),
        (say('Cite'), say('Cite the archive reference, the file path and the record reference beside a message. Record numbers apply only to this copy.')),
        (say('Check'), say("Before relying on this copy, ask for the ZIP verification result and confirm the signer's key through a separate trusted channel.")),
    ]
    return ('<section class="panel recipient-guide" id="start"><h2>' + e(say('Start here')) + '</h2><ol class="recipient-steps">' +
            ''.join('<li><h3>' + e(title) + '</h3><p>' + e(body) + '</p></li>' for title, body in steps) +
            '</ol><p><a href="#verification">' + e(say('How to check the ZIP')) + '</a></p></section>')


def copy_context(context, say, sharing=False):
    parts = ['<section class="panel" id="context"><h2>' + e(say('About this copy')) + '</h2><dl class="facts">']
    # Sharing has its own reference and creation time; source metadata stays private.
    for key, label in CONTEXT_LABELS.items():
        if sharing and key not in ('archive_reference', 'created_at'):
            continue
        value = text(context.get(key))
        if value:
            shown = '<code dir="ltr">' + e(value) + '</code>' if key == 'archive_reference' else timestamp(value, say)
            parts.append('<dt>' + e(say(label)) + '</dt><dd>' + shown + '</dd>')
    if not sharing:
        method = context.get('options', {}).get('transport')
        if method in ('regular', 'takeout'):
            parts.append('<dt>' + e(say('Collection method')) + '</dt><dd>' + e(say(VALUES[method])) + '</dd>')
    parts.append('<dt>' + e(say('Report language')) + '</dt><dd><bdi>' + e(say.language) + '</bdi></dd></dl>')
    parts.append('<p class="muted">' + e(say('Times retain their recorded timezone. UTC is the common time reference; an offset shows the difference from UTC. Missing timezones are marked.')) + '</p>')
    if not sharing and (context.get('captured_from') or context.get('captured_until')):
        parts.append('<p class="muted">' + e(say("Capture times come from the collector's clock. Collection may pause or resume between the first and last recorded capture.")) + '</p>')
    return ''.join(parts) + '</section>'


def opening(context, title, sharing=False):
    say = Words(context.get('report_language', 'en'))
    kind = say('Sharing copy') if sharing else say('Account export')
    lead = (say('A minimized, signed copy for review and sharing. The original account export is unchanged.') if sharing else
            say('A snapshot of history visible to this Telegram account during acquisition.'))
    yield encoded('<!doctype html><html lang="' + say.language + '" dir="' + say.direction + '"><head><meta charset="utf-8">'
                  '<meta name="viewport" content="width=device-width,initial-scale=1">'
                  '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'
                  '<title>' + e(title) + ' · TgWitness</title><style>' + CSS + '</style></head><body><main>'
                  '<header><div class="brand" dir="ltr">TGWITNESS</div><p class="badge">' + e(kind) + '</p>'
                  '<h1 class="user" dir="auto">' + e(title) + '</h1><p class="lead">' + e(lead) + '</p></header>')


def stats(counts, say):
    parts = ['<dl class="stats">']
    for key, label in COUNT_LABELS.items():
        value = counts.get(key)
        if key == 'media_skipped' and value == 0 or key == 'records' and value == counts.get('messages'):
            continue
        if type(value) is int and value >= 0:
            parts.append('<div class="stat"><dt>' + e(say(label)) + '</dt><dd>' + str(value) + '</dd></div>')
    return ''.join(parts) + '</dl>'


def scope(policy, say, sharing=False):
    parts = ['<section class="panel"><h2>' + e(say('Selected scope')) + '</h2><dl class="facts">']
    for key, label in SCOPE_LABELS.items():
        value = policy.get(key)
        if not sharing and key in ('sender_filter_count', 'text_filter_count'):
            terms = policy.get('sender_ids' if key == 'sender_filter_count' else 'text_contains', ())
            value = len(terms) if isinstance(terms, (list, tuple)) else value
        if value is None or value == '' or key == 'report_language':
            continue
        if key.endswith('_count') and value == 0 or key == 'own_messages_only' and value is False:
            continue
        if type(value) is bool:
            shown = say('Yes') if value else say('No')
        elif key == 'identity_mode' and value == 'keep':
            shown = say('Keep identities')
        else:
            shown = say(VALUES.get(value, value)) if isinstance(value, str) else str(value)
        parts.append('<dt>' + e(say(label)) + '</dt><dd class="user" dir="auto">' + e(shown) + '</dd>')
    if not policy.get('from_utc') and not policy.get('to_utc'):
        parts.append('<dt>' + e(say('History dates')) + '</dt><dd>' +
                     e(say('No additional date restriction') if sharing else say('Full visible history')) + '</dd>')
    parts.append('</dl>')
    parts.append('<p class="muted">' + e(say('Inactive filters are not listed. Public settings are recorded in manifest.json.') if sharing else
                                        say('Inactive filters are not listed. The archive retains the full saved settings.')) + '</p>')
    if sharing:
        parts.append('<p>' + e(say('Account profile, contacts and other account metadata are not included. Some message fields are omitted; consult messages.jsonl for the retained fields.')) + '</p>')
    purpose = text(policy.get('purpose'))
    if purpose:
        parts.append('<h3>' + e(say('Disclosure purpose') if sharing else say('Collection purpose')) +
                     '</h3><p class="user" dir="auto">' + e(purpose) + '</p>')
    if not sharing:
        parts.append(technical(policy, say))
    parts.append('</section>')
    return ''.join(parts)


def verification(context, say, sharing=False):
    parts = ['<section id="verification"><h2>' + e(say('Verification')) + '</h2><p>' +
             e(say('TgWitness signs this archive; Telegram does not. A valid signature does not establish completeness or truth.')) + '</p>',
             '<p>' + e(say('This HTML is protected by the archive manifest. Verify the ZIP; this page alone has no standalone signature.')) + '</p>',
             '<p>' + e(say("Get the signer's key fingerprint from a trusted channel, not from this archive.")) + '</p>',
             '<h3>' + e(say('Signing key fingerprint (SHA-256)')) + '</h3><p><code dir="ltr">' + e(context.get('fingerprint')) + '</code></p>',
             '<p>' + e(say('Run the verifier from an independently trusted installation.')) + '</p><code class="command">python verify.py ' +
             ('disclosure.zip' if sharing else 'account-export.zip') + ' --fingerprint TRUSTED_SHA256</code>']
    parts.append('<p>' + e(say('Replace the example ZIP filename with the file you received, and TRUSTED_SHA256 with the fingerprint confirmed separately. Keep the verification result with your review notes.')) + '</p>')
    if sharing:
        parts += ['<p>' + e(say('Optional source comparison checks the archive reference, not the correctness of filtering or redaction.')) + '</p>',
                  '<code class="command">python verify.py disclosure.zip --fingerprint TRUSTED_SHA256 --evidence original.zip</code>',
                  '<p>' + e(say('Source archive SHA-256')) + ': <code dir="ltr">' + e(context.get('source_archive_sha256')) + '</code></p>']
    parts.append('</section><section><h2>' + e(say('Limitations')) + '</h2><ul>')
    for limitation in context.get('limitations', ()):
        if isinstance(limitation, str):
            parts.append('<li>' + e(say(limitation)) + '</li>')
    parts.append('</ul></section>')
    return ''.join(parts)


def ending(say):
    return encoded('<footer><p>' + e(say('Report labels may include English fallbacks. Original messages are not translated.')) +
                   '</p><p>' + e(say('Message text and dates can still identify people. Review the full copy and included files before sharing.')) +
                   '</p></footer></main></body></html>')


def account_index(context, chats):
    say = Words(context.get('report_language', 'en'))
    yield from opening(context, say('Account export'))
    yield encoded('<nav><a href="#start">' + e(say('Start here')) + '</a><a href="#chats">' + e(say('Chats')) + '</a><a href="#coverage">' + e(say('Coverage')) +
                  '</a><a href="#verification">' + e(say('Verification')) + '</a></nav>')
    yield encoded(recipient_guide(say))
    yield encoded('<p class="notice">' + e(say('Original account data may contain personal information. Prepare a separate minimized copy before sharing.')) + '</p>')
    yield encoded(stats(context.get('counts', {}), say) + copy_context(context, say) + scope(context.get('options', {}), say))
    coverage = context.get('coverage', {})
    complete = (context.get('complete_within_scope') is True and coverage.get('inventory_complete') is True
                and type(coverage.get('failures')) is int and coverage['failures'] == 0
                and type(coverage.get('tasks_total')) is int and coverage.get('tasks_done') == coverage['tasks_total'])
    yield encoded('<section id="coverage"><h2>' + e(say('Coverage')) + '</h2><p class="badge">' +
                  e(say('Completed within selected scope') if complete else say('Partial acquisition')) + '</p><p>' +
                  e(say('Acquisition is not an atomic account snapshot. Deleted, inaccessible or previously edited data may be unavailable.')) + '</p><dl class="facts">')
    for label, value in (('Tasks completed', coverage.get('tasks_done')), ('Tasks planned', coverage.get('tasks_total')),
                         ('Failures and gaps', coverage.get('failures'))):
        if type(value) is int:
            yield encoded('<dt>' + e(say(label)) + '</dt><dd>' + str(value) + '</dd>')
    yield encoded('</dl>' + technical(coverage, say) + '</section><section id="chats"><h2>' + e(say('Chats')) + '</h2><ul class="chat-list">')
    for chat in chats:
        if type(chat.get('id')) is not int:
            continue
        yield encoded('<li><a class="user" dir="auto" href="chats/' + str(chat['id']) + '.html">' +
                      e(text(chat.get('title')) or str(chat['id'])) + '</a><span>' + e(say('Messages')) + ': ' +
                      e(chat.get('message_count', '—')) + '</span></li>')
    yield encoded('</ul></section><section><h2>' + e(say('Omissions and unavailable data')) + '</h2><ul>')
    omissions = context.get('omissions', ())
    if not omissions:
        note = (say('See signed page receipts for recorded acquisition failures.') if coverage.get('failures') else
                say('No acquisition gaps recorded. User-selected exclusions still apply.'))
        yield encoded('<li>' + e(note) + '</li>')
    for omission in omissions:
        if isinstance(omission, str):
            shown = omission
        elif isinstance(omission, dict):
            shown = ' · '.join(str(omission.get(key, '')) for key in ('section', 'reason') if omission.get(key))
        else:
            continue
        yield encoded('<li class="user" dir="auto">' + e(shown) + '</li>')
    yield encoded('</ul><p>' + e(say('Signed JSONL pages and capture receipts are authoritative. Other account data is retained in those pages.')) + '</p></section>')
    yield encoded(verification(context, say))
    yield ending(say)


def shared_row(row):
    """Only the transformed schema can enter readable sharing output, including raw details."""
    chat = row.get('chat') if isinstance(row.get('chat'), dict) else {}
    message = row.get('message') if isinstance(row.get('message'), dict) else {}
    safe_chat = {key: chat[key] for key in ('id', 'title', 'kind') if type(chat.get(key)) in (str, int)}
    safe_message = {key: message[key] for key in ('id', 'date', 'edited', 'from_id', 'sender', 'username', 'text')
                    if key in message and (type(message[key]) in (str, int) or message[key] is None)}
    if type(message.get('outgoing')) is bool:
        safe_message['outgoing'] = message['outgoing']
    safe_message['attachments'] = []
    for attachment in message.get('attachments', ()):
        if isinstance(attachment, dict) and attachment.get('outcome') == 'saved' and MEDIA_PATH.fullmatch(text(attachment.get('file'))):
            safe = {'outcome': 'saved', 'file': attachment['file']}
            if isinstance(attachment.get('sha256'), str) and re.fullmatch('[0-9a-f]{64}', attachment['sha256']):
                safe['sha256'] = attachment['sha256']
            if type(attachment.get('bytes')) is int and attachment['bytes'] >= 0:
                safe['bytes'] = attachment['bytes']
            safe_message['attachments'].append(safe)
    return {'chat': safe_chat, 'message': safe_message}


def message_card(row, say, prefix='', sharing=False, number=1, page_path='index.html'):
    if sharing:
        row = shared_row(row)
        chat, message = row['chat'], row['message']
        sender = text(message.get('sender'))
    else:
        chat, message = {}, row
        person = message.get('sender')
        sender = ' '.join(text(person.get(key)) for key in ('first_name', 'last_name')).strip() if isinstance(person, dict) else ''
        sender = sender or (text(person.get('title')) if isinstance(person, dict) else text(person)) or text(message.get('from'))
    sender = sender or say('Sender not available')
    body = next((message[key] for key in ('text', 'message', 'caption') if isinstance(message.get(key), str) and message[key]), '')
    identifier = message.get('id')
    marker = ' data-message-id="' + e(identifier) + '"' if type(identifier) in (str, int) else ''
    reference = f'record-{number:06d}'
    parts = ['<article class="message" id="' + reference + '"' + marker + '><div class="message-head"><h3 class="user" dir="auto">' + e(sender) +
             '</h3><a class="record-link" href="#' + reference + '">' + e(say('Record')) + ' <bdi>' + f'{number:06d}' + '</bdi></a></div>',
             '<p class="message-meta"><span>' + e(say('Message date')) + ': ' + timestamp(message.get('date'), say) + '</span>']
    edited = text(message.get('edited')) or text(message.get('edit_date'))
    if edited:
        parts.append('<span>' + e(say('Edited date')) + ': ' + timestamp(edited, say) + '</span>')
    parts.append('</p>')
    if sharing:
        parts.append('<p class="muted user" dir="auto">' + e(text(chat.get('title'))) + '</p>')
    if text(message.get('username')):
        parts.append('<p class="muted user" dir="auto">@' + e(message['username']) + '</p>')
    parts.append('<p class="message-text" dir="auto">' + e(body or say('No message text in this record.')) + '</p>')
    for attachment in message.get('attachments', ()):
        if not isinstance(attachment, dict):
            continue
        if attachment.get('outcome') == 'saved' and MEDIA_PATH.fullmatch(text(attachment.get('file'))):
            parts.append('<p><a download href="' + prefix + attachment['file'] + '">' + e(say('Included original attachment')) + '</a></p>')
        elif not sharing:
            parts.append('<p class="muted">' + e(say('Attachment not included')) + ': <span class="user" dir="auto">' + e(text(attachment.get('reason'))) + '</span></p>')
    parts.append('<p class="record-citation">' + e(say('Record reference')) + ': <code dir="ltr">' + e(page_path) + '#' + reference + '</code></p>')
    parts.append(technical(row, say))
    parts.append('</article>')
    return ''.join(parts)


def account_chat(context, chat, rows):
    say = Words(context.get('report_language', 'en'))
    yield from opening(context, text(chat.get('title')) or str(chat.get('id', '')))
    yield encoded('<p><a href="../index.html">← ' + e(say('Account export')) + '</a></p><p>' +
                  e(say('Message records are shown in captured page order. Signed JSONL remains authoritative.')) + '</p>')
    yield encoded(copy_context(context, say))
    yield encoded('<p>' + e(say('Cite the archive reference, the file path and the record reference beside a message. Record numbers apply only to this copy.')) + '</p>')
    yield encoded('<nav><a href="#messages">' + e(say('Messages')) + '</a><a href="#verification">' +
                  e(say('Verification')) + '</a></nav><section id="messages">')
    page_path = 'chats/' + str(chat['id']) + '.html' if type(chat.get('id')) is int else 'chat.html'
    seen = False
    for number, row in enumerate(rows, 1):
        seen = True
        yield encoded(message_card(row, say, prefix='../', number=number, page_path=page_path))
    if not seen:
        yield encoded('<p>' + e(say('No message records are included in this view. Check the scope and omissions before drawing conclusions.')) + '</p>')
    yield encoded('</section>')
    yield encoded(verification(context, say))
    yield ending(say)


def sharing_report(context, rows):
    say = Words(context.get('report_language', 'en'))
    yield from opening(context, say('Sharing copy'), sharing=True)
    yield encoded('<nav><a href="#start">' + e(say('Start here')) + '</a><a href="#messages">' + e(say('Messages')) + '</a><a href="#verification">' +
                  e(say('Verification')) + '</a></nav>')
    yield encoded(recipient_guide(say, sharing=True))
    # Only explicitly public policy fields are rendered. No private criteria, map or source rows.
    public = {key: context.get('policy', {}).get(key) for key in (*SCOPE_LABELS, 'purpose')}
    yield encoded(stats(context.get('counts', {}), say) + copy_context(context, say, sharing=True) + scope(public, say, sharing=True))
    yield encoded('<p class="notice">' + e(say('This sharing copy is a separate derivative, not the complete original account export.')) + '</p>')
    yield encoded('<section id="messages"><h2>' + e(say('Messages')) + '</h2>')
    yield encoded('<p class="muted">' + e(say('Record numbers follow messages.jsonl line order. They identify records in this copy, not original Telegram message IDs.')) + '</p>')
    seen = False
    for number, row in enumerate(rows, 1):
        seen = True
        yield encoded(message_card(row, say, sharing=True, number=number))
    if not seen:
        yield encoded('<p>' + e(say('No message records are included in this view. Check the scope and omissions before drawing conclusions.')) + '</p>')
    yield encoded('</section>')
    yield encoded(verification(context, say, sharing=True))
    yield ending(say)


def text_keys():
    """English labels for explicit dictionary fallback maintenance; message text is excluded."""
    import ast
    from pathlib import Path
    tree = ast.parse(Path(__file__).read_text(encoding='utf-8'))
    keys = [node.args[0].value for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == 'say' and node.args
            and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)]
    return list(dict.fromkeys(keys + list(COUNT_LABELS.values()) + list(SCOPE_LABELS.values()) +
                              list(VALUES.values()) + list(CONTEXT_LABELS.values()) + ['Tasks completed', 'Tasks planned', 'Failures and gaps']))
