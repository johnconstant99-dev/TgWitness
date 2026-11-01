"""Explicit, previewed disclosure derivatives. Original account evidence is never rewritten."""
import asyncio
import base64
import hashlib
import hmac
import json
import re
import secrets
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .account_export import AccountExportOptions, file_sha
from . import account_report
from .security import private_write
from .store import canonical, utcnow
from .verify import MAX_MEMBERS, MAX_UNCOMPRESSED_GIB, fingerprint, verify_account_export, verify_account_disclosure
from .workers import complete_in_thread

METADATA = ('profile', 'contacts', 'profile_photos', 'stories', 'session_metadata', 'other_data')
WARNINGS = [
    'This is a minimized derivative, not the complete original account export.',
    'Pseudonymization is not anonymization. Dates, context and message content can still identify people.',
    'Automatic text masking cannot find every personal detail. Review the disclosed content before sharing.',
    'A signature protects this derivative. Source linkage alone does not prove that filtering or redaction was correct.',
    'Purpose and settings do not establish a legal basis, GDPR compliance or court admissibility.',
]
MAX_MASK_TERMS = 5000


class DisclosurePolicy(BaseModel):
    model_config = ConfigDict(extra='forbid')
    purpose: str = Field(min_length=1, max_length=1000)
    report_language: str = 'en'
    from_utc: str | None = None
    to_utc: str | None = None
    sender_ids: list[int] = Field(default_factory=list, max_length=10000)
    text_contains: list[str] = Field(default_factory=list, max_length=100)
    redact_terms: list[str] = Field(default_factory=list, max_length=100)
    identity_mode: Literal['keep', 'pseudonymize_third_parties', 'pseudonymize_all'] = 'pseudonymize_third_parties'
    disclose_user_ids: list[int] = Field(default_factory=list, max_length=10000)
    text_mode: Literal['keep', 'omit'] = 'keep'
    include_media: bool = False
    include_profile: bool = False
    include_contacts: bool = False
    include_profile_photos: bool = False
    include_stories: bool = False
    include_session_metadata: bool = False
    include_other_data: bool = False

    @field_validator('report_language')
    @classmethod
    def report_language_supported(cls, value):
        return account_report.validate_language(value)

    @field_validator('purpose')
    @classmethod
    def purpose_present(cls, value):
        if not value.strip():
            raise ValueError('Record the purpose of this disclosure.')
        return value.strip()

    @field_validator('sender_ids', 'disclose_user_ids', mode='before')
    @classmethod
    def valid_ids(cls, values):
        return AccountExportOptions.ids(values)

    @field_validator('text_contains', 'redact_terms')
    @classmethod
    def valid_terms(cls, values):
        return AccountExportOptions.terms(values)

    @field_validator('from_utc', 'to_utc')
    @classmethod
    def valid_date(cls, value):
        return AccountExportOptions.date_bound(value)

    @model_validator(mode='after')
    def constraints(self):
        if self.from_utc and self.to_utc and self.from_utc >= self.to_utc:
            raise ValueError('The disclosure period must end after it starts.')
        if any(getattr(self, 'include_' + name) for name in METADATA):
            raise ValueError('Minimized disclosure excludes account profiles, contacts, avatars, sessions and other personal metadata.')
        self.sender_ids = sorted(set(self.sender_ids))
        self.disclose_user_ids = sorted(set(self.disclose_user_ids))
        return self


def source_rows(archive):
    """Read only sealed message pages; account/contacts/avatars are never copied."""
    inventory = json.loads(archive.read('inventory.json'))['statement']
    chats = {row['id']: row for row in inventory['chats']}
    for name in sorted(n for n in archive.namelist() if n.startswith('receipts/')):
        receipt = json.loads(archive.read(name))['statement']
        if receipt['category'] != 'messages':
            continue
        with archive.open(receipt['data_file']) as stream:
            for raw in stream:
                row = json.loads(raw)
                yield chats[row['chat_id']], row


def sender_id(row):
    value = row.get('from_id')
    person = row.get('sender')
    if type(value) is not int and isinstance(person, dict):
        value = person.get('id')
    return value if type(value) is int else None


def visible_text(row):
    for field in ('text', 'message'):
        value = row.get(field)
        if isinstance(value, str) and value:
            return value
    return ''


def date_text(value):
    """A date field cannot carry nested source metadata into the projection."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def plain_string(value):
    return value if isinstance(value, str) else ''


def mask_literals(text, pattern, replacement):
    """Match full Unicode casefolds, replacing spans in the unchanged original text."""
    if not pattern:
        return text
    matches = list(pattern.finditer(text.casefold()))
    if not matches:
        return text
    offsets = []
    for index, char in enumerate(text):
        part = char.casefold()
        offsets.extend([index] * len(part))
    spans = []
    for match in matches:
        start, end = offsets[match.start()], offsets[match.end() - 1] + 1
        if spans and start <= spans[-1][1]:
            spans[-1] = (spans[-1][0], max(end, spans[-1][1]))
        else:
            spans.append((start, end))
    result, position = [], 0
    for start, end in spans:
        result.extend((text[position:start], replacement))
        position = end
    result.append(text[position:])
    return ''.join(result)


def matches(row, policy):
    if policy.sender_ids and sender_id(row) not in policy.sender_ids:
        return False
    if policy.text_contains and not any(term in visible_text(row).casefold() for term in policy.text_contains):
        return False
    date = row.get('date')
    if policy.from_utc or policy.to_utc:
        try:
            instant = datetime.fromisoformat(str(date).replace('Z', '+00:00'))
            instant = instant.replace(tzinfo=instant.tzinfo or timezone.utc).astimezone(timezone.utc).isoformat()
        except (TypeError, ValueError):
            return False
        if policy.from_utc and instant < policy.from_utc or policy.to_utc and instant >= policy.to_utc:
            return False
    return True


class Projection:
    def __init__(self, policy, seed, source):
        self.policy, self.seed = policy, seed
        terms = set(policy.redact_terms)
        ids = set()
        self.identity_count = set()
        purpose_only = policy.text_mode == 'omit'
        folded_purpose = policy.purpose.casefold()

        def add_term(value):
            if isinstance(value, str) and 2 <= len(value) <= 200:
                folded = value.casefold()
                # Omitted message text needs no name dictionary, but the public
                # purpose still needs masking. Retain only its possible matches.
                if purpose_only and folded not in folded_purpose:
                    return
                terms.add(folded)
                if len(terms) + len(ids) > MAX_MASK_TERMS:
                    raise ValueError('Too many known identities to mask safely. Narrow the source export or omit message text.')

        if policy.identity_mode != 'keep':
            for chat, row in source_rows(source):
                # Direct-chat titles can identify a person even when its sender
                # object was unavailable. Generic group/channel titles are not
                # treated as personal names in arbitrary message text.
                if chat.get('kind') in ('private', 'bot'):
                    add_term(chat.get('title'))
                if self.reveal(sender_id(row)):
                    continue
                if sender_id(row) is not None and (not purpose_only or str(sender_id(row)) in folded_purpose):
                    ids.add(str(sender_id(row)))
                    if len(terms) + len(ids) > MAX_MASK_TERMS:
                        raise ValueError('Too many known identities to mask safely. Narrow the source export or omit message text.')
                add_term(row.get('from'))
                add_term(row.get('from_username'))
                person = row.get('sender') or {}
                if not isinstance(person, dict):
                    continue
                for field in ('first_name', 'last_name', 'username', 'phone', 'title'):
                    add_term(person.get(field))
                usernames = person.get('usernames')
                if isinstance(usernames, list):
                    for username in usernames:
                        if isinstance(username, dict):
                            add_term(username.get('username'))
                if len(terms) + len(ids) > MAX_MASK_TERMS:
                    raise ValueError('Too many known identities to mask safely. Narrow the source export or omit message text.')
        # Matching on casefolded text covers expansions such as Straße/STRASSE.
        # IDs match whole numeric tokens, never a substring of another ID or decimal.
        patterns = [re.escape(t) for t in sorted(terms, key=len, reverse=True)]
        patterns += [r'(?<![\w.+-])' + re.escape(t) + r'(?![\w.])' for t in sorted(ids, key=len, reverse=True)]
        self.pattern = re.compile('|'.join(patterns)) if patterns else None

    def mask_known(self, text):
        return mask_literals(text, self.pattern, '[redacted]')

    def mask_text(self, text):
        if self.policy.identity_mode != 'keep':
            text = re.sub(r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', '[email withheld]', text)
            text = re.sub(r'(?i)(?:https?://|tg://|www\.)\S+|@[\w]+', '[link or handle withheld]', text)
            text = re.sub(r'(?<!\w)\+?\d[\d ()-]{6,}\d(?!\w)', '[number withheld]', text)
        return self.mask_known(text)

    def alias(self, category, value):
        digest = hmac.new(self.seed, canonical([category, value]), hashlib.sha256).hexdigest()[:16]
        return category + '-' + digest

    def reveal(self, user):
        return self.policy.identity_mode == 'keep' or (
            self.policy.identity_mode == 'pseudonymize_third_parties' and user in self.policy.disclose_user_ids)

    def apply(self, chat, row):
        policy, uid = self.policy, sender_id(row)
        private = policy.identity_mode != 'keep'
        public_chat = {'id': self.alias('chat', chat['id']) if private else chat['id'],
                       'title': self.alias('Chat', chat['id']) if private else plain_string(chat.get('title')),
                       'kind': chat.get('kind') if isinstance(chat.get('kind'), str) else None}
        message = {'id': self.alias('message', [chat['id'], row['id']]) if private else row['id'],
                   'date': date_text(row.get('date')), 'edited': date_text(row.get('edit_date') or row.get('edited')),
                   'outgoing': bool(row.get('outgoing', row.get('out', False))), 'redacted_fields': []}
        person = row.get('sender') or {}
        if not isinstance(person, dict):
            person = {}
        if self.reveal(uid):
            message.update(from_id=uid, sender=' '.join(plain_string(person.get(k)) for k in ('first_name', 'last_name')).strip()
                           or plain_string(person.get('title')) or plain_string(row.get('from')) or str(uid or 'Unknown'),
                           username=plain_string(person.get('username')) or plain_string(row.get('from_username')) or None)
        else:
            # An absent sender ID does not establish that two messages share a sender.
            subject = uid if uid is not None else ['unknown', chat['id'], row['id']]
            message.update(from_id=self.alias('participant', subject), sender=self.alias('Participant', subject))
            message['redacted_fields'].extend(['sender_identity', 'chat_identity', 'message_id'])
            if uid is not None:
                self.identity_count.add(message['from_id'])
        text = visible_text(row)
        if policy.text_mode == 'omit':
            text = '[text withheld]'
            message['redacted_fields'].append('text')
        else:
            original = text
            text = self.mask_text(text)
            if text != original:
                message['redacted_fields'].append('text')
        message['text'] = text
        message['attachments'] = []
        if policy.include_media:
            for item in row.get('attachments', []):
                if item.get('outcome') == 'saved':
                    message['attachments'].append({k: item[k] for k in ('outcome', 'file', 'sha256', 'bytes')})
        elif row.get('attachments'):
            message['redacted_fields'].append('attachments')
        # Forward headers, entities, reply quotes, usernames, locations, contact cards,
        # avatars and raw Telegram payloads are deliberately outside this allowlist.
        return {'chat': public_chat, 'message': message}


def public_policy(policy, projection=None):
    # The public purpose must not echo otherwise-private selection or identity criteria.
    private_terms = {str(value) for value in (*policy.sender_ids, *policy.disclose_user_ids)}
    private_terms.update(policy.text_contains)
    private_terms.update(policy.redact_terms)
    pattern = re.compile('|'.join(re.escape(value.casefold()) for value in sorted(private_terms, key=len, reverse=True))) if private_terms else None
    purpose = mask_literals(policy.purpose, pattern, '[private criterion]')
    if projection is not None:
        purpose = projection.mask_text(purpose)
    return {'purpose': purpose, 'report_language': policy.report_language,
            'identity_mode': policy.identity_mode, 'text_mode': policy.text_mode,
            'from_utc': policy.from_utc, 'to_utc': policy.to_utc, 'include_media': policy.include_media,
            **{'include_' + name: False for name in METADATA},
            'sender_filter_count': len(policy.sender_ids), 'text_filter_count': len(policy.text_contains),
            'disclosed_identity_count': len(policy.disclose_user_ids), 'manual_redaction_count': len(policy.redact_terms),
            'selection_criteria': 'Sensitive identifiers and literal filter terms are retained privately, not in this package.'}


def archive_limit(path):
    """Allow the local ZIP's expanded size, independently of its media-only budget.

    Completed sources are pinned to their published ZIP digest/size before this
    allowance is used. The full verifier still authenticates the collector and
    streams every hash, with its member-count, whole-member and line limits.
    Locally generated derivatives use the same bounded per-call allowance;
    external CLI verification retains its explicit --max-gib requirement.
    """
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise ValueError('Archive has more members than the verifier accepts')
        expanded = sum(member.file_size for member in members)
    return max(MAX_UNCOMPRESSED_GIB, (expanded + 1024**3 - 1) // 1024**3)


class Disclosures:
    def __init__(self, exports, vault):
        self.exports, self.vault, self.previews, self.active = exports, vault, {}, set()

    def busy(self, job_id=None):
        return bool(self.active) if job_id is None else job_id in self.active

    def directory(self, job_id):
        path = self.exports.directory(job_id) / 'disclosures'
        if path.is_symlink() or path.resolve().parent != self.exports.directory(job_id).resolve():
            raise ValueError('Invalid disclosure storage path.')
        return path

    def source(self, job_id):
        path = self.exports.result_path(job_id)
        if not path:
            raise ValueError('Finish the source account export before preparing a disclosure.')
        published = self.exports.public(job_id)
        digest = file_sha(path)
        if (published.get('archive_sha256') not in (None, digest)
                or published.get('archive_bytes') not in (None, path.stat().st_size)):
            raise ValueError('The source export differs from its published archive digest or size.')
        limit = archive_limit(path)
        verify_account_export(path, fingerprint(self.vault.public_key), max_gib=limit)
        return path, digest, limit

    def preview(self, job_id, policy, owner):
        policy = DisclosurePolicy.model_validate(policy)
        path, digest, limit = self.source(job_id)
        seed = secrets.token_bytes(32)
        summary = dict(messages_before=0, messages_after=0, chats_before=0, chats_after=0,
                       media_included=0, identities_pseudonymized=0)
        samples, before_chats, after_chats, media = [], set(), set(), set()
        with zipfile.ZipFile(path) as source:
            projection = Projection(policy, seed, source)
            for chat, row in source_rows(source):
                summary['messages_before'] += 1
                before_chats.add(chat['id'])
                if not matches(row, policy):
                    continue
                result = projection.apply(chat, row)
                summary['messages_after'] += 1
                after_chats.add(result['chat']['id'])
                media.update(a['file'] for a in result['message']['attachments'])
                if len(samples) < 12:
                    sample = json.loads(json.dumps(result))
                    sample['message']['text'] = sample['message']['text'][:2000]
                    samples.append({'after': sample})
            summary.update(chats_before=len(before_chats), chats_after=len(after_chats), media_included=len(media),
                           identities_pseudonymized=len(projection.identity_count))
        now = time.time()
        self.previews = {k: v for k, v in self.previews.items() if v['expires_at'] > now
                         and not (v['owner'] == owner and v['job_id'] == job_id)}
        if len(self.previews) >= 20:
            self.previews.pop(next(iter(self.previews)))
        preview_id = secrets.token_urlsafe(24)
        self.previews[preview_id] = dict(job_id=job_id, policy=policy, seed=seed, owner=owner,
                                       source_sha=digest, max_gib=limit, summary=summary, expires_at=now + 900)
        warnings = list(WARNINGS)
        if policy.include_media:
            warnings.append('Included files are unchanged originals; their pixels, audio, text and metadata have not been anonymized.')
        return dict(preview_id=preview_id, summary=summary, samples=samples, warnings=warnings, expires_at=now + 900)

    async def create(self, job_id, preview_id, owner):
        ticket = self.previews.get(preview_id)
        if not ticket or ticket['owner'] != owner or ticket['job_id'] != job_id or ticket['expires_at'] <= time.time():
            raise ValueError('The disclosure preview expired or belongs to another session. Preview it again.')
        if self.busy(job_id):
            raise ValueError('A disclosure is already being prepared for this export.')
        self.previews.pop(preview_id)
        self.active.add(job_id)
        try:
            return await complete_in_thread(self.build, ticket)
        finally:
            self.active.discard(job_id)

    def build(self, ticket):
        path, digest, _limit = self.source(ticket['job_id'])
        if digest != ticket['source_sha']:
            raise ValueError('The source export changed after preview. Refusing to create a disclosure.')
        root = self.directory(ticket['job_id'])
        root.mkdir(mode=0o700, exist_ok=True)
        identity = secrets.token_hex(16)
        stage, final = root / (identity + '.partial'), root / (identity + '.zip')
        hashes, counts, media, chats = {}, dict(messages=0, chats=0, media=0), set(), set()
        created = utcnow()
        policy = ticket['policy']
        try:
            with zipfile.ZipFile(path) as source, zipfile.ZipFile(stage, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as target:
                projection = Projection(policy, ticket['seed'], source)
                shared_policy = public_policy(policy, projection)

                def write(name, chunks):
                    digest = hashlib.sha256()
                    with target.open(name, 'w', force_zip64=True) as stream:
                        for part in chunks:
                            stream.write(part)
                            digest.update(part)
                    hashes[name] = digest.hexdigest()

                def rows():
                    for chat, row in source_rows(source):
                        if matches(row, policy):
                            yield projection.apply(chat, row)

                def message_bytes():
                    for row in rows():
                        counts['messages'] += 1
                        chats.add(row['chat']['id'])
                        media.update(a['file'] for a in row['message']['attachments'])
                        yield canonical(row) + b'\n'
                write('messages.jsonl', message_bytes())
                counts.update(chats=len(chats), media=len(media))
                report_context = {'report_language': policy.report_language, 'policy': shared_policy,
                    'archive_reference': identity, 'created_at': created,
                    'counts': counts, 'fingerprint': fingerprint(self.vault.public_key),
                    'source_archive_sha256': digest, 'limitations': WARNINGS}
                write('index.html', account_report.sharing_report(report_context, rows()))
                for name in sorted(media):
                    with source.open(name) as stream:
                        write(name, iter(lambda: stream.read(1024**2), b''))
                write('verify.py', [Path(__file__).with_name('verify.py').read_bytes()])
                write('README.txt', [('Minimized disclosure\n\n' + '\n'.join(WARNINGS)
                    + '\n\nThe original source, identity map and private selection criteria are NOT included.\n'
                    + 'Verify from an independently trusted installation:\n'
                    + 'python verify.py disclosure.zip --fingerprint TRUSTED_SHA256\n'
                    + 'Optional --evidence original.zip checks source linkage, not the correctness of redaction.\n'
                    + 'For large packages add --max-gib with the expanded size. index.html is protected by the manifest.\n').encode()])
                write('SHA256SUMS', [''.join(f'{v}  {k}\n' for k, v in sorted(hashes.items())).encode()])
                manifest = dict(format='tgwitness-account-disclosure-v1', public_key=self.vault.public_key,
                    report_language=policy.report_language,
                    fingerprint=fingerprint(self.vault.public_key), disclosure_id=identity, created_at=created,
                    source_archive_sha256=digest, source_collector_fingerprint=fingerprint(self.vault.public_key),
                    policy=shared_policy, counts=counts, files=hashes, limitations=WARNINGS)
                target.writestr('manifest.json', canonical(manifest))
                target.writestr('manifest.sig', self.vault.sign(canonical(manifest)))
            verify_account_disclosure(stage, fingerprint(self.vault.public_key), max_gib=archive_limit(stage))
            self.vault.save('disclosure-' + identity, {'source_job': ticket['job_id'], 'source_sha256': digest,
                'policy': policy.model_dump(), 'pseudonym_key': base64.b64encode(ticket['seed']).decode()})
            stage.replace(final)
            info = dict(id=identity, ready=True, summary=ticket['summary'], created_at=created,
                        download_url=f'account-export/{ticket["job_id"]}/disclosures/{identity}/download')
            private_write(root / (identity + '.json'), canonical(info))
            return info
        finally:
            stage.unlink(missing_ok=True)

    def list(self, job_id):
        root = self.directory(job_id)
        if not root.exists():
            return []
        result = []
        for item in root.glob('*.json'):
            if re.fullmatch(r'[a-f0-9]{32}', item.stem) and not item.is_symlink() and item.stat().st_size < 65536:
                row = json.loads(item.read_bytes())
                if self.result_path(job_id, item.stem):
                    result.append(row)
        return sorted(result, key=lambda item: item['created_at'], reverse=True)

    def result_path(self, job_id, identity):
        if not re.fullmatch(r'[a-f0-9]{32}', identity):
            return None
        path = self.directory(job_id) / (identity + '.zip')
        return path if path.is_file() and not path.is_symlink() else None

    async def close(self):
        while self.active:
            await asyncio.sleep(0.05)
