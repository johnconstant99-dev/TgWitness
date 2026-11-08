"""Build a new offline, signed fictional dossier."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import evidence, report
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint, verify_bundle

TITLES = {'ru': 'Изменение условий сделки', 'en': 'A change in the terms', 'de': 'Geänderte Vertragsbedingungen'}
DEMO = {'ru': 'УЧЕБНЫЙ ПРИМЕР · Все сообщения и участники вымышлены. Подключения к Telegram не было.',
        'en': 'SYNTHETIC DEMO · All messages and participants are fictional. No Telegram connection.',
        'de': 'FIKTIVES BEISPIEL · Alle Nachrichten und Personen sind erfunden. Keine Telegram-Verbindung.'}
TITLES['ar'] = report.Words('ar')('Telegram observation journal')
DEMO['ar'] = 'SYNTHETIC DEMO · '+report.Words('ar')('Sample data')

PRESETS = {
    'dossier': {},
    'brief': {'timeline':False,'raw_records':False,'media_previews':False,
              'hourly_chart':False,'participant_chart':False,'chat_chart':False},
    'activity': {'timeline':False,'raw_records':False,'media_previews':False},
    'custom': {'timeline':False,'raw_records':False,'media_previews':False,
               'hourly_chart':False,'chat_chart':False,'chart_limit':5},
}


def seed(store):
    store.set_setting('demo', True)
    store.set_setting('account', {'id':70000, 'username':'synthetic_observer'})
    for cid, title in ((-100100001, 'DEMO · Project Meridian'), (-100100002, 'DEMO · Delivery review')):
        store.set_target(cid, title, 'supergroup', True)
    start = datetime(2026, 11, 1, 9, tzinfo=timezone.utc)

    def append(minute, kind, payload, cid=None, mid=None):
        at = (start + timedelta(minutes=minute)).isoformat()
        with patch('tgwitness.store.utcnow', return_value=at):
            store.append(kind, {'synthetic':True, 'source':'synthetic_demo', **payload}, cid, mid,
                         70001 if mid else None, at if mid else None)

    append(0, 'demo.created', {'meaning':DEMO['en']})
    append(0, 'observation.started', {'parameters':{'heartbeat_seconds':60}})
    for minute in range(1, 37):
        if 16 < minute < 23:
            continue
        if minute == 16:
            append(minute, 'coverage.gap', {'reason':'transport_disconnected'})
            continue
        if minute == 23:
            append(minute, 'connection.restored', {})
        append(minute, 'collector.heartbeat', {'connected':True, 'interval_seconds':60})
        if minute <= 15 or minute >= 24:
            append(minute, 'message.new', {
                'text': ('DEMO · Agreed delivery: 20 November. Total: 48,000.' if minute == 8 else
                         'DEMO · Review note ' + str(minute) + '. Please keep the agreed terms in this conversation.'),
                'sender_id':70001, 'sender_observation':{'id':70001,'display_name':'Alex · Fictional participant'},
                'has_media':False}, -100100001 if minute % 2 == 0 else -100100002, 400+minute)
        if minute == 26:
            append(minute, 'message.edited', {'text':'DEMO · Revised delivery: 27 November. Total: 64,000.',
                'sender_id':70001, 'editor_id':None}, -100100001, 408)
        if minute == 29:
            append(minute, 'message.deleted', {'deleted_by':None,'deletion_time':None}, -100100002, 409)
    append(37, 'observation.stopped', {'reason':'operator'})


def seed_activity(store):
    start=datetime(2026,11,2,0,tzinfo=timezone.utc)
    for day in range(14):
        for index in range(2+day%6):
            at=(start+timedelta(days=day,hours=(day*7+index*3)%24)).isoformat()
            sender=70100+(day+index)%8
            kind='message.snapshot' if day%5==0 else 'message.recovered' if day%7==0 else 'message.new'
            with patch('tgwitness.store.utcnow',return_value=at):
                store.append(kind,{'synthetic':True,'text':'DEMO · Fictional review note.',
                                   'sender_id':sender,'has_media':False},-100100001-index%2,1000+day*10+index,sender,at)


def build(output, languages=('en', 'de', 'ru'), templates=False):
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError('Choose a new empty directory; signed examples are immutable.')
    output.mkdir(parents=True, exist_ok=True)
    receipts = {}
    with tempfile.TemporaryDirectory(prefix='tgwitness-dossier-demo-') as scratch:
        vault, store = Vault(Path(scratch)), Store(Path(scratch))
        store.bind(vault)
        try:
            seed(store)
            if templates:
                seed_activity(store)
            pin = fingerprint(vault.public_key)
            for language in languages:
                if language not in TITLES:
                    raise ValueError('Unsupported example language')
                base = {**report.resolved(), 'language':language, 'theme':'light',
                           'case_title':TITLES[language], 'case_id':'DEMO · MRD-024/26',
                           'examiner':'DEMO · Synthetic analyst', 'organization':'Fictional case lab',
                           'notes':DEMO[language], 'raw_records':False}
                for template in PRESETS if templates else ('dossier',):
                    options={**base,**PRESETS[template], 'template':template}
                    if templates:
                        options.update(review_question='Did the recorded delivery terms change?',
                            review_method='Compare the saved versions of message 408 in chat -100100001 in events.jsonl. Review coverage before drawing conclusions about the missing period.',
                            review_findings='The first saved version names 20 November and 48,000. A later edit names 27 November and 64,000. A deletion notice is also recorded for message 409 in another chat; it does not identify who deleted it.',
                            review_conclusion='The saved versions differ, and both are kept with their observation times. All participants, messages and times here are fictional.')
                    bundle = evidence.export_file(store, vault, 'zip', options)
                    verified = verify_bundle(bundle, pin)
                    assert verified['key_pinned'] and verified['report_pdf']
                    key=language+'/'+template if templates else language
                    folder = output / key
                    folder.mkdir(parents=True)
                    shutil.copyfile(bundle, folder / 'dossier.zip')
                    with zipfile.ZipFile(bundle) as archive:
                        archive.extractall(folder)
                    receipts[key] = {'synthetic':True, 'fingerprint':pin,
                                     'archive_sha256':hashlib.sha256(bundle.read_bytes()).hexdigest()}
        finally:
            store.close()
    (output / 'example.json').write_text(json.dumps(receipts, indent=2) + '\n', encoding='utf-8')
    return receipts


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'test-results/report-dossier')
    parser.add_argument('--language', action='append', choices=tuple(TITLES))
    parser.add_argument('--templates', action='store_true', help='Build all four report presets with synthetic activity')
    args = parser.parse_args()
    print(json.dumps(build(args.output,languages=args.language or ('en','de','ru'),templates=args.templates), indent=2))
