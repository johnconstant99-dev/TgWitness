"""Build a signed, explicitly fictional Case Board dossier. Never contacts Telegram."""
import argparse
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
from tools.build_report_studio_example import seed
from tgwitness import evidence, report
from tgwitness.access import Principal
from tgwitness.board import Board
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint, verify_bundle


def seed_board(store):
    board = Board(store)
    chat = -10020261102
    store.set_target(chat, 'DEMO · Meridian delivery review', 'supergroup', True)
    def analyst(identifier, label):
        return Principal(False, label, {'id': identifier * 16, 'permissions': ['view','board.read','board.write','board.manage'],
            'all_workspaces': True, 'workspaces': {}})
    a, b = analyst('a', 'Avery Chen · Analyst'), analyst('b', 'Morgan Ellis · Reviewer')
    def observe(minute, kind, payload, message=42, actor=None):
        at = '2026-11-02T14:%02d:00.000+00:00' % minute
        with patch('tgwitness.store.utcnow', return_value=at):
            return store.append(kind, {'synthetic':True, **payload}, chat, message, actor_id=actor,
                                source_at=at if kind in {'message.new','message.edited'} else None)
    original = observe(0, 'message.new', {'text':'The revised delivery window is Friday, 17:00 UTC. Please preserve the original schedule with this amendment.',
        'sender_id':71000, 'sender_observation':{'id':71000,'display_name':'DEMO · Alex Morgan'}}, actor=71000)
    observe(2, 'message.edited', {'text':'The revised delivery window is Monday, 17:00 UTC. Please preserve the original schedule with this amendment.', 'sender_id':71000})
    def reactions(count):
        return {'raw':{'reactions':{'results':[{'reaction':{'emoticon':'👍'},'count':count}], 'recent_reactions':[]}}}
    observe(3, 'reaction.snapshot', reactions(2))
    observe(5, 'membership.update', {'action':'join','user_id':71001}, None)
    observe(7, 'reaction.snapshot', reactions(3))
    observe(8, 'button.pressed', {'button_text':'Review schedule','own_action':True}, actor=71002)
    observe(9, 'media.skipped', {'reason':'Synthetic example: no real attachment was collected.'})
    with patch('tgwitness.board.utcnow', return_value='2026-11-02T14:10:00.000+00:00'):
        collection = board.append('collection', {'title':'01 · Delivery timeline', 'description':'Saved observations and the team’s reasoning, with unresolved questions kept visible.', 'chat_ids':[chat]}, a)
        bookmark = board.append('bookmark', {'target':{'event_hash':original['hash']}, 'title':'The original commitment',
            'labels':['schedule','primary observation'], 'note':'This record preserves what the observing account received at 14:00 UTC. The signature protects the saved record; it does not independently authenticate the sender’s real-world identity.'}, a)
        board.append('move', {'card_id':bookmark['payload']['id'], 'collection_id':collection['payload']['id']}, a)
        board.append('comment', {'parent_id':bookmark['payload']['id'], 'text':'The journal contains a later saved edit. Compare both versions before describing the agreement. We have no independent statement from Telegram confirming authorship.'}, b)
        quote = 'Friday, 17:00 UTC'
        highlight = board.append('highlight', {'target':{'event_hash':original['hash']}, 'title':'A deadline tied to its exact version',
            'range':{'start':original['payload']['text'].index(quote),'length':len(quote),'quote':quote}, 'color':'amber',
            'labels':['version comparison'], 'note':'The later text says Monday. This highlight remains attached to Friday in the first observation; it is never moved onto the edited text.'}, a)
        board.append('move', {'card_id':highlight['payload']['id'], 'collection_id':collection['payload']['id']}, a)
        slice_ = board.append('slice', {'query':{'chat_id':chat,'from':'2026-11-02T14:00:00Z','to':'2026-11-02T14:20:00Z'},
            'title':'Twenty minutes, every observed action', 'labels':['complete query','reactions'],
            'note':'Includes messages, the edit, reaction snapshots, membership, the account’s button action and a skipped attachment. Reaction counts changed between snapshots; the exact reaction time and complete actor list are unknown.'}, a)
        board.append('move', {'card_id':slice_['payload']['id'], 'collection_id':collection['payload']['id']}, a)
        board.append('status', {'card_id':highlight['payload']['id'],'state':'review','reason':'Request independent context for the schedule change.'}, b)
    observe(12, 'message.deleted', {'deleted_by':None, 'notice':'The observer received a deletion notice; no deletion actor was supplied.'})
    with patch('tgwitness.board.utcnow', return_value='2026-11-02T14:15:00.000+00:00'):
        board.append('comment', {'parent_id':slice_['payload']['id'], 'text':'One deletion notice arrived after this slice was bookmarked. Recomputed exports show +1 record. This is a disclosed addition, not a claim that the original bookmark already contained it.'}, b)
    return {'bookmark':bookmark['payload']['id'], 'slice':slice_['payload']['id'], 'collection':collection['payload']['id']}


def build(output):
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError('Choose a new empty directory; signed examples are immutable.')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='tgwitness-board-example-') as scratch:
        vault, store = Vault(Path(scratch)), Store(Path(scratch))
        store.bind(vault)
        try:
            seed(store)
            seed_board(store)
            options = {**report.resolved(), 'language':'en', 'design':'analytical', 'template':'activity',
                'theme':'light', 'timeline':False, 'case_board':'comments', 'chart_limit':6,
                'case_title':'Project Meridian — Evidence & interpretation', 'case_id':'DEMO / MRD–2026.11',
                'organization':'Fictional Research Office', 'examiner':'Avery Chen · Synthetic investigator',
                'notes':'SYNTHETIC EXAMPLE · All people, messages and actions are fictional. No Telegram connection, external timestamp or independent witness was used. Team notes are opinions. Signature verification establishes integrity relative to the signing key; it does not establish the truth of a statement or guarantee court acceptance.',
                'selection':{'id_gaps':False}}
            bundle = evidence.export_file(store,vault,'zip',options)
            verified = verify_bundle(bundle,fingerprint(vault.public_key))
            assert verified['board']['slice_changes'][0]['added'] == 1
            shutil.copyfile(bundle,output/'dossier.zip')
            with zipfile.ZipFile(bundle) as archive:
                archive.extractall(output)
            receipt = {'synthetic':True, 'fingerprint':fingerprint(vault.public_key),
                'sha256':hashlib.sha256(bundle.read_bytes()).hexdigest(), 'verification':verified}
            (output/'example.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
            return receipt
        finally:
            store.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    result = build(args.output)
    print(json.dumps({'fingerprint':result['fingerprint'],'sha256':result['sha256'],'board':result['verification']['board']},indent=2))
