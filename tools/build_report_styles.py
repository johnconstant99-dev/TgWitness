"""Build signed, fictional report layouts from the same journal for visual review."""
import argparse
import hashlib
import html
import json
from pathlib import Path
import shutil
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_dossier_example import seed, seed_activity
from tgwitness import evidence, report, report_design
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint, verify_bundle

LABELS = {
    'classic': ('Classic', 'A traditional dossier with a dark cover and numbered sections.'),
    'quire': ('Editorial', 'A spacious folio with serif headings and a narrow reference column.'),
    'meridian': ('Briefing', 'A compact briefing with a horizontal register and clear summary figures.'),
    'atlas': ('Analytics', 'A modular workspace for charts, activity patterns and comparisons.'),
    'ledger': ('Technical', 'A precise register with ruled tables and prominent record references.'),
    'horizon': ('Overview', 'A visual overview with an asymmetric cover and a clear reading path.'),
    'reading_series': ('Reading series', 'A section rail, clear findings and a focused history of changes.'),
    'ledger_margin': ('Ledger & margin', 'Numbered sections, a generous margin and figures with exact tables.'),
}


def build(output, designs=report_design.DESIGNS, language='en'):
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError('Choose a new empty directory; signed examples are immutable.')
    if any(design not in report_design.DESIGNS for design in designs):
        raise ValueError('Unknown report design')
    output.mkdir(parents=True, exist_ok=True)
    receipts = {}
    with tempfile.TemporaryDirectory(prefix='tgwitness-styles-') as scratch:
        root = Path(scratch)
        vault, store = Vault(root), Store(root)
        store.bind(vault)
        try:
            seed(store)
            seed_activity(store)
            pin = fingerprint(vault.public_key)
            options = {**report.resolved(), 'language': language, 'theme': 'light',
                       'template': 'dossier', 'case_title': 'A change in the terms',
                       'case_id': 'DEMO · MRD-024/26', 'examiner': 'Synthetic analyst',
                       'organization': 'Fictional case lab', 'raw_records': False,
                       'notes': 'SYNTHETIC EXAMPLE · All messages, participants and findings are fictional. No Telegram connection.',
                       'review_question': 'Did the recorded delivery terms change?',
                       'review_method': 'Compare the preserved versions of message 408. Review the recorded observation gap before interpreting missing content.',
                       'review_findings': 'The saved terms changed from 20 November and 48,000 to 27 November and 64,000. A separate message was later reported deleted; its earlier saved text remains available.',
                       'review_conclusion': 'The preserved versions differ. These fictional observations do not identify who changed or deleted the messages.'}
            for design in designs:
                bundle = evidence.export_file(store, vault, 'zip', {**options, 'design': design})
                verified = verify_bundle(bundle, pin)
                assert verified['key_pinned'] and verified['report_pdf']
                folder = output / design
                folder.mkdir()
                shutil.copyfile(bundle, folder / 'evidence.zip')
                with zipfile.ZipFile(bundle) as archive:
                    archive.extractall(folder)
                    data = json.loads(archive.read('report.json'))['report']
                    receipts[design] = {'synthetic': True, 'fingerprint': pin, 'design': design,
                        'source_sha256': hashlib.sha256(archive.read('events.jsonl')).hexdigest(),
                        'subject': data['subject'], 'summary': data['summary'],
                        'archive_sha256': hashlib.sha256(bundle.read_bytes()).hexdigest()}
        finally:
            store.close()
    (output / 'examples.json').write_text(json.dumps(receipts, indent=2) + '\n', encoding='utf-8')
    cards = []
    for design in designs:
        title, detail = LABELS[design]
        cards.append('<article><a class="sample" href="'+design+'/report.html"><iframe tabindex="-1" aria-hidden="true" '
                     'sandbox src="'+design+'/report.html" title="'+title+' preview"></iframe></a>'
                     '<h2>'+html.escape(title)+'</h2><p>'+html.escape(detail)+'</p><nav>'
                     '<a href="'+design+'/report.html">Open HTML</a><a href="'+design+'/report.pdf">PDF</a>'
                     '<a href="'+design+'/evidence.zip">Signed ZIP</a></nav></article>')
    (output / 'index.html').write_text('''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer">
<title>TgWitness · Report styles</title><style>
*{box-sizing:border-box}body{margin:0;background:#f2f1ed;color:#172f3b;font:16px/1.6 system-ui,sans-serif}
main{max-width:1320px;margin:auto;padding:48px 28px}h1{font:500 clamp(32px,5vw,62px)/1.1 Georgia,serif;letter-spacing:-.03em;margin:12px 0 22px}
.intro{max-width:780px}.eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:.16em}.notice{border-inline-start:3px solid #a56723;padding:12px 18px;background:#fff8e8}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:28px;margin-top:36px}article{min-width:0;background:#fff;padding:16px;border:1px solid #d9deda;border-radius:8px}
h2{margin:18px 0 4px;font:600 23px/1.3 Georgia,serif}p{margin:8px 0 20px}article p{font-size:14px;min-height:4em;color:#53636b}nav{display:flex;flex-wrap:wrap;gap:14px}a{color:#175575;text-underline-offset:4px}
.sample{display:block;height:280px;overflow:hidden;border:1px solid #d9deda;position:relative}iframe{width:1200px;height:1000px;border:0;transform:scale(.3);transform-origin:top left;pointer-events:none}
@media(max-width:1000px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:640px){.grid{grid-template-columns:1fr}main{padding:28px 16px}}
</style><main><div class="intro"><p class="eyebrow">TgWitness / Report collection</p><h1>One record. Different ways to read it.</h1>
<p>Compare the same messages, saved edits, deletion observations and activity figures in complete report layouts. Each includes HTML, a signed PDF and the original journal.</p>
<p class="notice">Fictional example. No Telegram account was connected. The signatures check these demonstration files; they do not make the invented messages real.</p></div>
<div class="grid">'''+''.join(cards)+'</div></main></html>', encoding='utf-8')
    return receipts


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--language', default='en', choices=tuple(report.i18n.LANGUAGES))
    args = parser.parse_args()
    print(json.dumps(build(args.output, language=args.language), indent=2))
