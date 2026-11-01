"""Publish a new fictional report example once; never rewrite existing signed samples."""
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
from tools.demo_account_export import build_demo_account_exports
from tgwitness.verify import verify_account_disclosure


def build(output):
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError('Choose a new empty directory; published examples are immutable.')
    with tempfile.TemporaryDirectory(prefix='tgwitness-fictional-report-') as scratch:
        job, sharing = build_demo_account_exports(scratch)
        source = Path(scratch) / 'account-exports' / job / 'disclosures' / (sharing + '.zip')
        with zipfile.ZipFile(source) as bundle:
            manifest = json.loads(bundle.read('manifest.json'))
            report = bundle.read('index.html')
        assert manifest['format'] == 'tgwitness-account-disclosure-v1'
        assert 'SYNTHETIC DEMO' in manifest['policy']['purpose']
        assert manifest['policy']['identity_mode'] == 'pseudonymize_all'
        verify_account_disclosure(source, manifest['fingerprint'])
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        output.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, output / 'sharing-copy.zip')
        (output / 'report.html').write_bytes(report)
        descriptor = {'synthetic': True, 'archive': 'sharing-copy.zip', 'sha256': digest,
                      'fingerprint': manifest['fingerprint'], 'report': 'report.html',
                      'report_sha256': hashlib.sha256(report).hexdigest(),
                      'report_archive_member': 'index.html', 'language': 'en'}
        (output / 'example.json').write_text(json.dumps(descriptor, indent=2) + '\n', encoding='utf-8')
        fingerprint = html.escape(manifest['fingerprint'])
        page = '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; frame-src 'self'; base-uri 'none'; form-action 'none'">
<title>A report your recipient can read · TgWitness</title>
<style>
:root{color-scheme:light dark;--bg:#f2f5fa;--paper:#fff;--ink:#17263c;--muted:#52647c;--line:#d6dfec;--accent:#235dcc}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 system-ui,sans-serif}
main{max-width:1200px;margin:auto;padding:24px}header{display:flex;justify-content:space-between;gap:20px;align-items:center}
a{color:var(--accent);text-underline-offset:3px}.brand{font-size:13px;font-weight:750;letter-spacing:.12em}h1{font-size:clamp(28px,4vw,44px);line-height:1.15;max-width:22ch;margin:24px 0 14px}
.lead{max-width:75ch;color:var(--muted);margin-bottom:18px}.actions{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0 24px}.actions a{display:inline-block;padding:10px 16px;min-height:44px;border:1px solid var(--line);border-radius:8px;text-decoration:none;background:var(--paper)}.actions a:first-child{background:var(--accent);color:#fff;border-color:var(--accent)}
.preview{background:var(--paper);border:1px solid var(--line);border-radius:12px;overflow:hidden}iframe{display:block;width:100%;height:76vh;min-height:420px;border:0;background:var(--paper)}
.caption{margin:0;padding:12px 16px;border-bottom:1px solid var(--line);color:var(--muted);font-size:13px}details{padding:18px 0}summary{cursor:pointer;font-weight:650}code{font:12px/1.7 ui-monospace,monospace;overflow-wrap:anywhere}.facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:24px;margin:24px 0}.facts h2{font-size:18px}p{margin:8px 0 14px}
@media(prefers-color-scheme:dark){:root{--bg:#111a28;--paper:#1a2637;--ink:#ecf2fc;--muted:#b4c2d7;--line:#394a63;--accent:#90b8ff}.actions a:first-child{color:#101722}}
@media(max-width:600px){main{padding:18px 14px}.facts{grid-template-columns:1fr;gap:6px}.actions a{flex:1;text-align:center}header{align-items:flex-start}iframe{height:72vh}}
</style></head><body><main><header><a class="brand" href="../">TGWITNESS</a><a href="../">Back to the demo</a></header>
<h1>A report your recipient can read.</h1>
<p class="lead">Open the messages, follow a record reference, and see what was included or left out. This English example uses fictional messages. No Telegram account was connected.</p>
<div class="actions"><a href="sharing-copy.zip" download>Download the signed example</a><a href="report.html">Open the report on its own</a></div>
<section class="preview" aria-label="Fictional sharing report"><p class="caption">This preview is the exact index.html file from the downloadable ZIP.</p><iframe title="Fictional sharing report" src="report.html#messages" sandbox="allow-same-origin"></iframe></section>
<div class="facts"><section><h2>Keep the complete ZIP.</h2><p>The report is for reading and citing. The ZIP also carries the signed manifest, message records and verification instructions. A screenshot or printout does not carry those signatures.</p></section>
<section><h2>Choose what you disclose.</h2><p>This example replaces identities and omits attachments. In your own workspace, review the selected messages and files before preparing a separate sharing copy.</p></section></div>
<details><summary>Check this example</summary><p>Extract the ZIP to read index.html and README.txt. To check the complete archive, use the verifier from an independently trusted TgWitness installation. The key below is a disposable demonstration key.</p>
<p>Signing key fingerprint (SHA-256):<br><code>@@FINGERPRINT@@</code></p><p>Archive SHA-256:<br><code>@@DIGEST@@</code></p>
<p><code>python verify.py sharing-copy.zip --fingerprint @@FINGERPRINT@@</code></p>
<p>A valid signature establishes integrity against the chosen key. It does not establish Telegram authorship, completeness or legal admissibility.</p><a href="../../docs/exports/">Read the verification guide</a></details>
</main></body></html>
'''.replace('@@FINGERPRINT@@', fingerprint).replace('@@DIGEST@@', digest)
        (output / 'index.html').write_text(page, encoding='utf-8', newline='\n')
    return descriptor


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'website/demo/report')
    print(json.dumps(build(parser.parse_args().output), indent=2))
