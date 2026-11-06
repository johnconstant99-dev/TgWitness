import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


parser = argparse.ArgumentParser(description='Verify the TgWitness audit report signature and included file hashes.')
parser.add_argument('--key-sha256')
args = parser.parse_args()
root = Path(__file__).resolve().parent
proof = json.loads((root / 'PROOF.json').read_text(encoding='utf-8'), object_pairs_hook=unique)
statement = proof['statement']
assert statement['format'] == 'tgwitness-audit-summary-v1' and statement['complete']
public = base64.b64decode(proof['public_key'], validate=True)
key_hash = hashlib.sha256(public).hexdigest()
if args.key_sha256 and args.key_sha256.lower() != key_hash:
    raise ValueError('Audit public key does not match the supplied fingerprint')
encoded = json.dumps(statement, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(proof['signature'], validate=True), encoded)
expected = {'REPORT.md', 'MEASUREMENTS.csv', 'VERIFY.py'}
assert set(statement['included_files_sha256']) == expected
for name, expected_hash in statement['included_files_sha256'].items():
    path = root / name
    assert path.is_file() and not path.is_symlink()
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
        raise ValueError('File hash differs: ' + name)
print('Signature and 3 file hashes verified.')
print('Audit public-key SHA256: ' + key_hash)
print('This confirms report integrity, not independent validation of its measurements.')
