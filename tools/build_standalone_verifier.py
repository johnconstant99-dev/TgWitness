import argparse
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / 'tgwitness' / 'verifier'
OUTPUT = ROOT / 'tgwitness' / 'verify.py'
PARTS = ('common', 'password', 'timestamps', 'chain', 'coverage', 'outside', 'journal', 'reports', 'board',
         'bundles', 'distributed', 'chat', 'handover', 'account', 'capture', 'witness',
         'presentation', 'languages', 'console', 'cli')
HEADER = '# TgWitness verifier sources SHA-256: '


def source_body(source, name):
    tree = ast.parse(source, filename=name)
    lines = source.splitlines(keepends=True)
    omitted = set()
    for node in ast.walk(tree):
        relative = isinstance(node, ast.ImportFrom) and node.level
        exports = isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == '__all__' for t in node.targets)
        if relative:
            if node.level != 1 or node.module not in PARTS or any(n.name == '*' or n.asname for n in node.names):
                raise ValueError('Unsupported verifier import in ' + name)
        if relative or exports:
            if exports and node not in tree.body:
                raise ValueError('Nested verifier export declaration in ' + name)
            if (lines[node.lineno - 1][:node.col_offset].strip()
                    or lines[node.end_lineno - 1].encode('utf-8')[node.end_col_offset:].strip()):
                raise ValueError('Build directives must occupy separate lines in ' + name)
            omitted.update(range(node.lineno, node.end_lineno + 1))
    return ''.join(line for number, line in enumerate(lines, 1) if number not in omitted)


def build(sources=SOURCES):
    found = {path.stem for path in sources.glob('*.py')} - {'__init__'}
    if found != set(PARTS):
        raise ValueError('Verifier source list differs from the reviewed build order')
    bodies, hashes = [], {}
    for name in PARTS:
        source = (sources / (name + '.py')).read_text(encoding='utf-8')
        hashes[name + '.py'] = hashlib.sha256(source.encode('utf-8')).hexdigest()
        bodies.append(source_body(source, name))
    manifest = json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode()
    body = ''.join(bodies)
    ast.parse(body, filename='verify.py')
    return HEADER + hashlib.sha256(manifest).hexdigest() + '\n' + body


def main():
    parser = argparse.ArgumentParser(description='Assemble the standalone verifier without importing application code.')
    parser.add_argument('--check', action='store_true', help='Fail if the committed verifier differs from its sources.')
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    expected = build()
    if args.check:
        if args.output.read_text(encoding='utf-8') != expected:
            parser.exit(1, 'Standalone verifier is stale; run python tools/build_standalone_verifier.py\n')
    else:
        args.output.write_text(expected, encoding='utf-8', newline='\n')


if __name__ == '__main__':
    main()
