"""Publish API JSON Schemas from the exact Pydantic models used by Case Board."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness.board_models import MODELS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    directory = ROOT / 'tgwitness' / 'schemas'
    directory.mkdir(exist_ok=True)
    for kind, model in MODELS.items():
        schema = {'$schema': 'https://json-schema.org/draft/2020-12/schema',
                  '$id': 'urn:tgwitness:board:' + kind + ':v1', **model.model_json_schema(by_alias=True)}
        data = json.dumps(schema, ensure_ascii=False, indent=2) + '\n'
        path = directory / ('board-' + kind + '.json')
        if args.check:
            if not path.is_file() or path.read_text(encoding='utf-8') != data:
                raise SystemExit('Schema differs from runtime model: ' + path.name)
        else:
            path.write_text(data, encoding='utf-8', newline='\n')
    print('Case Board input schemas match runtime models')


if __name__ == '__main__':
    main()
