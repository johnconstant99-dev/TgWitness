"""Check generated site metadata in addition to the source-level pytest tests."""
import json

from test_site_metadata import ROOT, check_built_site


if __name__ == "__main__":
    print(json.dumps(check_built_site(ROOT / "dist/site"), indent=2))
