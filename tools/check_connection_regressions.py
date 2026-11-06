"""Run connection regressions explicitly from the bounded CI check runner."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest


def main():
    checks = ("test_client_initialization.py", "test_client_timezone.py", "test_client_transport.py",
              "test_client_checks.py", "test_lookup_backoff.py", "check_client_checks_browser.py")
    return pytest.main([*[str(ROOT / "tools" / name) for name in checks], "-q"])


if __name__ == "__main__":
    raise SystemExit(main())
