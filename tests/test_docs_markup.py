"""Collapsible sections in Markdown keep their content inside (audit A11)."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = sorted(p for p in [ROOT / "README.md", *(ROOT / "docs").rglob("*.md"), *(ROOT / ".github").rglob("*.md")]
                   if "<details" in p.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", DOCUMENTS, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_every_disclosure_has_content_after_its_summary(path):

    text = re.sub(r"^```.*?^```", "", path.read_text(encoding="utf-8"), flags=re.S | re.M)
    text = re.sub(r"`[^`\n]*`", "", text)
    depth = 0
    for match in re.finditer(r"<details\b[^>]*>|</details>", text):
        depth += 1 if match.group(0).startswith("<details") else -1
        assert depth >= 0, "unmatched </details>"
    assert depth == 0, "unclosed <details>"
    for block in re.findall(r"<details\b[^>]*>(.*?)</details>", text, re.S):
        after_summary = re.sub(r"^\s*<summary>.*?</summary>", "", block, count=1, flags=re.S)
        assert after_summary.strip(), "disclosure with only a summary"
