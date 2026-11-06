import copy
import base64
import csv
import hashlib
import json
from pathlib import Path
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import build_site, build_source, site_validation


def snapshot():
    return json.loads((ROOT / "website/validation/snapshot.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("field,value", [
    ("acquisition_records_per_second", 9999),
    ("end_to_end_seconds", 1),
    ("archive_verified", False),
    ("key_pinned", False),
    ("reused_records", 1),
    ("attachments", True),
    ("finished_at", "2099-01-01T00:00:00Z"),
    ("acquisition_seconds", float("nan")),
])
def test_rejects_measurements_that_do_not_support_claims(field, value):
    data = snapshot()
    data["benchmarks"][0][field] = value
    with pytest.raises(ValueError):
        site_validation.validate(data)


def test_snapshot_preserves_unmeasured_host_and_failed_tests():
    data = site_validation.validate(snapshot())
    assert {s["id"] for s in data["servers"]} == {"A", "B", "C"}
    assert {r["server"] for r in data["benchmarks"]} == {"A", "B"}
    assert data["tests"] == {"passed": 1585, "failed": 3, "skipped": 37}
    assert sum(s["journals"] for s in data["servers"]) == 56


@pytest.mark.parametrize("lang", site_validation.LANGUAGES)
def test_render_keeps_data_accessible_without_javascript(lang):
    words = json.loads((ROOT / "website/validation/texts.json").read_text(encoding="utf-8"))[lang]
    def read_public(path):
        return (ROOT / path).read_bytes()
    result = site_validation.content(read_public, build_site.render, {"ROOT": "../../", "REPO_URL": "https://github.com/phishdestroy/TgWitness", "BRANCH": "main"}, lang)
    assert "@@" not in result
    for value in ("142.983", "160.531", "127.713", "141.781", "2026-11-06", "1585"):
        assert value in result.replace("\u202f", "")
    assert words["unmeasured"] in result
    assert 'data-rate="C"' not in result
    assert 'class="v-test v-failed"><strong>3</strong>' in result
    assert 'class="v-test v-skipped"><strong>37</strong>' in result
    assert 'href="../../validation/snapshot.json"' in result
    assert "aria-live=\"polite\"" in result
    assert result.count('class="v-run-card"') == 2
    assert '56\u202f329' in result.split('</header>', 1)[0]
    assert 'href="../../demo/?lang=en"' in result
    assert '<details class="v-technical">' in result


def test_snapshot_values_cannot_inject_html():
    data = copy.deepcopy(snapshot())
    data["release_id"] = '<img src=x onerror="alert(1)">'
    def read_public(path):
        return json.dumps(data).encode() if path.endswith("snapshot.json") else (ROOT / path).read_bytes()
    result = site_validation.content(read_public, build_site.render, {"ROOT": "../../", "REPO_URL": "https://github.com/phishdestroy/TgWitness", "BRANCH": "main"}, "en")
    assert '<img src=x' not in result
    assert '&lt;img src=x' in result


def test_localized_routes_have_matching_metadata_and_downloads():
    assert set(site_validation.LANGUAGES) == {"en", "ru"}
    assert set(build_site.page_languages(site_validation.PATH)) == {"en", "ru"}
    for lang in site_validation.LANGUAGES:
        assert (lang, site_validation.PATH) in build_site.PAGE_LOCALES
        prefix = "" if lang == "en" else lang + "/"
        assert prefix + site_validation.PATH + "index.html" in build_site.MARKDOWN_PAGES
    assert "validation/snapshot.json" in build_site.STATIC


def test_published_audit_keeps_its_signature_and_original_bytes():
    root = ROOT / "website/validation/audit"
    proof = json.loads((root / "PROOF.json").read_bytes())
    public = base64.b64decode(proof["public_key"], validate=True)
    assert hashlib.sha256(public).hexdigest() == "e419743db20096763ea06e480c2e6c161341de2f1023cd339c77758fb69e212f"
    statement = proof["statement"]
    encoded = json.dumps(statement, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(proof["signature"], validate=True), encoded)
    assert statement["complete"] and statement["source_revision"] == snapshot()["source_revision"]
    assert set(statement["included_files_sha256"]) == {"REPORT.md", "MEASUREMENTS.csv", "VERIFY.py"}
    distributed = {path.relative_to(ROOT).as_posix() for path in build_source.public_sources(ROOT)}
    for name, digest in statement["included_files_sha256"].items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
    for name in ("REPORT.md", "MEASUREMENTS.csv", "PROOF.json", "VERIFY.py", "SHA256SUMS.txt"):
        assert build_site.STATIC["validation/audit/" + name] == "website/validation/audit/" + name
        assert "website/validation/audit/" + name in distributed
    assert "website/validation/performance.svg" in distributed
    assert "website/validation/snapshot.json" in distributed
    assert "website/validation/texts.json" in distributed


def test_chart_and_page_use_the_signed_measurements():
    with (ROOT / "website/validation/audit/MEASUREMENTS.csv").open(encoding="utf-8", newline="") as stream:
        rows = {row["server"]: row for row in csv.DictReader(stream)}
    chart = (ROOT / "website/validation/performance.svg").read_text(encoding="utf-8")
    assert set(rows) == {run["server"] for run in snapshot()["benchmarks"]}
    for run in snapshot()["benchmarks"]:
        row = rows[run["server"]]
        assert int(row["records"]) == run["records"]
        assert row["archive_sha256"] == run["archive_sha256"]
        for phase in ("acquisition", "end_to_end"):
            for unit in ("seconds", "records_per_second"):
                assert float(row[phase + "_" + unit]) == run[phase + "_" + unit]
            assert f'>{run[phase + "_records_per_second"]:.3f}</text>' in chart
        assert f'{run["records"]:,} messages' in chart
