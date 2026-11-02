import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
from contextlib import redirect_stdout

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import check_ocr_advisories as check


def advisory(version_range, identity="GHSA-jrf4-mx9r-v94h", patched="5.5.4"):
    return {"ghsa_id": identity, "state": "published", "withdrawn_at": None,
            "vulnerabilities": [{"package": {"name": "tesseract", "ecosystem": "other"},
                                 "vulnerable_version_range": version_range, "patched_versions": patched}]}


class Response(io.BytesIO):
    def __init__(self, values, link=""):
        super().__init__(json.dumps(values).encode())
        self.headers = {"Link": link}


class Opener:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        return next(self.responses)


class AdvisoryChecks(unittest.TestCase):
    def test_published_upstream_range_formats_and_fixed_versions(self):
        cases = (
            (">= 4.0.0, <= 5.5.3", "3.9.9", False),
            (">= 4.0.0, <= 5.5.3", "4.0.0", True),
            (">= 4.0.0, <= 5.5.3", "5.5.3", True),
            (">= 4.0.0, <= 5.5.3", "5.5.4", False),
            (">= 5.4.0, <= 5.5.3", "5.3.4", False),
            (">= 5.4.0, <= 5.5.3", "5.4.0", True),
            ("<= 5.5.1", "5.5.1", True), ("<= 5.5.1", "5.5.2", False),
            ("<= 5.5.3", "5.5.3", True), ("<= 5.5.3", "5.5.4", False),
            ("< 5.5.3", "5.5.2", True), ("< 5.5.3", "5.5.3", False),
            ("< 5.5.4", "5.5.3", True), ("< 5.5.4", "5.5.4", False),
        )
        for version_range, version, expected in cases:
            with self.subTest(version_range=version_range, version=version):
                self.assertIs(check.affected(version, version_range), expected)

    def test_numeric_order_and_other_supported_boundaries(self):
        for version_range, version, expected in (
            ("< 5.9.0", "5.10.0", False), ("> 5.5.4", "5.5.4", False),
            ("> 5.5.4", "5.5.5", True), ("5.5.4", "5.5.4", True),
            ("= 5.5.4", "5.5.5", False), (">= 5.5.4, <= 5.5.4", "5.5.4", True),
        ):
            with self.subTest(version_range=version_range):
                self.assertIs(check.affected(version, version_range), expected)

    def test_unsupported_or_ambiguous_ranges_fail_closed(self):
        for version_range in (None, "", "*", "< 5.5", "~5.5.4", "^5.5.4", "5.5.x",
                              "< 5.5.4 || > 6.0.0", "5.0.0 - 5.5.3", "< 5.5.4-rc1",
                              "< v5.5.4", "< 05.5.4", "< 5.5.3, unknown", "!= 5.5.4",
                              ">= 6.0.0, < 5.0.0", "> 5.5.4, <= 5.5.4", "< 5.5.4,",
                              "< 5.5.4, = 5.5.4"):
            with self.subTest(version_range=version_range), self.assertRaises(check.AdvisoryError):
                check.affected("5.5.4", version_range)
        with self.assertRaises(check.AdvisoryError):
            check.affected("5.5.4-rc1", "< 5.5.4")

    def test_all_ranges_are_checked_and_patched_metadata_cannot_override(self):
        item = advisory("< 5.5.4")
        item["vulnerabilities"].append(advisory("<= 5.5.4", patched="5.5.4")["vulnerabilities"][0])
        result = check.evaluate("5.5.4", [item])
        self.assertEqual(result["status"], "affected")
        self.assertEqual([row["affected"] for row in result["advisories"][0]["ranges"]], [False, True])
        item["vulnerabilities"].append(advisory("unparseable")["vulnerabilities"][0])
        result = check.evaluate("5.5.4", [item])
        self.assertEqual(result["status"], "error")
        self.assertTrue(result["errors"])

    def test_no_fix_and_blank_ecosystem_are_still_evaluated(self):
        item = advisory(">= 5.0.0", patched=None)
        item["vulnerabilities"][0]["package"]["ecosystem"] = ""
        self.assertEqual(check.evaluate("5.5.4", [item])["status"], "affected")
        item["withdrawn_at"] = "2026-11-02T00:00:00Z"
        self.assertEqual(check.evaluate("5.5.4", [item])["advisories"][0]["status"], "withdrawn")
        for value in (False, "unknown", "2026-11-02T00:00:00"):
            item["withdrawn_at"] = value
            with self.subTest(value=value), self.assertRaises(check.AdvisoryError):
                check.evaluate("5.5.4", [item])

    def test_incomplete_or_changed_feed_does_not_pass(self):
        for value in ([], None):
            item = advisory("< 5.5.4")
            item["vulnerabilities"] = value
            self.assertEqual(check.evaluate("5.5.4", [item])["status"], "error")
        item = advisory("< 5.5.4")
        item["vulnerabilities"][0]["package"]["name"] = "renamed-package"
        self.assertEqual(check.evaluate("5.5.4", [item])["status"], "error")
        for items in ([], [None], [advisory("< 5.5.4")] * 2):
            with self.subTest(items=items), self.assertRaises(check.AdvisoryError):
                check.evaluate("5.5.4", items)

    def test_pagination_finds_affected_second_page(self):
        second = check.FIRST_PAGE + "&after=cursor"
        opener = Opener([Response([advisory("< 5.5.4")], '<' + second + '>; rel="next"'),
                         Response([advisory(">= 5.5.4", "GHSA-h9g4-frjx-6cj3")])])
        items, pages = check.fetch_advisories(opener=opener)
        self.assertEqual([request.full_url for request in opener.requests], [check.FIRST_PAGE, second])
        self.assertEqual(len(pages), 2)
        self.assertTrue(all(len(page["sha256"]) == 64 for page in pages))
        self.assertEqual(check.evaluate("5.5.4", items)["status"], "affected")

    def test_pagination_never_sends_token_to_another_destination(self):
        for destination in ("https://example.invalid/advisories", "http://api.github.com/test",
                            "https://api.github.com@other.invalid/test", check.API + "/other"):
            opener = Opener([Response([advisory("< 5.5.4")], '<' + destination + '>; rel="next"')])
            with self.subTest(destination=destination), self.assertRaises(check.AdvisoryError):
                check.fetch_advisories("synthetic-value", opener)
            self.assertEqual(len(opener.requests), 1)
        self.assertIsNone(check.NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.invalid"))

    def test_empty_malformed_repeated_or_oversized_feed_fails(self):
        for response in (Response([]), Response({"message": "error"}),
                         Response([advisory("< 5.5.4")], '<' + check.FIRST_PAGE + '>; rel="next"'),
                         Response([advisory("< 5.5.4")], "unsupported-link")):
            with self.subTest(response=response), self.assertRaises(check.AdvisoryError):
                check.fetch_advisories(opener=Opener([response]))
        with patch.object(check, "MAX_PAGE_BYTES", 1), self.assertRaises(check.AdvisoryError):
            check.fetch_advisories(opener=Opener([Response([advisory("< 5.5.4")])]))

    def test_cli_report_exit_status_and_network_error_redaction(self):
        with tempfile.TemporaryDirectory(prefix="tgwitness-ocr-advisories-") as temporary:
            root = Path(temporary)
            lock = root / "source-lock.json"
            lock.write_text(json.dumps({"tesseract": {"version": "5.5.4", "commit": "a" * 40,
                            "sha256": "b" * 64, "url": "https://github.com/tesseract-ocr/tesseract/archive/refs/tags/5.5.4.tar.gz"}}))
            output = root / "report.json"
            with patch.object(check, "LOCK", lock), redirect_stdout(io.StringIO()):
                for version_range, status, code in (("< 5.5.4", "pass", 0), ("<= 5.5.4", "affected", 1),
                                                     ("unknown", "error", 2)):
                    with patch.object(check, "fetch_advisories", return_value=([advisory(version_range)], [])):
                        self.assertEqual(check.check(output), code)
                        self.assertEqual(json.loads(output.read_text())["status"], status)
                secret = "synthetic-value-not-for-output"
                with patch.object(check.urllib.request.OpenerDirector, "open", side_effect=urllib.error.HTTPError(
                        check.API, 403, secret, None, None)):
                    self.assertEqual(check.check(output, secret), 2)
                    self.assertNotIn(secret, output.read_text())
                    self.assertIn("HTTP 403", output.read_text())


if __name__ == "__main__":
    unittest.main()
