import http.client
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import urllib.response


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import check_container_tag as check


TOKEN = "synthetic.pull-token=="
MISSING = {"errors": [{"code": "MANIFEST_UNKNOWN", "message": "manifest unknown"}]}
VERSION = "0.8.1"
MANIFEST = check.MANIFEST_ROOT + VERSION


def response(status, value, url=MANIFEST, content_type="application/json"):
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    result = urllib.response.addinfourl(io.BytesIO(raw), {"Content-Type": content_type}, url, status)
    result.msg = "Synthetic response"
    return result


def token_response(value=None):
    return response(200, {"token": TOKEN} if value is None else value, check.TOKEN_URL)


class Opener:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        item = next(self.responses)
        if isinstance(item, Exception):
            raise item
        return item


class ContainerTagChecks(unittest.TestCase):
    def test_authenticated_manifest_unknown_allows_publication(self):
        opener = Opener([token_response(), response(404, MISSING)])
        self.assertIsNone(check.require_absent(check.IMAGE, VERSION, opener))
        first, second = [item[0] for item in opener.requests]
        self.assertEqual(first.full_url, check.TOKEN_URL)
        self.assertIsNone(first.get_header("Authorization"))
        self.assertEqual(second.full_url, MANIFEST)
        self.assertEqual(second.get_header("Authorization"), "Bearer " + TOKEN)
        self.assertEqual(second.get_header("Accept"), check.MANIFEST_ACCEPT)
        self.assertTrue(all(request.get_method() == "GET" and timeout == check.TIMEOUT_SECONDS
                            for request, timeout in opener.requests))

    def test_http_error_404_is_validated_like_a_response(self):
        missing = urllib.error.HTTPError(MANIFEST, 404, "Not Found", {"Content-Type": "application/json"},
                                         io.BytesIO(json.dumps(MISSING).encode()))
        check.require_absent(check.IMAGE, VERSION, Opener([token_response(), missing]))
        repeated = {"errors": [{"code": "MANIFEST_UNKNOWN"}, {"code": "MANIFEST_UNKNOWN"}]}
        check.require_absent(check.IMAGE, VERSION, Opener([token_response(), response(404, repeated)]))

    def test_other_http_statuses_never_allow_publication(self):
        for status in (200, 201, 204, 301, 302, 303, 307, 308, 400, 401, 403, 405, 429, 500, 502, 503):
            for raised in (False, True):
                with self.subTest(status=status, raised=raised), self.assertRaises(check.TagCheckError):
                    value = response(status, MISSING)
                    if raised:
                        value = urllib.error.HTTPError(MANIFEST, status, "Rejected", value.headers, value)
                    check.require_absent(check.IMAGE, VERSION, Opener([token_response(), value]))

    def test_missing_mixed_or_invalid_registry_errors_refuse(self):
        for value in ({}, {"errors": []}, {"errors": None}, {"errors": "MANIFEST_UNKNOWN"},
                      {"errors": [None]}, {"errors": ["MANIFEST_UNKNOWN"]}, {"errors": [{}]},
                      {"errors": [{"code": "NAME_UNKNOWN"}]}, {"errors": [{"code": "UNAUTHORIZED"}]},
                      {"errors": [{"code": "MANIFEST_UNKNOWN"}, {"code": "DENIED"}]},
                      {"errors": [{"code": "manifest_unknown"}]}, [], None):
            with self.subTest(value=value), self.assertRaises(check.TagCheckError):
                check.require_absent(check.IMAGE, VERSION, Opener([token_response(), response(404, value)]))

    def test_invalid_json_and_ambiguous_objects_refuse(self):
        for raw in (b"", b"not json", b"\xff", b'{"errors":',
                    b'{"errors":[],"errors":[{"code":"MANIFEST_UNKNOWN"}]}',
                    b'{"errors":[{"code":"DENIED","code":"MANIFEST_UNKNOWN"}]}',
                    b'{"errors":[{"code":"MANIFEST_UNKNOWN"}],"extra":NaN}',
                    b'[' * 2000 + b']' * 2000):
            with self.subTest(raw=raw[:80]), self.assertRaises(check.TagCheckError):
                check.require_absent(check.IMAGE, VERSION, Opener([token_response(), response(404, raw)]))

    def test_content_type_size_and_response_url_are_checked(self):
        cases = [response(404, MISSING, content_type="text/html"),
                 response(404, MISSING, url="https://other.invalid/manifest"),
                 response(404, b" " * (check.MAX_JSON_BYTES + 1)),
                 response(404, MISSING, content_type="")]
        for item in cases:
            with self.subTest(response=item), self.assertRaises(check.TagCheckError):
                check.require_absent(check.IMAGE, VERSION, Opener([token_response(), item]))

    def test_token_failures_refuse_before_requesting_manifest(self):
        cases = [response(status, MISSING, check.TOKEN_URL) for status in (301, 401, 403, 404, 429, 500)]
        cases += [token_response(value) for value in ({}, {"token": ""}, {"token": 42},
                  {"token": "has space"}, {"token": "header\r\ninjection"},
                  {"token": "x" * (check.MAX_TOKEN_LENGTH + 1)},
                  {"token": TOKEN, "access_token": "different"})]
        cases += [response(200, b"invalid", check.TOKEN_URL),
                  response(200, b" " * (check.MAX_JSON_BYTES + 1), check.TOKEN_URL),
                  response(200, {"token": TOKEN}, check.TOKEN_URL, "text/html")]
        for item in cases:
            opener = Opener([item])
            with self.subTest(response=item), self.assertRaises(check.TagCheckError):
                check.require_absent(check.IMAGE, VERSION, opener)
            self.assertEqual(len(opener.requests), 1)

    def test_access_token_and_matching_token_fields_are_supported(self):
        for value in ({"access_token": TOKEN}, {"token": TOKEN, "access_token": TOKEN}):
            check.require_absent(check.IMAGE, VERSION,
                                 Opener([token_response(value), response(404, MISSING)]))

    def test_network_and_body_read_errors_refuse_without_disclosing_tokens(self):
        errors = (urllib.error.URLError(TOKEN), TimeoutError(TOKEN), OSError(TOKEN),
                  http.client.RemoteDisconnected(TOKEN), http.client.IncompleteRead(b"partial"))
        for error in errors:
            for phase in ("token", "manifest", "read"):
                with self.subTest(error=type(error).__name__, phase=phase):
                    if phase == "token":
                        opener = Opener([error])
                    elif phase == "manifest":
                        opener = Opener([token_response(), error])
                    else:
                        item = response(404, MISSING)
                        item.read = lambda size, error=error: (_ for _ in ()).throw(error)
                        opener = Opener([token_response(), item])
                    with self.assertRaises(check.TagCheckError) as captured:
                        check.require_absent(check.IMAGE, VERSION, opener)
                    self.assertNotIn(TOKEN, str(captured.exception))

    def test_real_urllib_redirect_dispatch_never_forwards_authorization(self):
        class SyntheticHTTPS(urllib.request.HTTPSHandler):
            def __init__(self, manifest_redirect):
                super().__init__()
                self.requests = []
                self.manifest_redirect = manifest_redirect

            def https_open(self, request):
                self.requests.append(request)
                if self.manifest_redirect and request.full_url == check.TOKEN_URL:
                    return token_response()
                result = response(302, {}, request.full_url)
                result.headers["Location"] = "https://other.invalid/leak"
                return result

        for manifest_redirect in (False, True):
            handler = SyntheticHTTPS(manifest_redirect)
            opener = urllib.request.build_opener(check.NoRedirect(), handler)
            with self.subTest(manifest_redirect=manifest_redirect), self.assertRaises(check.TagCheckError):
                check.require_absent(check.IMAGE, VERSION, opener)
            self.assertEqual(len(handler.requests), 2 if manifest_redirect else 1)
            self.assertTrue(all(request.host == "ghcr.io" for request in handler.requests))

    def test_untrusted_image_and_unsafe_version_are_rejected_before_network(self):
        for image in (None, "", "ghcr.io/other/image", check.IMAGE + ":latest", "https://" + check.IMAGE):
            opener = Opener([])
            with self.subTest(image=image), self.assertRaises(check.TagCheckError):
                check.require_absent(image, VERSION, opener)
            self.assertFalse(opener.requests)
        for version in (None, "", "latest", "v0.8.1", "../0.8.1", "0.8.1?x=1", "0.8.1/other",
                        "0.8.1\n", "0.8.1\r", "0.8.1 ", "0.8.1:other", "0.8.1+local", "0" * 129):
            opener = Opener([])
            with self.subTest(version=version), self.assertRaises(check.TagCheckError):
                check.require_absent(check.IMAGE, version, opener)
            self.assertFalse(opener.requests)

    def test_cli_reports_only_sanitized_decision(self):
        for last_response, expected in ((response(404, MISSING), 0), (response(403, {"secret": TOKEN}), 1)):
            opener = Opener([token_response(), last_response])
            output, errors = io.StringIO(), io.StringIO()
            with patch.dict("os.environ", {"IMAGE": check.IMAGE, "VERSION": VERSION}, clear=True), \
                    patch.object(check.urllib.request, "build_opener", return_value=opener), \
                    redirect_stdout(output), redirect_stderr(errors):
                self.assertEqual(check.main(), expected)
            self.assertNotIn(TOKEN, output.getvalue() + errors.getvalue())
            self.assertTrue(errors.getvalue() if expected else output.getvalue())


if __name__ == "__main__":
    unittest.main()
