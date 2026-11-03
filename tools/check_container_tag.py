"""Permit publication only when GHCR confirms the version manifest is absent."""
import http.client
import json
import os
import re
import sys
import urllib.error
import urllib.request


IMAGE = "ghcr.io/phishdestroy/tgwitness"
TOKEN_URL = "https://ghcr.io/token?service=ghcr.io&scope=repository:phishdestroy/tgwitness:pull"
MANIFEST_ROOT = "https://ghcr.io/v2/phishdestroy/tgwitness/manifests/"
MANIFEST_ACCEPT = ", ".join((
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))
MAX_JSON_BYTES = 64 * 1024
MAX_TOKEN_LENGTH = 16 * 1024
TIMEOUT_SECONDS = 20


class TagCheckError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise TagCheckError("Registry redirects are not allowed")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise TagCheckError("Registry JSON contains duplicate keys")
        result[key] = value
    return result


def invalid_constant(value):
    raise TagCheckError("Registry JSON contains a nonstandard constant")


def fetch_json(opener, url, headers, expected_status, label):
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        try:
            response = opener.open(request, timeout=TIMEOUT_SECONDS)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status = response.getcode()
            if status != expected_status:
                if label == "Manifest" and status == 200:
                    raise TagCheckError("Container version already exists; use a new version")
                raise TagCheckError(label + " request returned unexpected HTTP " + str(status))
            if response.geturl() != url:
                raise TagCheckError("Registry response URL changed")
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise TagCheckError(label + " response is not JSON")
            raw = response.read(MAX_JSON_BYTES + 1)
    except (urllib.error.URLError, OSError, http.client.HTTPException):
        raise TagCheckError(label + " request could not be completed") from None
    if len(raw) > MAX_JSON_BYTES:
        raise TagCheckError(label + " response exceeds the size limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise TagCheckError(label + " response contains invalid JSON") from None
    if not isinstance(value, dict):
        raise TagCheckError(label + " response must be a JSON object")
    return value


def require_absent(image, version, opener=None):
    if image != IMAGE:
        raise TagCheckError("Only the configured TgWitness container image is supported")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9][A-Za-z0-9_.-]{0,127}", version):
        raise TagCheckError("VERSION must be a Docker version tag starting with a digit")
    opener = opener or urllib.request.build_opener(NoRedirect())
    headers = {"Accept": "application/json", "User-Agent": "TgWitness-container-tag-check"}
    credentials = fetch_json(opener, TOKEN_URL, headers, 200, "Token")
    token = credentials.get("token", credentials.get("access_token"))
    if (not isinstance(token, str) or not 1 <= len(token) <= MAX_TOKEN_LENGTH or
            not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token)):
        raise TagCheckError("Registry returned an invalid anonymous pull token")
    if credentials.get("token", token) != token or credentials.get("access_token", token) != token:
        raise TagCheckError("Registry returned conflicting anonymous pull tokens")
    manifest_headers = {**headers, "Accept": MANIFEST_ACCEPT, "Authorization": "Bearer " + token}
    result = fetch_json(opener, MANIFEST_ROOT + version, manifest_headers, 404, "Manifest")
    errors = result.get("errors")
    if (not isinstance(errors, list) or not errors or
            any(not isinstance(error, dict) or error.get("code") != "MANIFEST_UNKNOWN" for error in errors)):
        raise TagCheckError("Registry did not confirm that the version manifest is absent")


def main():
    image, version = os.environ.get("IMAGE"), os.environ.get("VERSION")
    try:
        require_absent(image, version)
    except TagCheckError as error:
        print("Container publication refused: " + str(error), file=sys.stderr)
        return 1
    print("Registry confirmed the version manifest is absent: " + image + ":" + version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
