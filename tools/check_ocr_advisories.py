import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "deploy/media-worker/sources.lock.json"
API = "https://api.github.com/repos/tesseract-ocr/tesseract/security-advisories"
FIRST_PAGE = API + "?state=published&per_page=100"
VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
MAX_PAGE_BYTES = 4 * 1024 * 1024
MAX_PAGES = 100


class AdvisoryError(ValueError):
    pass


def release_version(value):
    if not isinstance(value, str) or not re.fullmatch(VERSION, value):
        raise AdvisoryError("Unsupported release version; expected three numeric components")
    return tuple(int(part) for part in value.split("."))


def affected(version, version_range):
    current = release_version(version)
    if not isinstance(version_range, str) or not version_range.strip():
        raise AdvisoryError("Missing vulnerable version range")
    outcomes = []
    lower, upper = None, None
    for term in version_range.split(","):
        match = re.fullmatch(r"\s*(<=|>=|<|>|=)?\s*(" + VERSION + r")\s*", term)
        if not match:
            raise AdvisoryError("Unsupported range syntax; expected comma-separated numeric comparisons")
        operator, target = match[1] or "=", release_version(match[2])
        outcomes.append({"<": current < target, "<=": current <= target, ">": current > target,
                         ">=": current >= target, "=": current == target}[operator])
        if operator in (">", ">=", "="):
            bound = (target, operator != ">")
            if lower is None or (bound[0], not bound[1]) > (lower[0], not lower[1]):
                lower = bound
        if operator in ("<", "<=", "="):
            bound = (target, operator != "<")
            if upper is None or bound < upper:
                upper = bound
    if lower and upper and (lower[0] > upper[0] or
                            lower[0] == upper[0] and not (lower[1] and upper[1])):
        raise AdvisoryError("Contradictory vulnerable version range")
    return all(outcomes)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def page_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.netloc != "api.github.com" or
            parsed.path != urllib.parse.urlsplit(API).path or parsed.fragment):
        raise AdvisoryError("Unexpected advisory pagination URL")
    return url


def next_page(header):
    found = []
    if header:
        for link in header.split(","):
            match = re.fullmatch(r'\s*<([^<>]+)>;\s*rel="([a-z ]+)"\s*', link)
            if not match:
                raise AdvisoryError("Unsupported advisory pagination header")
            if "next" in match[2].split():
                found.append(page_url(match[1]))
    if len(found) > 1:
        raise AdvisoryError("Ambiguous advisory pagination")
    return found[0] if found else None


def fetch_advisories(token=None, opener=None):
    opener = opener or urllib.request.build_opener(NoRedirect())
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": "TgWitness-OCR-advisory-check"}
    if token:
        headers["Authorization"] = "Bearer " + token
    url, seen, advisories, pages = FIRST_PAGE, set(), [], []
    while url:
        page_url(url)
        if url in seen or len(seen) >= MAX_PAGES:
            raise AdvisoryError("Advisory pagination repeated or exceeded the page limit")
        seen.add(url)
        request = urllib.request.Request(url, headers=headers)
        try:
            with opener.open(request, timeout=45) as response:
                raw = response.read(MAX_PAGE_BYTES + 1)
                following = next_page(response.headers.get("Link", ""))
        except urllib.error.HTTPError as error:
            raise AdvisoryError("GitHub advisory API HTTP " + str(error.code)) from None
        except (urllib.error.URLError, OSError, TimeoutError):
            raise AdvisoryError("GitHub advisory API could not be reached") from None
        if len(raw) > MAX_PAGE_BYTES:
            raise AdvisoryError("Advisory API page exceeds the size limit")
        try:
            values = json.loads(raw)
        except (ValueError, UnicodeError):
            raise AdvisoryError("Advisory API returned invalid JSON") from None
        if not isinstance(values, list):
            raise AdvisoryError("Advisory API response is not a list")
        advisories.extend(values)
        pages.append({"url": url, "sha256": hashlib.sha256(raw).hexdigest(), "count": len(values)})
        url = following
    if not advisories:
        raise AdvisoryError("Upstream advisory history is unexpectedly empty")
    return advisories, pages


def evaluate(version, advisories):
    release_version(version)
    results, errors, seen = [], [], set()
    for item in advisories:
        if not isinstance(item, dict) or not re.fullmatch(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}",
                                                        str(item.get("ghsa_id", ""))):
            raise AdvisoryError("Invalid upstream advisory identity")
        identity = item["ghsa_id"]
        if identity in seen or item.get("state") != "published":
            raise AdvisoryError("Duplicate or non-published upstream advisory")
        seen.add(identity)
        entry = {"ghsa_id": identity, "cve_id": item.get("cve_id"),
                 "url": "https://github.com/tesseract-ocr/tesseract/security/advisories/" + identity,
                 "withdrawn_at": item.get("withdrawn_at"), "ranges": []}
        results.append(entry)
        if entry["withdrawn_at"] is not None:
            try:
                withdrawn = datetime.fromisoformat(entry["withdrawn_at"].replace("Z", "+00:00"))
            except (AttributeError, ValueError):
                raise AdvisoryError("Invalid advisory withdrawal timestamp") from None
            if withdrawn.tzinfo is None:
                raise AdvisoryError("Invalid advisory withdrawal timestamp")
            entry["status"] = "withdrawn"
            continue
        vulnerabilities = item.get("vulnerabilities")
        if not isinstance(vulnerabilities, list) or not vulnerabilities:
            errors.append(identity + ": Missing vulnerability ranges")
            entry["status"] = "error"
            continue
        for vulnerability in vulnerabilities:
            try:
                if not isinstance(vulnerability, dict):
                    raise AdvisoryError("Invalid vulnerability entry")
                package = vulnerability.get("package")
                if (not isinstance(package, dict) or package.get("name") != "tesseract" or
                        package.get("ecosystem") not in ("", "other")):
                    raise AdvisoryError("Unexpected upstream package identity")
                version_range = vulnerability.get("vulnerable_version_range")
                row = {"vulnerable_version_range": version_range,
                       "patched_versions": vulnerability.get("patched_versions"), "affected": None}
                entry["ranges"].append(row)
                row["affected"] = affected(version, version_range)
            except AdvisoryError as error:
                errors.append(identity + ": " + str(error))
                entry["status"] = "error"
        if entry.get("status") != "error":
            entry["status"] = "affected" if any(row["affected"] for row in entry["ranges"]) else "unaffected"
    if not results:
        raise AdvisoryError("Upstream advisory history is unexpectedly empty")
    status = "error" if errors else "affected" if any(row["status"] == "affected" for row in results) else "pass"
    return {"status": status, "advisory_count": len(results), "advisories": results, "errors": errors}


def check(output, token=None):
    report = {"schema": 1, "source": API, "checked_at": datetime.now(timezone.utc).isoformat(),
              "scope": "Published upstream Tesseract advisories; supplements the container vulnerability scan",
              "status": "error", "errors": []}
    try:
        source = json.loads(LOCK.read_text(encoding="utf-8"))["tesseract"]
        version = source["version"]
        release_version(version)
        if source["url"] != "https://github.com/tesseract-ocr/tesseract/archive/refs/tags/" + version + ".tar.gz":
            raise AdvisoryError("Pinned OCR source is not the expected upstream release")
        report["pinned_source"] = {key: source[key] for key in ("version", "commit", "sha256", "url")}
        advisories, pages = fetch_advisories(token)
        report["pages"] = pages
        report.update(evaluate(version, advisories))
    except AdvisoryError as error:
        report["errors"].append(str(error))
    except (OSError, ValueError, KeyError, TypeError):
        report["errors"].append("Invalid or unreadable pinned OCR source lock")
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("Tesseract upstream advisory check: " + report["status"] + "; report: " + str(output))
    return {"pass": 0, "affected": 1, "error": 2}[report["status"]]


def main():
    parser = argparse.ArgumentParser(description="Check pinned source-built Tesseract against published upstream advisories.")
    parser.add_argument("--output", type=Path, required=True, help="Write the JSON audit report to this artifact path.")
    args = parser.parse_args()
    return check(args.output, os.environ.get("GH_TOKEN"))


if __name__ == "__main__":
    raise SystemExit(main())
