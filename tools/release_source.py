"""Validate the immutable application source for a release or container recovery."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "phishdestroy/TgWitness"
IMAGE = "ghcr.io/phishdestroy/tgwitness"
MANIFEST_NAME = "RELEASE-MANIFEST.json"
MANIFEST_LIMIT = 128 * 1024


class SourceError(ValueError):
    pass


@dataclass(frozen=True)
class Request:
    event: str
    tag: str
    revision: str
    version: str
    output: str


def validate_request(environment, version):
    if environment.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise SourceError("Release source checks require repository " + REPOSITORY)
    event = environment.get("EVENT_NAME")
    if event not in ("release", "workflow_dispatch"):
        raise SourceError("Only release and workflow_dispatch events are supported")
    if not isinstance(version, str) or not version or version.strip() != version or "\n" in version or "\r" in version:
        raise SourceError("pyproject.toml must contain a nonempty single-line project version")
    tag = environment.get("RELEASE_TAG")
    if tag != "v" + version:
        raise SourceError("RELEASE_TAG must equal v plus the pyproject.toml version")
    expected_ref = "refs/tags/" + tag if event == "release" else "refs/heads/main"
    if environment.get("GITHUB_REF") != expected_ref:
        raise SourceError("This event requires GITHUB_REF=" + expected_ref)
    revision = environment.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise SourceError("GITHUB_SHA must be a full lowercase commit SHA")
    output = environment.get("GITHUB_OUTPUT")
    if not isinstance(output, str) or not output:
        raise SourceError("GITHUB_OUTPUT is required")
    return Request(event, tag, revision, version, output)


def validate_source(request, head, tag_commit, *, ancestor=False, changed_paths=()):
    if head != request.revision:
        raise SourceError("Checked-out HEAD differs from GITHUB_SHA")
    if not re.fullmatch(r"[0-9a-f]{40}", tag_commit):
        raise SourceError("The exact release tag must resolve to a commit")
    if request.event == "release":
        if head != tag_commit:
            raise SourceError("A release event must check out the exact release tag commit")
    else:
        if not ancestor:
            raise SourceError("The release tag commit must be an ancestor of the manual main checkout")
        disallowed = [name for name in changed_paths
                      if not name.startswith(("tools/", ".github/workflows/"))]
        if disallowed:
            raise SourceError("Manual container recovery changes application inputs: " + ", ".join(disallowed))
    return {"version": request.version, "image": IMAGE, "source_revision": tag_commit}


def validate_release(release, tag):
    if not isinstance(release, dict) or release.get("tag_name") != tag:
        raise SourceError("GitHub release metadata does not match the exact release tag")
    if release.get("draft") is not False:
        raise SourceError("The GitHub release must exist and must not be a draft")


def manifest_asset(release):
    assets = release.get("assets")
    if not isinstance(assets, list) or any(not isinstance(asset, dict) for asset in assets):
        raise SourceError("The published release must list its assets")
    matches = [asset for asset in assets if asset.get("name") == MANIFEST_NAME]
    if len(matches) != 1:
        raise SourceError("Manual recovery requires exactly one published " + MANIFEST_NAME)
    asset = matches[0]
    if asset.get("state") != "uploaded" or type(asset.get("id")) is not int or asset["id"] <= 0:
        raise SourceError("The published release manifest must be an uploaded asset with a valid ID")
    if type(asset.get("size")) is not int or not 0 < asset["size"] <= MANIFEST_LIMIT:
        raise SourceError("The published release manifest must be at most 128 KiB")
    if not isinstance(asset.get("digest"), str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", asset["digest"]):
        raise SourceError("The published release manifest needs a GitHub SHA-256 digest")
    return asset


def validate_manifest(asset, content, version, tag_commit):
    if len(content) > MANIFEST_LIMIT or len(content) != asset["size"]:
        raise SourceError("Published release manifest bytes differ from the GitHub asset size")
    if "sha256:" + hashlib.sha256(content).hexdigest() != asset["digest"]:
        raise SourceError("Published release manifest bytes differ from the GitHub asset SHA-256 digest")
    try:
        manifest = json.loads(content)
    except (ValueError, UnicodeError) as error:
        raise SourceError("Published release manifest is not valid JSON") from error
    if not isinstance(manifest, dict) or manifest.get("schema") != "tgwitness-release-v1":
        raise SourceError("Published release manifest has an unsupported schema")
    if manifest.get("version") != version or manifest.get("source_revision") != tag_commit:
        raise SourceError("Published release manifest does not match the version and exact tag commit")


def git(root, *arguments, allowed_codes=(0,)):
    try:
        result = subprocess.run(
            ["git", "-c", "safe.directory=" + root.resolve().as_posix(), *arguments], cwd=root,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SourceError("Cannot complete local Git check: " + arguments[0]) from error
    if result.returncode not in allowed_codes:
        raise SourceError("Local Git check failed: " + arguments[0] + " (exit " + str(result.returncode) + ")")
    return result


def fetch_release(tag):
    try:
        result = subprocess.run(
            ["gh", "api", "--hostname", "github.com", "--method", "GET",
             "repos/" + REPOSITORY + "/releases/tags/" + quote(tag, safe="")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SourceError("Cannot read the published GitHub release") from error
    if result.returncode:
        raise SourceError("GitHub release " + tag + " is unavailable (gh api exit " + str(result.returncode) + ")")
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeError) as error:
        raise SourceError("GitHub release API returned invalid JSON") from error


def fetch_manifest(asset):
    try:
        result = subprocess.run(
            ["gh", "api", "--hostname", "github.com", "--method", "GET", "--header", "Accept: application/octet-stream",
             "repos/" + REPOSITORY + "/releases/assets/" + str(asset["id"])],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SourceError("Cannot read the published release manifest asset") from error
    if result.returncode:
        raise SourceError("Published release manifest is unavailable (gh api exit " + str(result.returncode) + ")")
    return result.stdout


def resolve_source(environment, root, *, release_loader=None, asset_loader=None):
    try:
        config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        version = config["project"]["version"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SourceError("Cannot read the project version from pyproject.toml") from error
    request = validate_request(environment, version)
    head = git(root, "rev-parse", "--verify", "HEAD^{commit}").stdout.decode().strip()
    tag_commit = git(root, "rev-parse", "--verify", "refs/tags/" + request.tag + "^{commit}").stdout.decode().strip()
    ancestor = False
    paths = ()
    if request.event == "workflow_dispatch":
        ancestor = git(root, "merge-base", "--is-ancestor", tag_commit, head, allowed_codes=(0, 1)).returncode == 0
        differences = git(root, "diff", "--name-only", "--no-renames", "-z", tag_commit, head, "--").stdout
        paths = [name.decode("utf-8", errors="surrogateescape") for name in differences.split(b"\0") if name]
    outputs = validate_source(request, head, tag_commit, ancestor=ancestor, changed_paths=paths)
    release = (release_loader or fetch_release)(request.tag)
    validate_release(release, request.tag)
    if request.event == "workflow_dispatch":
        asset = manifest_asset(release)
        content = (asset_loader or fetch_manifest)(asset)
        validate_manifest(asset, content, request.version, tag_commit)
    return outputs


def main():
    try:
        outputs = resolve_source(os.environ, ROOT)
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8", newline="\n") as stream:
            for name, value in outputs.items():
                stream.write(name + "=" + value + "\n")
    except (SourceError, OSError) as error:
        print("Release source validation failed: " + str(error), file=sys.stderr)
        return 1
    print("Validated immutable application source " + outputs["source_revision"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
