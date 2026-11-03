import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stderr

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_source as check


BASE = "a" * 40
HEAD = "b" * 40


def environment(event="release", revision=BASE):
    return {"EVENT_NAME": event, "RELEASE_TAG": "v0.8.1", "GITHUB_REPOSITORY": check.REPOSITORY,
            "GITHUB_SHA": revision, "GITHUB_OUTPUT": "synthetic-output",
            "GITHUB_REF": "refs/tags/v0.8.1" if event == "release" else "refs/heads/main"}


def published_manifest(revision=BASE, version="0.8.1", schema="tgwitness-release-v1"):
    content = json.dumps({"schema": schema, "version": version, "source_revision": revision}).encode()
    asset = {"name": check.MANIFEST_NAME, "id": 123, "state": "uploaded", "size": len(content),
             "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
             "browser_download_url": "https://untrusted.example.invalid/ignored"}
    return {"tag_name": "v0.8.1", "draft": False, "assets": [asset]}, content


class SourceValidationTests(unittest.TestCase):
    def test_release_and_manual_recovery_return_the_immutable_revision(self):
        request = check.validate_request(environment(), "0.8.1")
        self.assertEqual(check.validate_source(request, BASE, BASE),
                         {"version": "0.8.1", "image": check.IMAGE, "source_revision": BASE})
        request = check.validate_request(environment("workflow_dispatch", HEAD), "0.8.1")
        self.assertEqual(check.validate_source(request, HEAD, BASE, ancestor=True,
                                              changed_paths=["tools/check_install.py", ".github/workflows/release.yml"]),
                         {"version": "0.8.1", "image": check.IMAGE, "source_revision": BASE})
        check.validate_source(request, HEAD, BASE, ancestor=True, changed_paths=[])

    def test_unknown_repository_event_ref_tag_and_sha_are_rejected(self):
        cases = (("GITHUB_REPOSITORY", "fork/TgWitness"), ("EVENT_NAME", "push"),
                 ("EVENT_NAME", "pull_request"), ("GITHUB_REF", "refs/heads/main"),
                 ("RELEASE_TAG", "v0.8.0"), ("RELEASE_TAG", "refs/tags/v0.8.1"),
                 ("GITHUB_SHA", "a" * 12), ("GITHUB_SHA", "g" * 40), ("GITHUB_OUTPUT", ""))
        for key, value in cases:
            with self.subTest(key=key, value=value), self.assertRaises(check.SourceError):
                check.validate_request({**environment(), key: value}, "0.8.1")
        for ref in ("refs/tags/v0.8.1", "refs/heads/recovery", "main", ""):
            with self.subTest(ref=ref), self.assertRaises(check.SourceError):
                check.validate_request({**environment("workflow_dispatch"), "GITHUB_REF": ref}, "0.8.1")

    def test_head_tag_and_ancestry_mismatches_are_rejected(self):
        request = check.validate_request(environment(), "0.8.1")
        for head, tag in ((HEAD, BASE), (BASE, HEAD), (BASE, "missing")):
            with self.subTest(head=head, tag=tag), self.assertRaises(check.SourceError):
                check.validate_source(request, head, tag)
        manual = check.validate_request(environment("workflow_dispatch", HEAD), "0.8.1")
        with self.assertRaisesRegex(check.SourceError, "ancestor"):
            check.validate_source(manual, HEAD, BASE, ancestor=False)

    def test_all_non_harness_paths_are_rejected(self):
        request = check.validate_request(environment("workflow_dispatch", HEAD), "0.8.1")
        for name in ("tgwitness/app.py", "tgwitness_capture/app.py", "pyproject.toml", "README.md",
                     "docs/OPERATIONS.md", "deploy/Dockerfile", ".dockerignore", "tools-other/check.py",
                     ".github/workflows-other/release.yml", ".github/actions/check/action.yml", "tools"):
            with self.subTest(name=name), self.assertRaisesRegex(check.SourceError, "application inputs"):
                check.validate_source(request, HEAD, BASE, ancestor=True, changed_paths=[name])

    def test_missing_draft_mismatched_or_malformed_release_is_rejected(self):
        check.validate_release({"tag_name": "v0.8.1", "draft": False}, "v0.8.1")
        for release in (None, [], {}, {"tag_name": "v0.8.0", "draft": False},
                        {"tag_name": "v0.8.1"}, {"tag_name": "v0.8.1", "draft": True},
                        {"tag_name": "v0.8.1", "draft": 0}):
            with self.subTest(release=release), self.assertRaises(check.SourceError):
                check.validate_release(release, "v0.8.1")

    def test_api_lookup_is_read_only_and_unavailable_or_invalid_response_fails_closed(self):
        release = {"tag_name": "v0.8.1", "draft": False}
        completed = subprocess.CompletedProcess([], 0, json.dumps(release).encode(), b"")
        with patch.object(check.subprocess, "run", return_value=completed) as run:
            self.assertEqual(check.fetch_release("v0.8.1"), release)
        self.assertEqual(run.call_args.args[0], ["gh", "api", "--hostname", "github.com", "--method", "GET",
                                                "repos/phishdestroy/TgWitness/releases/tags/v0.8.1"])
        for code, content in ((1, b""), (0, b"not JSON")):
            with self.subTest(code=code), patch.object(check.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], code, content, b"private diagnostic")):
                with self.assertRaises(check.SourceError) as error:
                    check.fetch_release("v0.8.1")
                self.assertNotIn("private diagnostic", str(error.exception))


    def test_manifest_requires_one_uploaded_bounded_asset_and_a_digest(self):
        release, content = published_manifest()
        asset = check.manifest_asset(release)
        check.validate_manifest(asset, content, "0.8.1", BASE)
        for assets in ([], [asset, asset], [None]):
            with self.subTest(assets=assets), self.assertRaises(check.SourceError):
                check.manifest_asset({**release, "assets": assets})
        for key, value in (("state", "new"), ("id", "123"), ("id", True), ("id", -1),
                           ("size", 0), ("size", check.MANIFEST_LIMIT + 1), ("size", "100"),
                           ("digest", None), ("digest", "sha256:missing")):
            changed = copy.deepcopy(release)
            changed["assets"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(check.SourceError):
                check.manifest_asset(changed)

    def test_manifest_revision_version_schema_and_bytes_are_bound(self):
        for revision, version, schema in ((HEAD, "0.8.1", "tgwitness-release-v1"),
                                          (BASE, "0.8.0", "tgwitness-release-v1"),
                                          (BASE, "0.8.1", "unknown")):
            release, content = published_manifest(revision, version, schema)
            with self.subTest(revision=revision, version=version, schema=schema), self.assertRaises(check.SourceError):
                check.validate_manifest(check.manifest_asset(release), content, "0.8.1", BASE)
        release, content = published_manifest()
        asset = check.manifest_asset(release)
        for changed in (content + b" ", content.replace(b"0.8.1", b"0.8.0")):
            with self.subTest(changed_size=len(changed)), self.assertRaises(check.SourceError):
                check.validate_manifest(asset, changed, "0.8.1", BASE)

    def test_manifest_download_uses_fixed_asset_api_instead_of_external_urls(self):
        release, content = published_manifest()
        completed = subprocess.CompletedProcess([], 0, content, b"")
        with patch.object(check.subprocess, "run", return_value=completed) as run:
            self.assertEqual(check.fetch_manifest(check.manifest_asset(release)), content)
        self.assertEqual(run.call_args.args[0], ["gh", "api", "--hostname", "github.com", "--method", "GET",
                                                "--header", "Accept: application/octet-stream",
                                                "repos/phishdestroy/TgWitness/releases/assets/123"])


class GitSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="release-source-check-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.git("init", "--quiet")
        self.git("config", "user.name", "Synthetic Release Check")
        self.git("config", "user.email", "release-check@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.autocrlf", "false")
        self.write("pyproject.toml", '[project]\nversion = "0.8.1"\n')
        self.write("tgwitness/app.py", "synthetic_application = True\n")
        self.write("tgwitness_capture/app.py", "synthetic_capture = True\n")
        self.base = self.commit("Synthetic release")
        self.git("tag", "-a", "v0.8.1", "-m", "Synthetic immutable release")

    def git(self, *arguments):
        return check.git(self.root, *arguments).stdout.decode().strip()

    def write(self, name, content):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def commit(self, message):
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", message)
        return self.git("rev-parse", "HEAD")

    def resolve(self, event="release", revision=None, **changes):
        values = {**environment(event, revision or self.git("rev-parse", "HEAD")), **changes}
        release, content = published_manifest(self.base)
        with patch.object(check, "fetch_release", return_value=release) as loader, \
                patch.object(check, "fetch_manifest", return_value=content) as download:
            result = check.resolve_source(values, self.root)
        loader.assert_called_once_with("v0.8.1")
        if event == "workflow_dispatch":
            download.assert_called_once_with(release["assets"][0])
        else:
            download.assert_not_called()
        return result

    def test_real_annotated_release_tag_and_harness_only_descendant(self):
        self.assertEqual(self.resolve()["source_revision"], self.base)
        self.write("tools/check_install.py", "synthetic_harness = True\n")
        self.write(".github/workflows/release.yml", "name: Synthetic\n")
        revision = self.commit("Synthetic harness recovery")
        self.assertNotEqual(revision, self.base)
        self.assertEqual(self.resolve("workflow_dispatch")["source_revision"], self.base)

    def test_product_rename_into_tools_is_not_hidden_by_rename_detection(self):
        (self.root / "tools").mkdir()
        self.git("mv", "tgwitness/app.py", "tools/moved.py")
        self.commit("Synthetic prohibited product rename")
        with self.assertRaisesRegex(check.SourceError, "tgwitness/app.py"), patch.object(check, "fetch_release") as loader:
            check.resolve_source(environment("workflow_dispatch", self.git("rev-parse", "HEAD")), self.root)
        loader.assert_not_called()

    def test_exact_tag_is_required_even_if_same_named_branch_exists(self):
        self.git("tag", "--delete", "v0.8.1")
        self.git("branch", "v0.8.1")
        with self.assertRaisesRegex(check.SourceError, "rev-parse"), patch.object(check, "fetch_release") as loader:
            check.resolve_source(environment("release", self.base), self.root)
        loader.assert_not_called()

    def test_real_unrelated_tag_commit_is_rejected(self):
        self.git("checkout", "--quiet", "--orphan", "unrelated")
        self.git("rm", "--quiet", "--cached", "-r", ".")
        self.commit("Synthetic unrelated history")
        with self.assertRaisesRegex(check.SourceError, "ancestor"):
            self.resolve("workflow_dispatch")

    def test_manual_recovery_rejects_a_moved_tag_against_published_manifest(self):
        self.write("tgwitness/app.py", "synthetic_application = False\n")
        revision = self.commit("Synthetic product change hidden by a moved tag")
        self.git("tag", "--force", "v0.8.1", revision)
        release, content = published_manifest(self.base)
        with patch.object(check, "fetch_release", return_value=release), \
                patch.object(check, "fetch_manifest", return_value=content), \
                self.assertRaisesRegex(check.SourceError, "exact tag commit"):
            check.resolve_source(environment("workflow_dispatch", revision), self.root)

    def test_cli_writes_outputs_only_after_all_checks_pass(self):
        output = self.root / "github-output"
        values = {**environment("release", self.base), "GITHUB_OUTPUT": str(output)}
        with patch.object(check, "ROOT", self.root), patch.dict(os.environ, values), \
                patch.object(check, "fetch_release", return_value={"tag_name": "v0.8.1", "draft": True}), \
                redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(check.main(), 1)
        self.assertIn("must not be a draft", errors.getvalue())
        self.assertFalse(output.exists())
        with patch.object(check, "ROOT", self.root), patch.dict(os.environ, values), \
                patch.object(check, "fetch_release", return_value={"tag_name": "v0.8.1", "draft": False}):
            self.assertEqual(check.main(), 0)
        self.assertEqual(output.read_text().splitlines(),
                         ["version=0.8.1", "image=" + check.IMAGE, "source_revision=" + self.base])


if __name__ == "__main__":
    unittest.main()
