import base64
import csv
from email.parser import BytesParser
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
import warnings
import zipfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_installer as builder
import installer_publication as publication


class WheelVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="installer-wheel-check-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.version = tomllib.loads((builder.ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
        result = subprocess.run(
            [sys.executable, "-m", "pip", "wheel", "--no-index", "--no-deps", "--no-build-isolation",
             "--disable-pip-version-check", "--wheel-dir", str(cls.directory), str(builder.ROOT)],
            capture_output=True, text=True, encoding="utf-8", timeout=120,
        )
        if result.returncode:
            raise AssertionError("Real application wheel build failed:\n" + result.stdout + result.stderr)
        wheels = list(cls.directory.glob("tgwitness-*-py3-none-any.whl"))
        if len(wheels) != 1:
            raise AssertionError("Expected one real application wheel")
        cls.wheel = wheels[0]
        with zipfile.ZipFile(cls.wheel) as archive:
            cls.files = {name: archive.read(name) for name in archive.namelist()}
        cls.dist_info = "tgwitness-" + cls.version + ".dist-info/"
        cls.record_name = cls.dist_info + "RECORD"

    def rewrite(self, files, *, record=None):
        if record is None:
            rows = io.StringIO(newline="")
            writer = csv.writer(rows)
            for name, data in files.items():
                if name != self.record_name:
                    checksum = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
                    writer.writerow((name, "sha256=" + checksum, str(len(data))))
            writer.writerow((self.record_name, "", ""))
            record = rows.getvalue().encode()
        target = self.directory / "mutated.whl"
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                if name != self.record_name:
                    archive.writestr(name, data)
            archive.writestr(self.record_name, record)
        return target

    def test_real_wheel_includes_both_application_packages(self):
        for name in ("tgwitness/__init__.py", "tgwitness_capture/__init__.py", "tgwitness_capture/static/app.js"):
            self.assertIn(name, self.files)
        builder.verify_wheel(self.wheel, self.version)

    def test_missing_capture_source_or_resource_with_valid_record_is_rejected(self):
        for name in ("tgwitness_capture/format.py", "tgwitness_capture/static/app.js"):
            with self.subTest(name=name):
                files = dict(self.files)
                del files[name]
                with self.assertRaisesRegex(ValueError, "Incomplete or damaged"):
                    builder.verify_wheel(self.rewrite(files), self.version)

    def test_changed_application_bytes_with_valid_record_are_rejected(self):
        for name in ("tgwitness/__init__.py", "tgwitness_capture/format.py", "tgwitness_capture/static/app.js"):
            with self.subTest(name=name):
                files = {**self.files, name: self.files[name] + b"\nsynthetic changed bytes\n"}
                with self.assertRaisesRegex(ValueError, "Wheel differs from checked source"):
                    builder.verify_wheel(self.rewrite(files), self.version)

    def test_unexpected_package_or_metadata_entry_with_valid_record_is_rejected(self):
        for name in ("tgwitness_capture/private.txt", self.dist_info + "unexpected.txt"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Unexpected wheel entry"):
                builder.verify_wheel(self.rewrite({**self.files, name: b"unexpected"}), self.version)

    def test_duplicate_package_entry_is_rejected(self):
        target = self.rewrite(self.files)
        name = "tgwitness_capture/__init__.py"
        with warnings.catch_warnings(), zipfile.ZipFile(target, "a") as archive:
            warnings.simplefilter("ignore", UserWarning)
            archive.writestr(name, self.files[name])
        with self.assertRaisesRegex(ValueError, "Incomplete or damaged"):
            builder.verify_wheel(target, self.version)

    def test_wrong_version_with_valid_record_is_rejected(self):
        name = self.dist_info + "METADATA"
        metadata = BytesParser().parsebytes(self.files[name])
        self.assertEqual(metadata["Version"], self.version)
        metadata.replace_header("Version", "0.0.0")
        with self.assertRaisesRegex(ValueError, "Wheel version differs"):
            builder.verify_wheel(self.rewrite({**self.files, name: metadata.as_bytes()}), self.version)

    def test_incomplete_or_changed_record_is_rejected(self):
        rows = list(csv.reader(io.StringIO(self.files[self.record_name].decode())))
        selected = next(index for index, row in enumerate(rows) if row[0] == "tgwitness_capture/format.py")
        for kind in ("missing", "checksum", "size"):
            changed = [list(row) for row in rows]
            if kind == "missing":
                del changed[selected]
            else:
                changed[selected][1 if kind == "checksum" else 2] = "invalid"
            record = io.StringIO(newline="")
            csv.writer(record).writerows(changed)
            expected = "RECORD does not cover" if kind == "missing" else "RECORD mismatch"
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, expected):
                builder.verify_wheel(self.rewrite(self.files, record=record.getvalue().encode()), self.version)


class PublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.public = cls.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                     serialization.PublicFormat.SubjectPublicKeyInfo)

    def setUp(self):
        self.release_id = "a" * 12 + "-" + "b" * 12
        self.files = {name: ("synthetic " + name).encode() for name in
                      ("install.sh", "install.ps1", "install.cmd", "constraints.txt", "tgwitness-0.0-py3-none-any.whl")}
        self.files.update({name + ".sig": self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
                           for name, data in list(self.files.items())})
        self.files["release-signing.pub"] = self.public
        self.manifest = {
            "schema": "tgwitness-installer-v1", "release_id": self.release_id,
            "test_only": False, "base_url": publication.ORIGIN,
            "signing_key_sha256": hashlib.sha256(self.public).hexdigest(),
            "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                             "url": f"{publication.ORIGIN}/releases/{self.release_id}/{name}"}
                      for name, data in self.files.items()},
        }

    def raw(self):
        return json.dumps(self.manifest).encode()

    def remote(self, path, limit=None):
        if path == "releases.json":
            return json.dumps({"schema": "tgwitness-installer-archive-v1", "releases": [self.release_id]}).encode()
        name = path.removeprefix("releases/" + self.release_id + "/")
        if name == "manifest.json":
            return self.raw()
        if name == "manifest.json.sig":
            return self.key.sign(self.raw(), padding.PKCS1v15(), hashes.SHA256())
        return self.files[name]

    def test_valid_release_retained_with_signed_manifest_and_sidecars(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(publication, "fetch", side_effect=self.remote):
            site = Path(temporary)
            publication.retain(site, self.public)
            release = site / "releases" / self.release_id
            for name, content in self.files.items():
                self.assertEqual((release / name).read_bytes(), content)
                self.assertEqual((release / (name + ".sha256")).read_text(),
                                 hashlib.sha256(content).hexdigest() + "  " + name + "\n")
            self.key.public_key().verify((release / "manifest.json.sig").read_bytes(),
                                         (release / "manifest.json").read_bytes(), padding.PKCS1v15(), hashes.SHA256())
            self.assertEqual(publication.release_ids((site / "releases.json").read_bytes()), [self.release_id])

    def test_rehashed_replacement_without_signing_key_is_rejected(self):
        self.files["install.sh"] = b"replaced installer"
        entry = self.manifest["files"]["install.sh"]
        entry.update(sha256=hashlib.sha256(self.files["install.sh"]).hexdigest(), bytes=len(self.files["install.sh"]))
        with self.assertRaises(InvalidSignature):
            publication.verify_release(self.raw(), self.release_id, self.files.__getitem__, self.public)

    def test_manifest_cannot_redirect_downloads_or_escape_release_directory(self):
        for name in ("../outside", "a/b", "C:\\outside"):
            with self.subTest(name=name):
                forged = dict(self.manifest, files={**self.manifest["files"], name: {}})
                with self.assertRaises(ValueError):
                    publication.validate_manifest(json.dumps(forged).encode(), self.release_id, self.public)
        self.manifest["files"]["install.sh"]["url"] = "https://example.invalid/install.sh"
        with self.assertRaises(ValueError):
            publication.validate_manifest(self.raw(), self.release_id, self.public)

    def test_invalid_or_duplicate_release_catalog_rejected(self):
        for values in ([], ["../outside"], [self.release_id, self.release_id], [None], [self.release_id] * 513):
            with self.subTest(values=str(values)[:80]), self.assertRaises(ValueError):
                publication.release_ids(json.dumps({"schema": "tgwitness-installer-archive-v1", "releases": values}).encode())

    def test_missing_catalog_fails_without_claiming_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            site = Path(temporary)
            with patch.object(publication, "fetch", side_effect=HTTPError("synthetic", 404, "missing", {}, None)):
                with self.assertRaises(HTTPError):
                    publication.retain(site, self.public)
            self.assertEqual(list(site.iterdir()), [])

    def test_immutable_collision_keeps_existing_bytes(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(publication, "fetch", side_effect=self.remote):
            site = Path(temporary)
            target = site / "releases" / self.release_id / "install.sh"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"existing local bytes")
            with self.assertRaisesRegex(ValueError, "collision"):
                publication.retain(site, self.public)
            self.assertEqual(target.read_bytes(), b"existing local bytes")
            self.assertFalse((site / "releases.json").exists())

    def test_publication_waits_for_exact_bytes_without_rechecking_matching_files(self):
        calls = []
        def remote(path):
            calls.append(path)
            if path == "missing-installer-publication-check":
                raise HTTPError("synthetic", 404, "missing", {}, None)
            if path == "install.ps1.sig" and calls.count(path) == 1:
                return b"previous signature"
            return b"expected"
        with tempfile.TemporaryDirectory() as temporary:
            site = Path(temporary)
            for name in ("install.ps1", "install.ps1.sig"):
                (site / name).write_bytes(b"expected")
            with patch.object(publication, "fetch", side_effect=remote), patch.object(publication.time, "sleep") as pause:
                publication.verify_public(site, attempts=2)
            self.assertEqual(calls.count("install.ps1"), 1)
            self.assertEqual(calls.count("install.ps1.sig"), 2)
            pause.assert_called_once_with(5)

    def test_publication_never_accepts_a_permanent_mismatch_or_missing_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            site = Path(temporary)
            (site / "install.ps1.sig").write_bytes(b"expected")
            for response in (b"wrong", HTTPError("synthetic", 404, "missing", {}, None)):
                effect = lambda *_: response
                if isinstance(response, Exception):
                    effect = response
                with self.subTest(response=type(response).__name__), patch.object(publication, "fetch", side_effect=effect) as read:
                    with patch.object(publication.time, "sleep"), self.assertRaisesRegex(ValueError, "Published bytes"):
                        publication.verify_public(site, attempts=2)
                    self.assertEqual(read.call_count, 2)

    def test_publication_redirect_refusal_is_not_retried(self):
        with tempfile.TemporaryDirectory() as temporary:
            site = Path(temporary)
            (site / "install.ps1").write_bytes(b"expected")
            with patch.object(publication, "fetch", side_effect=ValueError("must not redirect")) as read:
                with patch.object(publication.time, "sleep") as pause, self.assertRaisesRegex(ValueError, "redirect"):
                    publication.verify_public(site)
                self.assertEqual(read.call_count, 1)
                pause.assert_not_called()


if __name__ == "__main__":
    unittest.main()
