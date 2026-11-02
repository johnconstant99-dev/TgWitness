"""Exercise installer retention with forged inventories and interrupted downloads."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, str(Path(__file__).resolve().parent))
import installer_publication as publication


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


if __name__ == "__main__":
    unittest.main()
