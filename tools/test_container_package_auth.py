import gzip
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import check_container_package_auth as check


def tar_member(name, content):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        info = tarfile.TarInfo(name)
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    return gzip.compress(out.getvalue(), mtime=0)


class PackageAuthenticationFixtures(unittest.TestCase):
    def test_control_and_data_mutations_preserve_valid_archive_structure(self):
        data = tar_member("usr/lib/synthetic", b"original synthetic content")
        control = tar_member(".PKGINFO", b"pkgname = synthetic\npkgdesc = Synthetic fixture\ndatahash = " +
                             hashlib.sha256(data).hexdigest().encode() + b"\n")
        original = control + data
        for section, changed_index in (("control", 0), ("data", 1)):
            modified = check.mutate_archive(original, section)
            members = check.gzip_members(modified)
            self.assertEqual(len(members), 2)
            self.assertNotEqual(members[changed_index][0], [control, data][changed_index])
            self.assertEqual(members[1 - changed_index][0], [control, data][1 - changed_index])
            for _, raw in members:
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                    self.assertEqual(len(archive.getmembers()), 1)
            if section == "data":
                self.assertNotEqual(hashlib.sha256(members[1][0]).hexdigest(), hashlib.sha256(data).hexdigest())
                with tarfile.open(fileobj=io.BytesIO(members[0][1]), mode="r:") as archive:
                    self.assertIn(hashlib.sha256(data).hexdigest().encode(), archive.extractfile(".PKGINFO").read())

    def test_index_mutation_keeps_original_signature_stream(self):
        signature = tar_member(".SIGN.RSA256.synthetic.pub", b"synthetic signature bytes")
        index = tar_member("APKINDEX", b"P:synthetic\nV:1.2.3-r0\nT:Synthetic fixture\n\n")
        modified = check.mutate_archive(signature + index, "index")
        members = check.gzip_members(modified)
        self.assertEqual(members[0][0], signature)
        self.assertNotEqual(members[1][0], index)
        with tarfile.open(fileobj=io.BytesIO(members[1][1]), mode="r:") as archive:
            self.assertIn(b"P:synthetic\nV:1.2.3-r0\nT:", archive.extractfile("APKINDEX").read())

    def test_cache_canonical_names_preserve_dotted_versions(self):
        with tempfile.TemporaryDirectory(prefix="tgwitness-cache-fixture-") as temporary:
            root = Path(temporary)
            (root / "libbz2-1-1.0.8-r29.a1b2c3d4.apk").write_bytes(b"synthetic")
            self.assertEqual(set(check.cache_packages(root)), {"libbz2-1-1.0.8-r29.apk"})
            (root / "libbz2-1-1.0.8-r29.11223344.apk").write_bytes(b"other")
            with self.assertRaises(AssertionError):
                check.cache_packages(root)

    def test_truncated_archive_or_wrong_section_cannot_masquerade_as_a_tamper_test(self):
        original = tar_member(".PKGINFO", b"pkgname = synthetic\npkgdesc = Fixture\n")
        with self.assertRaises(AssertionError):
            check.gzip_members(original[:-4])
        with self.assertRaises(AssertionError):
            check.mutate_archive(original, "data")


if __name__ == "__main__":
    unittest.main()
