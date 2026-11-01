"""Offline regressions for signed Python inventory coverage; no package installation."""
import copy
import importlib.util
import json
import tempfile
import zipfile
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("sbom_locks", Path(__file__).with_name("sbom_locks.py"))
locks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(locks)


def package(name, version):
    return {"name": name, "versionInfo": version,
            "externalRefs": [{"referenceType": "purl", "referenceLocator": f"pkg:pypi/{name}@{version}"}]}


def rejected(call, meaning):
    try:
        call()
    except (ValueError, FileNotFoundError):
        return
    raise AssertionError("Accepted " + meaning)


def main():
    with tempfile.TemporaryDirectory(prefix="tgwitness-sbom-check-") as temporary:
        root = Path(temporary)
        deploy = root / "deploy"
        deploy.mkdir()
        original = {
            "requirements.lock": "Alpha_Package==1.2 \\\n    --hash=sha256:" + "a" * 64 + "\n",
            "build.lock": "build-package==2.0\n",
            "constraints.txt": "alpha-package==1.2\n",
            "constraints-mcp.txt": "-c constraints.txt\nmcp-package==3.0\nwin-package==4.0; sys_platform == 'win32'\n",
        }
        for name, text in original.items():
            (deploy / name).write_text(text, encoding="utf-8")
        output = root / "derived"
        manifest = locks.stage(root, output)
        assert manifest["unique_python_packages"] == 4
        assert len(manifest["scopes"]["mcp"]) == 3
        assert set(manifest["inputs_sha256"]) == {"deploy/" + name for name in original}
        assert "sys_platform == 'win32'" in (output / "mcp-requirements.txt").read_text()
        assert "--hash=sha256:" + "a" * 64 in (output / "runtime-requirements.txt").read_text()
        document = {"spdxVersion": "SPDX-2.3", "creationInfo": {"created": "2026-11-01T00:00:00Z"},
                    "packages": [package("alpha-package", "1.2"), package("build-package", "2.0"),
                                 package("mcp-package", "3.0"), package("win-package", "4.0")]}
        sbom = root / "sbom.json"
        source = root / "source.zip"
        with zipfile.ZipFile(source, "w") as archive:
            for name in original:
                archive.writestr("TgWitness/deploy/" + name, (deploy / name).read_bytes())

        def save(document):
            sbom.write_text(json.dumps(document), encoding="utf-8")

        save(document)
        locks.verify(root, output, sbom, source)
        verified = json.loads(sbom.read_text(encoding="utf-8"))
        assert json.loads(verified["annotations"][0]["comment"]) == manifest
        locks.verify(root, output, sbom)
        assert len(json.loads(sbom.read_text())["annotations"]) == 1
        wrong_source = root / "wrong-source.zip"
        with zipfile.ZipFile(wrong_source, "w") as archive:
            for name in original:
                archive.writestr("TgWitness/deploy/" + name, b"changed" if name == "build.lock" else (deploy / name).read_bytes())
        rejected(lambda: locks.verify(root, output, sbom, wrong_source), "source ZIP/lock mismatch")

        mutations = []
        missing = copy.deepcopy(document)
        missing["packages"].pop()
        mutations.append((missing, "missing platform-specific package"))
        wrong = copy.deepcopy(document)
        wrong["packages"][0] = package("alpha-package", "9.9")
        mutations.append((wrong, "wrong frozen version"))
        inconsistent = copy.deepcopy(document)
        inconsistent["packages"][0]["versionInfo"] = "9.9"
        mutations.append((inconsistent, "purl/version disagreement"))
        extra = copy.deepcopy(document)
        extra["packages"].append(package("unlisted", "1.0"))
        mutations.append((extra, "unexpected Python declaration"))
        for changed, meaning in mutations:
            save(changed)
            previous = sbom.read_bytes()
            rejected(lambda: locks.verify(root, output, sbom), meaning)
            assert sbom.read_bytes() == previous  # Never annotate incomplete output as checked.

        save(document)
        derived = output / "runtime-requirements.txt"
        good = derived.read_bytes()
        derived.write_text("alpha-package==9.9\n", encoding="utf-8")
        rejected(lambda: locks.verify(root, output, sbom), "changed scanner input")
        derived.write_bytes(good)
        (deploy / "build.lock").write_text("build-package==2.1\n", encoding="utf-8")
        rejected(lambda: locks.verify(root, output, sbom), "lock changed after staging")
        (deploy / "build.lock").write_text(original["build.lock"], encoding="utf-8")

        invalid = ["alpha-package>=1.2\n", "alpha-package==1.*\n", "# empty\n",
                   "alpha-package==1.2 \\\n", "alpha-package==1.2 --hash=sha256:invalid\n",
                   "-c constraints-mcp.txt\n", "-c ../outside.txt\n", "alpha-package==8.0\n"]
        (root / "outside.txt").write_text("outside==1.0\n", encoding="utf-8")
        for value in invalid:
            (deploy / "constraints-mcp.txt").write_text(value, encoding="utf-8")
            rejected(lambda: locks.plan(root), "invalid or conflicting frozen dependency input")
    actual, _ = locks.plan(locks.ROOT)
    identities = {(item["name"], item["version"]) for records in actual["scopes"].values() for item in records}
    for name in ("fastapi", "telethon", "pydantic", "setuptools", "mcp"):
        assert any(candidate == name for candidate, _ in identities), name
    print("SBOM lock coverage: positive derivation,15 negative controls and real frozen inputs passed")


if __name__ == "__main__":
    main()
