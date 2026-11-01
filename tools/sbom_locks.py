"""Expose frozen Python pins to Syft and reject incomplete inventory before signing.

Syft 1.55 discovers *requirements*.txt, not our deployment lock filenames, and
does not follow pip's -c includes. Stage derived inputs AFTER building the source
ZIP. This is a declaration inventory across platforms, not an installed SBOM.
"""
import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {"runtime": "deploy/requirements.lock", "build": "deploy/build.lock",
           "mcp": "deploy/constraints-mcp.txt"}
ANNOTATOR = "Tool: TgWitness locked-dependency inventory"
PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)(?:\s*;\s*(.+))?")
INCLUDE = re.compile(r"(?:-c\s*|--constraint(?:=|\s+)|-r\s*|--requirement(?:=|\s+))(\S+)")


def canonical_name(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def read_pins(root, relative, inputs, stack=()):
    path = root / relative
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root / "deploy") or path.is_symlink():
        raise ValueError("Dependency includes must stay inside deploy: " + relative)
    if resolved in stack:
        raise ValueError("Dependency include cycle: " + relative)
    raw = path.read_bytes()
    inputs[relative] = hashlib.sha256(raw).hexdigest()
    pending, records = "", []
    for number, text in enumerate(raw.decode("utf-8").splitlines(), 1):
        text = text.split("#", 1)[0].strip()
        if not text:
            continue
        pending += text
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        line, pending = pending.strip(), ""
        include = INCLUDE.fullmatch(line)
        if include:
            target = (path.parent / include[1]).resolve(strict=True)
            if not target.is_relative_to(root / "deploy"):
                raise ValueError("Dependency include escapes deploy: " + relative)
            records.extend(read_pins(root, target.relative_to(root).as_posix(), inputs, (*stack, resolved)))
            continue
        parts = re.split(r"\s+(?=--hash=)", line)
        if any(not re.fullmatch(r"--hash=sha256:[0-9a-f]{64}", item) for item in parts[1:]):
            raise ValueError(f"Unsupported dependency hash: {relative}:{number}")
        match = PIN.fullmatch(parts[0])
        if not match:
            raise ValueError(f"Expected an exact package==version pin: {relative}:{number}")
        name, version, marker = match.groups()
        if marker and ("--" in marker or "\\" in marker):
            raise ValueError(f"Unsupported dependency marker: {relative}:{number}")
        records.append({"name": canonical_name(name), "version": version,
                        "marker": marker or "", "source": relative, "requirement": line})
    if pending:
        raise ValueError("Unfinished dependency continuation: " + relative)
    if not records:
        raise ValueError("No pinned dependencies: " + relative)
    return records


def plan(root):
    root = root.resolve()
    inputs, scopes, files, versions = {}, {}, {}, {}
    for scope, source in SOURCES.items():
        records = read_pins(root, source, inputs)
        for record in records:
            name, version = record["name"], record["version"]
            if name in versions and versions[name] != version:
                raise ValueError("Conflicting frozen versions for " + name)
            versions[name] = version
        scopes[scope] = [{key: value for key, value in record.items() if key != "requirement"}
                         for record in records]
        lines = ["# Derived for Syft from " + source + "; includes resolved from deploy only.",
                 "# Declared cross-platform pins; optional MCP and build pins are not installed-runtime claims."]
        lines.extend(record["requirement"] for record in records)
        files[scope + "-requirements.txt"] = ("\n".join(lines) + "\n").encode("utf-8")
    manifest = {"schema": "tgwitness.lock-inventory.v1", "inputs_sha256": inputs, "scopes": scopes,
                "derived_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
                "unique_python_packages": len(versions),
                "meaning": "Declared frozen Python versions across all platform markers, runtime, build and optional MCP. "
                           "No resolution or installation is performed; no claim of complete installed or transitive dependencies."}
    return manifest, files


def stage(root, output):
    manifest, files = plan(root)
    output.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        (output / name).write_bytes(data)
    (output / "derivation.json").write_text(canonical_json(manifest) + "\n", encoding="utf-8")
    return manifest


def verify(root, output, sbom_path, source_archive=None):
    manifest, files = plan(root)
    if json.loads((output / "derivation.json").read_text(encoding="utf-8")) != manifest:
        raise ValueError("Dependency inputs changed after staging")
    for name, data in files.items():
        if (output / name).read_bytes() != data:
            raise ValueError("Derived dependency input changed: " + name)
    if source_archive is not None:
        with zipfile.ZipFile(source_archive) as archive:
            for name, digest in manifest["inputs_sha256"].items():
                if hashlib.sha256(archive.read("TgWitness/" + name)).hexdigest() != digest:
                    raise ValueError("Dependency input differs from the fixed source archive: " + name)
    expected = {(record["name"], record["version"]) for records in manifest["scopes"].values() for record in records}
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    if sbom.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("Expected an SPDX2.3 JSON inventory")
    actual = set()
    for package in sbom.get("packages", []):
        for ref in package.get("externalRefs", []):
            locator = ref.get("referenceLocator", "")
            if ref.get("referenceType") != "purl" or not locator.startswith("pkg:pypi/"):
                continue
            match = re.fullmatch(r"pkg:pypi/([^/@]+)@([^?#]+)(?:[?#].*)?", locator)
            if not match:
                raise ValueError("Invalid Python package identity in SBOM")
            identity = canonical_name(unquote(match[1])), unquote(match[2])
            if identity != (canonical_name(package.get("name", "")), package.get("versionInfo")):
                raise ValueError("Python SBOM package name/version disagrees with its purl")
            actual.add(identity)
    if actual != expected:
        missing = sorted("==".join(pair) for pair in expected - actual)
        extra = sorted("==".join(pair) for pair in actual - expected)
        raise ValueError(f"Python lock inventory mismatch; missing={missing}; unexpected={extra}")
    # Preserve the derivation in the attested predicate, not just in temporary scanner inputs.
    annotations = [item for item in sbom.get("annotations", []) if item.get("annotator") != ANNOTATOR]
    annotations.append({"annotationType": "OTHER", "annotator": ANNOTATOR,
                        "annotationDate": sbom["creationInfo"]["created"], "comment": canonical_json(manifest)})
    sbom["annotations"] = annotations
    sbom_path.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("stage", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sbom", type=Path)
    parser.add_argument("--archive-dir", type=Path)
    args = parser.parse_args()
    if args.command == "stage":
        result = stage(ROOT, args.output)
    else:
        if not args.sbom or not args.archive_dir:
            parser.error("verify requires --sbom and --archive-dir")
        archives = list(args.archive_dir.glob("*.zip"))
        if len(archives) != 1:
            parser.error("Expected exactly one fixed source ZIP in --archive-dir")
        result = verify(ROOT, args.output, args.sbom, archives[0])
    print("Frozen Python inventory:", result["unique_python_packages"], "unique packages;",
          ", ".join(f"{name}={len(records)}" for name, records in result["scopes"].items()))


if __name__ == "__main__":
    main()
