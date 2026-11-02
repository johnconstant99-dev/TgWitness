import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zlib


def command(args, cwd=None, timeout=180):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return {"command": [str(arg) for arg in args], "returncode": result.returncode,
            "stdout": result.stdout[-12000:], "stderr": result.stderr[-12000:]}


def success(result):
    assert result["returncode"] == 0, result
    return result


def gzip_members(data):
    members = []
    while data:
        stream = zlib.decompressobj(31)
        expanded = stream.decompress(data) + stream.flush()
        assert stream.eof, "Incomplete gzip stream"
        consumed = len(data) - len(stream.unused_data)
        assert consumed > 0
        members.append((data[:consumed], expanded))
        data = stream.unused_data
    return members


def mutate_archive(data, section):
    members = gzip_members(data)
    for index, (compressed, expanded) in enumerate(members):
        with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
            files = archive.getmembers()
        names = {file.name for file in files}
        wanted = "APKINDEX" if section == "index" else ".PKGINFO"
        if section == "data":
            if ".PKGINFO" in names or any(name.startswith(".SIGN.") for name in names):
                continue
            candidate = next((file for file in files if file.isfile() and file.size), None)
        else:
            candidate = next((file for file in files if file.name == wanted and file.size), None)
        if candidate is None:
            continue
        position = candidate.offset_data
        if section in ("index", "control"):
            field = b"\nT:" if section == "index" else b"\npkgdesc = "
            relative = expanded[position:position + candidate.size].find(field)
            assert relative >= 0, "Expected descriptive metadata was not found"
            position += relative + len(field)
        changed = bytearray(expanded)
        changed[position] = ord("X") if changed[position] != ord("X") else ord("Y")
        members[index] = (gzip.compress(bytes(changed), mtime=0), bytes(changed))
        result = b"".join(member[0] for member in members)
        assert result != data
        for _, raw in gzip_members(result):
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                archive.getmembers()
        return result
    raise AssertionError("Requested APK archive section was not found: " + section)


def cache_packages(cache):
    packages = {}
    for path in cache.glob("*.apk"):
        match = re.fullmatch(r"(.+)\.([0-9a-f]{8})\.apk", path.name)
        assert match, "Unexpected cache package name: " + path.name
        canonical = match[1] + ".apk"
        assert canonical not in packages, "Duplicate canonical package"
        packages[canonical] = path
    return packages


def lock_inputs(path):
    expected, specs = {}, []
    for line in path.read_text().splitlines():
        digest, name = line.split()
        assert re.fullmatch(r"[0-9a-f]{64}", digest)
        assert re.fullmatch(r"[a-zA-Z0-9+_.-]+\.apk", name) and not name.startswith(".")
        assert name not in expected
        package, version, release = name[:-4].rsplit("-", 2)
        expected[name] = digest
        specs.append(package + "=" + version + "-" + release)
    assert expected
    return expected, specs


def check_sums(cache, expected, folder):
    verified = folder / "verified"
    verified.mkdir()
    packages = cache_packages(cache)
    assert set(packages) == set(expected), "Cache differs from the complete locked package set"
    for name, path in packages.items():
        os.link(path, verified / name)
    lock = folder / "check.lock"
    lock.write_text("".join(digest + "  " + name + "\n" for name, digest in sorted(expected.items())))
    return command(["sha256sum", "-c", str(lock)], cwd=verified)


def install(cache, folder, specs):
    root = folder / "root"
    shutil.copytree("/etc/apk/keys", root / "etc/apk/keys")
    shutil.copyfile("/etc/apk/repositories", root / "etc/apk/repositories")
    return command(["apk", "add", "--root", str(root), "--initdb", "--no-network",
                    "--cache-dir", str(cache), *specs])


def run_checks(report):
    assert sys.platform == "linux" and os.geteuid() == 0, "Run this check as root inside the built Linux runtime image"
    repositories = [line.strip() for line in Path("/etc/apk/repositories").read_text().splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
    assert repositories == ["https://apk.cgr.dev/chainguard"]
    arch = success(command(["apk", "--print-arch"]))["stdout"].strip()
    assert arch in ("x86_64", "aarch64")
    lock = Path("/usr/share/tgwitness-build/containers") / ("runtime-" + arch + ".lock")
    expected, specs = lock_inputs(lock)
    report.update({"architecture": arch, "lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
                   "package_count": len(expected), "apk": success(command(["apk", "--version"]))["stdout"].strip()})
    with tempfile.TemporaryDirectory(prefix="tgwitness-apk-auth-") as temporary:
        directory = Path(temporary)
        original = directory / "original"
        original.mkdir()
        report["update"] = success(command(["apk", "update", "--cache-dir", str(original)]))
        report["download"] = success(command(["apk", "cache", "--cache-dir", str(original), "download", *specs], timeout=300))
        indexes = sorted(original.glob("APKINDEX.*.tar.gz"))
        assert len(indexes) == 1, "Expected one authenticated repository index"
        success(command(["apk", "verify", str(indexes[0])]))
        packages = cache_packages(original)
        assert set(packages) == set(expected)
        target = next(name for name in packages if name.startswith("libbz2-1-"))
        target_path = packages[target]
        target_members = gzip_members(target_path.read_bytes())
        for _, raw in target_members:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                assert not any(file.name.startswith(".SIGN.") for file in archive), "The target must exercise an unsigned repository leaf"
        report["unsigned_leaf"] = target
        for case in ("pristine", "wrong-sha256-pin", "signed-index", "control-with-new-pin", "data-with-new-pin"):
            folder = directory / case
            cache = folder / "cache"
            cache.mkdir(parents=True)
            for path in [*indexes, *packages.values()]:
                shutil.copyfile(path, cache / path.name)
            entry = {"case": case}
            report["cases"].append(entry)
            pinned = expected.copy()
            if case == "signed-index":
                path = cache / indexes[0].name
                path.write_bytes(mutate_archive(path.read_bytes(), "index"))
            elif case != "pristine":
                path = cache / target_path.name
                section = "control" if case == "control-with-new-pin" else "data"
                path.write_bytes(mutate_archive(path.read_bytes(), section))
                entry["modified_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                assert entry["modified_sha256"] != expected[target]
                if case != "wrong-sha256-pin":
                    pinned[target] = entry["modified_sha256"]
            entry["sha256_check"] = check_sums(cache, pinned, folder)
            if case == "wrong-sha256-pin":
                assert entry["sha256_check"]["returncode"] != 0, "Changed APK bytes passed the original pin"
            else:
                success(entry["sha256_check"])
                entry["index_check"] = command(["apk", "verify", str(cache / indexes[0].name)])
                if case == "signed-index":
                    assert entry["index_check"]["returncode"] != 0, "Changed index passed signature verification"
                else:
                    success(entry["index_check"])
                entry["offline_install"] = install(cache, folder, specs)
                if case == "pristine":
                    success(entry["offline_install"])
                    entry["installed"] = success(command(["apk", "info", "--root", str(folder / "root"), "--installed", "python-3.12-base"]))
                else:
                    assert entry["offline_install"]["returncode"] != 0, "Unauthenticated archive installed successfully"
            entry["status"] = "pass"
            print("APK authentication check passed: " + case, flush=True)
    report["status"] = "pass"


def main():
    parser = argparse.ArgumentParser(description="Exercise APK cache authentication in the built runtime image.")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {"schema": 1, "status": "error", "cases": []}
    try:
        run_checks(report)
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("APK repository authentication: " + report["status"] + "; report: " + str(args.output))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
