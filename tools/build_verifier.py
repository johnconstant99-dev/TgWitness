"""Build a Windows verifier with an embedded runtime; no recipient installation."""
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_portable import HOST_ARCH, PYTHON, VERSION, embedded_runtime  # noqa: E402
from tools.sync_verifier_languages import validate  # noqa: E402

VERIFIER_LANGUAGES = json.loads((ROOT / "tgwitness/verifier_languages.json").read_text(encoding="utf-8"))


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_launchers(stage, language):
    # Run in the newly built runtime: the build host need not have cryptography.
    from tgwitness.verification_kit import files, quickstart

    stage = Path(stage)
    for filename, body in files(language).items():
        (stage / filename).write_bytes(body)
    (stage.parent / "VERIFY-language-menu.cmd").write_bytes(files("auto")["VERIFY.cmd"])
    (stage / "README.txt").write_bytes(quickstart(language))
    (stage / "languages").mkdir()
    for lang in VERIFIER_LANGUAGES:
        instructions = quickstart(lang) + b"\n" + (
            "python/python.exe -I verify.py archive.zip --interactive --lang " + lang + " --checkpoint retained.json\n"
            "python/python.exe -I verify.py archive.zip --pretty --explain --lang " + lang + " --fingerprint TRUSTED_SHA256 --tsa-ca trusted-root.pem\n"
            "python/python.exe -I verify.py archive.zip --pretty --explain --lang " + lang + " --witness witness.zip --witness-fingerprint TRUSTED_WITNESS_SHA256 --require-witness\n"
            "python/python.exe -I verify.py archive.zip --interactive --lang " + lang + " --max-gib 16\n").encode("utf-8")
        (stage / "languages" / ("START_HERE-" + lang + ".txt")).write_bytes(instructions)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python-zip", type=Path)
    parser.add_argument("--language", choices=("auto", *VERIFIER_LANGUAGES), default="auto",
                        help="Default language; auto shows a language menu. Every build includes all languages.")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    validate(VERIFIER_LANGUAGES)
    subprocess.run([sys.executable, str(ROOT / "tools/sync_verifier_languages.py"), "--check"], check=True)
    arch = HOST_ARCH.get(platform.machine().upper())
    if os.name != "nt" or sys.version_info[:2] != (3, 12) or not arch:
        raise SystemExit("Build on 64-bit Windows with Python 3.12 so the wheels match the embedded runtime.")
    work = ROOT / "build/verifier"
    work.mkdir(parents=True, exist_ok=True)
    runtime = embedded_runtime(arch, ROOT / "build/portable/cache", args.python_zip)
    name = "TgWitness-verifier-" + VERSION + "-windows-" + arch + "-" + ("all" if args.language == "auto" else args.language)
    with tempfile.TemporaryDirectory(prefix="stage-", dir=work) as temporary:
        stage = Path(temporary) / name
        (stage / "python").mkdir(parents=True)
        with zipfile.ZipFile(runtime) as archive:
            archive.extractall(stage / "python")  # Runtime bytes checked against embedded_runtime's pinned hash.
        tag = "python" + PYTHON.replace(".", "")[:3]
        (stage / "python" / (tag + "._pth")).write_text(
            tag + ".zip\n.\nLib\\site-packages\nimport site\n", encoding="ascii")
        subprocess.run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
                        "--only-binary=:all:", "--no-compile", "--no-warn-script-location",
                        "--target", str(stage / "python/Lib/site-packages"),
                        "-c", str(ROOT / "deploy/constraints.txt"), "cryptography"], check=True)
        shutil.copyfile(ROOT / "tgwitness/verify.py", stage / "verify.py")
        # A short-lived child also releases its loaded Windows DLLs before cleanup.
        subprocess.run([str(stage / "python/python.exe"), "-I", "-B", "-X", "utf8", "-c",
                        "import sys; sys.path.insert(0, sys.argv[1]); "
                        "from tools.build_verifier import write_launchers; write_launchers(sys.argv[2], sys.argv[3])",
                        str(ROOT), str(stage), args.language], check=True)
        default_launcher = (stage / "VERIFY.cmd").read_bytes()
        menu_launcher = (stage.parent / "VERIFY-language-menu.cmd").read_bytes()
        for filename in ("LICENSE", "NOTICE"):
            shutil.copyfile(ROOT / filename, stage / filename)
        # Test the actual bundled interpreter/dependencies against existing signed evidence.
        checked = subprocess.run([str(stage / "python/python.exe"), "-I", "-B", "-X", "utf8",
                                  str(stage / "verify.py"), str(ROOT / "tools/fixtures/evidence-before-fulltext.zip"),
                                  "--json"], capture_output=True, text=True, encoding="utf-8")
        if checked.returncode or not json.loads(checked.stdout).get("verified"):
            raise SystemExit("Portable verifier failed its signed-fixture check: " + checked.stdout + checked.stderr)
        probe = Path(temporary) / "Renamed (synthetic).zip"
        shutil.copyfile(ROOT / "tools/fixtures/evidence-before-fulltext.zip", probe)
        env = {**os.environ, "PATH": str(Path(os.environ["SystemRoot"]) / "System32"),
               "TGWITNESS_VERIFY_NO_PAUSE": "1"}
        command = '"' + os.environ["COMSPEC"] + '" /d /s /c ""' + str(stage / "VERIFY.cmd") + '" "' + str(probe) + '""'
        for expected in (0, 1):
            if expected:
                with zipfile.ZipFile(probe, "a") as archive:
                    archive.writestr("unsigned-change.txt", "synthetic tamper")
            checked = subprocess.run(command, input=("en\n" if args.language == "auto" else "") + "\n", env=env, cwd=stage, capture_output=True,
                                     text=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)
            if checked.returncode != expected:
                raise SystemExit("Portable VERIFY.cmd returned an incorrect status: " + checked.stdout + checked.stderr)
        if len(list(Path(temporary).glob("verify-result-*.txt"))) != 2:
            raise SystemExit("Portable VERIFY.cmd did not save both verification transcripts")
        print("VERIFY.cmd: clean/tampered ZIP and saved transcripts passed with system Python absent from PATH.")
        # Exercise every translation in the actual isolated recipient runtime.
        shutil.copyfile(ROOT / "tools/fixtures/evidence-before-fulltext.zip", probe)
        (stage / "VERIFY.cmd").write_bytes(menu_launcher)
        for lang, entry in VERIFIER_LANGUAGES.items():
            checked = subprocess.run(command, input=lang + "\n\n", env=env, cwd=stage, capture_output=True,
                                     text=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW, timeout=45)
            if checked.returncode or entry["reader"]["key_unconfirmed"].upper() not in checked.stdout:
                raise SystemExit("Portable language check failed: " + lang + "\n" + checked.stdout + checked.stderr)
        (stage / "VERIFY.cmd").write_bytes(default_launcher)
        print("All", len(VERIFIER_LANGUAGES), "languages passed through VERIFY.cmd without system Python on PATH.")
        shipped = sorted(p for p in stage.rglob("*") if p.is_file())
        if any(p.is_symlink() or getattr(p, "is_junction", lambda: False)() for p in stage.rglob("*")):
            raise SystemExit("Refusing linked files in portable verifier")
        (stage / "SHA256SUMS").write_text("".join(sha256(p) + "  " + p.relative_to(stage).as_posix() + "\n"
                                                  for p in shipped), encoding="utf-8")
        shipped.append(stage / "SHA256SUMS")
        args.output.mkdir(parents=True, exist_ok=True)
        output = args.output / (name + ".zip")
        partial = output.with_suffix(".zip.part")
        with zipfile.ZipFile(partial, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in shipped:
                archive.write(path, name + "/" + path.relative_to(stage).as_posix())
        partial.replace(output)
        output.with_suffix(".zip.sha256").write_text(sha256(output) + "  " + output.name + "\n", encoding="ascii")
        print("Portable verifier:", output)
        print("MiB:", round(output.stat().st_size / 1024**2, 1))
        print("SHA-256:", sha256(output))


if __name__ == "__main__":
    main()
