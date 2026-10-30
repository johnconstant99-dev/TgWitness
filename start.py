"""Cross-platform launcher with an isolated environment."""
import os
import subprocess
import sys

# Check before importing tomllib, which is unavailable on older interpreters.
if sys.version_info < (3, 11):
    raise SystemExit("Install Python 3.11 or newer.")

import venv
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
VENV_HINT = ("On Debian/Ubuntu install the venv package for this Python, for example "
             "'sudo apt install python3-venv', delete the .venv folder and run the launcher again.")


def step(command, failure):
    """Run one setup step; replace a traceback with an actionable message."""
    try:
        subprocess.run(command, check=True, cwd=ROOT)
    except (subprocess.CalledProcessError, OSError):
        raise SystemExit("\n" + failure) from None


def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print("Launcher: --setup-only installs the private environment; --check checks it without starting.", flush=True)
        raise SystemExit(subprocess.call([sys.executable, "-m", "tgwitness", "--help"], cwd=ROOT))
    env = ROOT / ".venv"
    python = env / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    marker = env / ".tgwitness-ready"
    setup = "--setup-only" in sys.argv
    if "--check" in sys.argv:
        if not python.exists():
            raise SystemExit("Environment not created. Run python start.py --setup-only first.")
        raise SystemExit(subprocess.call([str(python), "-m", "tgwitness", *sys.argv[1:]], cwd=ROOT))
    if not python.exists():
        print("Creating the TgWitness Python environment…", flush=True)
        try:
            venv.EnvBuilder(with_pip=True).create(env)
        except (subprocess.CalledProcessError, OSError) as exc:
            raise SystemExit("\nCould not create the private Python environment (.venv): " + str(exc)
                             + "\n" + VENV_HINT) from None
    if not marker.exists() or marker.read_text(encoding="utf-8") != VERSION or setup:
        # Repair an environment whose initial pip bootstrap was interrupted.
        step([str(python), "-m", "ensurepip", "--upgrade"], "Could not set up pip in .venv. " + VENV_HINT)
        print("Installing TgWitness dependencies…", flush=True)
        step([str(python), "-m", "pip", "install", "--disable-pip-version-check", "-c", str(ROOT / "deploy/constraints.txt"),
              "-e", str(ROOT)],
             "Installing dependencies failed (details above). Check the Internet connection or proxy "
             "(pip honours HTTPS_PROXY) and run the launcher again.")
        marker.write_text(VERSION, encoding="utf-8")
    if not setup:
        raise SystemExit(serve([str(python), "-m", "tgwitness", *sys.argv[1:]]))


def serve(command):
    process = subprocess.Popen(command, cwd=ROOT)
    try:
        return process.wait()
    except KeyboardInterrupt:
        # The server receives the same Ctrl+C and records an orderly stop; let it finish.
        try:
            process.wait(timeout=30)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            process.kill()
        return 0


if __name__ == "__main__":
    main()
