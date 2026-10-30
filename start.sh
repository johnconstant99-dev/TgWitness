#!/bin/sh
# Run with: sh start.sh [--demo | --setup-only | --check]
set -eu
cd -- "$(dirname -- "$0")"
for interpreter in python3.13 python3.12 python3.11 python3 python; do
    if command -v "$interpreter" >/dev/null 2>&1 &&
       "$interpreter" -c 'import sys; sys.exit(sys.version_info < (3, 11))' >/dev/null 2>&1; then
        exec "$interpreter" start.py "$@"
    fi
done
printf '%s\n' 'TgWitness needs Python 3.11 or newer with venv support. Install it, then run sh start.sh again:' >&2
if command -v apt-get >/dev/null 2>&1; then
    hint='sudo apt-get update && sudo apt-get install -y python3 python3-venv   # Ubuntu 22.04: python3.11 python3.11-venv'
elif command -v dnf >/dev/null 2>&1; then
    hint='sudo dnf install -y python3.12'
elif command -v pacman >/dev/null 2>&1; then
    hint='sudo pacman -S --needed python'
elif command -v zypper >/dev/null 2>&1; then
    hint='sudo zypper install -y python312'
elif command -v apk >/dev/null 2>&1; then
    hint='sudo apk add python3'
elif command -v brew >/dev/null 2>&1; then
    hint='brew install python@3.12'
elif [ "$(uname -s)" = Darwin ]; then
    hint='Install Python from https://www.python.org/downloads/macos/'
else
    hint='Install Python from https://www.python.org/downloads/'
fi
printf '    %s\n' "$hint" >&2
printf '%s\n' 'Alternatively, install Docker with Compose and run sh scripts/docker-start.sh.' >&2
exit 1
