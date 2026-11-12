#!/bin/bash -eu
python3 -m pip install --require-hashes --only-binary=:all: -r deploy/installer.lock
for fuzzer in fuzz/*_fuzzer.py; do
  compile_python_fuzzer "$fuzzer" --paths "$SRC/tgwitness"
done
