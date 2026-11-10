[TgWitness](../README.md) / [Documentation](README.md) · [Evidence and verification](EVIDENCE.md)

![Evidence & verification](assets/presentation/chapter-evidence.svg)

# Verify an archive without typing a command

Keep the original ZIP unchanged. Extract the complete archive and double-click
`VERIFY.cmd` on Windows. Alternatively, drag the original ZIP onto `VERIFY.cmd`.
On macOS/Linux run `sh VERIFY.sh` from a terminal.

If exactly one nearby ZIP has the same manifest as the extracted copy, the
verifier shows its path and asks for confirmation. Otherwise it asks for the
original ZIP path. Discovery is not verification: the full checks still run.
Moving or renaming the ZIP does not invalidate the archive. The extracted files
are not the verification target. HTML-only seal verification is not substituted
for ZIP verification.

The launcher asks for the signing key fingerprint obtained **separately**, from
a source the recipient trusts. Spaces, colons and uppercase hexadecimal are
accepted. Enter without a fingerprint keeps the signer unconfirmed. The key
printed inside the archive is never automatically accepted as a trusted pin.
Fingerprint input is handled in Python, never evaluated by a shell.

The existing verifier displays a coloured integrity result with explanations
and writes a UTF-8 `verify-result-<UTC>-<random>.txt` beside the original ZIP. If
that directory is not writable it tries `~/TgWitness-verifications/`. Results
do not overwrite earlier transcripts or become members of the signed archive.
The transcript records the archive path and SHA-256, verifier path and SHA-256,
local start/end times, trust warnings, checks, and exit status. It is unsigned.
The archive hash is checked again after verification to detect changes during
the run. A verifier supplied by an adversarial sender can still lie: obtain
the code and runtime independently when independent verification is needed.

Exit status 0 means the requested integrity checks passed. Read signer pinning,
coverage and timestamp verification from their individual results in the report.
Status 1 means verification failed; 2 means
the workflow did not complete (for example no runtime, cancellation, invalid
input, or inability to save the transcript). A missing fingerprint produces an
amber verdict. A pinned key can produce a green **integrity** verdict while
coverage or independent-time limitations remain visible.

## Runtime and language

The Windows launcher tries an embedded interpreter in `python/`, then
`verifier/python/`, then a compatible installed Python. The Python path must
provide Python 3.11+ and `cryptography`. It does not install dependencies or
download a runtime. Discovery disables Python launcher's automatic-install and
dry-run environment switches. Python runs with `-I -B -X utf8`: evidence-folder
modules and user site packages are excluded from imports, bytecode is not
written, and input/output is UTF-8. See the official
[isolated-mode documentation](https://docs.python.org/3/using/cmdline.html#cmdoption-I)
and [Windows launcher configuration](https://docs.python.org/3/using/windows.html#configuration).

The standalone Windows bundle contains the same `verify.py`, launchers, an
embedded official Python runtime, and the pinned cryptography dependencies and
their licences. It does not include the panel or start a server. Use its own
`VERIFY.cmd` with any supported original ZIP, or copy its `python/` directory
beside a bundled launcher. Obtain the distribution and authenticate its checksum
through a trusted channel, separate from the download itself. The build uses the repository's
existing pinned Python runtime and `deploy/constraints.txt`.

Build on Windows with Python 3.12. The build host needs no preinstalled application
dependencies: launcher generation runs inside the newly assembled embedded runtime.

```powershell
python tools/build_verifier.py
```

This builds `dist/TgWitness-verifier-<version>-windows-<arch>-all.zip` and a
SHA-256 sidecar. `VERIFY.cmd` lists all language names and accepts a language
number or code. Enter selects the detected system language. `--language de`,
for example, builds with a fixed default; every build still contains all
languages. Localized instructions are also in `languages/START_HERE-<code>.txt`.
The build checks the public fictional demo archive with the embedded runtime;
`--validation-archive PATH` selects another retained archive. It runs the real bat
launcher against clean and tampered ZIPs, and then runs it in every language
with system Python absent from PATH. Building does not publish a release. Publishing at
GitHub Releases or get.destroy.tools remains a separate release operation.

Launcher instructions, prompts, check labels, explanations, failure summaries,
and saved transcripts support all 25 panel languages: English, Russian,
Ukrainian, Spanish, Portuguese, Turkish, Arabic, Persian, Urdu, Hindi,
Indonesian, Vietnamese, Simplified Chinese, French, German, Italian, Uzbek,
Korean, Traditional Chinese, Malay, Polish, Japanese, Thai, Hebrew and Bengali.
Generated archive launchers use the report language; unknown language codes
are rejected instead of silently producing an English launcher. The standalone
verifier accepts every panel code with `--lang`, including regional aliases
such as `pt-BR` and `zh-TW`. `--choose-language --interactive` opens the menu.
File names, hashes, source records and original technical diagnostics are kept
verbatim; translating them would change the evidence or obscure an error.
Detailed CLI option descriptions remain technical documentation in English.
No new GUI is required. The Windows runtime is not a macOS/Linux runtime;
`VERIFY.sh` needs an already installed compatible `python3` and dependency.

The readable source catalogue is `tgwitness/verifier_languages.json`. The
existing panel translations supply established evidence terminology; recipient
workflow messages are translated in that catalogue. A compressed copy is embedded
in `verify.py`, which therefore works without a catalogue file, app installation,
network translation service or imports from the evidence directory. After editing
translations run `python tools/sync_verifier_languages.py`; `--check` verifies that
the embedded copy is synchronized. Catalogue checks require the exact panel
language set, complete keys and unchanged placeholders. CJK, Indic and right-to-left
explanations keep complete Unicode paragraphs rather than inserting line breaks
inside shaping sequences; terminal rendering still depends on its fonts.

## Extra verification inputs

The double-click defaults check the ZIP locally. They do not invent trust in
timestamp authorities or automatically trust a checkpoint inside the same ZIP.
Advanced users can supply independently retained inputs to the same code:

```text
python -I verify.py archive.zip --interactive --lang en --checkpoint retained.json
python -I verify.py archive.zip --pretty --explain --fingerprint TRUSTED_SHA256
python -I verify.py archive.zip --pretty --explain --fingerprint TRUSTED_SHA256 --tsa-ca trusted-root.pem
python -I verify.py archive.zip --pretty --explain --witness witness.zip --witness-fingerprint TRUSTED_WITNESS_SHA256 --require-witness
```

Use `python/python.exe` in place of `python` for the embedded Windows runtime.
RFC 3161 verification also requires OpenSSL and a trusted root; OpenSSL is not
bundled here. OpenTimestamps Bitcoin authentication remains a separate check.
The default maximum expanded ZIP size is 4 GiB; `--max-gib` explicitly changes
it. `--json` keeps its machine-readable format, including when `--explain` is
supplied. `--plain --explain` gives readable explanations without colour.

Interactive mode also preserves `--strict`, `--require-tier`, `--check-bitcoin`,
`--bitcoin-source` and the sealed-attestation options. Strict or unmet assurance requirements return
status 2; an authenticated newer format returns status 3 with `--strict`.
`--check-drand`, `--check-bitcoin` and the corresponding required tiers can use
network services. `--check-bitcoin` takes block headers from two public explorers
and requires them to agree; `--bitcoin-source URL` uses the Esplora API of your own
node instead (repeat it to require several sources to agree). Attestation verification requires the installed TgWitness
sealed verifier and `gh`; the standalone archive does not provide those tools.

`VERIFY.cmd`, `VERIFY.sh` and `START_HERE.txt` are generated before signing the
manifest for evidence, chat, handover, account, disclosure and witness exports.
They are hashed and signed as ordinary archive members. Encrypted transport
wrappers must first be opened to obtain the original signed ZIP. Earlier ZIPs
remain verifiable without repackaging; use the separately obtained verifier.

An old verifier that restricts disclosure members to a fixed list may reject
new disclosure ZIPs containing these launchers. Use the updated verifier from
an independently trusted source. Do not remove files from a signed ZIP to make
an old verifier accept it.
