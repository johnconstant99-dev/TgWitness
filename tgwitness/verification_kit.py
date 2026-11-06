"""Signed launchers and instructions in every panel language, fully offline."""

from .verify import VERIFIER_LANGUAGES, reader_message, verifier_language


CMD = r'''@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul
title TgWitness
rem Never install a runtime or dependencies on the recipient's computer.
set "PYTHON_MANAGER_AUTOMATIC_INSTALL=false"
set "PYLAUNCHER_ALLOW_INSTALL="
set "PYLAUNCHER_ALWAYS_INSTALL="
set "PYLAUNCHER_DRYRUN="
if exist "%~dp0python\python.exe" goto portable
if exist "%~dp0verifier\python\python.exe" goto nested
py -3 -I -c "import sys, cryptography; assert sys.version_info >= (3, 11)" >nul 2>&1
if not errorlevel 1 goto py
python -I -c "import sys, cryptography; assert sys.version_info >= (3, 11)" >nul 2>&1
if not errorlevel 1 goto python
echo @RUNTIME@
echo @NOT_VERIFIED@
echo @INSTRUCTIONS@
echo https://github.com/phishdestroy/TgWitness/releases
echo @PAUSE@
if not defined TGWITNESS_VERIFY_NO_PAUSE pause >nul
exit /b 2
:portable
"%~dp0python\python.exe" -I -B -X utf8 "%~dp0verify.py" --interactive --pause @LANG_ARGS@ "%~1"
goto result
:nested
"%~dp0verifier\python\python.exe" -I -B -X utf8 "%~dp0verify.py" --interactive --pause @LANG_ARGS@ "%~1"
goto result
:py
py -3 -I -B -X utf8 "%~dp0verify.py" --interactive --pause @LANG_ARGS@ "%~1"
goto result
:python
python -I -B -X utf8 "%~dp0verify.py" --interactive --pause @LANG_ARGS@ "%~1"
:result
set "result=%errorlevel%"
exit /b %result%
'''

SH = '''#!/bin/sh
# Run with: sh VERIFY.sh [original.zip]
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 2
if ! python3 -I -c 'import sys, cryptography; assert sys.version_info >= (3, 11)' >/dev/null 2>&1; then
    printf '%s\\n' @SH_RUNTIME@ @SH_NOT_VERIFIED@ @SH_INSTRUCTIONS@
    exit 2
fi
python3 -I -B -X utf8 "$base/verify.py" --interactive --pause @LANG_ARGS@ "${1:-}"
result=$?
exit "$result"
'''


def language(value):
    if value == "auto":
        return "auto"
    selected = verifier_language(value or "en")
    if not selected:
        raise ValueError("Unsupported verifier language: " + str(value))
    return selected


def quickstart(lang="en"):
    lang = language(lang)
    if lang == "auto":
        return ("TgWitness\n\n" + "\n".join(entry["name"] + " [" + code + "]: languages/START_HERE-" + code + ".txt"
                                            for code, entry in VERIFIER_LANGUAGES.items())
                + "\n\nVERIFY.cmd\n\n" + quickstart("en").decode("utf-8")).encode("utf-8")
    reader = VERIFIER_LANGUAGES[lang]["reader"]
    paragraphs = [VERIFIER_LANGUAGES[lang]["words"]["TgWitness verifier"]]
    paragraphs += [reader[key] for key in ("launch", "keep_zip", "runtime", "standalone", "trust", "key_advice",
                                         "key", "output", "unsigned", "limits_exit", "limits", "instructions", "advanced")]
    paragraphs += ["https://github.com/phishdestroy/TgWitness/releases"]
    return ("\n\n".join(paragraphs) + "\n").encode("utf-8")


def cmd_text(value):
    # Translations are data, never batch syntax. Delayed expansion is disabled.
    value = value.replace("%", "%%")
    for char in "^&|<>()":
        value = value.replace(char, "^" + char)
    return value


def shell_text(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def files(lang="en"):
    lang = language(lang)
    cmd, sh = CMD, SH
    args = "--choose-language" if lang == "auto" else "--lang " + lang
    cmd, sh = cmd.replace("@LANG_ARGS@", args), sh.replace("@LANG_ARGS@", args)
    for key in ("runtime", "not_verified", "instructions", "pause"):
        value = reader_message(key, "en" if lang == "auto" else lang)
        cmd = cmd.replace("@" + key.upper() + "@", cmd_text(value))
        sh = sh.replace("@SH_" + key.upper() + "@", shell_text(value))
    return {"VERIFY.cmd": cmd.replace("\n", "\r\n").encode("utf-8"),
            "VERIFY.sh": sh.encode("utf-8"), "START_HERE.txt": quickstart(lang)}


def write(write_member, lang="en"):
    for name, body in files(lang).items():
        write_member(name, [body])
