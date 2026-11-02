#!/bin/sh
# Install reviewed APK bytes authenticated by the signed repository index.
set -eu
profile=${1:?Usage: install-packages.sh runtime|media|build}
case "$profile" in runtime|media|build) ;; *) echo "Unknown profile" >&2; exit 2 ;; esac
root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
arch=$(apk --print-arch)
case "$arch" in x86_64|aarch64) ;; *) echo "Unsupported architecture" >&2; exit 2 ;; esac
lock="$root/$profile-$arch.lock"
test -s "$lock"
cache=$(mktemp -d)
trap 'rm -rf "$cache"' EXIT HUP INT TERM
test "$(awk 'NF && $1 !~ /^#/ {print $1}' /etc/apk/repositories)" = 'https://apk.cgr.dev/chainguard'

mkdir -p "$cache/apks" "$cache/verified"
: > "$cache/names"
set --
while read -r digest name extra; do
    test -z "$extra"
    test "${#digest}" -eq 64
    case "$digest" in *[!0-9a-f]*) echo "Invalid APK digest" >&2; exit 2 ;; esac
    case "$name" in ''|*[!a-zA-Z0-9+_.-]*|.*) echo "Invalid APK filename" >&2; exit 2 ;; esac
    case "$name" in *.apk) ;; *) echo "Invalid APK extension" >&2; exit 2 ;; esac
    # APK filenames are package-name-upstream_version-rN.apk. The name can
    # contain hyphens; split the two version components from the right.
    stem=${name%.apk}
    release=${stem##*-}
    prefix=${stem%-*}
    version=${prefix##*-}
    package=${prefix%-*}
    case "$release" in r[0-9]*) ;; *) echo "Invalid APK release" >&2; exit 2 ;; esac
    case "$version" in [0-9]*) ;; *) echo "Invalid APK version" >&2; exit 2 ;; esac
    set -- "$@" "$package=$version-$release"
    printf '%s\n' "$name" >> "$cache/names"
done < "$lock"
# The index signature authenticates package control checksums and data hashes.
# No fetched dependency may be installed without its reviewed SHA-256 as well.
apk update --cache-dir "$cache/apks"
for index in "$cache"/apks/APKINDEX.*.tar.gz; do apk verify "$index"; done
apk cache --cache-dir "$cache/apks" download "$@"
for archive in "$cache"/apks/*.apk; do
    name=${archive##*/}
    stem=${name%.apk}
    suffix=${stem##*.}
    test "${#suffix}" -eq 8
    case "$suffix" in *[!0-9a-f]*) echo "Invalid APK cache filename" >&2; exit 2 ;; esac
    ln "$archive" "$cache/verified/${stem%.*}.apk"
done
sort "$cache/names" > "$cache/expected"
ls "$cache/verified" | sort > "$cache/actual"
cmp "$cache/expected" "$cache/actual"
(
    cd "$cache/verified"
    sha256sum -c "$lock"
)
# Preserve the authenticated index and cache during installation. Direct local
# APK installation would require signatures absent from these repository files.
apk add --no-network --cache-dir "$cache/apks" "$@"
