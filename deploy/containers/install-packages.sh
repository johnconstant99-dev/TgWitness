#!/bin/sh
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

retry_fetch() {
    attempt=1
    while ! "$@"; do
        if test "$attempt" -ge 3; then
            echo 'Package fetch failed after three attempts' >&2
            return 1
        fi
        echo 'Package fetch failed; retrying with the same authenticated cache' >&2
        sleep "$((attempt * 2))"
        attempt=$((attempt + 1))
    done
}

mkdir -p "$cache/apks" "$cache/verified"
: > "$cache/names"
set --
while read -r digest name extra; do
    test -z "$extra"
    test "${#digest}" -eq 64
    case "$digest" in *[!0-9a-f]*) echo "Invalid APK digest" >&2; exit 2 ;; esac
    case "$name" in ''|*[!a-zA-Z0-9+_.-]*|.*) echo "Invalid APK filename" >&2; exit 2 ;; esac
    case "$name" in *.apk) ;; *) echo "Invalid APK extension" >&2; exit 2 ;; esac
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
retry_fetch apk update --cache-dir "$cache/apks"
for index in "$cache"/apks/APKINDEX.*.tar.gz; do apk verify "$index"; done
retry_fetch apk cache --cache-dir "$cache/apks" download "$@"
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
apk add --no-network --cache-dir "$cache/apks" "$@"
