#!/bin/sh
# Maintainer command: run inside the pinned Wolfi base; inspect results before updating locks.
set -eu
profile=${1:?Usage: resolve-packages.sh runtime|media|build [output-directory]}
case "$profile" in runtime|media|build) ;; *) echo "Unknown profile" >&2; exit 2 ;; esac
root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
arch=$(apk --print-arch)
case "$arch" in x86_64|aarch64) ;; *) echo "Unsupported architecture" >&2; exit 2 ;; esac
out=${2:-/out}
mkdir -p "$out"
cache=$(mktemp -d)
trap 'rm -rf "$cache"' EXIT HUP INT TERM

# This digest-pinned Wolfi image ships the public Chainguard repository and keys.
# Keep resolution and installation on that same authenticated package source.
repository=https://apk.cgr.dev/chainguard
test "$(awk 'NF && $1 !~ /^#/ {print $1}' /etc/apk/repositories)" = "$repository"
cp /etc/apk/repositories "$out/$profile-$arch.repositories"
# Repository signatures are checked by apk; no caller-supplied repository or key is used.
apk update
awk 'NF && $1 !~ /^#/ {print $1}' "$root/$profile.packages" > "$cache/roots"
apk add --no-cache $(cat "$cache/roots")
cp /lib/apk/db/installed "$out/$profile-$arch.installed"
cp "$root/$profile.packages" "$out/$profile-$arch.packages"
awk '/^P:/ {name=substr($0,3)} /^V:/ {print name "=" substr($0,3)}' \
    /lib/apk/db/installed | sort > "$out/$profile-$arch.versions"
mkdir "$cache/apks"
# These repository packages are authenticated by the signed index, which binds
# their control checksum and data hash; they do not carry individual signatures.
# Unlike apk fetch arguments, apk cache download accepts version constraints.
apk update --cache-dir "$cache/apks"
for index in "$cache"/apks/APKINDEX.*.tar.gz; do
    apk verify "$index"
    cp "$index" "$out/$profile-$arch.${index##*/}"
done
apk cache --cache-dir "$cache/apks" download $(cat "$out/$profile-$arch.versions")
(
    for package in "$cache"/apks/*.apk; do
        name=${package##*/}
        stem=${name%.apk}
        suffix=${stem##*.}
        test "${#suffix}" -eq 8
        case "$suffix" in *[!0-9a-f]*) exit 2 ;; esac
        canonical=${stem%.*}.apk
        digest=$(sha256sum "$package")
        printf '%s  %s\n' "${digest%% *}" "$canonical"
    done
) > "$out/$profile-$arch.lock"
sort -k2 "$out/$profile-$arch.lock" > "$cache/sorted.lock"
cp "$cache/sorted.lock" "$out/$profile-$arch.lock"
printf 'Resolved %s/%s: %s authenticated repository packages\n' "$profile" "$arch" "$(wc -l < "$out/$profile-$arch.lock")"
