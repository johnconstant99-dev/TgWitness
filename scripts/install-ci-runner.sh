#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
bootstrap_lock="$repo_root/deploy/site.lock"
if [[ ! -r "$bootstrap_lock" ]]; then
  echo 'Copy the reviewed checkout, including deploy/site.lock, before provisioning.' >&2
  exit 1
fi

if [[ ${EUID} -ne 0 ]]; then
  echo 'Run this provisioning script as root on a dedicated CI host.' >&2
  exit 1
fi
. /etc/os-release
if [[ ${ID} != ubuntu || ${VERSION_ID} != 24.04 ]]; then
  echo 'This installer targets Ubuntu 24.04.' >&2
  exit 1
fi

RUNNER_VERSION=2.338.2
RUNNER_SHA256=baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl git gh jq unzip zip rsync sudo build-essential \
  python3 python3-dev python3-venv libssl-dev libffi-dev \
  docker.io docker-compose-v2
systemctl enable --now docker

if ! id gha >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash gha
fi
usermod -aG docker gha
install -d -o gha -g gha /opt/actions-runner /opt/hostedtoolcache

if [[ ! -f /opt/actions-runner/config.sh ]]; then
  archive=$(mktemp /tmp/tgwitness-runner.XXXXXX.tar.gz)
  trap 'rm -f -- "$archive"' EXIT
  curl --fail --location --retry 3 \
    "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz" \
    --output "$archive"
  printf '%s  %s\n' "$RUNNER_SHA256" "$archive" | sha256sum --check --status
  tar -xzf "$archive" -C /opt/actions-runner
  chown -R gha:gha /opt/actions-runner
fi
/opt/actions-runner/bin/installdependencies.sh

python3 -m venv /opt/tgwitness-ci-bootstrap
/opt/tgwitness-ci-bootstrap/bin/python -m pip install --disable-pip-version-check --only-binary=:all: --require-hashes -r "$bootstrap_lock"
/opt/tgwitness-ci-bootstrap/bin/python -m playwright install-deps chromium

if ! grep -q '^AGENT_TOOLSDIRECTORY=' /opt/actions-runner/.env 2>/dev/null; then
  printf 'AGENT_TOOLSDIRECTORY=/opt/hostedtoolcache\n' >> /opt/actions-runner/.env
fi
chown gha:gha /opt/actions-runner/.env
chmod 600 /opt/actions-runner/.env
install -d /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=256M\n' > /etc/systemd/journald.conf.d/tgwitness-ci.conf
systemctl restart systemd-journald

echo 'Host prepared. Register /opt/actions-runner as gha, then install its service.'
