#!/bin/sh
# Requires Docker Engine/Desktop and Compose v2.20 or newer; no host Python needed.
set -eu
# Compose files and .env live in the project root, one level up.
cd -- "$(dirname -- "$0")/.."
if ! docker info >/dev/null 2>&1; then
    printf '%s\n' 'Install and start Docker Engine/Desktop, then run sh scripts/docker-start.sh again.' >&2
    printf '%s\n' 'Linux: https://docs.docker.com/engine/install/ (add your user to the docker group or use sudo).' >&2
    exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
    printf '%s\n' 'Docker Compose v2.20 or newer is required. Install or update the Compose plugin.' >&2
    exit 1
fi
printf '%s\n' 'Building and starting TgWitness. The first build takes a few minutes...'
if ! docker compose -f compose.yaml up -d --build --wait --wait-timeout 180; then
    printf '%s\n' 'Startup failed. Check: docker compose logs --tail 100' >&2
    exit 1
fi
panel_address=$(docker compose -f compose.yaml port tgwitness 8787)
printf '\nPanel: http://%s\n' "$panel_address"
if token=$(docker compose -f compose.yaml exec -T tgwitness cat /data/panel-token.txt 2>/dev/null) && [ -n "$token" ]; then
    printf 'Panel token: %s\n\n' "$token"
else
    printf '%s\n\n' 'Read the panel token: docker compose exec tgwitness cat /data/panel-token.txt'
fi
printf '%s\n' 'The collector runs in the background. Stop it with: docker compose stop'
printf '%s\n' 'Follow logs with: docker compose logs -f'
# Open the panel only in a desktop session; the token stays in this terminal.
if [ -z "${TGWITNESS_NO_BROWSER:-}" ] && [ -n "$panel_address" ]; then
    if [ "$(uname -s)" = Darwin ] && command -v open >/dev/null 2>&1; then
        open "http://$panel_address" >/dev/null 2>&1 || true
    elif [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v xdg-open >/dev/null 2>&1; then
        xdg-open "http://$panel_address" >/dev/null 2>&1 || true
    fi
fi
