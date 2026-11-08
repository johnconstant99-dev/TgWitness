#!/bin/sh
set -eu
umask 077
mkdir -p "$HOME"
Xvfb :99 -screen 0 1280x720x24 -nolisten tcp >/tmp/xvfb.log 2>&1 &
display_pid=$!
trap 'kill "$display_pid" 2>/dev/null || true' EXIT HUP INT TERM
attempt=0
while [ ! -S /tmp/.X11-unix/X99 ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -gt 40 ] || ! kill -0 "$display_pid" 2>/dev/null; then
    echo 'Virtual display unavailable' >&2
    exit 1
  fi
  sleep 0.1
done
exec "$@"
