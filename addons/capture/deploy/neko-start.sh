#!/bin/sh
set -eu
if [ ${#NEKO_MEMBER_MULTIUSER_USER_PASSWORD} -lt 16 ] || [ ${#NEKO_MEMBER_MULTIUSER_ADMIN_PASSWORD} -lt 16 ]; then
  echo "Set separate CAPTURE_NEKO_PASSWORD and CAPTURE_NEKO_ADMIN_PASSWORD values of at least 16 characters." >&2
  exit 1
fi
if [ "$NEKO_MEMBER_MULTIUSER_USER_PASSWORD" = "$NEKO_MEMBER_MULTIUSER_ADMIN_PASSWORD" ]; then
  echo "The user and admin passwords must be different." >&2
  exit 1
fi
exec /usr/bin/supervisord -c /etc/neko/supervisord.conf
