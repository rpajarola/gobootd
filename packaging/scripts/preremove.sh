#!/bin/sh
# Runs before removing package files. On removal the services are stopped
# and disabled; on upgrade they are left alone and restarted afterwards.
set -e

if [ "$1" = "remove" ] && [ -d /run/systemd/system ]; then
  systemctl disable --now bootd.service bootbridge.service || true
fi

exit 0
