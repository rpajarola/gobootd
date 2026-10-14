#!/bin/sh
# Runs after dpkg unpacks the package. The services are not enabled: both
# need a configuration first. On upgrade, running services are restarted.
set -e

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl try-restart bootd.service bootbridge.service || true
fi

if [ -z "$2" ]; then
  cat <<'MSG'
gobootd is installed but not started. To run it:
  1. Edit /etc/bootd.hcl (check it with: sudo bootd check)
  2. For real machines, set the interface in /etc/bootbridge.hcl and
       sudo systemctl enable --now bootbridge
  3. sudo systemctl enable --now bootd
MSG
fi

exit 0
