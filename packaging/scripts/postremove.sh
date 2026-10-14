#!/bin/sh
# Runs after removing package files. /var/lib/bootd (boot files, exports)
# and the bootd user are kept, even on purge. Remove them yourself with:
#   sudo rm -rf /var/lib/bootd
#   sudo deluser bootd && sudo delgroup bootd
set -e

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi

exit 0
