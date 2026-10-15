#!/bin/sh
# Removes gobootd installed from the .pkg. Configuration in /usr/local/etc
# and files in /usr/local/var/bootd are kept.
#   sudo /usr/local/share/gobootd/uninstall.sh
set -e
if [ "$(id -u)" != 0 ]; then
  echo "run with sudo" >&2
  exit 1
fi
for d in bootd bootbridge; do
  launchctl bootout "system/io.github.rpajarola.$d" 2>/dev/null || true
  rm -f "/Library/LaunchDaemons/io.github.rpajarola.$d.plist"
done
rm -f /usr/local/bin/bootd /usr/local/bin/bootbridge
rm -f /usr/local/share/man/man8/bootd.8 /usr/local/share/man/man8/bootbridge.8 \
  /usr/local/share/man/man5/bootd.hcl.5
rm -rf /usr/local/share/gobootd
pkgutil --forget io.github.rpajarola.gobootd >/dev/null 2>&1 || true
echo "gobootd removed; /usr/local/etc/bootd.hcl, /usr/local/etc/bootbridge.hcl and /usr/local/var/bootd are kept"
