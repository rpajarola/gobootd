#!/bin/sh
# Runs before dpkg unpacks the package. The bootd group must exist so that
# /etc/bootd.hcl and /etc/bootbridge.hcl can be laid down as root:bootd.
set -e

if ! getent group bootd >/dev/null 2>&1; then
  addgroup --system bootd
fi
if ! getent passwd bootd >/dev/null 2>&1; then
  adduser --system --ingroup bootd --home /var/lib/bootd \
    --no-create-home --shell /usr/sbin/nologin bootd
fi

exit 0
