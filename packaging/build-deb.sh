#!/usr/bin/env bash
# Builds the .deb for this machine's architecture. bootd and bootbridge use
# libpcap through cgo, so each architecture is built on its own kind of
# machine (CI uses ubuntu-24.04 and ubuntu-24.04-arm).
#
# Requires Go, libpcap-dev and nfpm (https://nfpm.goreleaser.com):
#   go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
#
# Usage:
#   packaging/build-deb.sh                 # version from git
#   VERSION=1.2.3 packaging/build-deb.sh
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
. packaging/version.sh

if ! command -v nfpm >/dev/null 2>&1; then
  echo "build-deb.sh: nfpm not found on PATH; see packaging/README.md" >&2
  exit 1
fi
ARCH="${ARCH:-$(dpkg --print-architecture)}"

mkdir -p dist/bin
for cmd in bootd bootbridge; do
  CGO_ENABLED=1 go build -trimpath -ldflags="-s -w -X $VERSION_VAR=$VERSION" -o "dist/bin/$cmd" "./cmd/$cmd"
done
VERSION="$VERSION" ARCH="$ARCH" nfpm pkg --config packaging/nfpm.yaml --packager deb \
  --target "dist/gobootd_${VERSION}_${ARCH}.deb"
rm -rf dist/bin
ls -l "dist/gobootd_${VERSION}_${ARCH}.deb"
