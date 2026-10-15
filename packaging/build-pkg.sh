#!/usr/bin/env bash
# Builds a macOS installer package with universal (arm64 and x86_64)
# binaries, on macOS with Go and the Xcode command line tools.
#
#   packaging/build-pkg.sh                 # version from git
#   VERSION=1.2.3 packaging/build-pkg.sh
#
# Set PKG_SIGN_IDENTITY to a "Developer ID Installer" identity to sign it.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
. packaging/version.sh

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root="$work/root"
mkdir -p "$root/usr/local/bin" "$root/usr/local/share/gobootd/defaults" \
  "$root/usr/local/share/gobootd/examples" "$root/usr/local/share/man/man5" \
  "$root/usr/local/share/man/man8" "$root/Library/LaunchDaemons"

for cmd in bootd bootbridge; do
  for arch in arm64 amd64; do
    cc_arch=$arch
    [ "$arch" = amd64 ] && cc_arch=x86_64
    CGO_ENABLED=1 GOOS=darwin GOARCH=$arch CC="clang -arch $cc_arch" MACOSX_DEPLOYMENT_TARGET=11.0 \
      go build -trimpath -ldflags="-s -w -X $VERSION_VAR=$VERSION" -o "$work/$cmd-$arch" "./cmd/$cmd"
  done
  lipo -create -output "$root/usr/local/bin/$cmd" "$work/$cmd-arm64" "$work/$cmd-amd64"
done

share="$root/usr/local/share/gobootd"
cp packaging/macos/bootd.hcl packaging/macos/bootbridge.hcl "$share/defaults/"
cp etc/bootd.hcl etc/bootbridge.hcl "$share/examples/"
cp README.md LICENSE "$share/"
cp cmd/bootbridge/README.md "$share/bootbridge.md"
install -m 0644 man/*.8 "$root/usr/local/share/man/man8/"
install -m 0644 man/*.5 "$root/usr/local/share/man/man5/"
install -m 0755 packaging/macos/uninstall.sh "$share/uninstall.sh"
install -m 0644 packaging/macos/launchd/*.plist "$root/Library/LaunchDaemons/"

pkgbuild --root "$root" --scripts packaging/macos/scripts \
  --identifier io.github.rpajarola.gobootd --version "$VERSION" \
  --install-location / --ownership recommended "$work/gobootd.pkg"

mkdir -p dist
out="dist/gobootd-$VERSION.pkg"
sign=()
[ -n "${PKG_SIGN_IDENTITY:-}" ] && sign=(--sign "$PKG_SIGN_IDENTITY")
productbuild --package "$work/gobootd.pkg" ${sign[@]+"${sign[@]}"} "$out"
ls -l "$out"
