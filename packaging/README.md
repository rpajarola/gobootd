# Packages

gobootd is packaged as a `.deb` for Debian and Ubuntu (amd64 and arm64,
built on Ubuntu 24.04, published in the shared apt repository
[rpajarola/apt](https://github.com/rpajarola/apt)), a `.pkg` for macOS (universal), and a Homebrew
formula in [rpajarola/homebrew-tap](https://github.com/rpajarola/homebrew-tap).
Publishing a GitHub release builds all of them
([`.github/workflows/release.yml`](../.github/workflows/release.yml)).

## Install

**Ubuntu and Debian**, from the [rpajarola apt repository](https://rpajarola.github.io/apt),
which also has the other packages built this way:

```
sudo curl -fsSLo /usr/share/keyrings/rpajarola.gpg https://rpajarola.github.io/apt/rpajarola.gpg
echo "deb [signed-by=/usr/share/keyrings/rpajarola.gpg] https://rpajarola.github.io/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/rpajarola.list
sudo apt update
sudo apt install gobootd
```

or a downloaded package: `sudo apt install ./gobootd_<version>_<arch>.deb`.

**macOS** with Homebrew:

```
brew install rpajarola/tap/gobootd
```

or the `.pkg` from a release: `sudo installer -pkg gobootd-<version>.pkg -target /`
(the package is not signed, so double-clicking it needs right-click → Open).

## What is installed

Debian and Ubuntu:

```
/usr/bin/bootd, /usr/bin/bootbridge
/etc/bootd.hcl, /etc/bootbridge.hcl        # conffiles, root:bootd 0640
/lib/systemd/system/bootd.service          # runs as the bootd user, unprivileged
/lib/systemd/system/bootbridge.service     # bootd user with CAP_NET_RAW, CAP_NET_ADMIN
/usr/share/man/man8/bootd.8, bootbridge.8, man5/bootd.hcl.5
/usr/share/doc/gobootd/examples/           # the full example configurations
/var/lib/bootd/                            # the default root for boot files
```

The `bootd` system user is created on install. Neither service is enabled:
both need a configuration first.

```
sudoedit /etc/bootd.hcl && sudo bootd check
sudoedit /etc/bootbridge.hcl                    # set the interface
sudo systemctl enable --now bootbridge bootd
journalctl -u bootd -f
```

Upgrades restart running services and keep edited configuration files.
Removing the package keeps `/var/lib/bootd` and the `bootd` user.

macOS (`.pkg`):

```
/usr/local/bin/bootd, /usr/local/bin/bootbridge
/usr/local/etc/bootd.hcl, bootbridge.hcl   # created if missing
/Library/LaunchDaemons/io.github.rpajarola.bootd.plist        # runs as nobody
/Library/LaunchDaemons/io.github.rpajarola.bootbridge.plist   # runs as root (BPF)
/usr/local/share/man/man8/bootd.8, bootbridge.8, man5/bootd.hcl.5
/usr/local/share/gobootd/                  # examples, docs, uninstall.sh
/usr/local/var/bootd/                      # the default root for boot files
/usr/local/var/log/bootd.log, bootbridge.log
```

The launch daemons are installed but not loaded:

```
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.rpajarola.bootbridge.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.rpajarola.bootd.plist
```

Remove it with `sudo /usr/local/share/gobootd/uninstall.sh`, which keeps
the configuration and `/usr/local/var/bootd`.

## Build

```
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest   # once
packaging/build-deb.sh      # on Linux, with libpcap-dev: dist/gobootd_<version>_<arch>.deb
packaging/build-pkg.sh      # on macOS: dist/gobootd-<version>.pkg
```

The version is the git tag without its `v`, or `0.0.0~git<sha>`; set
`VERSION` to override it. bootd and bootbridge use libpcap through cgo,
so the `.deb` is built for the machine's own architecture.
`build-pkg.sh` builds both macOS architectures and joins them, and signs
the package if `PKG_SIGN_IDENTITY` names a "Developer ID Installer"
identity.

## Releasing

Tag, then publish a GitHub release for the tag:

```
git tag v0.1.0 && git push origin v0.1.0
gh release create v0.1.0 --generate-notes
```

The release workflow then attaches the `.deb`s and the `.pkg`, has
[rpajarola/apt](https://github.com/rpajarola/apt) rebuild the apt
repository (from the `.deb`s of every release of every project in it),
and updates the formula's URL and checksum in
[rpajarola/homebrew-tap](https://github.com/rpajarola/homebrew-tap). To
rebuild a release's packages, run the workflow by hand with its tag.

One-time setup: a `PACKAGES_TOKEN` secret, a fine-grained token with
contents read and write on `rpajarola/homebrew-tap` and `rpajarola/apt`
(the same token in every project):

```
gh secret set PACKAGES_TOKEN
```

Without it, the release still gets its packages, but the formula is not
updated and the apt repository is only rebuilt by its weekly run (or by
hand: Actions → publish → Run workflow in rpajarola/apt). The signing key
lives in rpajarola/apt.
