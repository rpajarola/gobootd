#!/bin/sh
# Fetches NetBSD/sparc's netboot files into netbsd/ for TestNetBSDSparc:
# the second stage loader, the install root file system and a kernel,
# checked against the release's SHA512 sums. The root is extracted without
# privileges, so its device nodes and owners come from an mtree spec made
# from the tarball (bsdtar is needed for that).
set -eu
cd "$(dirname "$0")"
VERSION=${NETBSD_VERSION:-11.0}
BASE=https://cdn.netbsd.org/pub/NetBSD/NetBSD-$VERSION/sparc
mkdir -p netbsd
cd netbsd

fetch() { # dir file
	curl -sfLo "$2" "$BASE/$1/$2"
	want=$(curl -sfL "$BASE/$1/SHA512" | sed -n "s/^SHA512 ($2) = //p")
	got=$(shasum -a 512 "$2" 2>/dev/null || sha512sum "$2")
	[ "${got%% *}" = "$want" ] || { echo "$2: checksum mismatch" >&2; exit 1; }
}
fetch installation/netboot boot.net
fetch installation/netboot rootfs.tgz
fetch binary/kernel netbsd-GENERIC.gz

rm -rf root
mkdir root
# Device nodes cannot be created without privileges; the spec has them.
bsdtar -xf rootfs.tgz -C root 2>/dev/null || true
gunzip -c netbsd-GENERIC.gz > root/netbsd
bsdtar -cf root.mtree --format=mtree \
	--options='!all,type,mode,uid,gid,uname,gname,device,link' @rootfs.tgz
dd if=/dev/zero of=swap bs=1048576 count=16 2>/dev/null
echo "NetBSD $VERSION/sparc netboot files are in $(pwd)"
