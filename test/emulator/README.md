# Emulator tests

These tests boot emulated machines with their real boot PROMs against
bootd, over UDP, without privileges. PROM images are copyrighted and not
part of the repository; each test is skipped unless its image is given.

| Test | Machine | Needs |
|---|---|---|
| `TestSPARCstation5` | SPARCstation 5 (OBP 2.x): RARP, TFTP | `roms/ss5.bin`, `qemu-system-sparc` |
| `TestNetBSDSparc` | NetBSD/sparc installer, diskless: RARP, TFTP, bootparam, NFSv2 | as above, plus `./fetch-netbsd.sh` |

Put PROM images in `roms/` and emulator builds in `bin/`; `fetch-netbsd.sh`
downloads NetBSD's netboot files (checked against the release's SHA512
sums) into `netbsd/`. All three directories are ignored by git. Environment variables override them
(`GOBOOTD_SS5_PROM`, `GOBOOTD_QEMU_SPARC`), and without a build in `bin/`
the emulator is taken from `PATH`.

```
go test ./test/emulator
```

## QEMU 10.2 and later

Since QEMU commit a01344d9d7 ("net: pad packets to minimum length in
qemu_receive_packet()"), frames a NIC sends to itself in loopback mode are
padded to 60 bytes. The Sun PROM's LANCE self-test loops back a 36-byte
frame and checks its length, so `boot net` fails with:

    Internal loopback test -- Wrong packet length; expected 36, observed 64
    Can't open boot device

[`qemu-sparc.patch`](qemu-sparc.patch) makes the pcnet device (which
QEMU's LANCE uses) opt out of the padding. It also maps the SS-5's
parallel port (bpp, SBus slot 5 offset 0xc800000) as an unimplemented
device, as QEMU already does for the SS-20; without it NetBSD panics with
a data fault while attaching `bpp0`. To build a patched `qemu-system-sparc`:

```
tar xf qemu-11.1.2.tar.xz && cd qemu-11.1.2
patch -p1 < .../test/emulator/qemu-sparc.patch
mkdir build && cd build
../configure --target-list=sparc-softmmu --disable-docs
ninja qemu-system-sparc
cp qemu-system-sparc .../test/emulator/bin/
```

## The boot program

`helloSPARC` in `sparc_test.go` is a hand-assembled sun4m a.out. The PROM
loads it at 0x4000 and enters it with the romvec in `%o0`. OBP 2.x has a
version 3 romvec whose `pv_printf` is empty, so the program prints by
handing a Forth string to `pv_fortheval`, then calls `pv_halt`:

    gobootd: hello from the network
    Program terminated
    ok

## NetBSD

`TestNetBSDSparc` serves NetBSD's `boot.net` over TFTP and the installer's
root over NFS. The root is extracted without privileges, so its device
nodes and owners come from an mtree spec that `fetch-netbsd.sh` makes from
the tarball (`bsdtar --format=mtree`). The test waits for the installer's
`Terminal type?` prompt, which is printed from `/dev/console` on the NFS
root. The kernel first tries DHCP for about 30 seconds.
