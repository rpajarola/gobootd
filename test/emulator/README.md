# Emulator tests

These tests boot emulated machines with their real boot PROMs against
bootd, over UDP, without privileges. PROM images are copyrighted and not
part of the repository; each test is skipped unless its image is given.

| Test | Machine | Needs |
|---|---|---|
| `TestSPARCstation5` | SPARCstation 5 (OBP 2.x): RARP, TFTP | `GOBOOTD_SS5_PROM`, `qemu-system-sparc` |

```
GOBOOTD_SS5_PROM=~/roms/ss5.bin go test ./test/emulator
```

## QEMU 10.2 and later

Since QEMU commit a01344d9d7 ("net: pad packets to minimum length in
qemu_receive_packet()"), frames a NIC sends to itself in loopback mode are
padded to 60 bytes. The Sun PROM's LANCE self-test loops back a 36-byte
frame and checks its length, so `boot net` fails with:

    Internal loopback test -- Wrong packet length; expected 36, observed 64
    Can't open boot device

[`qemu-pcnet-loopback.patch`](qemu-pcnet-loopback.patch) makes the pcnet
device (which QEMU's LANCE uses) opt out of the padding. To build a patched
`qemu-system-sparc`:

```
tar xf qemu-11.1.2.tar.xz && cd qemu-11.1.2
patch -p1 < .../test/emulator/qemu-pcnet-loopback.patch
mkdir build && cd build
../configure --target-list=sparc-softmmu --disable-docs
ninja qemu-system-sparc
GOBOOTD_QEMU_SPARC=$PWD/qemu-system-sparc GOBOOTD_SS5_PROM=... go test ./test/emulator
```

## The boot program

`helloSPARC` in `sparc_test.go` is a hand-assembled sun4m a.out. The PROM
loads it at 0x4000 and enters it with the romvec in `%o0`. OBP 2.x has a
version 3 romvec whose `pv_printf` is empty, so the program prints by
handing a Forth string to `pv_fortheval`, then calls `pv_halt`:

    gobootd: hello from the network
    Program terminated
    ok
