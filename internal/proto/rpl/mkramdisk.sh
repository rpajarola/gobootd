#!/bin/sh
# Builds ramdisk.bin from ramdisk.S with GNU binutils.
set -e
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
as --32 -o "$tmp/ramdisk.o" ramdisk.S
ld -m elf_i386 -Ttext=0 -e _start --oformat=binary -o ramdisk.bin "$tmp/ramdisk.o"
