package mop

import (
	"bytes"
	"testing"

	"github.com/rpajarola/gobootd/internal/link"
)

func FuzzImage(f *testing.F) {
	file, _ := program()
	f.Add(file)
	f.Add(elf32(0x10, struct {
		vaddr, memsz uint32
		data         []byte
	}{0x1000, 0x10, []byte("text")}))
	f.Fuzz(func(t *testing.T, b []byte) {
		im, err := loadImage(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			return
		}
		buf := make([]byte, 1492)
		for off := int64(0); off < min(im.size, 1<<20); off += int64(len(buf)) {
			if _, err := im.readAt(bytes.NewReader(b), buf, off); err != nil {
				return
			}
		}
	})
}

func FuzzMessage(f *testing.F) {
	f.Add(wrap(ether, Multicast, vaxMAC, rpr("NETBSD", 1030)))
	f.Add(wrap(ieee8023, Multicast, vaxMAC, rpr("", 0)))
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, ok := link.Parse(b)
		if !ok {
			return
		}
		if msg, _, ok := unwrap(fr); ok && msg[0] == codeRPR {
			parseRequest(msg[1:])
		}
	})
}
