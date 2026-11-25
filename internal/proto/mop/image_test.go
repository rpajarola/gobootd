package mop

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// elf32 builds a little-endian ELF32 file with the given PT_LOAD segments.
func elf32(entry uint32, segs ...struct {
	vaddr, memsz uint32
	data         []byte
}) []byte {
	le := binary.LittleEndian
	h := make([]byte, 52)
	copy(h, "\x7fELF\x01\x01\x01")
	le.PutUint16(h[16:], 2)  // ET_EXEC
	le.PutUint16(h[18:], 75) // EM_VAX
	le.PutUint32(h[20:], 1)
	le.PutUint32(h[24:], entry)
	le.PutUint32(h[28:], 52) // phoff
	le.PutUint16(h[40:], 52)
	le.PutUint16(h[42:], 32)
	le.PutUint16(h[44:], uint16(len(segs)))
	off := uint32(52 + 32*len(segs))
	var data []byte
	for _, s := range segs {
		p := make([]byte, 32)
		le.PutUint32(p[0:], 1) // PT_LOAD
		le.PutUint32(p[4:], off+uint32(len(data)))
		le.PutUint32(p[8:], s.vaddr)
		le.PutUint32(p[12:], s.vaddr)
		le.PutUint32(p[16:], uint32(len(s.data)))
		le.PutUint32(p[20:], s.memsz)
		h = append(h, p...)
		data = append(data, s.data...)
	}
	return append(h, data...)
}

func readAll(t *testing.T, im *image, file []byte) []byte {
	t.Helper()
	// Read in odd-sized pieces to cross segment boundaries.
	var out []byte
	for off := int64(0); off < im.size; {
		b := make([]byte, 7)
		n, err := im.readAt(bytes.NewReader(file), b, off)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal("short read")
		}
		out = append(out, b[:n]...)
		off += int64(n)
	}
	return out
}

func TestELF(t *testing.T) {
	file := elf32(0x10,
		struct {
			vaddr, memsz uint32
			data         []byte
		}{0x1000, 0x10, []byte("text")},
		struct {
			vaddr, memsz uint32
			data         []byte
		}{0x1020, 0x8, []byte("data")},
	)
	im, err := loadImage(bytes.NewReader(file), int64(len(file)))
	if err != nil {
		t.Fatal(err)
	}
	if im.load != 0 || im.xfer != 0x10 || im.size != 0x28 {
		t.Errorf("image %v", im)
	}
	want := append(append(append([]byte("text"), make([]byte, 0x1c)...), "data"...), make([]byte, 4)...)
	if got := readAll(t, im, file); !bytes.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestAout(t *testing.T) {
	be, le := binary.BigEndian, binary.LittleEndian
	h := make([]byte, 32)
	be.PutUint32(h, 150<<16|zmagic) // NetBSD/vax: midmag in network order
	le.PutUint32(h[4:], 4100)       // text
	le.PutUint32(h[8:], 10)         // data
	le.PutUint32(h[12:], 5)         // bss
	le.PutUint32(h[20:], 0x22)      // entry
	file := append(append(h, bytes.Repeat([]byte{'t'}, 4100)...), bytes.Repeat([]byte{'d'}, 10)...)
	im, err := loadImage(bytes.NewReader(file), int64(len(file)))
	if err != nil {
		t.Fatal(err)
	}
	if im.xfer != 0x22 || im.size != 8192+4096+4096 || im.format != "a.out (vax)" {
		t.Errorf("image %v", im)
	}
	got := readAll(t, im, file)
	want := append(bytes.Repeat([]byte{'t'}, 4100), make([]byte, 8192-4100)...)
	want = append(append(want, bytes.Repeat([]byte{'d'}, 10)...), make([]byte, 4096-10+4096)...)
	if !bytes.Equal(got, want) {
		t.Error("contents differ")
	}
}

func TestMOPImage(t *testing.T) {
	le := binary.LittleEndian
	h := make([]byte, 512)
	le.PutUint16(h[ihdSize:], 0x30)
	le.PutUint16(h[ihdActivOff:], 0x60)
	h[ihdHdrBlkCnt] = 1
	le.PutUint16(h[ihdAlias:], 0xffff) // VAX
	le.PutUint16(h[0x30+isdPagCnt:], 1)
	le.PutUint32(h[0x30+isdVPN:], 0x1000)
	le.PutUint32(h[0x60+ihaTfrAdr1:], 0x80200010)
	file := append(h, []byte("program")...)
	im, err := loadImage(bytes.NewReader(file), int64(len(file)))
	if err != nil {
		t.Fatal(err)
	}
	if im.load != 0x200000 || im.xfer != 0x200010 || im.format != "MOP (VAX)" {
		t.Errorf("image %v", im)
	}
	if got := readAll(t, im, file); string(got) != "program" {
		t.Errorf("got %q", got)
	}
}

func TestBadImages(t *testing.T) {
	for name, file := range map[string][]byte{
		"short":          []byte("hello"),
		"ELF64":          append([]byte("\x7fELF\x02\x01\x01"), make([]byte, 100)...),
		"no PT_LOAD":     elf32(0),
		"unknown header": append(make([]byte, 510), 0x34, 0x12),
	} {
		if im, err := loadImage(bytes.NewReader(file), int64(len(file))); err == nil {
			t.Errorf("%s: loaded as %v", name, im)
		}
	}
}

func TestParseRequest(t *testing.T) {
	// A VAXstation 3100 asking for the default system: device 37, format
	// 4, operating system, no name, processor 0, buffer size 1030.
	msg := []byte{25, 4, 2, 0, 0, 0x91, 0x01, 2, 0x06, 0x04, 0x90, 0x01, 1, 1}
	r, ok := parseRequest(msg)
	if !ok || r.Device != 25 || r.Program != 2 || r.Software != "" || r.BufSize != 1030 {
		t.Errorf("request %+v, %v", r, ok)
	}
	r, ok = parseRequest([]byte{25, 1, 2, 6, 'N', 'E', 'T', 'B', 'S', 'D'})
	if !ok || r.Software != "NETBSD" {
		t.Errorf("version 3 request %+v, %v", r, ok)
	}
	r, ok = parseRequest([]byte{25, 4, 2, 0xff, 0})
	if !ok || r.Software != "" {
		t.Errorf("operating system request %+v, %v", r, ok)
	}
	if _, ok := parseRequest([]byte{25, 4, 2, 9, 'x'}); ok {
		t.Error("truncated name accepted")
	}
}
