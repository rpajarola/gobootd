package rpl

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

const lan = `
network "lan" {
  address = "192.168.1.1/24"
  mac     = "00:a0:c9:00:00:01"
  udp     = "127.0.0.1:0" # not used: tests run on an in-memory segment
}
service "rpl" {
  send_delay = 0
}
`

var (
	server = mustMAC("00:a0:c9:00:00:01")
	pcMAC  = mustMAC("00:60:8c:12:34:56")
)

func mustMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

type client struct {
	t  *testing.T
	st *linktest.Port
}

func setup(t *testing.T, conf string, files map[string][]byte) (client, *prototest.Log) {
	dir := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e := prototest.Setup(t, dir, lan+conf)
	log := e.Start(t, &Server{}, "rpl")
	return client{t, e.Segment.Station(pcMAC.String())}, log
}

func (c client) send(dst net.HardwareAddr, payload []byte) {
	c.st.WriteFrame(link.Pad(link.Build8023(dst, pcMAC, payload)))
}

// recv returns the next RPL frame's command and vectors.
func (c client) recv() (uint16, map[uint16][]byte, bool) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	for {
		b, err := c.st.ReadFrame(ctx)
		if err != nil {
			return 0, nil, false
		}
		f, ok := link.Parse(b)
		if !ok || !Match(f) {
			continue
		}
		if f.Src.String() != server.String() || f.Dst.String() != pcMAC.String() {
			c.t.Errorf("reply %s -> %s", f.Src, f.Dst)
		}
		p := f.Payload[3:]
		if n := int(binary.BigEndian.Uint16(p)); n != len(p) {
			c.t.Errorf("length %d, frame has %d", n, len(p))
		}
		vecs := map[uint16][]byte{}
		var walk func([]byte)
		walk = func(b []byte) {
			for len(b) >= 4 {
				n, id := int(binary.BigEndian.Uint16(b)), binary.BigEndian.Uint16(b[2:])
				if id&0xc000 == 0 {
					walk(b[4:n])
				} else {
					vecs[id] = b[4:n]
				}
				b = b[n:]
			}
		}
		walk(p[4:])
		return binary.BigEndian.Uint16(p[2:]), vecs, true
	}
}

// find is a FIND frame like a boot ROM's.
func find() []byte {
	group := builder{}.u16(vecFrameLen, 1500).u16(vecConnClass, 1).vec(vecSAP, []byte{sap})
	return newFrame(cmdFind).
		u32(vecCorrelator, 0x1234).
		vec(0x0004, builder{}.vec(vecSourceMAC, pcMAC)).
		vec(vecFoundGroup, group).
		vec(vecLoader, []byte("IBM RPL")).
		done()
}

func sendFile(block uint32, frameLen int) []byte {
	return newFrame(cmdSendFile).
		u32(vecCorrelator, 0x1234).
		u32(vecSequence, block).
		vec(0x0004, builder{}.vec(vecSourceMAC, pcMAC)).
		vec(vecFoundGroup, builder{}.u16(vecFrameLen, uint16(frameLen))).
		done()
}

func TestParse(t *testing.T) {
	p, ok := parse(find())
	if !ok || p.Cmd != cmdFind || p.Correlator != 0x1234 || p.MAC.String() != pcMAC.String() || p.FrameLen != 1500 || string(p.Loader) != "IBM RPL" {
		t.Errorf("FIND %+v, %v", p, ok)
	}
	p, ok = parse(sendFile(7, 1100))
	if !ok || p.Cmd != cmdSendFile || p.Sequence != 7 || !p.HasSeq || p.FrameLen != 1100 {
		t.Errorf("SEND.FILE.REQUEST %+v, %v", p, ok)
	}
}

// TestFound checks FOUND against the frame rpld builds.
func TestFound(t *testing.T) {
	want := "fcfc03" + "003a0002" +
		"00084003" + "00001234" +
		"0005400b" + "00" +
		"000a400c" + "00608c123456" +
		"000a4006" + "00a0c9000001" +
		"00100008" + "000640090" + "5dc" + "0006400a0000" +
		"00054007" + "fc"
	got := hex.EncodeToString(found(0x1234, pcMAC, server, 1500))
	if got != want {
		t.Errorf("FOUND\n%s\nwant\n%s", got, want)
	}
}

const generic = `
host "pc" {
  mac      = "00:60:8c:12:34:56"
  services = ["rpl"]
  file "loader.com" {
    load    = "0x8000"
  }
  file "kernel" {
    load    = "0x10000"
    execute = "0x10010"
  }
}
`

func TestLoad(t *testing.T) {
	loader := bytes.Repeat([]byte("L"), 1000)
	kernel := make([]byte, 3000)
	for i := range kernel {
		kernel[i] = byte(i)
	}
	c, log := setup(t, generic, map[string][]byte{"loader.com": loader, "kernel": kernel})

	c.send(Multicast, find())
	cmd, v, ok := c.recv()
	if !ok || cmd != cmdFound {
		t.Fatalf("FIND answered with %#x, %v", cmd, ok)
	}
	if !bytes.Equal(v[vecTargetMAC], pcMAC) || !bytes.Equal(v[vecSourceMAC], server) || binary.BigEndian.Uint32(v[vecCorrelator]) != 0x1234 {
		t.Errorf("FOUND %x", v)
	}

	mem := map[uint32]byte{}
	read := func(from uint32, upTo int) uint32 {
		c.send(server, sendFile(from, 1500))
		var last uint32
		for want := from; ; want++ {
			cmd, v, ok := c.recv()
			if !ok {
				t.Fatalf("no block %d", want)
			}
			if cmd != cmdFileData || binary.BigEndian.Uint32(v[vecSequence]) != want {
				t.Fatalf("got %#x block %d, want block %d", cmd, binary.BigEndian.Uint32(v[vecSequence]), want)
			}
			hdr := v[vecLoadHeader]
			load, exec, flags := binary.BigEndian.Uint32(hdr), binary.BigEndian.Uint32(hdr[4:]), hdr[8]
			if exec != 0x10010 {
				t.Errorf("execute %#x", exec)
			}
			for i, b := range v[vecData] {
				mem[load+uint32(i)] = b
			}
			last = want
			if flags == flagLast || int(want) == upTo {
				return last
			}
			if flags != flagMore {
				t.Fatalf("flags %#x", flags)
			}
		}
	}
	if last := read(0, -1); last != 3 {
		t.Errorf("last block %d, want 3 (1 for the loader, 3 for the kernel)", last)
	}
	for i, b := range loader {
		if mem[0x8000+uint32(i)] != b {
			t.Fatalf("loader byte %d differs", i)
		}
	}
	// A client that missed blocks asks again from the first it lacks.
	clear(mem)
	if last := read(1, -1); last != 3 {
		t.Errorf("last block %d, want 3 (1 for the loader, 3 for the kernel)", last)
	}
	if len(mem) != len(kernel) {
		t.Errorf("resent %d bytes, want the kernel's %d", len(mem), len(kernel))
	}
	for i, b := range kernel {
		if mem[0x10000+uint32(i)] != b {
			t.Fatalf("kernel byte %d differs", i)
		}
	}
	if !log.Contains("rpl transfer to pc sent") {
		t.Errorf("transfer not logged:\n%s", log)
	}
}

func TestSmallFrames(t *testing.T) {
	c, _ := setup(t, generic, map[string][]byte{"loader.com": make([]byte, 1000), "kernel": make([]byte, 3000)})
	c.send(server, sendFile(0, 600))
	n := 0
	for {
		cmd, v, ok := c.recv()
		if !ok || cmd != cmdFileData {
			t.Fatal("transfer stopped")
		}
		if len(v[vecData]) > 552 {
			t.Errorf("block of %d bytes", len(v[vecData]))
		}
		n++
		if v[vecLoadHeader][8] == flagLast {
			break
		}
	}
	// (600-48)&^7 = 552: 2 blocks of loader, 6 of kernel.
	if n != 2+6 {
		t.Errorf("%d blocks", n)
	}
}

func TestDenied(t *testing.T) {
	c, log := setup(t, `
host "pc" {
  mac      = "00:60:8c:12:34:56"
  services = ["rpl"]
  file "kernel" {}
}
`, map[string][]byte{"kernel": []byte("x")})
	c.send(Multicast, find())
	if _, _, ok := c.recv(); ok {
		t.Error("answered without a load address")
	}
	if !log.Contains("kernel has no load address") {
		t.Errorf("refusal not logged:\n%s", log)
	}
}

func TestUnknownClient(t *testing.T) {
	c, log := setup(t, "", nil)
	c.send(Multicast, find())
	if _, _, ok := c.recv(); ok {
		t.Error("answered an unknown client")
	}
	if !log.Contains("rpl request from 00:60:8c:12:34:56 denied") {
		t.Errorf("refusal not logged:\n%s", log)
	}
}

func TestFloppy(t *testing.T) {
	img := make([]byte, 360<<10)
	img[510], img[511] = 0x55, 0xaa
	c, log := setup(t, `
host "pc" {
  mac      = "00:60:8c:12:34:56"
  services = ["rpl"]
  file "dos.img" { floppy = true }
}
`, map[string][]byte{"dos.img": img})
	c.send(server, sendFile(0, 1500))
	var first, lastHdr []byte
	for {
		cmd, v, ok := c.recv()
		if !ok || cmd != cmdFileData {
			t.Fatal("transfer stopped")
		}
		if first == nil {
			first = v[vecData]
			if load := binary.BigEndian.Uint32(v[vecLoadHeader]); load != 0x35c00 {
				t.Errorf("loader at %#x", load)
			}
		}
		lastHdr = v[vecLoadHeader]
		if lastHdr[8] == flagLast {
			break
		}
	}
	le := binary.LittleEndian
	if string(first[4:8]) != "RDSK" || le.Uint16(first[8:]) != 0x3600 || le.Uint16(first[10:]) != 720 ||
		first[12] != 9 || first[13] != 2 || le.Uint16(first[14:]) != 40 || le.Uint16(first[18:]) != 0x35c00>>10 || le.Uint16(first[20:]) != 576 {
		t.Errorf("loader parameters %x", first[:24])
	}
	if exec := binary.BigEndian.Uint32(lastHdr[4:]); exec != 0x35c00 {
		t.Errorf("execute %#x", exec)
	}
	if load := binary.BigEndian.Uint32(lastHdr); load != 0x90000-1440 {
		t.Errorf("last block at %#x", load)
	}
	if !log.Contains("floppy image (360 KB, 40/2/9)") {
		t.Errorf("plan not logged:\n%s", log)
	}
}

func TestFloppySizes(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name     string
		size     int
		spt, hds uint16
		ok       bool
	}{
		{"160k", 160 << 10, 0, 0, true},
		{"400k with BPB", 400 << 10, 10, 2, true},
		{"100k", 100 << 10, 0, 0, false},
		{"720k", 720 << 10, 9, 2, false},
		{"empty", 0, 0, 0, false},
	} {
		img := make([]byte, tc.size)
		if tc.spt != 0 {
			binary.LittleEndian.PutUint16(img[11:], 512)
			binary.LittleEndian.PutUint16(img[24:], tc.spt)
			binary.LittleEndian.PutUint16(img[26:], tc.hds)
		}
		path := filepath.Join(dir, tc.name)
		os.WriteFile(path, img, 0o644)
		plan, err := floppyPlan(&inventory.File{Label: tc.name, Path: path, Floppy: true})
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v, %v", tc.name, plan, err)
		}
	}
}
