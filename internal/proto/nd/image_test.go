package nd

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

// sunDisk returns a disk image with a Sun label: partition a at sector 0
// (64 sectors), b at sector 64 (32 sectors), 1 head of 32 sectors per
// cylinder. Each sector is filled with its number.
func sunDisk() []byte {
	img := make([]byte, 96*512)
	for i := range 96 {
		for j := range 512 {
			img[i*512+j] = byte(i)
		}
	}
	l := img[:512]
	clear(l)
	binary.BigEndian.PutUint16(l[436:], 1)  // heads
	binary.BigEndian.PutUint16(l[438:], 32) // sectors
	binary.BigEndian.PutUint32(l[444:], 0)
	binary.BigEndian.PutUint32(l[448:], 64)
	binary.BigEndian.PutUint32(l[452:], 2) // b at cylinder 2
	binary.BigEndian.PutUint32(l[456:], 32)
	binary.BigEndian.PutUint16(l[508:], 0xdabe)
	var sum uint16
	for i := 0; i < 510; i += 2 {
		sum ^= binary.BigEndian.Uint16(l[i:])
	}
	binary.BigEndian.PutUint16(l[510:], sum)
	return img
}

const sunConf = `
network "lan" {
  address = "192.168.1.1/24"
  mac     = "00:a0:c9:00:00:01"
  udp     = "127.0.0.1:0"
}
service "nd" { send_delay = 0 }
host "sun2" {
  mac  = "8:0:20:0:0:1"
  ip   = "192.168.1.20"
  disk "pub" {
    path      = "disk.img"
    partition = "a"
    public    = true
    boot      = "bootnd"
  }
  disk "root" {
    path      = "disk.img"
    partition = "b"
    writable  = true
  }
  disk "swap" {
    path   = "disk.img"
    offset = 80
    size   = 8
    unit   = 1
  }
}
`

type ndClient struct {
	t  *testing.T
	st *linktest.Port
	ip netip.Addr
}

func setupImage(t *testing.T) (*ndClient, string, *prototest.Log) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "disk.img"), sunDisk(), 0o644)
	os.WriteFile(filepath.Join(dir, "bootnd"), bytes.Repeat([]byte{0xbb}, 1000), 0o644)
	e := prototest.Setup(t, dir, sunConf)
	log := e.Start(t, &Server{}, "nd")
	return &ndClient{t, e.Segment.Station("8:0:20:0:0:1"), netip.MustParseAddr("192.168.1.20")}, dir, log
}

func (c *ndClient) send(p Packet) {
	pkt := buildIPv4(1, c.ip, netip.MustParseAddr("192.168.1.1"), IPProto, p.marshal())
	c.st.WriteFrame(link.Build(link.Broadcast, c.st.Interface().MAC, link.TypeIPv4, pkt))
}

func (c *ndClient) recv() (Packet, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	for {
		b, err := c.st.ReadFrame(ctx)
		if err != nil {
			return Packet{}, false
		}
		f, _ := link.Parse(b)
		if ip, ok := parseIPv4(f.Payload); ok && ip.proto == IPProto {
			p, ok := parsePacket(ip.payload)
			p.Data = bytes.Clone(p.Data)
			return p, ok
		}
	}
}

// read reads count bytes at block of minor.
func (c *ndClient) read(minor uint8, block, count int32) ([]byte, int8) {
	var got []byte
	for {
		c.send(Packet{Op: OpRead, Minor: minor, Seq: 9, Block: block, Count: count, Offset: int32(len(got))})
		for {
			p, ok := c.recv()
			if !ok {
				c.t.Fatalf("no reply reading minor %#o block %d", minor, block)
			}
			// An error has no DONE flag; SunOS would take it for data.
			if p.Op&opMask == OpError {
				if p.Op != OpError {
					c.t.Fatalf("error reply %v", p)
				}
				return nil, p.Error
			}
			got = append(got, p.Data...)
			if int32(len(got)) == count {
				return got, 0
			}
			if p.Op&FlagWait != 0 {
				break
			}
		}
	}
}

func TestImage(t *testing.T) {
	c, _, _ := setupImage(t)
	disk := sunDisk()
	// ndp0 is partition a with the boot program in blocks 1-15.
	got, e := c.read(MinorPublic, 0, 32*512)
	want := bytes.Clone(disk[:32*512])
	copy(want[512:16*512], append(bytes.Repeat([]byte{0xbb}, 1000), make([]byte, 15*512-1000)...))
	if e != 0 || !bytes.Equal(got, want) {
		t.Errorf("ndp0: error %d, data differs", e)
	}
	// nd0 is partition b: its block 0 is sector 64 of the image.
	if got, e := c.read(0, 0, 1024); e != 0 || got[0] != 64 || got[512] != 65 {
		t.Errorf("nd0: error %d, first bytes %d %d", e, got[0], got[512])
	}
	// nd1 is sectors 80-87.
	if got, e := c.read(1, 7, 512); e != 0 || got[0] != 87 {
		t.Errorf("nd1: error %d, first byte %d", e, got[0])
	}
	// Reading past the end of a partition is an error, not data from the
	// next one.
	if _, e := c.read(1, 8, 512); e != errENXIO {
		t.Errorf("nd1 beyond its end: error %d, want ENXIO", e)
	}
	if _, e := c.read(0, 31, 1024); e != errENXIO {
		t.Errorf("nd0 across its end: error %d, want ENXIO", e)
	}
}

// writeAll writes data at block of minor, sending window packets before
// waiting like a Sun client, and returns the final reply.
func (c *ndClient) writeAll(minor uint8, seq, block int32, data []byte, window int) Packet {
	count := int32(len(data))
	off := int32(0)
	for tries := 0; tries < 100; tries++ {
		for i := 0; i < window && off < count; i++ {
			n := min(count-off, maxData)
			op := uint8(OpWrite)
			if i == window-1 || off+n == count {
				op |= FlagWait
			}
			c.send(Packet{Op: op, Minor: minor, Seq: seq, Block: block, Count: count, Offset: off, PacketCount: n, Data: data[off : off+n]})
			off += n
		}
		p, ok := c.recv()
		for ok && p.Seq != seq {
			p, ok = c.recv() // a late reply to an earlier request
		}
		switch {
		case !ok:
			// Ask where the server is: its offset is the data it
			// needs next, or the count once the data is on disk.
			c.send(Packet{Op: OpWrite | FlagWait, Minor: minor, Seq: seq, Block: block, Count: count, Offset: off})
			if p, ok = c.recv(); !ok || p.Seq != seq {
				continue
			}
			if p.Offset == count || p.Op&opMask == OpError {
				return p
			}
			off = p.Offset
		case p.Op&opMask == OpError:
			if p.Op != OpError {
				c.t.Fatalf("error reply %v", p)
			}
			return p
		case p.Op != OpWrite|FlagDone|FlagWait:
			c.t.Fatalf("write reply %v", p)
		case p.Offset == count:
			return p
		default:
			off = p.Offset // the server asks for this next
		}
	}
	c.t.Fatal("write did not complete")
	return Packet{}
}

func TestWrite(t *testing.T) {
	c, dir, log := setupImage(t)
	data := make([]byte, 8*1024)
	for i := range data {
		data[i] = byte(i * 7)
	}
	if p := c.writeAll(0, 100, 4, data, 6); p.Op != OpWrite|FlagDone|FlagWait || p.Error != 0 {
		t.Fatalf("write reply %v", p)
	}
	img, _ := os.ReadFile(filepath.Join(dir, "disk.img"))
	if !bytes.Equal(img[(64+4)*512:(64+4)*512+len(data)], data) {
		t.Error("data not written at nd0 block 4 (image sector 68)")
	}
	if got, _ := c.read(0, 4, int32(len(data))); !bytes.Equal(got, data) {
		t.Error("data not read back")
	}
	// A repeated request is answered as done again, not written twice.
	if p := c.writeAll(0, 100, 4, data, 6); p.Op&opMask != OpWrite || p.Offset != int32(len(data)) {
		t.Errorf("repeated write: %v", p)
	}
	// Read-only and out of range writes are errors.
	if p := c.writeAll(1, 101, 0, data[:512], 6); p.Op&opMask != OpError || p.Error != errEROFS {
		t.Errorf("write to read-only nd1: %v", p)
	}
	if p := c.writeAll(0, 102, 30, data[:2048], 6); p.Op&opMask != OpError || p.Error != errENXIO {
		t.Errorf("write past the end of nd0: %v", p)
	}
	if !log.Contains("nd write by sun2 to nd1 refused (read only)") {
		t.Error("refusal not logged")
	}
}

// TestLossyWrite writes through a link that loses, duplicates and reorders
// frames; the server asks for what it is missing.
func TestLossyWrite(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "disk.img"), sunDisk(), 0o644)
	os.WriteFile(filepath.Join(dir, "bootnd"), []byte{1}, 0o644)
	e := prototest.Setup(t, dir, sunConf)
	e.Segment.Impair(linktest.Impairment{Drop: 0.1, Duplicate: 0.1, Reorder: 0.1, Seed: 3})
	e.Start(t, &Server{}, "nd")
	c := &ndClient{t, e.Segment.Station("8:0:20:0:0:1"), netip.MustParseAddr("192.168.1.20")}
	data := bytes.Repeat([]byte("sun2"), 4*1024)
	for seq := int32(1); seq <= 3; seq++ {
		if p := c.writeAll(0, seq, 0, data, 6); p.Op&opMask != OpWrite || p.Error != 0 {
			t.Fatalf("write %d: %v", seq, p)
		}
	}
	img, _ := os.ReadFile(filepath.Join(dir, "disk.img"))
	if !bytes.Equal(img[64*512:64*512+len(data)], data) {
		t.Error("data not on disk")
	}
	t.Logf("%+v", e.Segment.Stats())
}
