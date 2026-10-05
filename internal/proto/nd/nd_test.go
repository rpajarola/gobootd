package nd

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

const conf = `
network "lan" {
  address = "192.168.1.1/24"
  mac     = "00:a0:c9:00:00:01"
  udp     = "127.0.0.1:0" # not used: tests run on an in-memory segment
}
service "nd" {
  send_delay = 0
}
host "sun2" {
  mac  = "8:0:20:0:0:1"
  ip   = "192.168.1.20"
  disk "boot" {
    path  = "bootyy"
    boot2 = "netboot"
    mode  = "bootfile"
  }
}
host "sun3" {
  mac      = "8:0:20:0:0:2"
  ip       = "192.168.1.21"
  services = ["rarp"]
}
`

var (
	boot1 = bytes.Repeat([]byte{1}, 5000)
	boot2 = bytes.Repeat([]byte{2}, 3000)
	// The disk the client should see.
	disk = func() []byte {
		d := make([]byte, 16*512+4096)
		copy(d[512:], boot1)
		copy(d[16*512:], boot2)
		return d
	}()
)

func setup(t *testing.T, mac string) (*linktest.Port, *prototest.Log) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "bootyy"), boot1, 0o644)
	os.WriteFile(filepath.Join(dir, "netboot"), boot2, 0o644)
	e := prototest.Setup(t, dir, conf)
	log := e.Start(t, &Server{}, "nd")
	return e.Segment.Station(mac), log
}

func send(st *linktest.Port, src, dst netip.Addr, p Packet) {
	pkt := buildIPv4(1, src, dst, IPProto, p.marshal())
	st.WriteFrame(link.Build(link.Broadcast, st.Interface().MAC, link.TypeIPv4, pkt))
}

func recv(st *linktest.Port) (ipv4, Packet, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	b, err := st.ReadFrame(ctx)
	if err != nil {
		return ipv4{}, Packet{}, false
	}
	f, _ := link.Parse(b)
	ip, ok := parseIPv4(f.Payload)
	if !ok {
		return ipv4{}, Packet{}, false
	}
	p, ok := parsePacket(ip.payload)
	return ip, p, ok
}

// readDisk reads count bytes from block like a client, asking again after
// every window.
func readDisk(t *testing.T, st *linktest.Port, src, dst netip.Addr, block, count int32) []byte {
	t.Helper()
	var got []byte
	req := Packet{Op: OpRead, Minor: MinorPublic, Seq: 7, Block: block, Count: count}
	for {
		req.Offset = int32(len(got))
		send(st, src, dst, req)
		for {
			ip, p, ok := recv(st)
			if !ok {
				t.Fatalf("no reply at offset %d", len(got))
			}
			if ip.src != netip.MustParseAddr("192.168.1.1") || ip.dst != netip.MustParseAddr("192.168.1.20") {
				t.Fatalf("reply %s -> %s", ip.src, ip.dst)
			}
			if p.Seq != 7 || p.Block != block || p.Offset != int32(len(got)) || int(p.PacketCount) != len(p.Data) {
				t.Fatalf("reply %v at offset %d", p, len(got))
			}
			got = append(got, p.Data...)
			if p.Op&FlagDone != 0 {
				return got
			}
			if p.Op&FlagWait != 0 {
				break
			}
		}
	}
}

func TestBootfile(t *testing.T) {
	st, log := setup(t, "8:0:20:0:0:1")
	zero := netip.IPv4Unspecified()
	// The PROM reads blocks 0-15 before it knows its address.
	if got := readDisk(t, st, zero, zero, 0, 16*512); !bytes.Equal(got, disk[:16*512]) {
		t.Error("blocks 0-15 differ")
	}
	// The first stage then reads the second from its own address.
	if got := readDisk(t, st, netip.MustParseAddr("192.168.1.20"), netip.MustParseAddr("192.168.1.1"), 16, 4096); !bytes.Equal(got, disk[16*512:]) {
		t.Error("blocks 16- differ")
	}
	if !log.Contains("nd read by sun2 from disk boot") {
		t.Error("read not logged")
	}
}

func TestDenied(t *testing.T) {
	zero := netip.IPv4Unspecified()
	for _, tc := range []struct{ mac, log string }{
		{"8:0:20:0:0:9", "nd request from 08:00:20:00:00:09 denied (client unknown)"},
		{"8:0:20:0:0:2", "nd request from sun3 denied (nd not allowed for this host)"},
	} {
		st, log := setup(t, tc.mac)
		send(st, zero, zero, Packet{Op: OpRead, Minor: MinorPublic, Count: 512})
		if _, _, ok := recv(st); ok {
			t.Errorf("%s: got a reply", tc.mac)
		}
		if !log.Contains(tc.log) {
			t.Errorf("log does not contain %q", tc.log)
		}
	}
	// Requests for another server are ignored.
	st, _ := setup(t, "8:0:20:0:0:1")
	send(st, netip.MustParseAddr("192.168.1.20"), netip.MustParseAddr("192.168.1.99"), Packet{Op: OpRead, Minor: MinorPublic, Count: 512})
	if _, _, ok := recv(st); ok {
		t.Error("answered a request for another server")
	}
}

func TestCheck(t *testing.T) {
	for _, tc := range []struct {
		p  Packet
		ok bool
	}{
		{Packet{Op: OpRead, Count: 1024}, true},
		{Packet{Op: OpRead | FlagWait, Count: 1024, Offset: 512, PacketCount: 512}, true},
		{Packet{Op: OpWrite, Count: 1024}, false},
		{Packet{Op: OpRead, Count: 0}, false},
		{Packet{Op: OpRead, Count: 64 * 1024}, false},
		{Packet{Op: OpRead, Count: 1024, Offset: 1024}, false},
		{Packet{Op: OpRead, Count: 1024, PacketCount: 2048}, false},
		{Packet{Op: OpRead, Count: 1024, DiskVersion: 1}, false},
	} {
		p := tc.p
		if got := check(&p) == ""; got != tc.ok {
			t.Errorf("%v: ok %v, want %v", tc.p, got, tc.ok)
		}
		if tc.ok && p.PacketCount != p.Count-p.Offset && tc.p.PacketCount == 0 {
			t.Errorf("%v: packet count not filled in", tc.p)
		}
	}
}

func TestChecksum(t *testing.T) {
	pkt := buildIPv4(1, netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), IPProto, []byte("x"))
	if checksum(pkt[:20]) != 0 {
		t.Error("header checksum does not verify")
	}
	if _, ok := parseIPv4(pkt); !ok {
		t.Error("cannot parse own packet")
	}
	pkt[15] ^= 1
	if _, ok := parseIPv4(pkt); ok {
		t.Error("accepted a corrupt header")
	}
}

func TestMatch(t *testing.T) {
	zero := netip.IPv4Unspecified()
	src := []byte{8, 0, 0x20, 0, 0, 1}
	nd := buildIPv4(1, zero, zero, IPProto, Packet{Op: OpRead, Count: 512}.marshal())
	if !Match(parse(link.Build(link.Broadcast, src, link.TypeIPv4, nd))) {
		t.Error("filter rejects an ND request")
	}
	udp := buildIPv4(1, zero, zero, 17, Packet{}.marshal())
	if Match(parse(link.Build(link.Broadcast, src, link.TypeIPv4, udp))) {
		t.Error("filter accepts UDP")
	}
}

func parse(b []byte) link.Frame {
	f, _ := link.Parse(link.Pad(b))
	return f
}
