package nd

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

// FuzzHandle feeds arbitrary ND packets from the Sun-2 to the handler.
func FuzzHandle(f *testing.F) {
	zero := netip.IPv4Unspecified()
	f.Add([]byte(Packet{Op: OpRead, Minor: MinorPublic, Count: 16 * 512}.marshal()), false)
	f.Add([]byte(Packet{Op: OpRead, Minor: MinorPublic, Block: 16, Count: 4096, Offset: 3072}.marshal()), true)
	f.Add([]byte(Packet{Op: OpWrite, Minor: MinorPublic, Count: 512}.marshal()), false)
	f.Add([]byte(Packet{Op: OpRead, Minor: MinorPublic, Block: 0x7fffffff, Count: 512}.marshal()), false)

	e, _ := setupFuzz(f)
	s := &Server{}
	env := e.ServiceEnv(f, s, "nd", &prototest.Log{})
	s.setup()
	port := &linktest.Recorder{Info: e.Networks["lan"].Interface()}
	src := []byte{8, 0, 0x20, 0, 0, 1}
	f.Fuzz(func(t *testing.T, nd []byte, addressed bool) {
		from, to := zero, zero
		if addressed {
			from, to = netip.MustParseAddr("192.168.1.20"), netip.MustParseAddr("192.168.1.1")
		}
		pkt := buildIPv4(1, from, to, IPProto, nd)
		if len(pkt) > link.MaxFrame-link.HeaderLen {
			return
		}
		s.handle(context.Background(), env, port, link.Build(link.Broadcast, src, link.TypeIPv4, pkt))
		for _, out := range port.Frames() {
			f, _ := link.Parse(out)
			ip, ok := parseIPv4(f.Payload)
			if !ok || len(out) > link.MaxFrame {
				t.Fatalf("sent %d bytes: %x", len(out), out[:min(len(out), 64)])
			}
			if p, ok := parsePacket(ip.payload); !ok || int(p.PacketCount) != len(p.Data) || len(p.Data) > maxData {
				t.Fatalf("sent %v", p)
			}
		}
	})
}

func setupFuzz(f *testing.F) (*prototest.Env, string) {
	dir := f.TempDir()
	os.WriteFile(filepath.Join(dir, "bootyy"), boot1, 0o644)
	os.WriteFile(filepath.Join(dir, "netboot"), boot2, 0o644)
	return prototest.Setup(f, dir, conf), dir
}

func FuzzParseIPv4(f *testing.F) {
	f.Add(buildIPv4(1, netip.IPv4Unspecified(), netip.IPv4Unspecified(), IPProto, make([]byte, 28)))
	f.Fuzz(func(t *testing.T, b []byte) {
		ip, ok := parseIPv4(b)
		if ok && len(ip.payload) > len(b) {
			t.Fatal("payload longer than the packet")
		}
	})
}
