package dhcp

import (
	"net"
	"net/netip"
	"testing"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

// FuzzHandle feeds arbitrary DHCP messages to the handler: it must not
// panic, and may only answer known hosts, with their own address.
func FuzzHandle(f *testing.F) {
	f.Add(newRequest(clientMAC, Discover).Marshal())
	f.Add(newRequest(clientMAC, Request, Option{OptRequestedIP, ip4(kaliIP)}).Marshal())
	f.Add(newRequest(clientMAC, 0).Marshal())
	f.Add(newRequest(clientMAC, Discover, Option{OptOverload, []byte{3}}, Option{OptMaxSize, []byte{0, 1}}).Marshal())

	e := prototest.Setup(f, f.TempDir(), conf)
	s := &Server{}
	env := e.ServiceEnv(f, s, "dhcp", &prototest.Log{})
	if err := s.setup(); err != nil {
		f.Fatal(err)
	}
	port := &linktest.Recorder{Info: e.Networks["lan"].Interface()}
	src := netip.AddrPortFrom(netip.IPv4Unspecified(), ClientPort)
	dst := netip.AddrPortFrom(broadcast, ServerPort)
	f.Fuzz(func(t *testing.T, msg []byte) {
		s.handle(env, port, buildUDP(link.Broadcast, clientMAC, src, dst, 1, msg))
		for _, out := range port.Frames() {
			f, _ := link.Parse(out)
			d, ok := parseUDP(f)
			if !ok {
				t.Fatalf("sent %x", out)
			}
			p, err := Parse(d.Payload)
			if err != nil || p.Op != OpReply {
				t.Fatalf("sent %v %v", p, err)
			}
			if p.Type() == Nak {
				continue
			}
			h, err := e.Inventory.ByMAC(net.HardwareAddr(p.CHAddr[:6]))
			if err != nil || (h.IP != p.YIAddr && !p.YIAddr.IsUnspecified()) {
				t.Fatalf("answered %v", p)
			}
		}
	})
}
