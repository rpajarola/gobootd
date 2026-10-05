package rarp

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
	"github.com/rpajarola/gobootd/internal/resolve"
)

const conf = `
network "lan" {
  address = "192.168.1.1/24"
  mac     = "00:11:22:33:44:55"
  udp     = "127.0.0.1:0" # not used: tests run on an in-memory segment
}
service "rarp" {}
service "tftp" {}
host "kali" {
  mac = "8:0:20:1:2:3"
  ip  = "192.168.1.5"
}
host "notallowed" {
  mac      = "8:0:20:1:2:4"
  ip       = "192.168.1.6"
  services = ["tftp"]
}
`

func request(st *linktest.Port, mac string) {
	hw, _ := resolve.ParseMAC(mac)
	p := Packet{Op: OpRequest, SenderHW: hw, TargetHW: hw, SenderIP: netip.IPv4Unspecified(), TargetIP: netip.IPv4Unspecified()}
	st.WriteFrame(link.Build(link.Broadcast, hw, link.TypeRARP, p.Marshal()))
}

func reply(t *testing.T, st *linktest.Port) (link.Frame, Packet, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	for {
		b, err := st.ReadFrame(ctx)
		if err != nil {
			return link.Frame{}, Packet{}, false
		}
		f, _ := link.Parse(b)
		if p, ok := Parse(f.Payload); ok && f.Type == link.TypeRARP && p.Op == OpReply {
			return f, p, true
		}
	}
}

func TestReply(t *testing.T) {
	e := prototest.Setup(t, t.TempDir(), conf)
	log := e.Start(t, &Server{}, "rarp")
	st := e.Segment.Station("8:0:20:1:2:3")

	request(st, "8:0:20:1:2:3")
	f, p, ok := reply(t, st)
	if !ok {
		t.Fatal("no reply")
	}
	if f.Dst.String() != "08:00:20:01:02:03" || f.Src.String() != "00:11:22:33:44:55" {
		t.Errorf("frame %s -> %s", f.Src, f.Dst)
	}
	if p.TargetIP != netip.MustParseAddr("192.168.1.5") {
		t.Errorf("target IP %s, want 192.168.1.5", p.TargetIP)
	}
	if p.SenderIP != netip.MustParseAddr("192.168.1.1") {
		t.Errorf("server IP %s, want 192.168.1.1", p.SenderIP)
	}
	if !log.Contains("rarp reply to kali: 192.168.1.5") {
		t.Error("reply not logged")
	}
}

func TestDenied(t *testing.T) {
	e := prototest.Setup(t, t.TempDir(), conf)
	log := e.Start(t, &Server{}, "rarp")
	st := e.Segment.Station("8:0:20:9:9:9")

	for _, tc := range []struct{ mac, want string }{
		{"8:0:20:9:9:9", "rarp request from 08:00:20:09:09:09 denied (client unknown)"},
		{"8:0:20:1:2:4", "rarp request from notallowed denied (rarp not allowed for this host)"},
	} {
		request(st, tc.mac)
		if _, _, ok := reply(t, st); ok {
			t.Errorf("%s: got a reply", tc.mac)
		}
		if !log.Contains(tc.want) {
			t.Errorf("log does not contain %q", tc.want)
		}
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	hw, _ := resolve.ParseMAC("8:0:20:1:2:3")
	p := Packet{Op: OpReply, SenderHW: hw, SenderIP: netip.MustParseAddr("1.2.3.4"), TargetHW: hw, TargetIP: netip.MustParseAddr("5.6.7.8")}
	q, ok := Parse(p.Marshal())
	if !ok || q.String() != p.String() {
		t.Errorf("round trip: %v %v, want %v", q, ok, p)
	}
}

func TestMatch(t *testing.T) {
	hw, _ := resolve.ParseMAC("8:0:20:1:2:3")
	req := Packet{Op: OpRequest, SenderHW: hw, TargetHW: hw}
	if !Match(parse(link.Build(link.Broadcast, hw, link.TypeRARP, req.Marshal()))) {
		t.Error("filter rejects a RARP request")
	}
	if Match(parse(link.Build(link.Broadcast, hw, link.TypeARP, req.Marshal()))) {
		t.Error("filter accepts ARP")
	}
}

func parse(b []byte) link.Frame {
	f, _ := link.Parse(link.Pad(b))
	return f
}
