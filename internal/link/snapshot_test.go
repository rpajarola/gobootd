package link

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestPeersSnapshot(t *testing.T) {
	static := netip.MustParseAddrPort("127.0.0.1:5099")
	u := listen(t, static)

	// A configured peer that has not been heard from yet.
	ps := u.PeersSnapshot()
	if len(ps) != 1 || !ps[0].Static || ps[0].Addr != static || !ps[0].LastSeen.IsZero() {
		t.Errorf("static peers %+v", ps)
	}

	// An unknown sender is learned, with its MAC.
	from := listen(t, u.Addr())
	m := net.HardwareAddr{0x08, 0, 0x20, 0, 0, 1}
	from.WriteFrame(Build(Broadcast, m, 0x9000, []byte("x")))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := u.ReadFrame(ctx); err != nil {
		t.Fatal(err)
	}
	ps = u.PeersSnapshot()
	if len(ps) != 2 {
		t.Fatalf("peers %+v", ps)
	}
	var learned *PeerState
	for i := range ps {
		if !ps[i].Static {
			learned = &ps[i]
		}
	}
	if learned == nil || learned.Addr != from.Addr() || learned.LastSeen.IsZero() {
		t.Errorf("learned peer %+v", learned)
	}

	ms := u.MACsSnapshot()
	if len(ms) != 1 || ms[0].MAC.String() != m.String() || ms[0].Addr != from.Addr() {
		t.Errorf("macs %+v", ms)
	}
}

func TestPeersSnapshotStaticHeard(t *testing.T) {
	// A listener answers a frame from the transport under test, so it
	// is heard as the configured peer it is, not as a learned one.
	peer := listen(t)
	u := listen(t, peer.Addr())

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := u.WriteFrame(Build(Broadcast, net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0a}, 0x9000, []byte("ping"))); err != nil {
		t.Fatal(err)
	}
	if read(t, peer) == nil {
		t.Fatal("peer did not receive")
	}
	m := net.HardwareAddr{0x08, 0, 0x20, 0, 0, 2}
	peer.WriteFrame(Build(Broadcast, m, 0x9000, []byte("pong")))
	if _, err := u.ReadFrame(ctx); err != nil {
		t.Fatal(err)
	}
	ps := u.PeersSnapshot()
	if len(ps) != 1 || !ps[0].Static || ps[0].LastSeen.IsZero() {
		t.Errorf("static peer after hearing from it: %+v", ps)
	}
	// The peer's MAC is attributed to the configured peer.
	if l := u.MACsSnapshot(); len(l) != 1 || l[0].Addr != peer.Addr() || l[0].LastSeen.IsZero() {
		t.Errorf("macs %+v", l)
	}
}

func TestGroupTransportSnapshots(t *testing.T) {
	a := listen(t)
	b := listen(t)
	g := NewGroup(a, b)
	ts := g.TransportSnapshots()
	if len(ts) != 2 || ts[0].Name != a.Interface().Name || ts[1].Name != b.Interface().Name {
		t.Fatalf("transports %+v", ts)
	}
	if ts[0].Encapsulation != "raw" {
		t.Errorf("encapsulation %q", ts[0].Encapsulation)
	}
}
