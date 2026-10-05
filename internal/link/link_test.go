package link

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func listen(t *testing.T, peers ...netip.AddrPort) *UDP {
	t.Helper()
	u, err := ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), peers)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	return u
}

func read(t *testing.T, p Port) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	b, err := p.ReadFrame(ctx)
	if err != nil {
		return nil
	}
	return b
}

func mac(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func TestUDPLearning(t *testing.T) {
	hub := listen(t)
	a := listen(t, hub.Addr())
	b := listen(t, hub.Addr())
	ma, mb := mac("02:00:00:00:00:0a"), mac("02:00:00:00:00:0b")

	// The hub only knows peers that have sent something.
	if err := hub.WriteFrame(Build(Broadcast, mac("02:00:00:00:00:01"), 0x9000, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	if read(t, a) != nil {
		t.Error("frame sent to a peer that never sent")
	}
	a.WriteFrame(Build(Broadcast, ma, 0x9000, []byte("from a")))
	b.WriteFrame(Build(Broadcast, mb, 0x9000, []byte("from b")))
	if read(t, hub) == nil || read(t, hub) == nil {
		t.Fatal("hub did not receive")
	}

	// Broadcasts go to every peer; unicast only to where the
	// destination was heard.
	hub.WriteFrame(Build(Broadcast, mac("02:00:00:00:00:01"), 0x9000, []byte("all")))
	if read(t, a) == nil || read(t, b) == nil {
		t.Error("broadcast did not reach both peers")
	}
	hub.WriteFrame(Build(mb, mac("02:00:00:00:00:01"), 0x9000, []byte("to b")))
	if read(t, b) == nil {
		t.Error("unicast did not reach b")
	}
	if read(t, a) != nil {
		t.Error("unicast for b reached a")
	}
	// A cancelled read does not break later reads.
	if read(t, a) != nil {
		t.Error("unexpected frame")
	}
	hub.WriteFrame(Build(ma, mac("02:00:00:00:00:01"), 0x9000, []byte("to a")))
	if read(t, a) == nil {
		t.Error("read after a timeout failed")
	}
}

func TestNetworkDispatch(t *testing.T) {
	hub := listen(t)
	peer := listen(t, hub.Addr())
	me := mac("02:00:00:00:00:01")
	n := NewNetwork("lan", hub, me, netip.MustParsePrefix("10.0.0.1/24"))
	rarp := n.Subscribe(MatchType(TypeRARP))
	def := n.SetDefault()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)

	other := mac("02:00:00:00:00:99")
	src := mac("02:00:00:00:00:0a")
	for _, tc := range []struct {
		name  string
		frame []byte
		want  Port
	}{
		{"rarp broadcast", Build(Broadcast, src, TypeRARP, []byte("r")), rarp},
		{"ip to us", Build(me, src, TypeIPv4, []byte("i")), def},
		{"ip to someone else", Build(other, src, TypeIPv4, []byte("o")), nil},
		{"our own frame", Build(Broadcast, me, TypeIPv4, []byte("m")), nil},
	} {
		peer.WriteFrame(tc.frame)
		gotR, gotD := read(t, rarp), read(t, def)
		switch {
		case tc.want == rarp && (gotR == nil || gotD != nil),
			tc.want == def && (gotD == nil || gotR != nil),
			tc.want == nil && (gotR != nil || gotD != nil):
			t.Errorf("%s: rarp got %v, default got %v", tc.name, gotR != nil, gotD != nil)
		}
	}
	// Frames written by a subscriber go out on the transport.
	rarp.WriteFrame(Build(src, me, TypeRARP, []byte("reply")))
	if f, ok := Parse(read(t, peer)); !ok || string(f.Src) != string(me) {
		t.Error("reply not sent")
	}
}
