package link

import (
	"bytes"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
)

func listenConfig(t *testing.T, cfg UDPConfig) *UDP {
	t.Helper()
	u, err := ListenUDPConfig(netip.MustParseAddrPort("127.0.0.1:0"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	return u
}

var cookie = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}

// TestL2TPWireFormat checks the datagrams against RFC 3931 as Linux and
// QEMU (udp=on, cookie64=on, counter=on) send them.
func TestL2TPWireFormat(t *testing.T) {
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	u := listenConfig(t, UDPConfig{
		Peers: []netip.AddrPort{sock.LocalAddr().(*net.UDPAddr).AddrPort()},
		L2TP:  &L2TPv3{Session: 0xffffffff, Cookie: cookie, Counter: true},
	})
	frame := Pad(Build(Broadcast, mac("02:00:00:00:00:0a"), TypeARP, []byte("who has")))
	if err := u.WriteFrame(frame); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2000)
	n, err := sock.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("00030000" + "ffffffff" + "0123456789abcdef" + "40000001")
	if !bytes.Equal(buf[:len(want)], want) || !bytes.Equal(buf[len(want):n], frame) {
		t.Errorf("datagram\n%x\nwant header\n%x", buf[:n], want)
	}

	// Received the same way, with any sequence number.
	dg := append(append([]byte(nil), want[:16]...), 0x40, 0x12, 0x34, 0x56)
	dg = append(dg, frame...)
	sock.WriteToUDPAddrPort(dg, u.Addr())
	if got := read(t, u); !bytes.Equal(got, frame) {
		t.Errorf("received %x", got)
	}
}

// TestL2TPCookie: datagrams without the right session and cookie, or raw
// frames, are dropped and do not make their sender a peer.
func TestL2TPCookie(t *testing.T) {
	good := &L2TPv3{Session: 7, Cookie: cookie, Counter: true}
	hub := listenConfig(t, UDPConfig{L2TP: good})
	a := listenConfig(t, UDPConfig{Peers: []netip.AddrPort{hub.Addr()}, L2TP: good})
	frame := Build(Broadcast, mac("02:00:00:00:00:0a"), 0x9000, []byte("hello"))
	for name, cfg := range map[string]UDPConfig{
		"raw":            {},
		"wrong cookie":   {L2TP: &L2TPv3{Session: 7, Cookie: []byte{1, 2, 3, 4, 5, 6, 7, 8}, Counter: true}},
		"wrong session":  {L2TP: &L2TPv3{Session: 8, Cookie: cookie, Counter: true}},
		"no cookie":      {L2TP: &L2TPv3{Session: 7, Counter: true}},
		"no sublayer":    {L2TP: &L2TPv3{Session: 7, Cookie: cookie}},
		"shorter cookie": {L2TP: &L2TPv3{Session: 7, Cookie: cookie[:4], Counter: true}},
	} {
		cfg.Peers = []netip.AddrPort{hub.Addr()}
		bad := listenConfig(t, cfg)
		bad.WriteFrame(frame)
		if got := read(t, hub); got != nil && name != "no sublayer" {
			t.Errorf("%s: received %x", name, got)
		}
		if hub.Knows(mac("02:00:00:00:00:0a")) {
			t.Errorf("%s: learned the sender", name)
		}
	}
	a.WriteFrame(frame)
	if got := read(t, hub); got == nil || !bytes.Equal(got[:len(frame)], frame) {
		t.Fatalf("good frame: %x", got)
	}
	if !hub.Knows(mac("02:00:00:00:00:0a")) {
		t.Error("did not learn the good sender")
	}
}

// TestKeepalive: a passive endpoint learns a peer from its keepalive, and
// does not pass the keepalive on.
func TestKeepalive(t *testing.T) {
	l := &L2TPv3{Session: 1, Cookie: cookie[:4]}
	hub := listenConfig(t, UDPConfig{L2TP: l})
	me := mac("02:00:00:00:00:0b")
	listenConfig(t, UDPConfig{Peers: []netip.AddrPort{hub.Addr()}, L2TP: l, KeepaliveMAC: me})
	if got := read(t, hub); got != nil {
		t.Errorf("keepalive delivered: %x", got)
	}
	if !hub.Knows(me) {
		t.Fatal("keepalive did not teach the peer")
	}
	// Now the hub reaches the peer without having heard anything else.
	if n, _ := hub.WriteFrameExcept(Build(me, mac("02:00:00:00:00:01"), 0x9000, nil), netip.AddrPort{}); n != 1 {
		t.Errorf("sent to %d peers", n)
	}
}

// TestGroup: a raw and an L2TPv3 transport bridged as one.
func TestGroup(t *testing.T) {
	l := &L2TPv3{Session: 1, Cookie: cookie}
	raw := listen(t)
	tun := listenConfig(t, UDPConfig{L2TP: l})
	g := NewGroup(raw, tun)
	a := listen(t, raw.Addr())
	b := listenConfig(t, UDPConfig{Peers: []netip.AddrPort{tun.Addr()}, L2TP: l})
	ma, mb := mac("02:00:00:00:00:0a"), mac("02:00:00:00:00:0b")

	a.WriteFrame(Build(Broadcast, ma, 0x9000, []byte("a")))
	if read(t, g) == nil {
		t.Fatal("raw frame not received")
	}
	b.WriteFrame(Build(Broadcast, mb, 0x9000, []byte("b")))
	if read(t, g) == nil {
		t.Fatal("L2TPv3 frame not received")
	}
	// Unicast goes to the member that knows the destination only.
	g.WriteFrame(Build(mb, ma, 0x9000, []byte("to b")))
	if read(t, b) == nil {
		t.Error("unicast not delivered")
	}
	if read(t, a) != nil {
		t.Error("unicast to b also went to a")
	}
	g.WriteFrame(Build(Broadcast, ma, 0x9000, []byte("all")))
	if read(t, a) == nil || read(t, b) == nil {
		t.Error("broadcast not delivered to both")
	}
}

func TestParseCookie(t *testing.T) {
	for s, ok := range map[string]bool{"0x0123456789abcdef": true, "DEADBEEF": true, "12345": false, "0x01234567890": false, "xyzzyxyz": false} {
		if _, err := ParseCookie(s); (err == nil) != ok {
			t.Errorf("%q: %v", s, err)
		}
	}
}
