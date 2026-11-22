package link

import (
	"bytes"
	"encoding/binary"
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

// TestRxErrors: every dropped datagram is counted with its reason, and
// sequence errors are counted for the frames delivered.
func TestRxErrors(t *testing.T) {
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	l := &L2TPv3{Session: 7, Cookie: cookie, Counter: true}
	u := listenConfig(t, UDPConfig{L2TP: l})
	frame := Pad(Build(Broadcast, mac("02:00:00:00:00:0a"), TypeARP, []byte("x")))
	hdr := func(word0, session uint32, ck []byte, seq uint32) []byte {
		b := binary.BigEndian.AppendUint32(nil, word0)
		b = binary.BigEndian.AppendUint32(b, session)
		b = append(b, ck...)
		return binary.BigEndian.AppendUint32(b, 0x40000000|seq)
	}
	send := func(dg []byte) { sock.WriteToUDPAddrPort(dg, u.Addr()) }
	good := func(seq uint32) {
		t.Helper()
		send(append(hdr(l2tpData, 7, cookie, seq), frame...))
		if read(t, u) == nil {
			t.Fatalf("frame %d not delivered", seq)
		}
	}

	send([]byte{0, 3, 0, 0})                                          // short
	send(append(hdr(0xc0030000, 7, cookie, 0), frame...))             // control message
	send(append(hdr(0x00020000, 7, cookie, 0), frame...))             // L2TPv2
	send(append(hdr(l2tpData, 8, cookie, 0), frame...))               // session
	send(append(hdr(l2tpData, 7, make([]byte, 8), 0), frame...))      // cookie
	send(append(hdr(l2tpData, 7, cookie, 0), frame[:HeaderLen-1]...)) // no Ethernet header
	good(1)
	good(2)
	good(5) // 3 and 4 lost...
	good(3) // ...or late
	good(6)
	good(1<<24 - 2000) // far behind: the peer started over
	good(1<<24 - 1999)

	want := RxErrors{Short: 2, BadHeader: 2, Session: 1, Cookie: 1, SeqLost: 2, SeqLate: 1, SeqRestart: 1}
	if got := u.RxErrors(); got != want {
		t.Errorf("counters %+v\nwant %+v", got, want)
	}
	if got := u.RxErrors().Dropped(); got != 6 {
		t.Errorf("dropped %d, want 6", got)
	}
}

func TestSeqCheck(t *testing.T) {
	const mod = 1 << 24
	for _, tc := range []struct {
		expect, seq   uint32
		lost          uint32
		late, restart bool
		next          uint32
	}{
		{5, 5, 0, false, false, 6},
		{5, 8, 3, false, false, 9},
		{5, 4, 0, true, false, 5},
		{5, 5 - seqWindow + mod, 0, true, false, 5},
		{5, 5 - seqWindow - 1 + mod, 0, false, true, 5 - seqWindow + mod},
		{mod - 1, mod - 1, 0, false, false, 0}, // wraps around
		{mod - 1, 1, 2, false, false, 2},
		{0, mod - 1, 0, true, false, 0},
	} {
		lost, late, restart, next := seqCheck(tc.expect, tc.seq)
		if lost != tc.lost || late != tc.late || restart != tc.restart || next != tc.next {
			t.Errorf("seqCheck(%d, %d) = %d %v %v %d, want %d %v %v %d", tc.expect, tc.seq,
				lost, late, restart, next, tc.lost, tc.late, tc.restart, tc.next)
		}
	}
}

// TestSeqPerPeer: each peer gets consecutive sequence numbers, even when
// frames go to only one of them.
func TestSeqPerPeer(t *testing.T) {
	l := &L2TPv3{Session: 7, Cookie: cookie, Counter: true}
	hub := listenConfig(t, UDPConfig{L2TP: l})
	a := listenConfig(t, UDPConfig{L2TP: l, Peers: []netip.AddrPort{hub.Addr()}})
	b := listenConfig(t, UDPConfig{L2TP: l, Peers: []netip.AddrPort{hub.Addr()}})
	// The hub learns both peers, and that station is behind a.
	station := mac("02:00:00:00:00:0a")
	a.WriteFrame(Build(Broadcast, station, TypeARP, []byte("a")))
	b.WriteFrame(Build(Broadcast, mac("02:00:00:00:00:0c"), TypeARP, []byte("b")))
	for range 2 {
		if read(t, hub) == nil {
			t.Fatal("hub did not hear a peer")
		}
	}
	for range 3 {
		hub.WriteFrame(Build(station, mac("02:00:00:00:00:0b"), TypeARP, []byte("to a")))
		if read(t, a) == nil {
			t.Fatal("a did not get its frame")
		}
	}
	for range 2 {
		hub.WriteFrame(Build(Broadcast, mac("02:00:00:00:00:0b"), TypeARP, []byte("all")))
	}
	for _, u := range []*UDP{a, b} {
		for range 2 {
			if read(t, u) == nil {
				t.Fatal("broadcast not delivered")
			}
		}
		if e := u.RxErrors(); e != (RxErrors{}) {
			t.Errorf("%s: %+v", u.Interface().Name, e)
		}
	}
}
