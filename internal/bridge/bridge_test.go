package bridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
)

func listen(t *testing.T, peers ...netip.AddrPort) *link.UDP {
	t.Helper()
	u, err := link.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), peers)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	return u
}

func read(p link.Port) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	b, err := p.ReadFrame(ctx)
	if err != nil {
		return nil
	}
	return b
}

func mac(s string) net.HardwareAddr {
	m, _ := net.ParseMAC(s)
	return m
}

func TestBridge(t *testing.T) {
	seg := linktest.NewSegment()
	lanPort := seg.Station("02:00:00:00:00:fe") // the bridge's capture
	sun := seg.Station("08:00:20:00:00:01")
	other := seg.Station("08:00:20:00:00:02")
	udp := listen(t)
	b := &Bridge{LAN: lanPort, UDP: udp, Log: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)

	bootd := listen(t, udp.Addr())
	simh := listen(t, udp.Addr())
	mBootd, mSimh := mac("02:00:00:00:00:01"), mac("02:00:00:00:00:02")
	mSun, mOther := mac("08:00:20:00:00:01"), mac("08:00:20:00:00:02")

	// Peers announce themselves; their broadcasts reach the LAN and the
	// other peer.
	bootd.WriteFrame(link.Build(link.Broadcast, mBootd, 0x9000, []byte("bootd")))
	if read(sun) == nil {
		t.Error("broadcast from a peer did not reach the LAN")
	}
	read(other)
	simh.WriteFrame(link.Build(link.Broadcast, mSimh, 0x9000, []byte("simh")))
	if read(bootd) == nil {
		t.Error("broadcast was not relayed to the other peer")
	}
	read(sun)
	read(other)

	// A broadcast from the LAN reaches both peers.
	sun.WriteFrame(link.Build(link.Broadcast, mSun, link.TypeRARP, []byte("rarp")))
	if read(bootd) == nil || read(simh) == nil {
		t.Error("LAN broadcast did not reach both peers")
	}
	// Unicast from the LAN only goes to the peer that has the address.
	sun.WriteFrame(link.Build(mBootd, mSun, link.TypeIPv4, []byte("tftp")))
	if read(bootd) == nil {
		t.Error("unicast did not reach bootd")
	}
	if read(simh) != nil {
		t.Error("unicast for bootd reached simh")
	}
	// Unicast from a peer to the LAN.
	bootd.WriteFrame(link.Build(mSun, mBootd, link.TypeIPv4, []byte("data")))
	if read(sun) == nil {
		t.Error("unicast from bootd did not reach the LAN")
	}
	if read(simh) != nil {
		t.Error("unicast for the LAN reached simh")
	}
	// Traffic between two LAN machines stays on the LAN.
	read(other)
	other.WriteFrame(link.Build(link.Broadcast, mOther, 0x9000, []byte("hello")))
	read(bootd)
	read(simh)
	sun.WriteFrame(link.Build(mOther, mSun, link.TypeIPv4, []byte("lan only")))
	if read(bootd) != nil || read(simh) != nil {
		t.Error("LAN unicast was sent to peers")
	}
}

type syncWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func TestBridgeHostAndStatsLogging(t *testing.T) {
	seg := linktest.NewSegment()
	lanPort := seg.Station("02:00:00:00:00:fe")
	sun := seg.Station("08:00:20:00:00:01")
	udp := listen(t)

	var logBuf bytes.Buffer
	var logMu sync.Mutex
	logHandler := &syncWriter{w: &logBuf, mu: &logMu}
	logger := slog.New(slog.NewTextHandler(logHandler, &slog.HandlerOptions{Level: slog.LevelInfo}))

	b := &Bridge{
		LAN:           lanPort,
		UDP:           udp,
		Log:           logger,
		StatsInterval: 30 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)

	bootd := listen(t, udp.Addr())
	mBootd := mac("02:00:00:00:00:01")
	mSun := mac("08:00:20:00:00:01")
	// 1. Peer announces itself first so udp learns the peer
	bootd.WriteFrame(link.Build(link.Broadcast, mBootd, 0x9000, []byte("bootd1")))
	if read(sun) == nil {
		t.Fatal("UDP frame did not reach LAN")
	}

	// Peer sends again (same host, should not trigger another "new host" log)
	bootd.WriteFrame(link.Build(link.Broadcast, mBootd, 0x9000, []byte("bootd2")))
	if read(sun) == nil {
		t.Fatal("UDP frame 2 did not reach LAN")
	}

	// 2. Now that udp knows the peer, send from LAN
	sun.WriteFrame(link.Build(link.Broadcast, mSun, link.TypeRARP, []byte("rarp1")))
	if read(bootd) == nil {
		t.Fatal("LAN frame did not reach bootd")
	}

	// Send from LAN again (same host, should not trigger another "new host" log)
	sun.WriteFrame(link.Build(link.Broadcast, mSun, link.TypeRARP, []byte("rarp2")))
	if read(bootd) == nil {
		t.Fatal("LAN frame 2 did not reach bootd")
	}

	// Wait for periodic stats logging ticker to fire
	time.Sleep(100 * time.Millisecond)

	logMu.Lock()
	logs := logBuf.String()
	logMu.Unlock()

	// 1) Verify "new host" was logged for Sun on LAN
	if !strings.Contains(logs, `msg="new host"`) || !strings.Contains(logs, "08:00:20:00:00:01") {
		t.Errorf("expected new host log for Sun (08:00:20:00:00:01), got:\n%s", logs)
	}
	// Verify "new host" was only logged once for Sun
	if n := strings.Count(logs, "08:00:20:00:00:01"); n != 1 {
		t.Errorf("expected exactly 1 log for Sun MAC, got %d:\n%s", n, logs)
	}

	// 2) Verify "new host" was logged for Bootd on UDP
	if !strings.Contains(logs, "02:00:00:00:00:01") {
		t.Errorf("expected new host log for bootd (02:00:00:00:00:01), got:\n%s", logs)
	}
	if n := strings.Count(logs, `msg="new host"`); n != 2 {
		t.Errorf("expected exactly 2 new host logs (1 LAN, 1 UDP), got %d:\n%s", n, logs)
	}

	// 3) Verify "interface stats" was logged periodically
	if !strings.Contains(logs, `msg="interface stats"`) {
		t.Errorf("expected interface stats log, got:\n%s", logs)
	}

	// Verify statistics snapshots
	ls := b.LANStats()
	if ls.Hosts != 1 {
		t.Errorf("LAN hosts = %d, want 1", ls.Hosts)
	}
	if ls.RxPackets != 2 {
		t.Errorf("LAN rx_packets = %d, want 2", ls.RxPackets)
	}
	if ls.TxPackets != 2 {
		t.Errorf("LAN tx_packets = %d, want 2", ls.TxPackets)
	}
	if ls.Errors != 0 {
		t.Errorf("LAN errors = %d, want 0", ls.Errors)
	}

	us := b.UDPStats()
	if us.Hosts != 1 {
		t.Errorf("UDP hosts = %d, want 1", us.Hosts)
	}
	if us.RxPackets != 2 {
		t.Errorf("UDP rx_packets = %d, want 2", us.RxPackets)
	}
	if us.TxPackets != 2 {
		t.Errorf("UDP tx_packets = %d, want 2", us.TxPackets)
	}
	if us.Errors != 0 {
		t.Errorf("UDP errors = %d, want 0", us.Errors)
	}
}

type mockPort struct {
	info     *link.Interface
	readCh   chan []byte
	writeErr error
}

func (m *mockPort) Interface() *link.Interface { return m.info }
func (m *mockPort) ReadFrame(ctx context.Context) ([]byte, error) {
	select {
	case f := <-m.readCh:
		return f, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (m *mockPort) WriteFrame(frame []byte) error { return m.writeErr }
func (m *mockPort) Close() error                  { return nil }

func TestBridgeErrorStats(t *testing.T) {
	mockLAN := &mockPort{
		info:     &link.Interface{Name: "mocklan"},
		readCh:   make(chan []byte, 10),
		writeErr: errors.New("tx error"),
	}
	udp := listen(t)

	b := &Bridge{
		LAN:           mockLAN,
		UDP:           udp,
		Log:           slog.New(slog.DiscardHandler),
		StatsInterval: -1,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)

	bootd := listen(t, udp.Addr())

	// 1. Deliver runt frame to LAN (< 14 bytes) -> triggers rx error
	mockLAN.readCh <- []byte("short")
	time.Sleep(20 * time.Millisecond)

	ls := b.LANStats()
	if ls.Errors != 1 {
		t.Errorf("LAN errors = %d, want 1 (for runt frame)", ls.Errors)
	}

	// 2. Deliver broadcast frame from UDP -> Bridge attempts to write to mockLAN, which fails with tx error
	bootd.WriteFrame(link.Build(link.Broadcast, mac("02:00:00:00:00:01"), 0x9000, []byte("data")))
	time.Sleep(20 * time.Millisecond)

	ls = b.LANStats()
	if ls.Errors != 2 {
		t.Errorf("LAN errors = %d, want 2 (for runt frame + tx error)", ls.Errors)
	}
}

func TestBridgeHostIPAndPeerPortVariation(t *testing.T) {
	seg := linktest.NewSegment()
	lanPort := seg.Station("02:00:00:00:00:fe")
	sun := seg.Station("08:00:20:00:00:01")
	sun2 := seg.Station("08:00:20:00:00:02")
	udp := listen(t)

	var logBuf bytes.Buffer
	var logMu sync.Mutex
	logHandler := &syncWriter{w: &logBuf, mu: &logMu}
	logger := slog.New(slog.NewTextHandler(logHandler, &slog.HandlerOptions{Level: slog.LevelInfo}))

	b := &Bridge{
		LAN:           lanPort,
		UDP:           udp,
		Log:           logger,
		StatsInterval: -1,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)

	// Peer 1 sends from socket A
	peerA := listen(t, udp.Addr())
	mPeerA := mac("02:00:00:00:00:01")

	// IPv4 packet from Peer A
	ipPktA := make([]byte, 20)
	ipPktA[0] = 0x45 // IPv4, IHL 5
	copy(ipPktA[12:16], []byte{10, 0, 0, 1})
	peerA.WriteFrame(link.Build(link.Broadcast, mPeerA, link.TypeIPv4, ipPktA))
	read(sun)

	// Same peer host sends from another socket B (different source port on 127.0.0.1)
	peerB := listen(t, udp.Addr())
	peerB.WriteFrame(link.Build(link.Broadcast, mPeerA, link.TypeIPv4, ipPktA))
	read(sun)

	// Host on LAN sends ARP packet
	mSun := mac("08:00:20:00:00:01")
	arpPkt := make([]byte, 28)
	binary.BigEndian.PutUint16(arpPkt[0:2], 1)             // HW Ethernet
	binary.BigEndian.PutUint16(arpPkt[2:4], link.TypeIPv4) // Proto IPv4
	arpPkt[4] = 6                                         // HW len
	arpPkt[5] = 4                                         // Proto len
	binary.BigEndian.PutUint16(arpPkt[6:8], 1)             // Op Request
	copy(arpPkt[8:14], mSun)                              // Sender MAC
	copy(arpPkt[14:18], []byte{192, 168, 1, 55})          // Sender IP
	sun.WriteFrame(link.Build(link.Broadcast, mSun, link.TypeARP, arpPkt))
	read(peerA)

	// Host on LAN sends non-IP frame first, then sends IPv4 packet later
	mSun2 := mac("08:00:20:00:00:02")
	sun2.WriteFrame(link.Build(link.Broadcast, mSun2, 0x9000, []byte("loopback")))
	read(peerA)

	ipPktSun2 := make([]byte, 20)
	ipPktSun2[0] = 0x45
	copy(ipPktSun2[12:16], []byte{192, 168, 1, 99})
	sun2.WriteFrame(link.Build(link.Broadcast, mSun2, link.TypeIPv4, ipPktSun2))
	read(peerA)

	time.Sleep(50 * time.Millisecond)

	logMu.Lock()
	logs := logBuf.String()
	logMu.Unlock()

	// 1. "new peer" should only be logged once for 127.0.0.1, even though peerA and peerB used different ports
	if n := strings.Count(logs, `msg="new peer"`); n != 1 {
		t.Errorf("expected 1 'new peer' log, got %d:\n%s", n, logs)
	}
	if !strings.Contains(logs, "peer=127.0.0.1") {
		t.Errorf("expected peer IP without port (peer=127.0.0.1), got:\n%s", logs)
	}

	// 2. Peer A's "new host" should include IP 10.0.0.1
	if !strings.Contains(logs, `mac=02:00:00:00:00:01 ip=10.0.0.1 peer=127.0.0.1`) {
		t.Errorf("expected new host with IP and peer for peer A, got:\n%s", logs)
	}

	// 3. Sun's "new host" should include IP 192.168.1.55 from ARP
	if !strings.Contains(logs, `mac=08:00:20:00:00:01 ip=192.168.1.55`) {
		t.Errorf("expected new host with ARP IP for sun, got:\n%s", logs)
	}

	// 4. Sun 2 had non-IP first, then IPv4 packet: should log "new host" without IP, then "host ip" with IP
	if !strings.Contains(logs, `msg="new host" interface=station mac=08:00:20:00:00:02`) {
		t.Errorf("expected new host without IP for sun2, got:\n%s", logs)
	}
	if !strings.Contains(logs, `msg="host ip" interface=station mac=08:00:20:00:00:02 ip=192.168.1.99`) {
		t.Errorf("expected host ip log for sun2, got:\n%s", logs)
	}
}

func TestBridgeSwitchFiltering(t *testing.T) {
	seg := linktest.NewSegment()
	lanPort := seg.Station("02:00:00:00:00:fe") // Bridge's LAN interface MAC
	hostA := seg.Station("08:00:20:00:00:10")
	hostB := seg.Station("08:00:20:00:00:20")
	udp := listen(t)

	b := &Bridge{
		LAN:           lanPort,
		UDP:           udp,
		Log:           slog.New(slog.DiscardHandler),
		StatsInterval: -1,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)

	peer1 := listen(t, udp.Addr())
	peer2 := listen(t, udp.Addr())
	mPeer1 := mac("02:00:00:00:00:11")
	mPeer2 := mac("02:00:00:00:00:22")
	mHostA := mac("08:00:20:00:00:10")
	mHostB := mac("08:00:20:00:00:20")
	mBridgeLAN := mac("02:00:00:00:00:fe")
	mUnknown := mac("08:00:20:ff:ff:ff")

	// 1. Peer 1 and Peer 2 announce themselves to UDP
	peer1.WriteFrame(link.Build(link.Broadcast, mPeer1, 0x9000, []byte("peer1-ann")))
	read(hostA)
	read(hostB)
	peer2.WriteFrame(link.Build(link.Broadcast, mPeer2, 0x9000, []byte("peer2-ann")))
	read(hostA)
	read(hostB)
	read(peer1)

	// 2. Host A and Host B announce themselves to LAN
	hostA.WriteFrame(link.Build(link.Broadcast, mHostA, 0x9000, []byte("hostA-ann")))
	read(peer1)
	read(peer2)
	read(hostB)
	hostB.WriteFrame(link.Build(link.Broadcast, mHostB, 0x9000, []byte("hostB-ann")))
	read(peer1)
	read(peer2)
	read(hostA)

	// Verify both sides are learned
	var mPeer1Arr, mHostAArr [6]byte
	copy(mPeer1Arr[:], mPeer1)
	copy(mHostAArr[:], mHostA)
	if !b.isUDP(mPeer1Arr) {
		t.Error("expected peer1 to be known on UDP")
	}
	if !b.isLAN(mHostAArr) {
		t.Error("expected hostA to be known on LAN")
	}

	// 3. Test: Unicast LAN-to-LAN traffic should be filtered from UDP
	hostA.WriteFrame(link.Build(mHostB, mHostA, link.TypeIPv4, []byte("lan-to-lan")))
	read(hostB) // hostB sees it on physical segment
	if p1 := read(peer1); p1 != nil {
		t.Errorf("expected peer1 NOT to receive LAN-to-LAN unicast, got: %s", p1)
	}
	if p2 := read(peer2); p2 != nil {
		t.Errorf("expected peer2 NOT to receive LAN-to-LAN unicast, got: %s", p2)
	}

	// 4. Test: Unicast UDP-to-UDP traffic should be filtered from LAN
	peer1.WriteFrame(link.Build(mPeer2, mPeer1, link.TypeIPv4, []byte("udp-to-udp")))
	if read(peer2) == nil {
		t.Error("expected peer2 to receive unicast from peer1")
	}
	if hA := read(hostA); hA != nil {
		t.Errorf("expected hostA NOT to receive UDP-to-UDP unicast, got: %s", hA)
	}
	if hB := read(hostB); hB != nil {
		t.Errorf("expected hostB NOT to receive UDP-to-UDP unicast, got: %s", hB)
	}

	// 5. Test: Unicast LAN to UDP peer (hostA -> peer1)
	hostA.WriteFrame(link.Build(mPeer1, mHostA, link.TypeIPv4, []byte("hostA-to-peer1")))
	if read(peer1) == nil {
		t.Error("expected peer1 to receive unicast from hostA")
	}
	if read(peer2) != nil {
		t.Error("expected peer2 NOT to receive unicast destined for peer1")
	}

	// 6. Test: Unicast UDP peer to LAN (peer1 -> hostA)
	peer1.WriteFrame(link.Build(mHostA, mPeer1, link.TypeIPv4, []byte("peer1-to-hostA")))
	if read(hostA) == nil {
		t.Error("expected hostA to receive unicast from peer1")
	}
	if read(peer2) != nil {
		t.Error("expected peer2 NOT to receive unicast destined for LAN hostA")
	}

	// 7. Test: Frame destined to bridge LAN interface MAC should be filtered from UDP
	hostA.WriteFrame(link.Build(mBridgeLAN, mHostA, link.TypeIPv4, []byte("to-bridge-mac")))
	if read(peer1) != nil || read(peer2) != nil {
		t.Error("expected traffic destined to bridge LAN interface MAC to be filtered from UDP")
	}

	// 8. Test: Unknown unicast from LAN should flood to UDP
	hostA.WriteFrame(link.Build(mUnknown, mHostA, link.TypeIPv4, []byte("lan-unknown")))
	read(hostB)
	if read(peer1) == nil && read(peer2) == nil {
		t.Error("expected unknown unicast from LAN to flood to UDP")
	}

	// 9. Test: Unknown unicast from UDP should flood to LAN and other UDP peers
	peer1.WriteFrame(link.Build(mUnknown, mPeer1, link.TypeIPv4, []byte("udp-unknown")))
	if read(hostA) == nil {
		t.Error("expected unknown unicast from UDP to flood to LAN")
	}
	read(hostB)
	if read(peer2) == nil {
		t.Error("expected unknown unicast from UDP to flood to other UDP peer")
	}

	// 10. Test: Invalid frames (multicast source, all-zero source, src==dst)
	badSrc1 := mac("01:00:5e:00:00:01") // multicast source
	peer1.WriteFrame(link.Build(mHostA, badSrc1, link.TypeIPv4, []byte("bad1")))
	if read(hostA) != nil {
		t.Error("expected frame with multicast source MAC to be dropped")
	}

	badSrc2 := mac("00:00:00:00:00:00") // all-zero source
	peer1.WriteFrame(link.Build(mHostA, badSrc2, link.TypeIPv4, []byte("bad2")))
	if read(hostA) != nil {
		t.Error("expected frame with all-zero source MAC to be dropped")
	}

	// src == dst loopback
	peer1.WriteFrame(link.Build(mPeer1, mPeer1, link.TypeIPv4, []byte("loopback")))
	if read(hostA) != nil {
		t.Error("expected frame with src == dst to be dropped")
	}
}


