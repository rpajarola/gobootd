package bridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
)

func rarpFrame(op uint16, src, client net.HardwareAddr, ip string) []byte {
	p := make([]byte, 28)
	binary.BigEndian.PutUint16(p[0:], 1)
	binary.BigEndian.PutUint16(p[2:], link.TypeIPv4)
	p[4], p[5] = 6, 4
	binary.BigEndian.PutUint16(p[6:], op)
	copy(p[8:], src)
	copy(p[18:], client)
	if ip != "" {
		a := netip.MustParseAddr(ip).As4()
		copy(p[24:], a[:])
	}
	dst := link.Broadcast
	if op == 4 {
		dst = client
	}
	return link.Build(dst, src, link.TypeRARP, p)
}

func bootpFrame(op byte, src, client net.HardwareAddr, yiaddr string) []byte {
	d := make([]byte, 300)
	d[0], d[1], d[2] = op, 1, 6
	if yiaddr != "" {
		a := netip.MustParseAddr(yiaddr).As4()
		copy(d[16:], a[:])
	}
	copy(d[28:], client)
	sport, dport := uint16(68), uint16(67)
	if op == 2 {
		sport, dport = 67, 68
	}
	return link.Build(link.Broadcast, src, link.TypeIPv4,
		buildIPv4UDP(netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255"), sport, dport, d))
}

func TestParseBoot(t *testing.T) {
	sun, bootd := mac("08:00:20:00:00:01"), mac("02:00:00:00:00:01")
	for _, tc := range []struct {
		name  string
		frame []byte
		want  bootMessage
		ok    bool
	}{
		{"RARP request", rarpFrame(3, sun, sun, ""), bootMessage{proto: "RARP", client: [6]byte(sun)}, true},
		{"RARP reply", rarpFrame(4, bootd, sun, "192.168.1.5"),
			bootMessage{proto: "RARP", reply: true, client: [6]byte(sun), ip: netip.MustParseAddr("192.168.1.5")}, true},
		{"ARP", arp("192.168.1.1", "192.168.1.2"), bootMessage{}, false},
		{"BOOTP request", bootpFrame(1, sun, sun, ""), bootMessage{proto: "BOOTP", client: [6]byte(sun)}, true},
		{"BOOTP reply", bootpFrame(2, bootd, sun, "192.168.1.6"),
			bootMessage{proto: "BOOTP", reply: true, client: [6]byte(sun), ip: netip.MustParseAddr("192.168.1.6")}, true},
		{"other UDP", ipv4UDP(link.Broadcast, netip.MustParseAddr("255.255.255.255"), 69), bootMessage{}, false},
	} {
		got, ok := parseBoot(tc.frame)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s: %+v, %v; want %+v, %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

func TestProtocolOf(t *testing.T) {
	src := mac("08:00:20:00:00:01")
	llc := func(sap byte) []byte { return link.Build8023(link.Broadcast, src, []byte{sap, sap, 3, 0}) }
	for _, tc := range []struct {
		frame []byte
		want  string
	}{
		{rarpFrame(3, src, src, ""), "RARP"},
		{arp("192.168.1.1", "192.168.1.2"), "ARP"},
		{bootpFrame(1, src, src, ""), "BOOTP"},
		{ipv4UDP(link.Broadcast, netip.MustParseAddr("192.168.1.1"), 69), "TFTP"},
		{ipv4UDP(link.Broadcast, netip.MustParseAddr("192.168.1.1"), 2049), "NFS"},
		{ipv4UDP(link.Broadcast, netip.MustParseAddr("192.168.1.1"), 40000), "UDP"},
		{link.Build(link.Broadcast, src, 0x6001, []byte{0, 0}), "MOP"},
		{llc(0xf8), "RMP"},
		{llc(0xfc), "RPL"},
		{llc(0x99), "802.3"},
	} {
		if got := protocolOf(tc.frame); got != tc.want {
			t.Errorf("%s: %q, want %q", FormatPacket(time.Time{}, "", tc.frame), got, tc.want)
		}
	}
}

// TestBootRequests: a RARP request without a reply is reported once and
// marks the host; the reply clears the mark and gives the host its address.
func TestBootRequests(t *testing.T) {
	seg := linktest.NewSegment()
	lanPort := seg.Station("02:00:00:00:00:fe")
	lanPort.Interface().Name = "lan"
	sun := seg.Station("08:00:20:00:00:01")
	udp := listen(t)
	var buf bytes.Buffer
	var mu sync.Mutex
	b := &Bridge{LAN: lanPort, UDP: udp, StatsInterval: -1,
		Log: slog.New(slog.NewTextHandler(&syncWriter{w: &buf, mu: &mu}, nil))}
	logs := func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)

	bootd := listen(t, udp.Addr())
	mBootd, mSun := mac("02:00:00:00:00:01"), mac("08:00:20:00:00:01")
	bootd.WriteFrame(link.Build(link.Broadcast, mBootd, link.TypeLoopback, []byte("hello")))
	if read(sun) == nil {
		t.Fatal("UDP frame did not reach the LAN")
	}
	start := time.Now()
	for range 2 {
		sun.WriteFrame(rarpFrame(3, mSun, mSun, ""))
		if read(bootd) == nil {
			t.Fatal("RARP request did not reach bootd")
		}
	}
	b.checkBoot(start.Add(time.Second))
	if strings.Contains(logs(), "not answered") {
		t.Fatal("reported before the timeout")
	}
	b.checkBoot(start.Add(bootReplyTimeout + time.Second))
	b.checkBoot(start.Add(bootReplyTimeout + 2*time.Second))
	if n := strings.Count(logs(), `msg="boot request not answered" interface=lan mac=08:00:20:00:00:01 protocol=RARP`); n != 1 {
		t.Errorf("%d reports, want 1:\n%s", n, logs())
	}
	hs := b.LANHosts()
	if len(hs) != 1 || hs[0].Unanswered != "RARP" || hs[0].IP.IsValid() || !slices.Equal(hs[0].Protocols, []string{"RARP"}) || hs[0].LastSeen.Before(start) {
		t.Errorf("LAN hosts %+v", hs)
	}

	bootd.WriteFrame(rarpFrame(4, mBootd, mSun, "192.168.1.5"))
	if read(sun) == nil {
		t.Fatal("RARP reply did not reach the LAN")
	}
	hs = b.LANHosts()
	if len(hs) != 1 || hs[0].Unanswered != "" || hs[0].IP != netip.MustParseAddr("192.168.1.5") {
		t.Errorf("LAN hosts after the reply %+v", hs)
	}
	for _, want := range []string{
		`msg="host ip" interface=lan mac=08:00:20:00:00:01 ip=192.168.1.5 from="RARP reply"`,
		`msg="boot request answered" interface=lan mac=08:00:20:00:00:01 protocol=RARP`,
	} {
		if !strings.Contains(logs(), want) {
			t.Errorf("log lacks %s:\n%s", want, logs())
		}
	}
	if u := b.UDPHosts(); len(u) != 1 || !slices.Equal(u[0].Protocols, []string{"loopback", "RARP"}) {
		t.Errorf("UDP hosts %+v", u)
	}

	// A request that is answered in time is not reported.
	sun.WriteFrame(bootpFrame(1, mSun, mSun, ""))
	read(bootd)
	bootd.WriteFrame(bootpFrame(2, mBootd, mSun, "192.168.1.5"))
	read(sun)
	b.checkBoot(time.Now().Add(time.Minute))
	if strings.Contains(logs(), "protocol=BOOTP") {
		t.Errorf("answered BOOTP request reported:\n%s", logs())
	}
}
