package bridge

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
)

// filterBridge is a bridge on en0 with a raw and an L2TPv3 transport.
func filterBridge(t *testing.T) (*Bridge, string, string) {
	t.Helper()
	raw := listen(t)
	l2, err := link.ListenUDPConfig(netip.MustParseAddrPort("127.0.0.1:0"), link.UDPConfig{L2TP: &link.L2TPv3{Session: 1}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l2.Close() })
	lan := linktest.NewSegment().Station("02:00:00:00:00:fe")
	lan.Interface().Name = "en0"
	return &Bridge{LAN: lan, UDP: link.NewGroup(raw, l2)}, raw.Interface().Name, l2.Interface().Name
}

func TestParseFilter(t *testing.T) {
	b, raw, l2 := filterBridge(t)
	for _, tc := range []struct {
		spec       string
		peers      bool
		lan, udp   bool
		auto       bool
		transports []string
	}{
		{"", false, true, true, true, nil},
		{"", true, true, true, false, nil},
		{"all", false, true, true, false, nil},
		{" Auto ", false, true, true, true, nil},
		{"lan", false, true, false, false, nil},
		{"EN0", false, true, false, false, nil},
		{"udp", false, false, true, false, nil},
		{b.udpName(), false, false, true, false, nil},
		{"-lan", false, false, true, false, nil},
		{"!lan", false, false, true, false, nil},
		{"-udp", false, true, false, false, nil},
		{"-en0", true, false, true, false, nil},
		{"l2tp", true, false, true, false, []string{l2}},
		{"raw", true, false, true, false, []string{raw}},
		{l2, true, false, true, false, []string{l2}},
		{"-l2tp", true, true, true, false, []string{raw}},
		{strings.TrimPrefix(raw, "udp:127.0.0.1:"), true, false, true, false, []string{raw}}, // the port
	} {
		f, err := b.ParseFilter(tc.spec, tc.peers)
		if err != nil {
			t.Errorf("%q: %v", tc.spec, err)
			continue
		}
		if f.LAN != tc.lan || f.UDP != tc.udp || f.Auto != tc.auto || !slices.Equal(f.Transports, tc.transports) {
			t.Errorf("%q (peers %v): %+v", tc.spec, tc.peers, f)
		}
	}

	for _, tc := range []struct {
		spec  string
		peers bool
		want  string
	}{
		{"nonsense", false, "no such interface; use all, auto, lan (en0) or udp"},
		{"nonsense", true, "a transport (" + raw + ", " + l2 + ")"},
		{"l2tp", false, "frames are shown by side, not by transport"},
		{"127.0.0.1", true, "say which"},
		{"-all", false, "all cannot be excluded"},
		{"-auto", true, "auto cannot be excluded"},
	} {
		_, err := b.ParseFilter(tc.spec, tc.peers)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q (peers %v): error %v, want %q", tc.spec, tc.peers, err, tc.want)
		}
	}

	// A bad filter leaves the printing filter as it was.
	if err := b.SetPrintInterface("udp"); err != nil {
		t.Fatal(err)
	}
	if err := b.SetPrintInterface("bogus"); err == nil || b.GetPrintInterface() != "udp" {
		t.Errorf("bogus filter: %v, now %q", err, b.GetPrintInterface())
	}
}

// TestSingleKindTransport: with only L2TPv3 transports, l2tp is the UDP
// side, as -print-iface l2tp always was.
func TestSingleKindTransport(t *testing.T) {
	l2, err := link.ListenUDPConfig(netip.MustParseAddrPort("127.0.0.1:0"), link.UDPConfig{L2TP: &link.L2TPv3{Session: 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	b := &Bridge{LAN: linktest.NewSegment().Station("02:00:00:00:00:fe"), UDP: l2}
	if f, err := b.ParseFilter("l2tp", ForFrames); err != nil || !f.UDP || f.LAN {
		t.Errorf("l2tp: %+v %v", f, err)
	}
}

func ipv4UDP(dst net.HardwareAddr, dstIP netip.Addr, port uint16) []byte {
	ip := make([]byte, 28)
	ip[0], ip[9] = 0x45, 17
	d := dstIP.As4()
	copy(ip[16:20], d[:])
	binary.BigEndian.PutUint16(ip[22:24], port)
	return link.Build(dst, mac("08:00:20:00:00:09"), link.TypeIPv4, ip)
}

func arp(sender, target string) []byte {
	p := make([]byte, 28)
	p[1], p[2], p[4], p[5], p[7] = 1, 8, 6, 4, 1
	s, d := netip.MustParseAddr(sender).As4(), netip.MustParseAddr(target).As4()
	copy(p[14:18], s[:])
	copy(p[24:28], d[:])
	return link.Build(link.Broadcast, mac("08:00:20:00:00:09"), link.TypeARP, p)
}

func TestLANNoise(t *testing.T) {
	b, _, _ := filterBridge(t)
	bootd := mac("02:00:00:00:00:01")
	b.udp = map[[6]byte]time.Time{[6]byte(bootd): time.Now()}
	b.udpStats.hosts = map[[6]byte]netip.Addr{[6]byte(bootd): netip.MustParseAddr("192.168.1.250")}
	bcast := netip.MustParseAddr("255.255.255.255")
	for _, tc := range []struct {
		name  string
		frame []byte
		noise bool
	}{
		{"BOOTP request", ipv4UDP(link.Broadcast, bcast, 67), false},
		{"portmap CALLIT", ipv4UDP(link.Broadcast, bcast, 111), false},
		{"TFTP", ipv4UDP(link.Broadcast, bcast, 69), false},
		{"PXE", ipv4UDP(link.Broadcast, bcast, 4011), false},
		{"NetBIOS", ipv4UDP(link.Broadcast, netip.MustParseAddr("10.3.0.255"), 137), true},
		{"Syncthing", ipv4UDP(link.Broadcast, netip.MustParseAddr("10.3.0.255"), 21027), true},
		{"Ubiquiti", ipv4UDP(link.Broadcast, bcast, 10001), true},
		{"Ubiquiti multicast", ipv4UDP(mac("01:00:5e:59:bc:01"), netip.MustParseAddr("233.89.188.1"), 10001), true},
		{"Plex GDM", ipv4UDP(link.Broadcast, netip.MustParseAddr("192.168.86.255"), 32414), true},
		{"multicast 48000", ipv4UDP(mac("01:00:5e:7e:7f:3f"), netip.MustParseAddr("239.254.127.63"), 48000), true},
		{"unicast to another host", ipv4UDP(mac("08:00:20:00:00:0a"), netip.MustParseAddr("10.3.0.9"), 21027), false},
		{"AppleTalk", link.Build(mac("09:00:07:ff:ff:ff"), mac("08:00:07:00:00:09"), 0x809b, nil), false},
		{"IEEE 1905", link.Build(mac("01:80:c2:00:00:13"), mac("08:00:20:00:00:09"), 0x893a, nil), true},
		{"RARP", link.Build(link.Broadcast, mac("08:00:20:00:00:09"), link.TypeRARP, make([]byte, 28)), false},
		{"MOP", link.Build(mac("ab:00:00:01:00:00"), mac("08:00:2b:00:00:09"), 0x6001, nil), false},
		{"mDNS", ipv4UDP(mac("01:00:5e:00:00:fb"), netip.MustParseAddr("224.0.0.251"), 5353), true},
		{"SSDP", ipv4UDP(mac("01:00:5e:7f:ff:fa"), netip.MustParseAddr("239.255.255.250"), 1900), true},
		{"mDNS to bootd", ipv4UDP(bootd, netip.MustParseAddr("192.168.1.250"), 5353), false},
		{"IPv6", link.Build(mac("33:33:00:00:00:01"), mac("08:00:20:00:00:09"), 0x86dd, nil), true},
		{"STP", link.Build8023(mac("01:80:c2:00:00:00"), mac("08:00:20:00:00:09"), make([]byte, 38)), true},
		{"ARP for bootd", arp("192.168.1.5", "192.168.1.250"), false},
		{"ARP among others", arp("192.168.1.5", "192.168.1.1"), true},
	} {
		if got := b.lanNoise(link.Pad(tc.frame)); got != tc.noise {
			t.Errorf("%s: noise %v, want %v", tc.name, got, tc.noise)
		}
	}

	// auto hides noise from the LAN only.
	f, _ := b.ParseFilter("", ForFrames)
	if f.Frame(FrameEvent{Interface: "en0", Noise: true}, "en0") || !f.Frame(FrameEvent{Interface: "en0"}, "en0") ||
		!f.Frame(FrameEvent{Interface: b.udpName(), Noise: true}, "en0") {
		t.Error("auto filter")
	}
	if f, _ := b.ParseFilter("all", ForFrames); !f.Frame(FrameEvent{Interface: "en0", Noise: true}, "en0") {
		t.Error("all hides noise")
	}
}

// TestLANNoiseCaptured: frames from a real LAN that auto showed.
func TestLANNoiseCaptured(t *testing.T) {
	b, _, _ := filterBridge(t)
	for _, h := range []string{
		// Syncthing local discovery to 10.3.0.255:21027 (truncated)
		"ffffffffffff6a7a0cf2044f08004500016a2edd40004011f59e0a0300030a0300ff875c52230156dfde2ea7d90b0a20f572",
		// Ubiquiti discovery, multicast and broadcast
		"01005e59bc011c0b8b161db5080045000020236b40000111a7030a030001e959bc01ed972711000c3ace010000000000000000000000000000000000",
		"ffffffffffff1c0b8b161db50800450000205d3240004011d3970a030001ffffffffed972711000ce029010000000000000000000000000000000000",
		// Plex GDM M-SEARCH to 192.168.86.255:32412
		"ffffffffffff6a7a0cf2044f080045000031521140004011ba59c0a85601c0a856ffb35b7e9c001d292c4d2d534541524348202a20485454502f312e310d0a",
		// to 239.254.127.63:48000
		"01005e7e7f3f847848fa9d600800450000744a4f40004011764a0a0300a7effe7f3fbb80bb80006072d1223344550202",
	} {
		frame, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		if !b.lanNoise(link.Pad(frame)) {
			t.Errorf("not noise: %s", h[:60])
		}
	}
}
