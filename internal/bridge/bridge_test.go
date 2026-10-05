package bridge

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
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
