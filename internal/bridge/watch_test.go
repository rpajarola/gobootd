package bridge

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
)

var testSunMAC = net.HardwareAddr{0x08, 0, 0x20, 0, 0, 1}

// startTest runs a bridge over an in-memory segment and a UDP transport.
func startTest(t *testing.T) (*Bridge, *linktest.Port, *link.UDP) {
	t.Helper()
	seg := linktest.NewSegment()
	lanPort := seg.Station("02:00:00:00:00:fe")
	sun := seg.Station("08:00:20:00:00:01")
	udp := listen(t)
	b := &Bridge{LAN: lanPort, UDP: udp, Log: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go b.Run(ctx)
	return b, sun, udp
}

func nextEvent(t *testing.T, w *Watcher) FrameEvent {
	t.Helper()
	select {
	case e, ok := <-w.Events:
		if !ok {
			t.Fatal("watcher stopped")
		}
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("no event arrived")
		return FrameEvent{}
	}
}

func TestWatchSeesForwardedFrames(t *testing.T) {
	b, sun, udp := startTest(t)
	peer := listen(t, udp.Addr())
	w := b.Watch(0)
	defer w.Stop()

	// LAN to peers.
	sun.WriteFrame(link.Build(link.Broadcast, testSunMAC, link.TypeIPv4, []byte("out")))
	e0 := nextEvent(t, w)
	if e0.Interface != b.LANName() || e0.Action != b.LANName()+" -> udp" {
		t.Errorf("LAN event %+v", e0)
	}

	// A broadcast from a peer floods the LAN and the other peers.
	peer.WriteFrame(link.Build(link.Broadcast, testSunMAC, link.TypeRARP, []byte("back")))
	e1 := nextEvent(t, w)
	if e1.Interface != b.UDPName() || e1.Action != b.UDPName()+" -> all" {
		t.Errorf("UDP event %+v", e1)
	}
	if e1.Peer != peer.Addr() {
		t.Errorf("UDP event lost the peer address: %+v", e1)
	}
	if e1.Seq <= e0.Seq {
		t.Errorf("sequences not increasing: %d, %d", e0.Seq, e1.Seq)
	}
}

func TestWatchHistory(t *testing.T) {
	b, sun, _ := startTest(t)
	for range 5 {
		sun.WriteFrame(link.Build(link.Broadcast, testSunMAC, link.TypeIPv4, []byte("x")))
	}
	// Wait until all five passed the bridge.
	w := b.Watch(0)
	for range 5 {
		nextEvent(t, w)
	}
	w.Stop()

	h := b.Watch(2).History()
	if len(h) != 2 {
		t.Fatalf("history %d entries, want 2", len(h))
	}
	all := b.Watch(-1).History()
	if len(all) != 5 {
		t.Errorf("whole ring has %d entries, want 5", len(all))
	}
	if all[0].Seq >= all[4].Seq {
		t.Error("history not oldest first")
	}
}

func TestWatchSlowConsumerDrops(t *testing.T) {
	b, sun, _ := startTest(t)
	w := b.Watch(0)
	defer w.Stop()
	n := watchQueue + 10
	for range n {
		sun.WriteFrame(link.Build(link.Broadcast, testSunMAC, link.TypeIPv4, []byte("x")))
	}
	// The forwarding loop must survive a watcher that never reads.
	deadline := time.After(3 * time.Second)
	for w.Dropped() == 0 {
		select {
		case <-deadline:
			t.Fatal("slow watcher did not cause drops")
		case <-time.After(time.Millisecond):
		}
	}
	if w.Dropped() >= uint64(n) {
		t.Errorf("dropped %d of %d", w.Dropped(), n)
	}
	// The bridge still works for a fresh watcher.
	w2 := b.Watch(0)
	defer w2.Stop()
	sun.WriteFrame(link.Build(link.Broadcast, testSunMAC, link.TypeIPv4, []byte("live")))
	nextEvent(t, w2)
}
