package bridge

import (
	"encoding/hex"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
)

// ringSize is how many forwarded frames are remembered for tail and for
// the start of a watch; a full-size frame costs about 1.5 kB.
const ringSize = 512

// watchQueue is how many frames a watcher may fall behind before its
// events are dropped; dropping never blocks the forwarding loops.
const watchQueue = 64

// FrameEvent is one frame as it passed through the bridge.
type FrameEvent struct {
	Seq  uint64
	Time time.Time
	// Interface is the name of the side the frame arrived on.
	Interface string
	// Action is what the bridge did with it, e.g. "lan -> udp" or
	// "lan (filtered)".
	Action string
	Frame  []byte
	// Peer is the UDP source address, for frames from the UDP side.
	Peer netip.AddrPort
}

type subscriber struct {
	ch      chan FrameEvent
	dropped atomic.Uint64
}

// Watcher receives the frames that pass through the bridge, newest first
// for the replayed history. Events are dropped, not delayed, when the
// channel is full; Dropped counts them.
type Watcher struct {
	Events  <-chan FrameEvent
	history []FrameEvent
	ch      chan FrameEvent
	sub     *subscriber
	b       *Bridge
}

// History returns the remembered frames, oldest first, that were forwarded
// before the watch started.
func (w *Watcher) History() []FrameEvent { return w.history }

// Dropped returns how many events were lost because the watcher fell
// behind.
func (w *Watcher) Dropped() uint64 { return w.sub.dropped.Load() }

// Stop unsubscribes from the bridge.
func (w *Watcher) Stop() { w.b.removeSubscriber(w.sub) }

// Watch subscribes to the frames that pass through the bridge and returns
// the last n remembered frames as history. The event channel is not
// closed; call Stop when done.
func (b *Bridge) Watch(n int) *Watcher {
	sub := &subscriber{ch: make(chan FrameEvent, watchQueue)}
	b.mu.Lock()
	b.subs = append(b.subs, sub)
	history := slices.Clone(b.ring)
	if n < 0 || n > len(history) {
		n = len(history)
	}
	history = history[len(history)-n:]
	b.mu.Unlock()
	return &Watcher{Events: sub.ch, history: history, ch: sub.ch, sub: sub, b: b}
}

func (b *Bridge) removeSubscriber(sub *subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subs = slices.DeleteFunc(b.subs, func(s *subscriber) bool { return s == sub })
	close(sub.ch)
}

// publish records e in the ring and hands it to the watchers, dropping
// events for watchers that are not keeping up.
func (b *Bridge) publish(e FrameEvent) {
	b.mu.Lock()
	b.seq++
	e.Seq = b.seq
	subs := slices.Clone(b.subs)
	b.ring = append(b.ring, e)
	if len(b.ring) > ringSize {
		copy(b.ring, b.ring[len(b.ring)-ringSize:])
		b.ring = b.ring[:ringSize]
	}
	b.mu.Unlock()
	for _, s := range subs {
		select {
		case s.ch <- e:
		default:
			s.dropped.Add(1)
		}
	}
}

// record publishes the frame and returns the event, for printing.
func (b *Bridge) record(iface, action string, frame []byte, peer netip.AddrPort) FrameEvent {
	e := FrameEvent{Time: time.Now(), Interface: iface, Action: action, Frame: slices.Clone(frame), Peer: peer}
	b.publish(e)
	return e
}

// Format returns e as the single-line summary bootbridge prints, with the
// hex dump of the frame appended when dump is set.
func (e FrameEvent) Format(dump bool) string {
	line := FormatPacket(e.Time, e.Action, e.Frame)
	if !dump {
		return line
	}
	return line + "\n" + hex.Dump(e.Frame)
}

// HostEntry is a host the bridge has seen on an interface.
type HostEntry struct {
	MAC net.HardwareAddr
	IP  netip.Addr
}

// LANHosts returns the hosts seen on the LAN side.
func (b *Bridge) LANHosts() []HostEntry { return b.hosts(b.lanStats.hosts) }

// UDPHosts returns the hosts seen on the UDP side.
func (b *Bridge) UDPHosts() []HostEntry { return b.hosts(b.udpStats.hosts) }

func (b *Bridge) hosts(m map[[6]byte]netip.Addr) []HostEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]HostEntry, 0, len(m))
	for mac, ip := range m {
		out = append(out, HostEntry{MAC: net.HardwareAddr(mac[:]), IP: ip})
	}
	slices.SortFunc(out, func(a, b HostEntry) int { return slices.Compare(a.MAC, b.MAC) })
	return out
}

// UDPPeers returns the peer state of each UDP transport, empty for a
// transport that is not one of the link types (a test double).
func (b *Bridge) UDPPeers() []link.TransportState {
	switch u := b.UDP.(type) {
	case *link.UDP:
		return []link.TransportState{{
			Name:          u.Interface().Name,
			Encapsulation: u.Encapsulation(),
			Peers:         u.PeersSnapshot(),
			MACs:          u.MACsSnapshot(),
		}}
	case *link.Group:
		return u.TransportSnapshots()
	}
	return nil
}
