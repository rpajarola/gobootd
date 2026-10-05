package link

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
)

// Network is bootd's attachment to an Ethernet segment: a transport, and
// the Ethernet and IP address bootd uses there. Protocols subscribe to the
// frames they handle; frames nobody claims go to the default port, which
// is the IP stack.
type Network struct {
	info      *Interface
	transport Port

	mu      sync.Mutex
	subs    []*sub
	def     *sub
	dropped atomic.Uint64
}

// NewNetwork creates a network on transport with bootd's address mac and
// IP address addr. Call Run to start receiving.
func NewNetwork(name string, transport Port, mac net.HardwareAddr, addr netip.Prefix) *Network {
	return &Network{
		info:      &Interface{Name: name, MAC: mac, Addrs: []netip.Prefix{addr}},
		transport: transport,
	}
}

// DefaultMAC returns a locally administered address derived from the
// network's name and address, so it stays the same across restarts.
func DefaultMAC(name string, addr netip.Prefix) net.HardwareAddr {
	h := sha256.Sum256([]byte(name + "\x00" + addr.String()))
	mac := net.HardwareAddr(h[:6])
	mac[0] = mac[0]&^1 | 2 // unicast, locally administered
	return mac
}

// Interface returns bootd's addresses on the network.
func (n *Network) Interface() *Interface { return n.info }

// Name returns the network's name.
func (n *Network) Name() string { return n.info.Name }

// Transport returns the underlying transport.
func (n *Network) Transport() Port { return n.transport }

// Dropped returns how many frames were dropped because a subscriber did not
// keep up.
func (n *Network) Dropped() uint64 { return n.dropped.Load() }

// Run receives frames and hands them to the subscribers until ctx is done.
// It closes the transport when it returns.
func (n *Network) Run(ctx context.Context) error {
	defer n.transport.Close()
	for {
		f, err := n.transport.ReadFrame(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		n.dispatch(f)
	}
}

// Deliver hands a received frame to the subscribers. Run calls it for every
// frame from the transport; tests may call it directly.
func (n *Network) Deliver(frame []byte) { n.dispatch(frame) }

func (n *Network) dispatch(frame []byte) {
	f, ok := Parse(frame)
	if !ok {
		return
	}
	// Frames for other stations (seen in promiscuous captures) and our
	// own transmissions echoed back are not ours.
	if f.Dst[0]&1 == 0 && string(f.Dst) != string(n.info.MAC) || string(f.Src) == string(n.info.MAC) {
		return
	}
	n.mu.Lock()
	target := n.def
	for _, s := range n.subs {
		if s.match(f) {
			target = s
			break
		}
	}
	n.mu.Unlock()
	if target == nil {
		return
	}
	select {
	case target.in <- slices.Clone(frame):
	default:
		n.dropped.Add(1)
	}
}

// Subscribe returns a port that receives the frames match accepts. A
// frame goes to the first subscriber that accepts it.
func (n *Network) Subscribe(match func(Frame) bool) Port {
	s := n.newSub(match)
	n.mu.Lock()
	defer n.mu.Unlock()
	n.subs = append(n.subs, s)
	return s
}

// SetDefault returns a port that receives the frames no subscriber
// accepts.
func (n *Network) SetDefault() Port {
	s := n.newSub(nil)
	n.mu.Lock()
	defer n.mu.Unlock()
	n.def = s
	return s
}

func (n *Network) newSub(match func(Frame) bool) *sub {
	return &sub{net: n, match: match, in: make(chan []byte, 512), done: make(chan struct{})}
}

func (n *Network) remove(s *sub) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.subs = slices.DeleteFunc(n.subs, func(x *sub) bool { return x == s })
	if n.def == s {
		n.def = nil
	}
}

type sub struct {
	net   *Network
	match func(Frame) bool
	in    chan []byte
	once  sync.Once
	done  chan struct{}
}

func (s *sub) Interface() *Interface { return s.net.info }

func (s *sub) ReadFrame(ctx context.Context) ([]byte, error) {
	select {
	case f := <-s.in:
		return f, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, errors.New("port closed")
	}
}

func (s *sub) WriteFrame(frame []byte) error { return s.net.transport.WriteFrame(frame) }

func (s *sub) Close() error {
	s.once.Do(func() {
		close(s.done)
		s.net.remove(s)
	})
	return nil
}

// MatchType accepts Ethernet II frames of the given type.
func MatchType(t uint16) func(Frame) bool {
	return func(f Frame) bool { return f.Type == t }
}
