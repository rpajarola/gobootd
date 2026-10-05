// Package linktest provides an in-memory Ethernet segment for testing
// link level protocols without capture privileges.
package linktest

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/resolve"
)

// Segment is an Ethernet segment. Every frame written by a port is
// delivered to every other port (filters are ignored).
type Segment struct {
	mu    sync.Mutex
	ports []*Port
	ifs   map[string]*link.Interface
}

// NewSegment returns an empty segment.
func NewSegment() *Segment { return &Segment{ifs: map[string]*link.Interface{}} }

// AddInterface makes an interface available to Open.
func (s *Segment) AddInterface(name, mac string, addrs ...string) {
	hw, err := resolve.ParseMAC(mac)
	if err != nil {
		panic(err)
	}
	i := &link.Interface{Name: name, MAC: hw}
	for _, a := range addrs {
		i.Addrs = append(i.Addrs, netip.MustParsePrefix(a))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ifs[name] = i
}

// Open implements link.Opener.
func (s *Segment) Open(iface, filter string) (link.Port, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.ifs[iface]
	if !ok {
		return nil, errors.New("no such interface")
	}
	p := &Port{seg: s, info: i, in: make(chan []byte, 256), done: make(chan struct{})}
	s.ports = append(s.ports, p)
	return p, nil
}

// Interfaces implements link.Opener.
func (s *Segment) Interfaces() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var names []string
	for n := range s.ifs {
		names = append(names, n)
	}
	return names, nil
}

// Station attaches a test client with the given MAC address.
func (s *Segment) Station(mac string) *Port {
	hw, err := resolve.ParseMAC(mac)
	if err != nil {
		panic(err)
	}
	p := &Port{seg: s, info: &link.Interface{Name: "station", MAC: hw}, in: make(chan []byte, 4096), done: make(chan struct{})}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ports = append(s.ports, p)
	return p
}

func (s *Segment) send(from *Port, frame []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.ports {
		if p == from {
			continue
		}
		select {
		case p.in <- slices.Clone(frame):
		case <-p.done:
		}
	}
}

// Port is a port on a Segment.
type Port struct {
	seg  *Segment
	info *link.Interface
	in   chan []byte
	once sync.Once
	done chan struct{}
}

// Interface implements link.Port.
func (p *Port) Interface() *link.Interface { return p.info }

// ReadFrame implements link.Port.
func (p *Port) ReadFrame(ctx context.Context) ([]byte, error) {
	select {
	case f := <-p.in:
		return f, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.done:
		return nil, errors.New("port closed")
	}
}

// WriteFrame implements link.Port.
func (p *Port) WriteFrame(frame []byte) error {
	select {
	case <-p.done:
		return errors.New("port closed")
	default:
	}
	p.seg.send(p, link.Pad(frame))
	return nil
}

// Close implements link.Port.
func (p *Port) Close() error {
	p.once.Do(func() { close(p.done) })
	return nil
}
