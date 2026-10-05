// Package linktest provides an in-memory Ethernet segment for testing
// link level protocols without capture privileges.
package linktest

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/resolve"
)

// Segment is an Ethernet hub: every frame written by a port is delivered to
// every other port.
type Segment struct {
	mu    sync.Mutex
	ports []*Port
}

// NewSegment returns an empty segment.
func NewSegment() *Segment { return &Segment{} }

// Station attaches a port with the given MAC address. The port receives
// every frame, like a promiscuous capture.
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
