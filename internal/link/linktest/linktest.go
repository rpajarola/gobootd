// Package linktest provides an in-memory Ethernet segment for testing
// link level protocols without capture privileges.
package linktest

import (
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"sync"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/resolve"
)

// Segment is an Ethernet hub: every frame written by a port is delivered to
// every other port.
type Segment struct {
	mu     sync.Mutex
	ports  []*Port
	impair Impairment
	rnd    *rand.Rand
	held   []byte // a frame being reordered
	heldBy *Port
	stats  Stats
}

// Impairment makes a segment lossy, like old network hardware. Each
// probability applies to each frame sent.
type Impairment struct {
	Drop      float64 // the frame is lost
	Duplicate float64 // the frame is delivered twice
	Reorder   float64 // the frame is delivered after the next one
	Seed      uint64
}

// Stats counts what an impaired segment did.
type Stats struct {
	Frames, Dropped, Duplicated, Reordered int
}

// Impair makes the segment lossy.
func (s *Segment) Impair(i Impairment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.impair = i
	s.rnd = rand.New(rand.NewPCG(i.Seed, i.Seed^0x9e3779b97f4a7c15))
}

// Stats returns what the impairment did so far.
func (s *Segment) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
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
	s.stats.Frames++
	if s.rnd == nil {
		s.deliver(from, frame)
		return
	}
	switch r := s.rnd.Float64(); {
	case r < s.impair.Drop:
		s.stats.Dropped++
		return
	case r < s.impair.Drop+s.impair.Duplicate:
		s.stats.Duplicated++
		s.deliver(from, frame)
	case r < s.impair.Drop+s.impair.Duplicate+s.impair.Reorder && s.held == nil:
		s.stats.Reordered++
		s.held, s.heldBy = slices.Clone(frame), from
		return
	}
	s.deliver(from, frame)
	if s.held != nil {
		held, by := s.held, s.heldBy
		s.held, s.heldBy = nil, nil
		s.deliver(by, held)
	}
}

func (s *Segment) deliver(from *Port, frame []byte) {
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

// Recorder is a port that records the frames written to it and never
// receives any, for calling protocol handlers directly.
type Recorder struct {
	Info *link.Interface

	mu     sync.Mutex
	frames [][]byte
}

// Interface implements link.Port.
func (r *Recorder) Interface() *link.Interface { return r.Info }

// ReadFrame implements link.Port; it blocks until ctx is done.
func (r *Recorder) ReadFrame(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// WriteFrame implements link.Port.
func (r *Recorder) WriteFrame(frame []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frames = append(r.frames, slices.Clone(frame))
	return nil
}

// Frames returns and forgets the frames written so far.
func (r *Recorder) Frames() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.frames
	r.frames = nil
	return f
}

// Close implements link.Port.
func (r *Recorder) Close() error { return nil }
