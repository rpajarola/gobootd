package link

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
)

// Group is several UDP transports used as one, e.g. a raw one on loopback
// for simh and an L2TPv3 one for remote peers. Frames are read from all of
// them; a unicast frame goes only to the transport its destination was
// last heard on, other frames to all.
type Group struct {
	members []*UDP
	info    *Interface

	once   sync.Once
	frames chan received
	errc   chan error
	stop   context.CancelFunc
	ctx    context.Context
}

type received struct {
	frame []byte
	from  netip.AddrPort
}

// NewGroup returns a group of transports.
func NewGroup(members ...*UDP) *Group {
	var names []string
	for _, u := range members {
		names = append(names, u.Interface().Name)
	}
	ctx, stop := context.WithCancel(context.Background())
	return &Group{
		members: members,
		info:    &Interface{Name: strings.Join(names, ",")},
		frames:  make(chan received),
		errc:    make(chan error, len(members)),
		ctx:     ctx,
		stop:    stop,
	}
}

// Members returns the transports in the group.
func (g *Group) Members() []*UDP { return g.members }

// Interface implements Port.
func (g *Group) Interface() *Interface { return g.info }

// ReadFrame implements Port.
func (g *Group) ReadFrame(ctx context.Context) ([]byte, error) {
	b, _, err := g.ReadFrameFrom(ctx)
	return b, err
}

// ReadFrameFrom returns the next frame from any member and the peer it
// came from. The first call starts reading from every member until the
// group is closed.
func (g *Group) ReadFrameFrom(ctx context.Context) ([]byte, netip.AddrPort, error) {
	g.once.Do(func() {
		for _, u := range g.members {
			go func() {
				for {
					f, from, err := u.ReadFrameFrom(g.ctx)
					if err != nil {
						if g.ctx.Err() == nil {
							g.errc <- err
						}
						return
					}
					select {
					case g.frames <- received{slices.Clone(f), from}:
					case <-g.ctx.Done():
						return
					}
				}
			}()
		}
	})
	select {
	case r := <-g.frames:
		return r.frame, r.from, nil
	case err := <-g.errc:
		return nil, netip.AddrPort{}, err
	case <-ctx.Done():
		return nil, netip.AddrPort{}, ctx.Err()
	}
}

// WriteFrame implements Port.
func (g *Group) WriteFrame(frame []byte) error {
	_, err := g.WriteFrameExcept(frame, netip.AddrPort{})
	return err
}

// WriteFrameExcept sends frame as UDP.WriteFrameExcept does, through the
// member that knows the destination, or through all.
func (g *Group) WriteFrameExcept(frame []byte, except netip.AddrPort) (int, error) {
	targets := g.members
	if len(frame) >= HeaderLen && frame[0]&1 == 0 {
		for _, u := range g.members {
			if u.Knows(frame[0:6]) {
				targets = []*UDP{u}
				break
			}
		}
	}
	var errs []error
	var sent int
	for _, u := range targets {
		n, err := u.WriteFrameExcept(frame, except)
		sent += n
		errs = append(errs, err)
	}
	return sent, errors.Join(errs...)
}

// Knows reports whether any member knows mac.
func (g *Group) Knows(mac net.HardwareAddr) bool {
	for _, u := range g.members {
		if u.Knows(mac) {
			return true
		}
	}
	return false
}

// Close implements Port.
func (g *Group) Close() error {
	g.stop()
	var errs []error
	for _, u := range g.members {
		errs = append(errs, u.Close())
	}
	return errors.Join(errs...)
}
