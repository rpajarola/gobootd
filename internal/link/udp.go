package link

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// UDP exchanges Ethernet frames over UDP, one frame per datagram with no
// other header. This is the format of the HECnet bridge, which simh
// ("attach xq udp:...") and QEMU ("-netdev dgram") also speak.
//
// Frames are sent to the configured peers and to every peer heard from in
// the last peerTimeout. Unicast frames go only to the peer the destination
// was last heard from, so several emulators can share one UDP address as
// if they were on a switch.
type UDP struct {
	conn *net.UDPConn
	info *Interface

	mu      sync.Mutex
	static  []netip.AddrPort
	learned map[netip.AddrPort]time.Time
	macs    map[[6]byte]netip.AddrPort
	buf     []byte
}

// peerTimeout is how long a learned peer keeps receiving frames after it
// last sent one; the HECnet bridge uses 180 seconds for passive peers.
const peerTimeout = 180 * time.Second

// ListenUDP opens a UDP transport on addr.
func ListenUDP(addr netip.AddrPort, peers []netip.AddrPort) (*UDP, error) {
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return nil, err
	}
	return &UDP{
		conn:    c,
		info:    &Interface{Name: "udp:" + c.LocalAddr().String()},
		static:  peers,
		learned: map[netip.AddrPort]time.Time{},
		macs:    map[[6]byte]netip.AddrPort{},
		buf:     make([]byte, 65536),
	}, nil
}

// Addr returns the local address.
func (u *UDP) Addr() netip.AddrPort { return u.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

// Interface implements Port. A UDP transport has no Ethernet address.
func (u *UDP) Interface() *Interface { return u.info }

// ReadFrame implements Port.
func (u *UDP) ReadFrame(ctx context.Context) ([]byte, error) {
	b, _, err := u.ReadFrameFrom(ctx)
	return b, err
}

// ReadFrameFrom is ReadFrame that also returns the peer the frame came
// from.
func (u *UDP) ReadFrameFrom(ctx context.Context) ([]byte, netip.AddrPort, error) {
	// Clear a deadline left by an earlier, cancelled read.
	u.conn.SetReadDeadline(time.Time{})
	stop := context.AfterFunc(ctx, func() { u.conn.SetReadDeadline(time.Now()) })
	defer stop()
	for {
		n, from, err := u.conn.ReadFromUDPAddrPort(u.buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil, netip.AddrPort{}, ctx.Err()
			}
			return nil, netip.AddrPort{}, err
		}
		if n < HeaderLen {
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		u.mu.Lock()
		if !slices.Contains(u.static, from) {
			u.learned[from] = time.Now()
		}
		if src := [6]byte(u.buf[6:12]); src[0]&1 == 0 {
			u.macs[src] = from
		}
		u.mu.Unlock()
		return u.buf[:n], from, nil
	}
}

// WriteFrame implements Port.
func (u *UDP) WriteFrame(frame []byte) error {
	_, err := u.WriteFrameExcept(frame, netip.AddrPort{})
	return err
}

// WriteFrameExcept is WriteFrame that does not send to the peer except,
// for relaying a frame between peers. It returns the number of peers the
// frame was sent to.
func (u *UDP) WriteFrameExcept(frame []byte, except netip.AddrPort) (int, error) {
	frame = Pad(frame)
	var err error
	var sent int
	for _, p := range u.destinations(frame) {
		if p == except {
			continue
		}
		if _, e := u.conn.WriteToUDPAddrPort(frame, p); e != nil {
			if err == nil {
				err = e
			}
		} else {
			sent++
		}
	}
	return sent, err
}

func (u *UDP) destinations(frame []byte) []netip.AddrPort {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := time.Now()
	for p, t := range u.learned {
		if now.Sub(t) > peerTimeout {
			delete(u.learned, p)
		}
	}
	if dst := [6]byte(frame[0:6]); dst[0]&1 == 0 {
		if p, ok := u.macs[dst]; ok && (slices.Contains(u.static, p) || !u.learned[p].IsZero()) {
			return []netip.AddrPort{p}
		}
	}
	out := slices.Clone(u.static)
	for p := range u.learned {
		out = append(out, p)
	}
	return out
}

// Knows reports whether mac was last heard from a peer that is still
// active.
func (u *UDP) Knows(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	p, ok := u.macs[[6]byte(mac)]
	return ok && (slices.Contains(u.static, p) || time.Since(u.learned[p]) <= peerTimeout)
}

// Close implements Port.
func (u *UDP) Close() error { return u.conn.Close() }
