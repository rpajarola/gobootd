package link

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// UDP exchanges Ethernet frames over UDP, one frame per datagram. Without
// encapsulation, the datagram is the frame with no other header: the
// format of the HECnet bridge, which simh ("attach xq udp:...") and QEMU
// ("-netdev dgram") also speak. With L2TPv3, each frame has an L2TPv3
// header, and datagrams without the right session and cookie are dropped
// before anything is learned from them.
//
// Frames are sent to the configured peers and to every peer heard from in
// the last peerTimeout. Unicast frames go only to the peer the destination
// was last heard from, so several emulators can share one UDP address as
// if they were on a switch.
type UDP struct {
	conn *net.UDPConn
	info *Interface
	l2tp *L2TPv3
	log  *slog.Logger
	done chan struct{}

	mu       sync.Mutex
	seq      uint32
	rejected map[netip.Addr]bool
	static   []netip.AddrPort
	learned  map[netip.AddrPort]time.Time
	macs     map[[6]byte]netip.AddrPort
	buf      []byte
}

// peerTimeout is how long a learned peer keeps receiving frames after it
// last sent one; the HECnet bridge uses 180 seconds for passive peers.
const peerTimeout = 180 * time.Second

// keepaliveInterval is how often keepalives are sent, well within
// peerTimeout.
const keepaliveInterval = 60 * time.Second

// TypeLoopback is the ethertype of the Ethernet configuration testing
// protocol, used for keepalives.
const TypeLoopback = 0x9000

// UDPConfig are the settings of a UDP transport.
type UDPConfig struct {
	// Peers always receive frames.
	Peers []netip.AddrPort
	// L2TP, if set, wraps frames in L2TPv3.
	L2TP *L2TPv3
	// KeepaliveMAC, if set, is the source of a keepalive frame sent to
	// the fixed peers every keepaliveInterval, so that they learn this
	// endpoint before it has anything to send. Keepalives are loopback
	// frames addressed to their sender; receivers learn the peer from
	// them and drop them.
	KeepaliveMAC net.HardwareAddr
	// Log, if set, gets a warning for the first rejected datagram from
	// each address.
	Log *slog.Logger
}

// ListenUDP opens a UDP transport on addr without encapsulation.
func ListenUDP(addr netip.AddrPort, peers []netip.AddrPort) (*UDP, error) {
	return ListenUDPConfig(addr, UDPConfig{Peers: peers})
}

// ListenUDPConfig opens a UDP transport on addr.
func ListenUDPConfig(addr netip.AddrPort, cfg UDPConfig) (*UDP, error) {
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return nil, err
	}
	name := "udp:"
	if cfg.L2TP != nil {
		name = "l2tp:"
	}
	u := &UDP{
		conn:     c,
		info:     &Interface{Name: name + c.LocalAddr().String()},
		l2tp:     cfg.L2TP,
		log:      cfg.Log,
		done:     make(chan struct{}),
		rejected: map[netip.Addr]bool{},
		static:   cfg.Peers,
		learned:  map[netip.AddrPort]time.Time{},
		macs:     map[[6]byte]netip.AddrPort{},
		buf:      make([]byte, 65536),
	}
	if len(cfg.KeepaliveMAC) == 6 && len(cfg.Peers) > 0 {
		go u.keepalive(cfg.KeepaliveMAC)
	}
	return u, nil
}

// keepaliveFrame is a loopback reply addressed to its sender: skip count 0,
// function 1 (reply), receipt number 0.
func keepaliveFrame(mac net.HardwareAddr) []byte {
	return Build(mac, mac, TypeLoopback, []byte{0, 0, 1, 0, 0, 0})
}

func isKeepalive(frame []byte) bool {
	return binary.BigEndian.Uint16(frame[12:14]) == TypeLoopback && [6]byte(frame[0:6]) == [6]byte(frame[6:12])
}

func (u *UDP) keepalive(mac net.HardwareAddr) {
	frame := keepaliveFrame(mac)
	t := time.NewTicker(keepaliveInterval)
	defer t.Stop()
	for {
		for _, p := range u.static {
			u.send(frame, p)
		}
		select {
		case <-t.C:
		case <-u.done:
			return
		}
	}
}

// reject notes a datagram that failed the L2TPv3 checks.
func (u *UDP) reject(from netip.AddrPort) {
	u.mu.Lock()
	first := !u.rejected[from.Addr()] && len(u.rejected) < 256
	if first {
		u.rejected[from.Addr()] = true
	}
	u.mu.Unlock()
	if first && u.log != nil {
		u.log.Warn("dropping datagrams with the wrong L2TPv3 session or cookie", "transport", u.info.Name, "from", from.String())
	}
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
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		frame := u.buf[:n]
		if u.l2tp != nil {
			var ok bool
			if frame, ok = u.l2tp.decode(frame); !ok {
				u.reject(from)
				continue
			}
		}
		if len(frame) < HeaderLen {
			continue
		}
		u.mu.Lock()
		if !slices.Contains(u.static, from) {
			u.learned[from] = time.Now()
		}
		if src := [6]byte(frame[6:12]); src[0]&1 == 0 {
			u.macs[src] = from
		}
		u.mu.Unlock()
		if isKeepalive(frame) {
			continue
		}
		return frame, from, nil
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
	dg := u.datagram(frame)
	for _, p := range u.destinations(frame) {
		if p == except {
			continue
		}
		if _, e := u.conn.WriteToUDPAddrPort(dg, p); e != nil {
			if err == nil {
				err = e
			}
		} else {
			sent++
		}
	}
	return sent, err
}

// datagram returns frame with the encapsulation header, if any.
func (u *UDP) datagram(frame []byte) []byte {
	if u.l2tp == nil {
		return frame
	}
	u.mu.Lock()
	u.seq++
	seq := u.seq
	u.mu.Unlock()
	return append(u.l2tp.encode(make([]byte, 0, u.l2tp.headerLen()+len(frame)), seq), frame...)
}

func (u *UDP) send(frame []byte, to netip.AddrPort) error {
	_, err := u.conn.WriteToUDPAddrPort(u.datagram(Pad(frame)), to)
	return err
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
		if p, ok := u.macs[dst]; ok {
			if slices.Contains(u.static, p) || !u.learned[p].IsZero() {
				return []netip.AddrPort{p}
			}
			for _, s := range u.static {
				if s.Addr() == p.Addr() {
					return []netip.AddrPort{s}
				}
			}
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
	if !ok {
		return false
	}
	for _, s := range u.static {
		if s == p || s.Addr() == p.Addr() {
			return true
		}
	}
	return time.Since(u.learned[p]) <= peerTimeout
}

// Close implements Port.
func (u *UDP) Close() error {
	u.mu.Lock()
	select {
	case <-u.done:
	default:
		close(u.done)
	}
	u.mu.Unlock()
	return u.conn.Close()
}
