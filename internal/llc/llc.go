// Package llc implements IEEE 802.2 logical link control on Ethernet: type
// 1 (connectionless UI, XID and TEST frames) and type 2, the
// connection-oriented links with sequence numbers, acknowledgements and
// retransmission that NetBEUI runs its sessions on.
//
// A Station serves one SAP on one port. Links are in extended (modulo 128)
// mode, as SABME sets up, and use go-back-N: a frame out of sequence is
// rejected and everything from it is sent again.
package llc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
)

// Control field values. U frames have one control byte, I and S frames
// two.
const (
	ctlUI    = 0x03
	ctlSABME = 0x6f
	ctlUA    = 0x63
	ctlDISC  = 0x43
	ctlDM    = 0x0f
	ctlFRMR  = 0x87
	ctlXID   = 0xaf
	ctlTEST  = 0xe3
	pfU      = 0x10 // poll/final bit of U frames

	sRR  = 0x01
	sRNR = 0x05
	sREJ = 0x09
)

const (
	// window is how many I frames may be unacknowledged.
	window = 7
	// maxRetries is how often a poll goes unanswered before the link is
	// given up (N2).
	maxRetries = 8
	// idlePoll is how long a link may be silent before it is polled.
	idlePoll = 30 * time.Second
	// maxQueue is how many I frames Wait lets wait to be sent.
	maxQueue = 32
	// MaxInfo is the longest information field of an I frame in an
	// Ethernet frame.
	MaxInfo = 1500 - 4
)

// ErrClosed is returned for a link that is down.
var ErrClosed = errors.New("llc: link closed")

// Handler receives what arrives on a link.
type Handler interface {
	// Receive is called with the information field of each I frame,
	// in order. It must not block; it may call Send.
	Receive(l *Link, info []byte)
	// Closed is called once when the link goes down.
	Closed(l *Link)
}

// Station is one SAP on a port.
type Station struct {
	SAP  byte
	Port link.Port
	Log  *slog.Logger
	// Accept is called when a remote station connects (SABME). It
	// returns the link's handler, or nil to refuse it.
	Accept func(l *Link) Handler
	// UI is called for unnumbered information frames: NetBIOS names
	// and datagrams.
	UI func(src, dst net.HardwareAddr, info []byte)
	// T1 is how long a sent frame may go unacknowledged before the
	// remote station is polled. The default is a second.
	T1 time.Duration

	mu    sync.Mutex
	links map[string]*Link // by remote MAC
	// connects are the links waiting for UA after Connect.
	connects map[string]chan struct{}
}

// Link is a type 2 connection with a remote station.
type Link struct {
	st      *Station
	Remote  net.HardwareAddr
	handler Handler

	mu       sync.Mutex
	space    *sync.Cond
	closed   bool
	vs, vr   byte // next sequence number to send, to receive
	va       byte // oldest unacknowledged
	unacked  [][]byte
	queue    [][]byte
	busy     bool // the remote station sent RNR
	rejected bool // a REJ is outstanding
	polling  bool // a poll is waiting for the final bit
	retries  int
	deadline time.Time // T1
	heard    time.Time
}

func (s *Station) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Station) t1() time.Duration {
	if s.T1 > 0 {
		return s.T1
	}
	return time.Second
}

// Match selects the frames of the station: 802.3 with its SAP or the
// global SAP as destination.
func (s *Station) Match(f link.Frame) bool {
	return f.Type == 0 && len(f.Payload) >= 3 && (f.Payload[0]&^1 == s.SAP || f.Payload[0] == 0xff)
}

// send writes an LLC frame to dst. cmd frames come from the station's SAP,
// responses have the response bit set.
func (s *Station) send(dst net.HardwareAddr, response bool, ctl []byte, info []byte) {
	ssap := s.SAP
	if response {
		ssap |= 1
	}
	b := make([]byte, 0, 2+len(ctl)+len(info))
	b = append(b, s.SAP, ssap)
	b = append(b, ctl...)
	b = append(b, info...)
	if err := s.Port.WriteFrame(link.Build8023(dst, s.Port.Interface().MAC, b)); err != nil {
		s.log().Debug("llc send failed", "err", err)
	}
}

// SendUI sends an unnumbered information frame.
func (s *Station) SendUI(dst net.HardwareAddr, info []byte) {
	s.send(dst, false, []byte{ctlUI}, info)
}

// Handle processes a received frame.
func (s *Station) Handle(frame []byte) {
	f, ok := link.Parse(frame)
	if !ok || !s.Match(f) || string(f.Src) == string(s.Port.Interface().MAC) || f.Src[0]&1 != 0 {
		return
	}
	p := f.Payload
	dsap, ssap := p[0], p[1]
	response := ssap&1 != 0
	c0 := p[2]
	if c0&3 == 3 {
		s.unnumbered(f, dsap, response, c0, p[3:])
		return
	}
	// I and S frames are only for this SAP, from the same SAP.
	if len(p) < 4 || dsap != s.SAP || ssap&^1 != s.SAP || f.Dst[0]&1 != 0 {
		return
	}
	c1 := p[3]
	pf := c1&1 != 0
	nr := c1 >> 1
	l := s.link(f.Src)
	if l == nil {
		if !response && pf {
			s.send(f.Src, true, []byte{ctlDM | pfU}, nil)
		}
		return
	}
	if c0&1 == 0 {
		l.info(c0>>1, nr, pf, response, p[4:])
		return
	}
	l.supervisory(c0, nr, pf, response)
}

func (s *Station) link(mac net.HardwareAddr) *Link {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.links[mac.String()]
}

func (s *Station) unnumbered(f link.Frame, dsap byte, response bool, c byte, info []byte) {
	pf := c & pfU
	switch c &^ pfU {
	case ctlUI:
		if s.UI != nil && dsap&^1 == s.SAP {
			s.UI(f.Src, f.Dst, info)
		}
	case ctlXID:
		if !response {
			// Basic format: types 1 and 2, our receive window.
			s.send(f.Src, true, []byte{ctlXID | pf}, []byte{0x81, 0x03, window << 1})
		}
	case ctlTEST:
		if !response {
			s.send(f.Src, true, []byte{ctlTEST | pf}, info)
		}
	case ctlSABME:
		if response || dsap != s.SAP {
			return
		}
		if old := s.link(f.Src); old != nil {
			old.down()
		}
		l := &Link{st: s, Remote: append(net.HardwareAddr(nil), f.Src...), heard: time.Now()}
		l.space = sync.NewCond(&l.mu)
		var h Handler
		if s.Accept != nil {
			h = s.Accept(l)
		}
		if h == nil {
			s.send(f.Src, true, []byte{ctlDM | pf}, nil)
			return
		}
		l.handler = h
		s.mu.Lock()
		if s.links == nil {
			s.links = map[string]*Link{}
		}
		s.links[f.Src.String()] = l
		s.mu.Unlock()
		s.send(f.Src, true, []byte{ctlUA | pf}, nil)
	case ctlDISC:
		if response {
			return
		}
		if l := s.link(f.Src); l != nil {
			s.send(f.Src, true, []byte{ctlUA | pf}, nil)
			l.down()
		} else {
			s.send(f.Src, true, []byte{ctlDM | pf}, nil)
		}
	case ctlUA:
		s.mu.Lock()
		ch := s.connects[f.Src.String()]
		delete(s.connects, f.Src.String())
		s.mu.Unlock()
		if ch != nil {
			close(ch)
		}
	case ctlDM, ctlFRMR:
		if l := s.link(f.Src); l != nil {
			l.down()
		}
	}
}

// Connect sets up a link to a remote station, as a client does.
func (s *Station) Connect(ctx context.Context, remote net.HardwareAddr, h Handler) (*Link, error) {
	ch := make(chan struct{})
	s.mu.Lock()
	if s.connects == nil {
		s.connects = map[string]chan struct{}{}
	}
	s.connects[remote.String()] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.connects, remote.String())
		s.mu.Unlock()
	}()
	for try := 0; ; try++ {
		if try == maxRetries {
			return nil, fmt.Errorf("llc: %s does not answer", remote)
		}
		s.send(remote, false, []byte{ctlSABME | pfU}, nil)
		select {
		case <-ch:
			l := &Link{st: s, Remote: remote, handler: h, heard: time.Now()}
			l.space = sync.NewCond(&l.mu)
			s.mu.Lock()
			if s.links == nil {
				s.links = map[string]*Link{}
			}
			if old := s.links[remote.String()]; old != nil {
				s.mu.Unlock()
				old.down()
				s.mu.Lock()
			}
			s.links[remote.String()] = l
			s.mu.Unlock()
			return l, nil
		case <-time.After(s.t1()):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Run polls links whose frames go unacknowledged or that fell silent,
// until ctx is done, then closes them.
func (s *Station) Run(ctx context.Context) {
	t := time.NewTicker(s.t1() / 4)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			var ls []*Link
			for _, l := range s.links {
				ls = append(ls, l)
			}
			s.mu.Unlock()
			for _, l := range ls {
				l.Disconnect()
			}
			return
		case now := <-t.C:
			s.mu.Lock()
			var ls []*Link
			for _, l := range s.links {
				ls = append(ls, l)
			}
			s.mu.Unlock()
			for _, l := range ls {
				l.tick(now)
			}
		}
	}
}

// Links returns the number of links up.
func (s *Station) Links() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.links)
}

func mod(x int) byte { return byte(x & 0x7f) }

// ctl returns the two control bytes of an I or S frame.
func ctl(c0, nr byte, pf bool) []byte {
	c1 := nr << 1
	if pf {
		c1 |= 1
	}
	return []byte{c0, c1}
}

// info handles a received I frame.
func (l *Link) info(ns, nr byte, pf, response bool, data []byte) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.heard = time.Now()
	l.ack(nr, pf && response)
	if ns != l.vr {
		// Out of sequence: ask for everything from the one expected,
		// once.
		if !l.rejected || pf {
			l.rejected = true
			l.st.send(l.Remote, true, ctl(sREJ, l.vr, pf && !response), nil)
		}
		l.mu.Unlock()
		return
	}
	l.rejected = false
	l.vr = mod(int(l.vr) + 1)
	before := l.vs
	l.mu.Unlock()

	l.handler.Receive(l, append([]byte(nil), data...))

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	// Acknowledge, unless the handler's answer already carried it.
	if pf && !response || l.vs == before {
		l.st.send(l.Remote, true, ctl(sRR, l.vr, pf && !response), nil)
	}
}

// supervisory handles RR, RNR and REJ.
func (l *Link) supervisory(c0, nr byte, pf, response bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.heard = time.Now()
	switch c0 {
	case sRR:
		l.busy = false
	case sRNR:
		l.busy = true
	case sREJ:
		l.busy = false
	default:
		return
	}
	l.ack(nr, pf && response)
	if c0 == sREJ {
		l.resend()
	}
	if pf && !response {
		l.st.send(l.Remote, true, ctl(sRR, l.vr, true), nil)
	}
	l.flush()
}

// ack takes the frames up to nr as received. final is set when the frame
// answers a poll, which makes the unacknowledged ones go again. l.mu is
// held.
func (l *Link) ack(nr byte, final bool) {
	n := int(mod(int(nr) - int(l.va)))
	if n > len(l.unacked) {
		// Not a valid N(R): ignore it rather than reset the link.
		return
	}
	if n > 0 {
		l.unacked = l.unacked[n:]
		l.va = nr
		l.retries = 0
		l.deadline = time.Now().Add(l.st.t1())
		l.space.Broadcast()
	}
	if final && l.polling {
		l.polling = false
		l.retries = 0
		l.resend()
	}
	l.flush()
}

// resend sends the unacknowledged frames again. l.mu is held.
func (l *Link) resend() {
	l.vs = l.va
	pending := l.unacked
	l.unacked = nil
	l.queue = append(pending, l.queue...)
	l.flush()
}

// flush sends queued frames while the window is open. l.mu is held.
func (l *Link) flush() {
	for len(l.queue) > 0 && len(l.unacked) < window && !l.busy && !l.polling {
		info := l.queue[0]
		l.queue = l.queue[1:]
		l.st.send(l.Remote, false, ctl(l.vs<<1, l.vr, false), info)
		l.unacked = append(l.unacked, info)
		l.vs = mod(int(l.vs) + 1)
		l.deadline = time.Now().Add(l.st.t1())
	}
	l.space.Broadcast()
}

// Send queues an I frame. It does not block; Wait does.
func (l *Link) Send(info []byte) error {
	if len(info) > MaxInfo {
		return fmt.Errorf("llc: %d bytes is too long for a frame", len(info))
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	l.queue = append(l.queue, info)
	l.flush()
	return nil
}

// Wait blocks until few enough frames wait to be sent, the link closes or
// ctx is done.
func (l *Link) Wait(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() {
		l.mu.Lock()
		l.space.Broadcast()
		l.mu.Unlock()
	})
	defer stop()
	l.mu.Lock()
	defer l.mu.Unlock()
	for !l.closed && len(l.queue) > maxQueue && ctx.Err() == nil {
		l.space.Wait()
	}
	if l.closed {
		return ErrClosed
	}
	return ctx.Err()
}

// tick polls the remote station when a frame went unacknowledged for T1,
// or the link was silent for a while, and gives up after maxRetries
// polls.
func (l *Link) tick(now time.Time) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	overdue := (len(l.unacked) > 0 || l.polling) && now.After(l.deadline)
	idle := !l.polling && now.Sub(l.heard) > idlePoll
	if !overdue && !idle {
		l.mu.Unlock()
		return
	}
	if l.retries >= maxRetries {
		l.mu.Unlock()
		l.st.log().Info("llc link lost", "remote", l.Remote.String())
		l.st.send(l.Remote, false, []byte{ctlDISC | pfU}, nil)
		l.down()
		return
	}
	l.retries++
	l.polling = true
	l.deadline = now.Add(l.st.t1())
	l.st.send(l.Remote, false, ctl(sRR, l.vr, true), nil)
	l.mu.Unlock()
}

// Disconnect sends DISC and takes the link down.
func (l *Link) Disconnect() {
	l.mu.Lock()
	closed := l.closed
	l.mu.Unlock()
	if !closed {
		l.st.send(l.Remote, false, []byte{ctlDISC | pfU}, nil)
	}
	l.down()
}

// down closes the link and tells the handler.
func (l *Link) down() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	l.space.Broadcast()
	l.mu.Unlock()
	s := l.st
	s.mu.Lock()
	if s.links[l.Remote.String()] == l {
		delete(s.links, l.Remote.String())
	}
	s.mu.Unlock()
	if l.handler != nil {
		l.handler.Closed(l)
	}
}
