package netbios

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/rpajarola/gobootd/internal/llc"
)

// SAP is the LLC SAP of NetBEUI.
const SAP = 0xf0

// Multicast is the address of NetBEUI name queries and broadcasts.
var Multicast = net.HardwareAddr{0x03, 0x00, 0x00, 0x00, 0x00, 0x01}

// NBF commands.
const (
	nbAddGroupName   = 0x00
	nbAddNameQuery   = 0x01
	nbNameInConflict = 0x02
	nbStatusQuery    = 0x03
	nbDatagram       = 0x08
	nbDatagramBcast  = 0x09
	nbNameQuery      = 0x0a
	nbAddNameResp    = 0x0d
	nbNameRecognized = 0x0e
	nbStatusResp     = 0x0f
	nbDataAck        = 0x14
	nbDataFirstMid   = 0x15
	nbDataOnlyLast   = 0x16
	nbSessionConfirm = 0x17
	nbSessionEnd     = 0x18
	nbSessionInit    = 0x19
	nbNoReceive      = 0x1a
	nbRecvOutstand   = 0x1b
	nbRecvContinue   = 0x1c
	nbSessionAlive   = 0x1f
)

// Flags in DATA1.
const (
	flagRecvContinue = 0x01 // DATA_FIRST_MIDDLE: answer RECEIVE_CONTINUE
	flagNoAck        = 0x02 // sent with SEND.NO.ACK: no DATA_ACK
	flagVersion2     = 0x01 // SESSION_INITIALIZE and _CONFIRM: NetBIOS 2.0
)

const (
	uiHeaderLen   = 44
	sessHeaderLen = 14
	delimiter     = 0xefff
	// maxData is the most session data in one frame.
	maxData = llc.MaxInfo - sessHeaderLen
	// pendingTimeout is how long a recognized name waits for its session.
	pendingTimeout = 30 * time.Second
)

// header is an NBF frame header.
type header struct {
	cmd            byte
	data1          byte
	data2          uint16
	xmit, resp     uint16
	dst, src       Name // UI frames
	dstNum, srcNum byte // session frames
}

func (h header) ui() []byte {
	b := make([]byte, uiHeaderLen)
	h.put(b)
	copy(b[12:], h.dst[:])
	copy(b[28:], h.src[:])
	return b
}

func (h header) session(data []byte) []byte {
	b := make([]byte, sessHeaderLen, sessHeaderLen+len(data))
	h.put(b)
	b[12], b[13] = h.dstNum, h.srcNum
	return append(b, data...)
}

func (h header) put(b []byte) {
	le := binary.LittleEndian
	le.PutUint16(b, uint16(len(b)))
	le.PutUint16(b[2:], delimiter)
	b[4], b[5] = h.cmd, h.data1
	le.PutUint16(b[6:], h.data2)
	le.PutUint16(b[8:], h.xmit)
	le.PutUint16(b[10:], h.resp)
}

// parseHeader parses the header of an NBF frame and returns the data after
// it.
func parseHeader(b []byte) (header, []byte, bool) {
	var h header
	if len(b) < sessHeaderLen {
		return h, nil, false
	}
	le := binary.LittleEndian
	n := int(le.Uint16(b))
	if le.Uint16(b[2:]) != delimiter || (n != uiHeaderLen && n != sessHeaderLen) || len(b) < n {
		return h, nil, false
	}
	h.cmd, h.data1 = b[4], b[5]
	h.data2, h.xmit, h.resp = le.Uint16(b[6:]), le.Uint16(b[8:]), le.Uint16(b[10:])
	if n == uiHeaderLen {
		copy(h.dst[:], b[12:28])
		copy(h.src[:], b[28:44])
	} else {
		h.dstNum, h.srcNum = b[12], b[13]
	}
	return h, b[n:], true
}

// NBF serves NetBIOS names and sessions on an LLC station.
type NBF struct {
	Station *llc.Station
	// Names are the names answered.
	Names []Name
	// Check decides whether to answer a name query from mac.
	Check func(mac net.HardwareAddr, called, calling Name) bool
	// Accept is called in a goroutine of its own for each new session.
	Accept func(s *NBFSession)
	Log    *slog.Logger

	mu      sync.Mutex
	remotes map[string]*remote
	corr    uint16
	// dials wait for NAME_RECOGNIZED, by correlator.
	dials map[uint16]chan recognized
}

type recognized struct {
	mac net.HardwareAddr
	h   header
}

// remote is what a remote station has with us: the LLC link and the
// sessions on it.
type remote struct {
	nbf      *NBF
	mac      net.HardwareAddr
	link     *llc.Link
	sessions map[byte]*NBFSession // by our session number
	pending  map[byte]*pending
}

// pending is a name recognized for a session that the client is yet to
// initialize.
type pending struct {
	called, calling Name
	resp            uint16 // the correlator SESSION_INITIALIZE sends back
	at              time.Time
}

// Init wires the NBF into its station.
func (n *NBF) Init() {
	n.Station.UI = n.ui
	n.Station.Accept = n.acceptLink
}

func (n *NBF) log() *slog.Logger {
	if n.Log != nil {
		return n.Log
	}
	return slog.Default()
}

func (n *NBF) correlator() uint16 {
	n.corr++
	if n.corr == 0 {
		n.corr = 1
	}
	return n.corr
}

func (n *NBF) remote(mac net.HardwareAddr) *remote {
	if n.remotes == nil {
		n.remotes = map[string]*remote{}
	}
	r := n.remotes[mac.String()]
	if r == nil {
		r = &remote{nbf: n, mac: append(net.HardwareAddr(nil), mac...), sessions: map[byte]*NBFSession{}, pending: map[byte]*pending{}}
		n.remotes[mac.String()] = r
	}
	return r
}

// number returns a free session number with r. n.mu is held.
func (r *remote) number() (byte, bool) {
	for i := 1; i < 255; i++ {
		b := byte(i)
		if r.sessions[b] == nil && r.pending[b] == nil {
			return b, true
		}
	}
	return 0, false
}

func (n *NBF) ours(name Name) bool {
	for _, m := range n.Names {
		if m.Equal(name) {
			return true
		}
	}
	return false
}

// ui handles unnumbered frames: name management.
func (n *NBF) ui(src, dst net.HardwareAddr, info []byte) {
	h, _, ok := parseHeader(info)
	if !ok {
		return
	}
	switch h.cmd {
	case nbNameQuery:
		n.nameQuery(src, h)
	case nbAddNameQuery, nbAddGroupName:
		// Someone claims one of our names: object.
		if n.ours(h.src) {
			n.Station.SendUI(src, header{cmd: nbAddNameResp, xmit: h.resp, dst: h.src, src: h.src}.ui())
		}
	case nbNameRecognized:
		n.mu.Lock()
		ch := n.dials[h.xmit]
		n.mu.Unlock()
		if ch != nil {
			select {
			case ch <- recognized{append(net.HardwareAddr(nil), src...), h}:
			default:
			}
		}
	}
}

// nameQuery answers a query for one of our names. With a session number
// the client wants a session, and the answer carries ours.
func (n *NBF) nameQuery(src net.HardwareAddr, h header) {
	if !n.ours(h.dst) {
		return
	}
	callerNum := byte(h.data2)
	if n.Check != nil && !n.Check(src, h.dst, h.src) {
		return
	}
	ans := header{cmd: nbNameRecognized, xmit: h.resp, dst: h.src, src: h.dst}
	if callerNum != 0 {
		n.mu.Lock()
		r := n.remote(src)
		now := time.Now()
		for num, p := range r.pending {
			if now.Sub(p.at) > pendingTimeout {
				delete(r.pending, num)
			}
		}
		num, ok := r.number()
		if ok {
			p := &pending{called: h.dst, calling: h.src, resp: n.correlator(), at: now}
			r.pending[num] = p
			ans.data2 = uint16(num)
			ans.resp = p.resp
		} else {
			ans.data2 = 0xff // no resources
		}
		n.mu.Unlock()
	}
	n.Station.SendUI(src, ans.ui())
}

// acceptLink takes LLC links from stations that may have sessions.
func (n *NBF) acceptLink(l *llc.Link) llc.Handler {
	n.mu.Lock()
	defer n.mu.Unlock()
	r := n.remote(l.Remote)
	r.link = l
	return r
}

// Receive implements llc.Handler: session frames.
func (r *remote) Receive(l *llc.Link, info []byte) {
	h, data, ok := parseHeader(info)
	if !ok {
		return
	}
	n := r.nbf
	n.mu.Lock()
	s := r.sessions[h.dstNum]
	n.mu.Unlock()
	switch h.cmd {
	case nbSessionInit:
		r.sessionInit(l, h)
	case nbSessionConfirm:
		if s != nil && s.remoteNum == h.srcNum {
			s.confirmed(h)
		}
	case nbDataFirstMid, nbDataOnlyLast:
		if s == nil || s.remoteNum != h.srcNum {
			return
		}
		if h.cmd == nbDataFirstMid && h.data1&flagRecvContinue != 0 {
			l.Send(header{cmd: nbRecvContinue, xmit: h.resp, dstNum: h.srcNum, srcNum: h.dstNum}.session(nil))
		}
		last := h.cmd == nbDataOnlyLast
		if last && h.data1&flagNoAck == 0 {
			l.Send(header{cmd: nbDataAck, xmit: h.resp, dstNum: h.srcNum, srcNum: h.dstNum}.session(nil))
		}
		s.received(data, last)
	case nbSessionEnd:
		if s != nil && s.remoteNum == h.srcNum {
			s.end(false)
		}
	case nbDataAck, nbSessionAlive, nbRecvContinue:
	case nbNoReceive, nbRecvOutstand:
		n.log().Debug("netbeui receiver short of buffers", "remote", r.mac.String(), "command", h.cmd)
	}
}

func (r *remote) sessionInit(l *llc.Link, h header) {
	n := r.nbf
	n.mu.Lock()
	p := r.pending[h.dstNum]
	if p == nil || p.resp != h.xmit {
		n.mu.Unlock()
		n.log().Debug("netbeui session initialize without a name query", "remote", r.mac.String(), "session", h.dstNum)
		l.Send(header{cmd: nbSessionEnd, data2: 1, dstNum: h.srcNum, srcNum: h.dstNum}.session(nil))
		return
	}
	delete(r.pending, h.dstNum)
	s := newSession(r, h.dstNum, h.srcNum, p.called, p.calling, int(h.data2))
	r.sessions[h.dstNum] = s
	n.mu.Unlock()
	l.Send(header{cmd: nbSessionConfirm, data1: flagVersion2, data2: maxData, xmit: h.resp, dstNum: h.srcNum, srcNum: h.dstNum}.session(nil))
	if n.Accept != nil {
		go n.Accept(s)
	}
}

// Closed implements llc.Handler: the sessions on the link end.
func (r *remote) Closed(l *llc.Link) {
	n := r.nbf
	n.mu.Lock()
	if r.link != l {
		n.mu.Unlock()
		return
	}
	r.link = nil
	var ss []*NBFSession
	for _, s := range r.sessions {
		ss = append(ss, s)
	}
	n.mu.Unlock()
	for _, s := range ss {
		s.end(false)
	}
}

// Dial sets up a session with called, as a client does: it finds the
// name, connects the LLC link and initializes the session.
func (n *NBF) Dial(ctx context.Context, called, calling Name) (*NBFSession, error) {
	n.mu.Lock()
	corr := n.correlator()
	ch := make(chan recognized, 1)
	if n.dials == nil {
		n.dials = map[uint16]chan recognized{}
	}
	n.dials[corr] = ch
	// The session number is chosen before the server is known; any
	// number free with every remote would do, so use one past theirs.
	num := byte(corr%250 + 1)
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		delete(n.dials, corr)
		n.mu.Unlock()
	}()
	var rec recognized
	for try := 0; ; try++ {
		if try == 5 {
			return nil, fmt.Errorf("netbios: %s not found", called)
		}
		n.Station.SendUI(Multicast, header{cmd: nbNameQuery, data2: uint16(num), resp: corr, dst: called, src: calling}.ui())
		select {
		case rec = <-ch:
		case <-time.After(500 * time.Millisecond):
			continue
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		break
	}
	srvNum := byte(rec.h.data2)
	if srvNum == 0 || srvNum == 0xff {
		return nil, fmt.Errorf("netbios: %s does not listen", called)
	}
	n.mu.Lock()
	r := n.remote(rec.mac)
	l := r.link
	n.mu.Unlock()
	if l == nil {
		var err error
		if l, err = n.Station.Connect(ctx, rec.mac, r); err != nil {
			return nil, err
		}
		n.mu.Lock()
		r.link = l
		n.mu.Unlock()
	}
	s := newSession(r, num, srvNum, called, calling, maxData)
	s.confirm = make(chan struct{})
	n.mu.Lock()
	r.sessions[num] = s
	n.mu.Unlock()
	l.Send(header{cmd: nbSessionInit, data1: flagVersion2, data2: maxData, xmit: rec.h.resp, resp: n.correlator(), dstNum: srvNum, srcNum: num}.session(nil))
	select {
	case <-s.confirm:
		return s, nil
	case <-s.done:
		return nil, errors.New("netbios: session refused")
	case <-time.After(5 * time.Second):
		s.Close()
		return nil, errors.New("netbios: session not confirmed")
	case <-ctx.Done():
		s.Close()
		return nil, ctx.Err()
	}
}

// NBFSession is a NetBIOS session over NetBEUI.
type NBFSession struct {
	r                *remote
	local, remoteNum byte
	maxData          int
	Called, Calling  Name

	mu      sync.Mutex
	msgs    [][]byte
	partial []byte
	notify  chan struct{}
	done    chan struct{}
	closed  bool
	corr    uint16
	confirm chan struct{}
}

func newSession(r *remote, local, remoteNum byte, called, calling Name, max int) *NBFSession {
	if max <= 0 || max > maxData {
		max = maxData
	}
	return &NBFSession{r: r, local: local, remoteNum: remoteNum, maxData: max, Called: called, Calling: calling,
		notify: make(chan struct{}, 1), done: make(chan struct{})}
}

// Remote returns the client's MAC address.
func (s *NBFSession) Remote() net.HardwareAddr { return s.r.mac }

func (s *NBFSession) confirmed(h header) {
	if h.data2 > 0 && int(h.data2) < s.maxData {
		s.maxData = int(h.data2)
	}
	if s.confirm != nil {
		select {
		case <-s.confirm:
		default:
			close(s.confirm)
		}
	}
}

func (s *NBFSession) received(data []byte, last bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.partial = append(s.partial, data...)
	if !last {
		return
	}
	s.msgs = append(s.msgs, s.partial)
	s.partial = nil
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// ReadMessage returns the next message, or io.EOF once the session ended.
func (s *NBFSession) ReadMessage(ctx context.Context) ([]byte, error) {
	for {
		s.mu.Lock()
		if len(s.msgs) > 0 {
			m := s.msgs[0]
			s.msgs = s.msgs[1:]
			s.mu.Unlock()
			return m, nil
		}
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return nil, io.EOF
		}
		select {
		case <-s.notify:
		case <-s.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (s *NBFSession) link() *llc.Link {
	s.r.nbf.mu.Lock()
	defer s.r.nbf.mu.Unlock()
	return s.r.link
}

// WriteMessage sends a message in as many frames as it takes.
func (s *NBFSession) WriteMessage(ctx context.Context, msg []byte) error {
	s.mu.Lock()
	closed := s.closed
	s.corr++
	if s.corr == 0 {
		s.corr = 1
	}
	corr := s.corr
	s.mu.Unlock()
	l := s.link()
	if closed || l == nil {
		return io.ErrClosedPipe
	}
	for {
		n := min(len(msg), s.maxData)
		h := header{cmd: nbDataFirstMid, dstNum: s.remoteNum, srcNum: s.local}
		if n == len(msg) {
			h.cmd, h.resp = nbDataOnlyLast, corr
		}
		if err := l.Send(h.session(msg[:n])); err != nil {
			return err
		}
		if err := l.Wait(ctx); err != nil {
			return err
		}
		msg = msg[n:]
		if len(msg) == 0 {
			return nil
		}
	}
}

// Close ends the session.
func (s *NBFSession) Close() error {
	s.end(true)
	return nil
}

// end closes the session, telling the other side if tell is set.
func (s *NBFSession) end(tell bool) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.done)
	s.mu.Unlock()
	n := s.r.nbf
	n.mu.Lock()
	if s.r.sessions[s.local] == s {
		delete(s.r.sessions, s.local)
	}
	l := s.r.link
	n.mu.Unlock()
	if tell && l != nil {
		l.Send(header{cmd: nbSessionEnd, dstNum: s.remoteNum, srcNum: s.local}.session(nil))
	}
}
