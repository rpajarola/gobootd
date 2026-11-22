package link

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// L2TPv3 is static L2TPv3 over UDP (RFC 3931) carrying Ethernet (RFC 4719),
// without the control connection: both ends are configured with the same
// session ID and cookie, as with Linux's "ip l2tp" and QEMU's
// "-netdev l2tpv3,udp=on". Each datagram is
//
//	flags and version (4) | session ID (4) | cookie (0, 4 or 8) |
//	[L2-specific sublayer (4)] | Ethernet frame
//
// Datagrams with another session ID or cookie are dropped, so the cookie
// works as a password against anyone who cannot see the traffic. It is
// sent in clear.
type L2TPv3 struct {
	// Session is the session ID, used in both directions. Not 0.
	Session uint32
	// Cookie is 0, 4 or 8 bytes, used in both directions.
	Cookie []byte
	// Counter adds the default L2-specific sublayer, which holds a
	// sequence number (Linux's l2spec_type default, QEMU's counter=on).
	Counter bool
}

// l2tpData is the first word of a data message over UDP: T bit clear,
// version 3.
const l2tpData = 0x00030000

// ParseCookie parses a cookie of 8 or 16 hex digits, optionally with 0x.
func ParseCookie(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(s), "0x"))
	if err != nil || len(b) != 4 && len(b) != 8 {
		return nil, fmt.Errorf("cookie %q is not 8 or 16 hex digits", s)
	}
	return b, nil
}

func (l *L2TPv3) headerLen() int {
	n := 8 + len(l.Cookie)
	if l.Counter {
		n += 4
	}
	return n
}

// encode appends the header for a frame with sequence number seq.
func (l *L2TPv3) encode(b []byte, seq uint32) []byte {
	b = binary.BigEndian.AppendUint32(b, l2tpData)
	b = binary.BigEndian.AppendUint32(b, l.Session)
	b = append(b, l.Cookie...)
	if l.Counter {
		b = binary.BigEndian.AppendUint32(b, 0x40000000|seq&0xffffff) // S bit and sequence
	}
	return b
}

// setSeq sets the sequence number in a datagram encode made.
func (l *L2TPv3) setSeq(dg []byte, seq uint32) {
	if l.Counter {
		n := l.headerLen()
		binary.BigEndian.PutUint32(dg[n-4:n], 0x40000000|seq&0xffffff)
	}
}

// rejectReason says why a datagram was dropped.
type rejectReason int

const (
	accepted rejectReason = iota
	// rejectShort: too short for the header and an Ethernet header.
	rejectShort
	// rejectHeader: a control message or another L2TP version.
	rejectHeader
	rejectSession
	rejectCookie
)

func (r rejectReason) String() string {
	switch r {
	case rejectShort:
		return "too short"
	case rejectHeader:
		return "not an L2TPv3 data message"
	case rejectSession:
		return "wrong session"
	case rejectCookie:
		return "wrong cookie"
	}
	return "accepted"
}

// decode returns the frame in a datagram, and its sequence number if the
// sender numbers them, or why it is not a data message for this session
// with the right cookie.
func (l *L2TPv3) decode(b []byte) (frame []byte, seq uint32, hasSeq bool, why rejectReason) {
	n := l.headerLen()
	if len(b) < n+HeaderLen {
		return nil, 0, false, rejectShort
	}
	switch {
	case binary.BigEndian.Uint32(b[0:4])&0x800f0000 != l2tpData:
		return nil, 0, false, rejectHeader
	case binary.BigEndian.Uint32(b[4:8]) != l.Session:
		return nil, 0, false, rejectSession
	case subtle.ConstantTimeCompare(b[8:8+len(l.Cookie)], l.Cookie) != 1:
		return nil, 0, false, rejectCookie
	}
	if l.Counter {
		// The default L2-specific sublayer: S bit, then 24 bits of
		// sequence number. Without the S bit, the sender does not
		// number its frames.
		w := binary.BigEndian.Uint32(b[n-4 : n])
		seq, hasSeq = w&0xffffff, w&0x40000000 != 0
	}
	return b[n:], seq, hasSeq, accepted
}

// seqWindow is how far behind the expected sequence number a frame may
// be and still count as late; a frame further back means the peer started
// over, e.g. after a restart.
const seqWindow = 1024

// seqCheck compares a received sequence number with the expected one and
// returns how many frames were skipped, whether this one is late (out of
// order or a duplicate), and the next expected number.
func seqCheck(expect, seq uint32) (lost uint32, late, restart bool, next uint32) {
	const mod = 1 << 24
	switch d := (seq - expect) % mod; {
	case d == 0:
		return 0, false, false, (seq + 1) % mod
	case d < mod-seqWindow:
		if d >= mod/2 {
			// Far behind: the peer started over.
			return 0, false, true, (seq + 1) % mod
		}
		return d, false, false, (seq + 1) % mod
	default:
		return 0, true, false, expect
	}
}
