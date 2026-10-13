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

// decode returns the frame in a datagram, or false if it is not a data
// message for this session with the right cookie.
func (l *L2TPv3) decode(b []byte) ([]byte, bool) {
	n := l.headerLen()
	if len(b) < n+HeaderLen {
		return nil, false
	}
	if binary.BigEndian.Uint32(b[0:4])&0x800f0000 != l2tpData ||
		binary.BigEndian.Uint32(b[4:8]) != l.Session ||
		subtle.ConstantTimeCompare(b[8:8+len(l.Cookie)], l.Cookie) != 1 {
		return nil, false
	}
	return b[n:], true
}
