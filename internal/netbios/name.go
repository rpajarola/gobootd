// Package netbios carries NetBIOS sessions for SMB: over TCP/IP (NBT, RFC
// 1001 and 1002), with the name service on UDP 137 and sessions on TCP
// 139, and over NetBEUI (the NetBIOS Frames Protocol on IEEE 802.2 LLC),
// which DOS and early Windows clients use without TCP/IP.
//
// Only what a server needs is here: answering name queries for the
// server's names and accepting sessions. There is no name registration,
// browsing or datagram service.
package netbios

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Name suffixes.
const (
	Workstation = 0x00
	Messenger   = 0x03
	Server      = 0x20
)

// Name is a NetBIOS name: 15 characters, space padded, and a suffix that
// says what the name is for.
type Name [16]byte

// MakeName returns s, in upper case and cut to 15 characters, with the
// suffix.
func MakeName(s string, suffix byte) Name {
	var n Name
	s = strings.ToUpper(s)
	for i := range 15 {
		n[i] = ' '
		if i < len(s) {
			n[i] = s[i]
		}
	}
	n[15] = suffix
	return n
}

// Base returns the name without padding and suffix.
func (n Name) Base() string { return strings.TrimRight(string(n[:15]), " \x00") }

// Suffix returns the 16th byte.
func (n Name) Suffix() byte { return n[15] }

func (n Name) String() string {
	b := n.Base()
	if strings.ContainsFunc(b, func(r rune) bool { return r < ' ' || r > '~' }) {
		b = fmt.Sprintf("%q", b)
	}
	return fmt.Sprintf("%s<%02x>", b, n[15])
}

// Equal compares names ignoring case.
func (n Name) Equal(m Name) bool {
	return n[15] == m[15] && strings.EqualFold(string(n[:15]), string(m[:15]))
}

// encode returns the first-level encoding of n with an empty scope, as in
// NBT packets: a length byte, 32 letters and the root label.
func (n Name) encode() []byte {
	b := make([]byte, 0, 34)
	b = append(b, 32)
	for _, c := range n {
		b = append(b, 'A'+c>>4, 'A'+c&0x0f)
	}
	return append(b, 0)
}

// decodeName decodes a first-level encoded name at the start of b, and
// returns it with the number of bytes it took, scope included.
func decodeName(b []byte) (Name, int, error) {
	var n Name
	if len(b) < 34 || b[0] != 32 {
		return n, 0, errors.New("netbios: bad name")
	}
	for i := range 16 {
		hi, lo := b[1+2*i]-'A', b[2+2*i]-'A'
		if hi > 15 || lo > 15 {
			return n, 0, errors.New("netbios: bad name encoding")
		}
		n[i] = hi<<4 | lo
	}
	// Skip the scope's labels.
	off := 33
	for off < len(b) && b[off] != 0 {
		if b[off]&0xc0 != 0 {
			return n, 0, errors.New("netbios: compressed name")
		}
		off += 1 + int(b[off])
	}
	if off >= len(b) {
		return n, 0, errors.New("netbios: name runs past the packet")
	}
	return n, off + 1, nil
}

// Conn is a NetBIOS session: a reliable exchange of messages.
type Conn interface {
	ReadMessage(ctx context.Context) ([]byte, error)
	WriteMessage(ctx context.Context, msg []byte) error
	Close() error
}
