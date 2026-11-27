package netbios

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// NBT ports.
const (
	NameServicePort    = 137
	SessionServicePort = 139
)

// Name service header flags.
const (
	nsResponse  = 0x8000
	nsOpcode    = 0x7800
	nsAA        = 0x0400
	nsRD        = 0x0100
	nsBroadcast = 0x0010

	typeNB     = 0x0020
	typeNBSTAT = 0x0021
	classIN    = 0x0001
)

// Query is a name query or node status request.
type Query struct {
	ID        uint16
	Name      Name
	Status    bool // a node status request
	Broadcast bool
	qname     []byte
}

// ParseQuery parses a name service packet, accepting only queries.
func ParseQuery(b []byte) (Query, bool) {
	var q Query
	if len(b) < 12 {
		return q, false
	}
	flags := binary.BigEndian.Uint16(b[2:])
	if flags&nsResponse != 0 || flags&nsOpcode != 0 || binary.BigEndian.Uint16(b[4:]) != 1 {
		return q, false
	}
	n, l, err := decodeName(b[12:])
	if err != nil || len(b) < 12+l+4 {
		return q, false
	}
	typ, class := binary.BigEndian.Uint16(b[12+l:]), binary.BigEndian.Uint16(b[14+l:])
	if class != classIN || typ != typeNB && typ != typeNBSTAT {
		return q, false
	}
	q.ID = binary.BigEndian.Uint16(b)
	q.Name = n
	q.Status = typ == typeNBSTAT
	q.Broadcast = flags&nsBroadcast != 0
	q.qname = append([]byte(nil), b[12:12+l]...)
	return q, true
}

// Wildcard is the name of node status requests that ask whoever receives
// them: "*" padded with zeros.
var Wildcard = Name{'*'}

func (q Query) header(flags uint16) []byte {
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b, q.ID)
	binary.BigEndian.PutUint16(b[2:], flags)
	binary.BigEndian.PutUint16(b[6:], 1) // ANCOUNT
	b = append(b, q.qname...)
	return b
}

// Answer returns the positive response to a name query: the name is at
// ip, a unique name of a B node.
func (q Query) Answer(ip netip.Addr) []byte {
	b := q.header(nsResponse | nsAA | nsRD)
	b = binary.BigEndian.AppendUint16(b, typeNB)
	b = binary.BigEndian.AppendUint16(b, classIN)
	b = binary.BigEndian.AppendUint32(b, 300) // TTL
	b = binary.BigEndian.AppendUint16(b, 6)
	b = binary.BigEndian.AppendUint16(b, 0) // NB_FLAGS: unique, B node
	a := ip.As4()
	return append(b, a[:]...)
}

// Entry is a name in a node status response.
type Entry struct {
	Name  Name
	Group bool
}

// StatusAnswer returns the node status response listing names, with mac as
// the unit ID.
func (q Query) StatusAnswer(names []Entry, mac net.HardwareAddr) []byte {
	b := q.header(nsResponse | nsAA)
	b = binary.BigEndian.AppendUint16(b, typeNBSTAT)
	b = binary.BigEndian.AppendUint16(b, classIN)
	b = binary.BigEndian.AppendUint32(b, 0)
	rd := []byte{byte(len(names))}
	for _, e := range names {
		rd = append(rd, e.Name[:]...)
		flags := uint16(0x0400) // active
		if e.Group {
			flags |= 0x8000
		}
		rd = binary.BigEndian.AppendUint16(rd, flags)
	}
	stats := make([]byte, 46)
	copy(stats, mac)
	rd = append(rd, stats...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rd)))
	return append(b, rd...)
}

// Session service packet types.
const (
	ssMessage  = 0x00
	ssRequest  = 0x81
	ssPositive = 0x82
	ssNegative = 0x83
	ssKeepAive = 0x85
)

// Negative session response codes.
const (
	NotListeningOnCalled  = 0x80
	NotListeningForCaller = 0x81
	CalledNotPresent      = 0x82
)

// maxMessage is the longest NBT session message: 17 bits of length.
const maxMessage = 0x1ffff

// NBTConn is a session over TCP.
type NBTConn struct {
	c   net.Conn
	r   *bufio.Reader
	wmu sync.Mutex
}

func readPacket(r *bufio.Reader) (byte, []byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := int(h[1]&1)<<16 | int(binary.BigEndian.Uint16(h[2:]))
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, nil, err
	}
	return h[0], b, nil
}

func writePacket(w io.Writer, typ byte, b []byte) error {
	if len(b) > maxMessage {
		return fmt.Errorf("netbios: %d bytes is too long for a message", len(b))
	}
	h := []byte{typ, byte(len(b) >> 16 & 1), byte(len(b) >> 8), byte(len(b))}
	_, err := w.Write(append(h, b...))
	return err
}

// AcceptNBT reads the session request on a new connection and answers it.
// check returns 0 to accept the session, or a negative response code.
func AcceptNBT(c net.Conn, check func(called, calling Name) byte) (*NBTConn, Name, Name, error) {
	var called, calling Name
	r := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	typ, b, err := readPacket(r)
	if err != nil {
		return nil, called, calling, err
	}
	c.SetReadDeadline(time.Time{})
	if typ != ssRequest {
		// Clients of port 445 send SMB at once; this is not that port.
		writePacket(c, ssNegative, []byte{0x8f})
		return nil, called, calling, fmt.Errorf("netbios: packet type %#02x instead of a session request", typ)
	}
	called, n, err := decodeName(b)
	if err == nil {
		calling, _, err = decodeName(b[n:])
	}
	if err != nil {
		writePacket(c, ssNegative, []byte{0x8f})
		return nil, called, calling, err
	}
	if code := check(called, calling); code != 0 {
		writePacket(c, ssNegative, []byte{code})
		return nil, called, calling, fmt.Errorf("netbios: session refused (%#02x)", code)
	}
	if err := writePacket(c, ssPositive, nil); err != nil {
		return nil, called, calling, err
	}
	return &NBTConn{c: c, r: r}, called, calling, nil
}

// DialNBT sets up a session on a connection, as a client.
func DialNBT(c net.Conn, called, calling Name) (*NBTConn, error) {
	if err := writePacket(c, ssRequest, append(called.encode(), calling.encode()...)); err != nil {
		return nil, err
	}
	r := bufio.NewReader(c)
	typ, b, err := readPacket(r)
	if err != nil {
		return nil, err
	}
	if typ != ssPositive {
		code := byte(0)
		if len(b) > 0 {
			code = b[0]
		}
		return nil, fmt.Errorf("netbios: session refused (%#02x)", code)
	}
	return &NBTConn{c: c, r: r}, nil
}

// ReadMessage returns the next message, skipping keepalives. It returns
// io.EOF when the connection is closed.
func (c *NBTConn) ReadMessage(ctx context.Context) ([]byte, error) {
	for {
		typ, b, err := readPacket(c.r)
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				err = io.EOF
			}
			return nil, err
		}
		switch typ {
		case ssMessage:
			return b, nil
		case ssKeepAive:
		default:
			return nil, fmt.Errorf("netbios: packet type %#02x in a session", typ)
		}
	}
}

// WriteMessage sends a message.
func (c *NBTConn) WriteMessage(ctx context.Context, msg []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return writePacket(c.c, ssMessage, msg)
}

// Close closes the connection.
func (c *NBTConn) Close() error { return c.c.Close() }

// EncodeQuery returns a name query, or a node status request, as a client
// sends it.
func EncodeQuery(id uint16, n Name, status, broadcast bool) []byte {
	b := make([]byte, 12, 50)
	binary.BigEndian.PutUint16(b, id)
	if broadcast {
		binary.BigEndian.PutUint16(b[2:], nsRD|nsBroadcast)
	}
	binary.BigEndian.PutUint16(b[4:], 1)
	b = append(b, n.encode()...)
	typ := uint16(typeNB)
	if status {
		typ = typeNBSTAT
	}
	b = binary.BigEndian.AppendUint16(b, typ)
	return binary.BigEndian.AppendUint16(b, classIN)
}
