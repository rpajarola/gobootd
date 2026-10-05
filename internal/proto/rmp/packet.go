package rmp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// Multicast is the address clients send boot requests to.
var Multicast = net.HardwareAddr{0x09, 0x00, 0x09, 0x00, 0x00, 0x04}

// HP 802.2 LLC with extended SAPs.
const (
	sapHP    = 0xf8
	cntlHP   = 0x0300
	dxsapHP  = 0x0608 // client to server
	sxsapHP  = 0x0609 // server to client
	llcLen   = 10
	hdrLen   = llcLen + 8 // + type, retcode, sequence, session
	machLen  = 20
	maxData  = 1514 - 14 - hdrLen
	hostLen  = 13 // longest server name in a server ID reply
	probeSID = 0xffff
	version  = 2
)

// Packet types.
const (
	BootReq  = 1
	ReadReq  = 2
	BootDone = 3
	BootRepl = 129
	ReadRepl = 130
)

// Return codes.
const (
	OK         = 0
	EOF        = 2
	Abort      = 3
	Busy       = 4
	NoFile     = 16
	OpenFailed = 17
	NoDefault  = 18
	BadSession = 25
	BadPacket  = 27
)

// Packet is an RMP packet without the Ethernet header.
type Packet struct {
	Type    uint8
	RetCode uint8
	// Seq is the sequence number, file number (probes) or file offset
	// (reads).
	Seq     uint32
	Session uint16

	// Boot request and reply.
	Version  uint16
	MachType string
	Filename string

	// Read request.
	Size uint16
	// Read reply.
	Data []byte
}

// Parse parses the payload of an 802.3 frame. ok is false if it is not an
// RMP packet from a client.
func Parse(b []byte) (p Packet, ok bool) {
	if len(b) < hdrLen || b[0] != sapHP ||
		binary.BigEndian.Uint16(b[2:4]) != cntlHP ||
		binary.BigEndian.Uint16(b[6:8]) != dxsapHP {
		return p, false
	}
	p = Packet{
		Type:    b[10],
		RetCode: b[11],
		Seq:     binary.BigEndian.Uint32(b[12:16]),
		Session: binary.BigEndian.Uint16(b[16:18]),
	}
	d := b[hdrLen:]
	switch p.Type {
	case BootReq:
		if len(d) < 2+machLen+1 {
			return p, false
		}
		p.Version = binary.BigEndian.Uint16(d[0:2])
		p.MachType = machType(d[2 : 2+machLen])
		n := int(d[2+machLen])
		name := d[2+machLen+1:]
		if n > len(name) {
			return p, false
		}
		p.Filename = string(name[:n])
	case ReadReq:
		if len(d) < 2 {
			return p, false
		}
		p.Size = binary.BigEndian.Uint16(d[0:2])
	}
	return p, true
}

// machType returns the machine type up to the first space or NUL.
func machType(b []byte) string {
	if i := bytes.IndexAny(b, " \x00"); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// Marshal encodes a reply from the server.
func (p Packet) Marshal() []byte {
	b := make([]byte, hdrLen, hdrLen+len(p.Data)+3+len(p.Filename))
	b[0], b[1] = sapHP, sapHP
	binary.BigEndian.PutUint16(b[2:4], cntlHP)
	binary.BigEndian.PutUint16(b[6:8], sxsapHP)
	binary.BigEndian.PutUint16(b[8:10], dxsapHP)
	b[10], b[11] = p.Type, p.RetCode
	binary.BigEndian.PutUint32(b[12:16], p.Seq)
	binary.BigEndian.PutUint16(b[16:18], p.Session)
	switch p.Type {
	case BootRepl:
		b = binary.BigEndian.AppendUint16(b, p.Version)
		b = append(b, byte(len(p.Filename)))
		b = append(b, p.Filename...)
	case ReadRepl:
		b = append(b, p.Data...)
	}
	return b
}

var retCodes = map[uint8]string{
	OK: "ok", EOF: "eof", Abort: "abort", Busy: "busy", NoFile: "no file",
	OpenFailed: "open failed", NoDefault: "no default file", BadSession: "bad session", BadPacket: "bad packet",
}

func (p Packet) String() string {
	rc := retCodes[p.RetCode]
	if rc == "" {
		rc = fmt.Sprint(p.RetCode)
	}
	switch p.Type {
	case BootReq:
		kind := "boot request"
		if p.Session == probeSID {
			kind = "boot request (server id)"
			if p.Seq != 0 {
				kind = fmt.Sprintf("boot request (file name #%d)", p.Seq)
			}
		}
		return fmt.Sprintf("%s seq %#x session %d version %d machtype %q file %q", kind, p.Seq, p.Session, p.Version, p.MachType, p.Filename)
	case BootRepl:
		return fmt.Sprintf("boot reply %s seq %#x session %d version %d name %q", rc, p.Seq, p.Session, p.Version, p.Filename)
	case ReadReq:
		return fmt.Sprintf("read request offset %d session %d size %d", p.Seq, p.Session, p.Size)
	case ReadRepl:
		return fmt.Sprintf("read reply %s offset %d session %d bytes %d", rc, p.Seq, p.Session, len(p.Data))
	case BootDone:
		return fmt.Sprintf("boot done session %d", p.Session)
	}
	return fmt.Sprintf("type %d %s seq %#x session %d", p.Type, rc, p.Seq, p.Session)
}
