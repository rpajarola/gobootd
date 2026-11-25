package rpl

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/rpajarola/gobootd/internal/link"
)

// sap is the LLC service access point of RPL.
const sap = 0xfc

// llcUI is the LLC control field of unnumbered information frames.
const llcUI = 0x03

// Multicast is the address clients send FIND frames to.
var Multicast = net.HardwareAddr{0x03, 0x00, 0x02, 0x00, 0x00, 0x00}

// Commands.
const (
	cmdFind     = 0x0001
	cmdFound    = 0x0002
	cmdSendFile = 0x0010
	cmdFileData = 0x0020
)

// Vector IDs. IDs with one of the top two bits set hold data; the others
// hold more vectors.
const (
	vecCorrelator = 0x4003
	vecSourceMAC  = 0x4006
	vecSAP        = 0x4007
	vecFrameLen   = 0x4009
	vecConnClass  = 0x400a
	vecResponse   = 0x400b
	vecTargetMAC  = 0x400c
	vecSequence   = 0x4011
	vecData       = 0x4018
	vecLoader     = 0xc005
	vecLoadHeader = 0xc014
	vecFoundGroup = 0x0008
)

// Load header flags.
const (
	flagAskMore = 0x10 // the client asks for each block
	flagMore    = 0x20 // more blocks follow
	flagLast    = 0xc0 // last block: start the program
)

// Match selects RPL frames: 802.3 with the RPL SAP.
func Match(f link.Frame) bool {
	return f.Type == 0 && len(f.Payload) >= 3 && f.Payload[0] == sap && f.Payload[1] == sap
}

// packet is an RPL frame from a client.
type packet struct {
	Cmd        uint16
	Correlator uint32
	MAC        net.HardwareAddr // the client's
	FrameLen   int
	Sequence   uint32
	HasSeq     bool
	Loader     []byte
}

func (p packet) LogValue() string {
	switch p.Cmd {
	case cmdFind:
		return fmt.Sprintf("FIND from %s (frame %d)", p.MAC, p.FrameLen)
	case cmdSendFile:
		return fmt.Sprintf("SEND.FILE.REQUEST from %s for block %d (frame %d)", p.MAC, p.Sequence, p.FrameLen)
	}
	return fmt.Sprintf("command %#04x", p.Cmd)
}

// parse parses the LLC payload of an RPL frame.
func parse(b []byte) (packet, bool) {
	var p packet
	if len(b) < 3+4 || b[0] != sap || b[2] != llcUI {
		return p, false
	}
	b = b[3:]
	n := min(int(binary.BigEndian.Uint16(b)), len(b))
	if n < 4 {
		return p, false
	}
	p.Cmd = binary.BigEndian.Uint16(b[2:])
	walk(b[4:n], &p, 0)
	return p, true
}

// walk reads the vectors in b.
func walk(b []byte, p *packet, depth int) {
	for len(b) >= 4 && depth < 8 {
		n, id := int(binary.BigEndian.Uint16(b)), binary.BigEndian.Uint16(b[2:])
		if n < 4 || n > len(b) {
			return
		}
		v := b[4:n]
		b = b[n:]
		if id&0xc000 == 0 {
			walk(v, p, depth+1)
			continue
		}
		switch {
		case id == vecCorrelator && len(v) == 4:
			p.Correlator = binary.BigEndian.Uint32(v)
		case id == vecSourceMAC && len(v) == 6:
			p.MAC = net.HardwareAddr(v)
		case id == vecFrameLen && len(v) == 2:
			p.FrameLen = int(binary.BigEndian.Uint16(v))
		case id == vecSequence && len(v) == 4:
			p.Sequence, p.HasSeq = binary.BigEndian.Uint32(v), true
		case id == vecLoader:
			p.Loader = v
		}
	}
}

// builder assembles an RPL frame.
type builder []byte

func newFrame(cmd uint16) builder {
	return builder{sap, sap, llcUI, 0, 0, byte(cmd >> 8), byte(cmd)}
}

func (b builder) vec(id uint16, v []byte) builder {
	b = binary.BigEndian.AppendUint16(b, uint16(4+len(v)))
	b = binary.BigEndian.AppendUint16(b, id)
	return append(b, v...)
}

func (b builder) u32(id uint16, v uint32) builder {
	return b.vec(id, binary.BigEndian.AppendUint32(nil, v))
}

func (b builder) u16(id uint16, v uint16) builder {
	return b.vec(id, binary.BigEndian.AppendUint16(nil, v))
}

// done fills in the length.
func (b builder) done() []byte {
	binary.BigEndian.PutUint16(b[3:], uint16(len(b)-3))
	return b
}

// found builds the answer to a FIND, as rpld does.
func found(correlator uint32, client, server net.HardwareAddr, frameLen int) []byte {
	group := builder{}.u16(vecFrameLen, uint16(frameLen)).u16(vecConnClass, 0)
	return newFrame(cmdFound).
		u32(vecCorrelator, correlator).
		vec(vecResponse, []byte{0}).
		vec(vecTargetMAC, client).
		vec(vecSourceMAC, server).
		vec(vecFoundGroup, group).
		vec(vecSAP, []byte{sap}).
		done()
}

// fileData builds a block of the boot image.
func fileData(seq, load, exec uint32, flags byte, data []byte) []byte {
	hdr := binary.BigEndian.AppendUint32(nil, load)
	hdr = binary.BigEndian.AppendUint32(hdr, exec)
	hdr = append(hdr, flags)
	return newFrame(cmdFileData).
		u32(vecSequence, seq).
		vec(vecLoadHeader, hdr).
		vec(vecData, data).
		done()
}
