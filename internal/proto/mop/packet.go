package mop

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
)

// typeDL is the ethertype of the MOP Dump/Load protocol.
const typeDL = 0x6001

// snapDL is the 802.2 LLC and SNAP header of MOP Dump/Load in 802.3
// frames.
var snapDL = []byte{0xaa, 0xaa, 0x03, 0x08, 0x00, 0x2b, 0x60, 0x01}

// Multicast is the Dump/Load assistance multicast address clients send
// their first program request to.
var Multicast = net.HardwareAddr{0xab, 0x00, 0x00, 0x01, 0x00, 0x00}

// Message codes.
const (
	codeMLT = 0  // memory load with transfer address
	codeMLD = 2  // memory load
	codeASV = 3  // assistance volunteer
	codeRPR = 8  // request program
	codeRML = 10 // request memory load
	codePLT = 20 // parameter load with transfer address
)

// Parameters of a parameter load.
const (
	pltEnd = 0
	pltHSN = 3 // host system name
	pltHSA = 4 // host system address
	pltHST = 5 // host system time
)

// Information fields of a program request.
const (
	infoDLBSZ = 401 // data link buffer size
)

// Program types.
var programTypes = []string{"secondary loader", "tertiary loader", "operating system", "management file"}

// framing is how a client wraps MOP messages.
type framing int

const (
	ether    framing = iota // Ethernet II, with a length word
	ieee8023                // 802.3 with SNAP, without one
)

func (f framing) String() string {
	if f == ieee8023 {
		return "802.3"
	}
	return "ethernet"
}

// Match selects MOP Dump/Load frames.
func Match(f link.Frame) bool {
	_, _, ok := unwrap(f)
	return ok
}

// unwrap returns the MOP message of a frame.
func unwrap(f link.Frame) ([]byte, framing, bool) {
	switch {
	case f.Type == typeDL:
		if len(f.Payload) < 2 {
			return nil, 0, false
		}
		n := int(binary.LittleEndian.Uint16(f.Payload))
		if n == 0 || n > len(f.Payload)-2 {
			return nil, 0, false
		}
		return f.Payload[2 : 2+n], ether, true
	case f.Type == 0 && bytes.HasPrefix(f.Payload, snapDL) && len(f.Payload) > len(snapDL):
		return f.Payload[len(snapDL):], ieee8023, true
	}
	return nil, 0, false
}

// wrap builds a frame carrying msg.
func wrap(fr framing, dst, src net.HardwareAddr, msg []byte) []byte {
	if fr == ieee8023 {
		return link.Pad(link.Build8023(dst, src, append(append([]byte{}, snapDL...), msg...)))
	}
	p := binary.LittleEndian.AppendUint16(make([]byte, 0, 2+len(msg)), uint16(len(msg)))
	return link.Pad(link.Build(dst, src, typeDL, append(p, msg...)))
}

// request is a program request.
type request struct {
	Device    byte
	Format    byte
	Program   byte
	Software  string // the requested image; "" for the default
	Processor byte
	BufSize   int // data link buffer size, or 0
}

func (r request) LogValue() string {
	pt := fmt.Sprintf("type %d", r.Program)
	if int(r.Program) < len(programTypes) {
		pt = programTypes[r.Program]
	}
	return fmt.Sprintf("program request for %q (%s, device %d, processor %d, buffer %d)", r.Software, pt, r.Device, r.Processor, r.BufSize)
}

// parseRequest parses a program request after its code.
func parseRequest(b []byte) (request, bool) {
	var r request
	if len(b) < 4 {
		return r, false
	}
	r.Device, r.Format, r.Program = b[0], b[1], b[2]
	n := int(b[3])
	b = b[4:]
	// Lengths 0xff and 0xfe mean "the operating system" and "the
	// maintenance system", without a name.
	if n < 0x80 {
		if n > len(b) {
			return r, false
		}
		r.Software = string(b[:n])
		b = b[n:]
	}
	if len(b) == 0 {
		return r, true // version 3 requests may end here
	}
	r.Processor = b[0]
	b = b[1:]
	for len(b) >= 3 {
		typ, n := binary.LittleEndian.Uint16(b), int(b[2])
		b = b[3:]
		if n > len(b) {
			break
		}
		if typ == infoDLBSZ && n == 2 {
			r.BufSize = int(binary.LittleEndian.Uint16(b))
		}
		b = b[n:]
	}
	return r, true
}

// memoryLoad builds a memory load message.
func memoryLoad(count byte, addr uint32, data []byte) []byte {
	m := []byte{codeMLD, count}
	m = binary.LittleEndian.AppendUint32(m, addr)
	return append(m, data...)
}

// parameterLoad builds the parameter load with transfer address that ends
// a load.
func parameterLoad(count byte, server string, mac net.HardwareAddr, now time.Time, xfer uint32) []byte {
	m := []byte{codePLT, count}
	if server != "" {
		m = append(m, pltHSN, byte(len(server)))
		m = append(m, server...)
	}
	m = append(m, pltHSA, 6)
	m = append(m, mac...)
	m = append(m, pltHST, 10, byte(now.Year()/100), byte(now.Year()%100), byte(now.Month()), byte(now.Day()),
		byte(now.Hour()), byte(now.Minute()), byte(now.Second()), byte(now.Nanosecond()/10_000_000), 0, 0)
	m = append(m, pltEnd)
	return binary.LittleEndian.AppendUint32(m, xfer)
}
