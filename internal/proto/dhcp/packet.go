package dhcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/rpajarola/gobootd/internal/link"
)

// UDP ports.
const (
	ServerPort = 67
	ClientPort = 68
)

// BOOTP operations.
const (
	OpRequest = 1
	OpReply   = 2
)

const (
	hwEther = 1
	// headerLen is the fixed part of a BOOTP message, before the vendor
	// area.
	headerLen = 236
	// minLen is the length of a BOOTP message with its 64 byte vendor
	// area (RFC 951). Shorter replies are padded, as some clients need.
	minLen = 300
	// minMaxSize is the message size every DHCP client accepts.
	minMaxSize = 576
	// flagBroadcast asks for replies to be broadcast (RFC 1542).
	flagBroadcast = 0x8000
)

// magic starts the options in the vendor area (RFC 1048).
var magic = []byte{99, 130, 83, 99}

// DHCP message types (option 53).
const (
	Discover = 1
	Offer    = 2
	Request  = 3
	Decline  = 4
	Ack      = 5
	Nak      = 6
	Release  = 7
	Inform   = 8
)

var typeNames = map[byte]string{
	Discover: "discover", Offer: "offer", Request: "request", Decline: "decline",
	Ack: "ack", Nak: "nak", Release: "release", Inform: "inform",
}

// Option codes (RFC 2132).
const (
	OptPad          = 0
	OptSubnetMask   = 1
	OptRouter       = 3
	OptDNS          = 6
	OptHostName     = 12
	OptBootSize     = 13
	OptDomainName   = 15
	OptRootPath     = 17
	OptBroadcast    = 28
	OptNISDomain    = 40
	OptNISServers   = 41
	OptRequestedIP  = 50
	OptLeaseTime    = 51
	OptOverload     = 52
	OptMessageType  = 53
	OptServerID     = 54
	OptParamRequest = 55
	OptMaxSize      = 57
	OptEnd          = 255
)

// Option is one option in the vendor area.
type Option struct {
	Code byte
	Data []byte
}

// Packet is a BOOTP message, with DHCP options if it has the magic cookie.
type Packet struct {
	Op, HType, HLen, Hops byte
	XID                   uint32
	Secs, Flags           uint16
	CIAddr, YIAddr        netip.Addr
	SIAddr, GIAddr        netip.Addr
	CHAddr                [16]byte
	SName, File           string
	// Cookie is set if the vendor area starts with the RFC 1048 magic
	// cookie; Options are then its options.
	Cookie  bool
	Options []Option
	// Vendor is the vendor area of a message without the cookie.
	Vendor []byte
}

// Parse parses a BOOTP or DHCP message.
func Parse(b []byte) (*Packet, error) {
	if len(b) < headerLen {
		return nil, errors.New("short message")
	}
	p := &Packet{
		Op: b[0], HType: b[1], HLen: b[2], Hops: b[3],
		XID:    binary.BigEndian.Uint32(b[4:8]),
		Secs:   binary.BigEndian.Uint16(b[8:10]),
		Flags:  binary.BigEndian.Uint16(b[10:12]),
		CIAddr: addr4(b[12:16]), YIAddr: addr4(b[16:20]),
		SIAddr: addr4(b[20:24]), GIAddr: addr4(b[24:28]),
		CHAddr: [16]byte(b[28:44]),
	}
	sname, file := b[44:108], b[108:236]
	vend := b[headerLen:]
	if !bytes.HasPrefix(vend, magic) {
		p.SName, p.File, p.Vendor = cstring(sname), cstring(file), vend
		return p, nil
	}
	p.Cookie = true
	opts, err := parseOptions(vend[len(magic):])
	if err != nil {
		return nil, err
	}
	p.Options = opts
	// Option overload puts more options in the file and sname fields.
	ov := p.Get(OptOverload)
	if len(ov) == 1 && ov[0]&1 != 0 {
		o, err := parseOptions(file)
		if err != nil {
			return nil, err
		}
		p.Options = append(p.Options, o...)
	} else {
		p.File = cstring(file)
	}
	if len(ov) == 1 && ov[0]&2 != 0 {
		o, err := parseOptions(sname)
		if err != nil {
			return nil, err
		}
		p.Options = append(p.Options, o...)
	} else {
		p.SName = cstring(sname)
	}
	return p, nil
}

func parseOptions(b []byte) ([]Option, error) {
	var opts []Option
	for len(b) > 0 {
		code := b[0]
		switch code {
		case OptPad:
			b = b[1:]
			continue
		case OptEnd:
			return opts, nil
		}
		if len(b) < 2 || len(b) < 2+int(b[1]) {
			return nil, fmt.Errorf("option %d truncated", code)
		}
		opts = append(opts, Option{Code: code, Data: b[2 : 2+int(b[1])]})
		b = b[2+int(b[1]):]
	}
	return opts, nil
}

// Get returns the data of option code, with repeated options joined
// (RFC 3396), or nil.
func (p *Packet) Get(code byte) []byte {
	var data []byte
	for _, o := range p.Options {
		if o.Code == code {
			data = append(data, o.Data...)
		}
	}
	return data
}

// Type returns the DHCP message type, or 0 for BOOTP.
func (p *Packet) Type() byte {
	if t := p.Get(OptMessageType); len(t) == 1 {
		return t[0]
	}
	return 0
}

// Addr returns option code as an IPv4 address, or the zero Addr.
func (p *Packet) Addr(code byte) netip.Addr {
	if b := p.Get(code); len(b) == 4 {
		return addr4(b)
	}
	return netip.Addr{}
}

// MAC returns the client's Ethernet address, or nil if the hardware type
// is not Ethernet.
func (p *Packet) MAC() net.HardwareAddr {
	if p.HType != hwEther || p.HLen != 6 {
		return nil
	}
	return net.HardwareAddr(p.CHAddr[:6])
}

// MaxSize returns the largest message the client accepts.
func (p *Packet) MaxSize() int {
	if b := p.Get(OptMaxSize); len(b) == 2 {
		return max(minMaxSize, int(binary.BigEndian.Uint16(b)))
	}
	return minMaxSize
}

// Marshal encodes p, padded to minLen bytes. The options are in the order
// given, and End is added.
func (p *Packet) Marshal() []byte {
	b := make([]byte, headerLen, minLen)
	b[0], b[1], b[2], b[3] = p.Op, p.HType, p.HLen, p.Hops
	binary.BigEndian.PutUint32(b[4:8], p.XID)
	binary.BigEndian.PutUint16(b[8:10], p.Secs)
	binary.BigEndian.PutUint16(b[10:12], p.Flags)
	put4(b[12:16], p.CIAddr)
	put4(b[16:20], p.YIAddr)
	put4(b[20:24], p.SIAddr)
	put4(b[24:28], p.GIAddr)
	copy(b[28:44], p.CHAddr[:])
	copy(b[44:107], p.SName)
	copy(b[108:235], p.File)
	if p.Cookie {
		b = append(b, magic...)
		for _, o := range p.Options {
			b = append(b, o.Code, byte(len(o.Data)))
			b = append(b, o.Data...)
		}
		b = append(b, OptEnd)
	} else {
		b = append(b, p.Vendor...)
	}
	if len(b) < minLen {
		b = append(b, make([]byte, minLen-len(b))...)
	}
	return b
}

func (p *Packet) String() string {
	var s strings.Builder
	kind := "bootp request"
	if p.Op == OpReply {
		kind = "bootp reply"
	}
	if t := p.Type(); t != 0 {
		kind = "dhcp " + typeName(t)
	}
	fmt.Fprintf(&s, "%s xid %#x chaddr %s", kind, p.XID, net.HardwareAddr(p.CHAddr[:min(int(p.HLen), 16)]))
	for _, a := range []struct {
		name string
		ip   netip.Addr
	}{{"ciaddr", p.CIAddr}, {"yiaddr", p.YIAddr}, {"siaddr", p.SIAddr}, {"giaddr", p.GIAddr}} {
		if a.ip.IsValid() && !a.ip.IsUnspecified() {
			fmt.Fprintf(&s, " %s %s", a.name, a.ip)
		}
	}
	if p.Flags&flagBroadcast != 0 {
		s.WriteString(" broadcast")
	}
	if p.File != "" {
		fmt.Fprintf(&s, " file %q", p.File)
	}
	for _, o := range p.Options {
		if o.Code != OptMessageType {
			fmt.Fprintf(&s, " %d=%x", o.Code, o.Data)
		}
	}
	return s.String()
}

func typeName(t byte) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("type %d", t)
}

func addr4(b []byte) netip.Addr { return netip.AddrFrom4([4]byte(b)) }

func put4(b []byte, ip netip.Addr) {
	if ip.Is4() {
		a := ip.As4()
		copy(b, a[:])
	}
}

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// Datagram is a UDP datagram in an Ethernet frame.
type Datagram struct {
	SrcMAC   net.HardwareAddr
	Src, Dst netip.AddrPort
	Payload  []byte
}

// parseUDP returns the UDP datagram in an IPv4 frame. Fragments and
// datagrams with a bad checksum are rejected.
func parseUDP(f link.Frame) (Datagram, bool) {
	if f.Type != link.TypeIPv4 {
		return Datagram{}, false
	}
	ip := header.IPv4(f.Payload)
	if !ip.IsValid(len(f.Payload)) || !ip.IsChecksumValid() ||
		ip.TransportProtocol() != header.UDPProtocolNumber || ip.More() || ip.FragmentOffset() != 0 {
		return Datagram{}, false
	}
	pl := ip.Payload()
	u := header.UDP(pl)
	if len(pl) < header.UDPMinimumSize || int(u.Length()) < header.UDPMinimumSize || int(u.Length()) > len(pl) {
		return Datagram{}, false
	}
	u = u[:u.Length()]
	if u.Checksum() != 0 && !u.IsChecksumValid(ip.SourceAddress(), ip.DestinationAddress(), checksum.Checksum(u.Payload(), 0)) {
		return Datagram{}, false
	}
	return Datagram{
		SrcMAC:  f.Src,
		Src:     netip.AddrPortFrom(addr4(ip.SourceAddressSlice()), u.SourcePort()),
		Dst:     netip.AddrPortFrom(addr4(ip.DestinationAddressSlice()), u.DestinationPort()),
		Payload: u.Payload(),
	}, true
}

// buildUDP returns an Ethernet frame with an IPv4 UDP datagram.
func buildUDP(dstMAC, srcMAC net.HardwareAddr, src, dst netip.AddrPort, id uint16, payload []byte) []byte {
	n := header.IPv4MinimumSize + header.UDPMinimumSize + len(payload)
	b := make([]byte, n)
	s, d := tcpip.AddrFrom4(src.Addr().As4()), tcpip.AddrFrom4(dst.Addr().As4())
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(n),
		ID:          id,
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     s,
		DstAddr:     d,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	u := header.UDP(b[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(u.Payload(), payload)
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, s, d, u.Length())
	xsum = checksum.Checksum(payload, xsum)
	if c := ^u.CalculateChecksum(xsum); c != 0 {
		u.SetChecksum(c)
	} else {
		u.SetChecksum(0xffff)
	}
	return link.Build(dstMAC, srcMAC, link.TypeIPv4, b)
}

// Match selects datagrams to the DHCP server port. It only looks at the
// headers; the server checks the rest.
func Match(f link.Frame) bool {
	ip := header.IPv4(f.Payload)
	if f.Type != link.TypeIPv4 || !ip.IsValid(len(f.Payload)) || ip.TransportProtocol() != header.UDPProtocolNumber {
		return false
	}
	u := header.UDP(ip.Payload())
	return len(u) >= header.UDPMinimumSize && u.DestinationPort() == ServerPort
}

// options builds a reply's options: required first, then those the
// client asked for in its order, then the rest, leaving out what does not
// fit in space bytes (including End).
func options(required, rest []Option, asked []byte, space int) (out []Option, dropped []byte) {
	slices.SortStableFunc(rest, func(a, b Option) int {
		ia, ib := slices.Index(asked, a.Code), slices.Index(asked, b.Code)
		if ia < 0 {
			ia = len(asked)
		}
		if ib < 0 {
			ib = len(asked)
		}
		return ia - ib
	})
	used := 1 // End
	for _, o := range append(slices.Clip(required), rest...) {
		if used+2+len(o.Data) > space {
			dropped = append(dropped, o.Code)
			continue
		}
		used += 2 + len(o.Data)
		out = append(out, o)
	}
	return out, dropped
}
