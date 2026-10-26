package link

import (
	"encoding/binary"
	"net/netip"
)

// TypeIPv6 is the IPv6 ethertype.
const TypeIPv6 = 0x86dd

// DefaultMSS is the TCP maximum segment size assumed when a SYN carries no
// MSS option (RFC 1122 4.2.2.6).
const DefaultMSS = 536

// TCP flags.
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpPSH = 0x08
	tcpCWR = 0x80
)

// TCPFlow is one direction of a TCP connection.
type TCPFlow struct {
	Src, Dst netip.AddrPort
}

// Reverse returns the opposite direction of f.
func (f TCPFlow) Reverse() TCPFlow { return TCPFlow{Src: f.Dst, Dst: f.Src} }

// tcpFrame locates the headers of a TCP segment in an Ethernet frame.
type tcpFrame struct {
	v6   bool
	ip   int // offset of the IP header
	tcp  int // offset of the TCP header
	data int // offset of the TCP payload
	end  int // end of the IP packet
	flow TCPFlow
}

// parseTCP finds an unfragmented TCP segment over IPv4, or over IPv6
// without extension headers, in an Ethernet II frame.
func parseTCP(frame []byte) (tcpFrame, bool) {
	var t tcpFrame
	if len(frame) < HeaderLen {
		return t, false
	}
	t.ip = HeaderLen
	p := frame[HeaderLen:]
	var src, dst netip.Addr
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case TypeIPv4:
		if len(p) < 20 || p[0]>>4 != 4 || p[9] != 6 {
			return t, false
		}
		ihl := int(p[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(p[2:4]))
		// More fragments, or a fragment offset.
		if ihl < 20 || total < ihl || total > len(p) || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
			return t, false
		}
		t.tcp, t.end = t.ip+ihl, t.ip+total
		src, dst = netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20]))
	case TypeIPv6:
		if len(p) < 40 || p[0]>>4 != 6 || p[6] != 6 {
			return t, false
		}
		total := 40 + int(binary.BigEndian.Uint16(p[4:6]))
		if total > len(p) {
			return t, false
		}
		t.v6 = true
		t.tcp, t.end = t.ip+40, t.ip+total
		src, dst = netip.AddrFrom16([16]byte(p[8:24])), netip.AddrFrom16([16]byte(p[24:40]))
	default:
		return t, false
	}
	if t.end-t.tcp < 20 {
		return t, false
	}
	th := frame[t.tcp:]
	t.data = t.tcp + int(th[12]>>4)*4
	if t.data-t.tcp < 20 || t.data > t.end {
		return t, false
	}
	t.flow = TCPFlow{
		Src: netip.AddrPortFrom(src, binary.BigEndian.Uint16(th[0:2])),
		Dst: netip.AddrPortFrom(dst, binary.BigEndian.Uint16(th[2:4])),
	}
	return t, true
}

// TCPFlowOf returns the direction of the TCP connection that frame
// belongs to.
func TCPFlowOf(frame []byte) (TCPFlow, bool) {
	t, ok := parseTCP(frame)
	return t.flow, ok
}

// SYNMSS returns the flow of a SYN (or SYN-ACK) segment and the maximum
// segment size its sender is willing to receive.
func SYNMSS(frame []byte) (TCPFlow, int, bool) {
	t, ok := parseTCP(frame)
	if !ok || frame[t.tcp+13]&tcpSYN == 0 {
		return TCPFlow{}, 0, false
	}
	opts := frame[t.tcp+20 : t.data]
	for len(opts) > 0 {
		switch opts[0] {
		case 0: // end of options
			return t.flow, DefaultMSS, true
		case 1: // no-op
			opts = opts[1:]
			continue
		}
		if len(opts) < 2 || int(opts[1]) < 2 || int(opts[1]) > len(opts) {
			return t.flow, DefaultMSS, true
		}
		if opts[0] == 2 && opts[1] == 4 {
			return t.flow, int(binary.BigEndian.Uint16(opts[2:4])), true
		}
		opts = opts[opts[1]:]
	}
	return t.flow, DefaultMSS, true
}

// SegmentTCP splits an oversized TCP frame into frames of at most MaxFrame
// bytes carrying at most mss bytes of payload each.
//
// Linux receive offload (GRO) merges consecutive segments of a TCP stream
// into one large packet before a packet capture sees it, and leaves only
// the pseudo-header sum in its TCP checksum. Like the kernel's own
// segmentation offload, this puts CWR on the first segment only, and PSH
// and FIN on the last only, and recomputes the checksums. It returns false
// if frame is not a TCP segment it can split.
func SegmentTCP(frame []byte, mss int) ([][]byte, bool) {
	t, ok := parseTCP(frame)
	if !ok {
		return nil, false
	}
	optLen := t.data - t.tcp - 20
	// The MSS does not include TCP options (RFC 6691).
	size := min(mss-optLen, MaxFrame-t.data)
	if size <= 0 {
		return nil, false
	}
	payload := frame[t.data:t.end]
	th := frame[t.tcp:t.data]
	seq := binary.BigEndian.Uint32(th[4:8])
	flags := th[13]
	var id uint16
	if !t.v6 {
		id = binary.BigEndian.Uint16(frame[t.ip+4 : t.ip+6])
	}

	var segs [][]byte
	for off := 0; off < len(payload) || off == 0; off += size {
		n := min(size, len(payload)-off)
		last := off+n >= len(payload)
		seg := make([]byte, 0, t.data+n)
		seg = append(seg, frame[:t.data]...)
		seg = append(seg, payload[off:off+n]...)

		ip := seg[t.ip:t.tcp]
		if t.v6 {
			binary.BigEndian.PutUint16(ip[4:6], uint16(len(seg)-t.tcp))
		} else {
			binary.BigEndian.PutUint16(ip[2:4], uint16(len(seg)-t.ip))
			binary.BigEndian.PutUint16(ip[4:6], id+uint16(len(segs)))
			ip[10], ip[11] = 0, 0
			binary.BigEndian.PutUint16(ip[10:12], ^sum(0, ip))
		}

		h := seg[t.tcp:t.data]
		binary.BigEndian.PutUint32(h[4:8], seq+uint32(off))
		f := flags
		if off != 0 {
			f &^= tcpCWR
		}
		if !last {
			f &^= tcpFIN | tcpPSH
		}
		h[13] = f
		h[16], h[17] = 0, 0
		binary.BigEndian.PutUint16(h[16:18], ^sum(pseudoSum(seg, t), seg[t.tcp:]))
		segs = append(segs, seg)
		if last {
			break
		}
	}
	return segs, true
}

// pseudoSum is the sum of the IP pseudo-header of the TCP segment in seg.
func pseudoSum(seg []byte, t tcpFrame) uint32 {
	addrs := seg[t.ip+12 : t.ip+20]
	if t.v6 {
		addrs = seg[t.ip+8 : t.ip+40]
	}
	s := uint32(sum(0, addrs))
	l := uint32(len(seg) - t.tcp)
	return s + l>>16 + l&0xffff + 6
}

// sum adds b to the one's complement sum s and folds the result.
func sum(s uint32, b []byte) uint16 {
	for len(b) >= 2 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		s += uint32(b[0]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return uint16(s)
}
