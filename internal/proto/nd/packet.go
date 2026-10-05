package nd

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// IPProto is the IP protocol number of ND.
const IPProto = 77

// Operations and flags.
const (
	OpRead   = 1
	OpWrite  = 2
	OpError  = 3
	opMask   = 7
	FlagWait = 1 << 3
	FlagDone = 1 << 4
)

const (
	hdrLen = 28
	// BlockSize is the disk block size.
	BlockSize = 512
	// maxData is the data carried by one reply packet.
	maxData = 1024
	// maxCount is the largest request.
	maxCount = 63 * 1024
	// MinorPublic marks public units (ndp<n>); the Sun-2 PROM boots
	// from ndp0.
	MinorPublic = 0x40
)

// Packet is an ND packet.
type Packet struct {
	Op          uint8
	Minor       uint8
	Error       int8
	DiskVersion int8
	Seq         int32
	Block       int32
	Count       int32 // bytes in the whole request
	Resid       int32
	Offset      int32 // of this packet's data within the request
	PacketCount int32 // bytes in this packet
	Data        []byte
}

func parsePacket(b []byte) (Packet, bool) {
	if len(b) < hdrLen {
		return Packet{}, false
	}
	i32 := func(o int) int32 { return int32(binary.BigEndian.Uint32(b[o:])) }
	return Packet{
		Op: b[0], Minor: b[1], Error: int8(b[2]), DiskVersion: int8(b[3]),
		Seq: i32(4), Block: i32(8), Count: i32(12), Resid: i32(16), Offset: i32(20), PacketCount: i32(24),
		Data: b[hdrLen:],
	}, true
}

func (p Packet) marshal() []byte {
	b := make([]byte, hdrLen, hdrLen+len(p.Data))
	b[0], b[1], b[2], b[3] = p.Op, p.Minor, byte(p.Error), byte(p.DiskVersion)
	for i, v := range []int32{p.Seq, p.Block, p.Count, p.Resid, p.Offset, p.PacketCount} {
		binary.BigEndian.PutUint32(b[4+4*i:], uint32(v))
	}
	return append(b, p.Data...)
}

func (p Packet) String() string {
	return fmt.Sprintf("op %#x minor %#x error %d version %d seq %d block %d count %d offset %d packet %d",
		p.Op, p.Minor, p.Error, p.DiskVersion, p.Seq, p.Block, p.Count, p.Offset, p.PacketCount)
}

// ipv4 is the part of an IPv4 header ND needs.
type ipv4 struct {
	src, dst netip.Addr
	proto    uint8
	payload  []byte
}

func parseIPv4(b []byte) (ipv4, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return ipv4{}, false
	}
	hl := int(b[0]&0xf) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if hl < 20 || total < hl || total > len(b) || checksum(b[:hl]) != 0 {
		return ipv4{}, false
	}
	// Fragments are not reassembled; ND requests are never fragmented.
	if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
		return ipv4{}, false
	}
	return ipv4{
		src:     netip.AddrFrom4([4]byte(b[12:16])),
		dst:     netip.AddrFrom4([4]byte(b[16:20])),
		proto:   b[9],
		payload: b[hl:total],
	}, true
}

// buildIPv4 returns an IPv4 packet with payload.
func buildIPv4(id uint16, src, dst netip.Addr, proto uint8, payload []byte) []byte {
	b := make([]byte, 20, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(b[4:6], id)
	b[8] = 4 // TTL; ND never leaves the local network
	b[9] = proto
	s, d := src.As4(), dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[10:12], checksum(b))
	return append(b, payload...)
}

// checksum is the Internet checksum. Over a header with a valid checksum
// it returns 0.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
