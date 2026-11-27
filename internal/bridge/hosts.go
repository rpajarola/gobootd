package bridge

import (
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
)

// maxProtocols bounds the protocols remembered per host.
const maxProtocols = 8

// bootReplyTimeout is how long a RARP or BOOTP request may wait for a
// reply before it is reported as unanswered.
const bootReplyTimeout = 5 * time.Second

// hostState is what the bridge knows about a host on one side.
type hostState struct {
	ip   netip.Addr
	seen time.Time
	// protocols it sent, in the order first seen.
	protocols []string
	// unanswered is the boot protocol of a request of the host that got
	// no reply, until one comes.
	unanswered string
}

// HostEntry is a host the bridge has seen on an interface.
type HostEntry struct {
	MAC      net.HardwareAddr
	IP       netip.Addr
	LastSeen time.Time
	// Protocols are those the host sent, in the order first seen; the
	// list stops at maxProtocols.
	Protocols []string
	// Unanswered is "RARP" or "BOOTP" while a boot request of the host
	// has had no reply.
	Unanswered string
}

// noteHost records a frame from mac, and reports whether the host is new
// and whether its address just became known. b.mu must be held.
func (s *ifStats) noteHost(mac [6]byte, ip netip.Addr, proto string, now time.Time) (newHost, newIP bool) {
	h, ok := s.hosts[mac]
	if !ok {
		h = &hostState{}
		s.hosts[mac] = h
		newHost = true
	}
	if !h.ip.IsValid() && ip.IsValid() {
		h.ip = ip
		newIP = !newHost
	}
	h.seen = now
	if proto != "" && !slices.Contains(h.protocols, proto) && len(h.protocols) < maxProtocols {
		h.protocols = append(h.protocols, proto)
	}
	return newHost, newIP
}

// LANHosts returns the hosts seen on the LAN side.
func (b *Bridge) LANHosts() []HostEntry { return b.hosts(&b.lanStats) }

// UDPHosts returns the hosts seen on the UDP side.
func (b *Bridge) UDPHosts() []HostEntry { return b.hosts(&b.udpStats) }

func (b *Bridge) hosts(s *ifStats) []HostEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]HostEntry, 0, len(s.hosts))
	for mac, h := range s.hosts {
		out = append(out, HostEntry{
			MAC:        net.HardwareAddr(mac[:]),
			IP:         h.ip,
			LastSeen:   h.seen,
			Protocols:  slices.Clone(h.protocols),
			Unanswered: h.unanswered,
		})
	}
	slices.SortFunc(out, func(a, b HostEntry) int { return slices.Compare(a.MAC, b.MAC) })
	return out
}

// etherPayload returns the ethertype and payload of an Ethernet II or
// 802.3 SNAP frame, and ethertype 0 with the LLC payload for other 802.3
// frames.
func etherPayload(frame []byte) (uint16, []byte) {
	if len(frame) < link.HeaderLen {
		return 0, nil
	}
	t := binary.BigEndian.Uint16(frame[12:14])
	p := frame[link.HeaderLen:]
	if t > link.MaxLength {
		return t, p
	}
	if int(t) <= len(p) {
		p = p[:t]
	}
	if len(p) >= 8 && p[0] == 0xaa && p[1] == 0xaa && p[2] == 0x03 {
		return binary.BigEndian.Uint16(p[6:8]), p[8:]
	}
	return 0, p
}

// udpOf returns the ports and payload of an unfragmented IPv4 UDP
// datagram.
func udpOf(p []byte) (src, dst uint16, data []byte, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != 17 || binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
		return 0, 0, nil, false
	}
	hl := int(p[0]&0x0f) * 4
	if hl < 20 || len(p) < hl+8 {
		return 0, 0, nil, false
	}
	return binary.BigEndian.Uint16(p[hl:]), binary.BigEndian.Uint16(p[hl+2:]), p[hl+8:], true
}

var udpNames = map[uint16]string{
	53: "DNS", 67: "BOOTP", 68: "BOOTP", 69: "TFTP", 111: "RPC", 123: "NTP",
	137: "NetBIOS", 138: "NetBIOS", 514: "syslog", 2049: "NFS", 5353: "mDNS",
}

var tcpNames = map[uint16]string{
	21: "FTP", 22: "SSH", 23: "telnet", 80: "HTTP", 111: "RPC", 513: "rlogin",
	514: "rsh", 2049: "NFS", 6000: "X11",
}

// protocolOf names the protocol of a frame for the hosts list: a well-known
// port of IP, or the protocol above Ethernet.
func protocolOf(frame []byte) string {
	t, p := etherPayload(frame)
	switch t {
	case 0:
		if len(p) < 3 {
			return "802.3"
		}
		switch p[0] {
		case 0xf8:
			return "RMP"
		case 0xfc:
			return "RPL"
		case 0x42:
			return "STP"
		case 0xe0:
			return "IPX"
		case 0xf0:
			return "NetBIOS"
		}
		return "802.3"
	case link.TypeARP:
		return "ARP"
	case link.TypeRARP:
		return "RARP"
	case link.TypeIPv4:
		if len(p) < 20 {
			return "IPv4"
		}
		switch p[9] {
		case 1:
			return "ICMP"
		case 6:
			hl := int(p[0]&0x0f) * 4
			if len(p) >= hl+4 {
				src, dst := binary.BigEndian.Uint16(p[hl:]), binary.BigEndian.Uint16(p[hl+2:])
				if n, ok := tcpNames[min(src, dst)]; ok {
					return n
				}
				if n, ok := tcpNames[max(src, dst)]; ok {
					return n
				}
			}
			return "TCP"
		case 17:
			if src, dst, _, ok := udpOf(p); ok {
				if n, ok := udpNames[min(src, dst)]; ok {
					return n
				}
				if n, ok := udpNames[max(src, dst)]; ok {
					return n
				}
			}
			return "UDP"
		}
		return "IPv4"
	case link.TypeIPv6:
		return "IPv6"
	case 0x6001:
		return "MOP"
	case 0x6002:
		return "MOP console"
	case 0x6003:
		return "DECnet"
	case 0x6004:
		return "LAT"
	case 0x8137:
		return "IPX"
	case 0x809b:
		return "AppleTalk"
	case link.TypeLoopback:
		return "loopback"
	}
	return "other"
}

// bootMessage is a RARP or BOOTP request or reply.
type bootMessage struct {
	proto  string // "RARP" or "BOOTP"
	reply  bool
	client [6]byte
	ip     netip.Addr // the client's, in a reply
}

// parseBoot recognises RARP and BOOTP requests and replies.
func parseBoot(frame []byte) (bootMessage, bool) {
	t, p := etherPayload(frame)
	switch t {
	case link.TypeRARP:
		if len(p) < 28 || binary.BigEndian.Uint16(p[0:2]) != 1 || binary.BigEndian.Uint16(p[2:4]) != link.TypeIPv4 || p[4] != 6 || p[5] != 4 {
			return bootMessage{}, false
		}
		m := bootMessage{proto: "RARP", client: [6]byte(p[18:24])}
		switch binary.BigEndian.Uint16(p[6:8]) {
		case 3:
		case 4:
			m.reply, m.ip = true, netip.AddrFrom4([4]byte(p[24:28]))
		default:
			return bootMessage{}, false
		}
		return m, true
	case link.TypeIPv4:
		src, dst, d, ok := udpOf(p)
		if !ok || len(d) < 236 || d[1] != 1 || d[2] != 6 {
			return bootMessage{}, false
		}
		m := bootMessage{proto: "BOOTP", client: [6]byte(d[28:34])}
		switch {
		case d[0] == 1 && dst == 67:
		case d[0] == 2 && src == 67:
			m.reply, m.ip = true, netip.AddrFrom4([4]byte(d[16:20]))
		default:
			return bootMessage{}, false
		}
		return m, true
	}
	return bootMessage{}, false
}

// bootRequest is a boot request of a client waiting for a reply.
type bootRequest struct {
	proto  string
	side   *ifStats
	iface  string
	first  time.Time
	logged bool
}

// observeBoot follows the RARP and BOOTP requests that pass, and the
// replies to them: a reply tells the client's address, and a request
// without one is reported by checkBoot.
func (b *Bridge) observeBoot(side *ifStats, iface string, frame []byte, now time.Time) {
	m, ok := parseBoot(frame)
	if !ok || m.client == [6]byte{} {
		return
	}
	mac := net.HardwareAddr(m.client[:])
	if !m.reply {
		b.mu.Lock()
		if b.boot == nil {
			b.boot = map[[6]byte]*bootRequest{}
		}
		if _, ok := b.boot[m.client]; !ok {
			b.boot[m.client] = &bootRequest{proto: m.proto, side: side, iface: iface, first: now}
		}
		b.mu.Unlock()
		return
	}
	var learned []string
	b.mu.Lock()
	r := b.boot[m.client]
	delete(b.boot, m.client)
	for _, s := range []*ifStats{&b.lanStats, &b.udpStats} {
		h, ok := s.hosts[m.client]
		if !ok {
			continue
		}
		h.unanswered = ""
		if m.ip.IsValid() && !m.ip.IsUnspecified() && h.ip != m.ip {
			h.ip = m.ip
			learned = append(learned, b.sideName(s))
		}
	}
	b.mu.Unlock()
	for _, side := range learned {
		b.logger().Info("host ip", "interface", side, "mac", mac.String(), "ip", m.ip.String(), "from", m.proto+" reply")
	}
	if r != nil && r.logged {
		b.logger().Info("boot request answered", "interface", r.iface, "mac", mac.String(),
			"protocol", m.proto, "after", now.Sub(r.first).Round(time.Millisecond).String())
	}
}

// checkBoot reports the boot requests that waited longer than
// bootReplyTimeout, once each, and forgets those that are too old.
func (b *Bridge) checkBoot(now time.Time) {
	type late struct {
		mac net.HardwareAddr
		r   bootRequest
	}
	var lates []late
	b.mu.Lock()
	for mac, r := range b.boot {
		age := now.Sub(r.first)
		if age >= lanTimeout {
			delete(b.boot, mac)
			continue
		}
		if r.logged || age < bootReplyTimeout {
			continue
		}
		r.logged = true
		if h, ok := r.side.hosts[mac]; ok {
			h.unanswered = r.proto
		}
		lates = append(lates, late{net.HardwareAddr(mac[:]), *r})
	}
	b.mu.Unlock()
	slices.SortFunc(lates, func(x, y late) int { return slices.Compare(x.mac, y.mac) })
	for _, l := range lates {
		b.logger().Warn("boot request not answered", "interface", l.r.iface, "mac", l.mac.String(),
			"protocol", l.r.proto, "waited", now.Sub(l.r.first).Round(time.Second).String())
	}
}

// sideName is the interface name of the side s holds the hosts of.
func (b *Bridge) sideName(s *ifStats) string {
	if s == &b.lanStats {
		return b.lanName()
	}
	return b.udpName()
}
